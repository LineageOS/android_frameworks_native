/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "InputDispatcherPolicyInterface.h"

#include "InputDispatcherInterface.h"
#include "NotifyArgs.h"

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/thread_annotations.h>
#include <binder/IBinder.h>
#include <gui/PidUid.h>
#include <gui/WindowInfo.h>
#include <input/BlockingQueue.h>
#include <input/Input.h>

namespace android {

class FakeInputDispatcherPolicy : public InputDispatcherPolicyInterface {
public:
    FakeInputDispatcherPolicy() = default;
    virtual ~FakeInputDispatcherPolicy() = default;

    struct AnrResult {
        sp<IBinder> token{};
        std::optional<gui::Pid> pid{};
    };

    struct UserActivityPokeEvent {
        nsecs_t eventTime;
        int32_t eventType;
        ui::LogicalDisplayId displayId;

        bool operator==(const UserActivityPokeEvent& rhs) const = default;
        inline friend std::ostream& operator<<(std::ostream& os, const UserActivityPokeEvent& ev) {
            os << "UserActivityPokeEvent[time=" << ev.eventTime << ", eventType=" << ev.eventType
               << ", displayId=" << ev.displayId << "]";
            return os;
        }
    };

    void assertFilterInputEventWasCalled(const NotifyKeyArgs& args);
    void assertFilterInputEventWasCalled(const NotifyMotionArgs& args, vec2 point);
    void assertFilterInputEventWasNotCalled();
    void assertNotifyConfigurationChangedWasCalled(nsecs_t when);
    void assertNotifySwitchWasCalled(const NotifySwitchArgs& args);
    void assertOnPointerDownEquals(const sp<IBinder>& touchedToken);
    void assertOnPointerDownWasNotCalled();
    /**
     * This function must be called soon after the expected ANR timer starts,
     * because we are also checking how much time has passed.
     */
    void assertNotifyNoFocusedWindowAnrWasCalled(
            std::chrono::nanoseconds timeout,
            const std::shared_ptr<InputApplicationHandle>& expectedApplication);
    void assertNotifyWindowUnresponsiveWasCalled(std::chrono::nanoseconds timeout,
                                                 const sp<gui::WindowInfoHandle>& window);
    void assertNotifyWindowUnresponsiveWasCalled(std::chrono::nanoseconds timeout,
                                                 const sp<IBinder>& expectedToken,
                                                 std::optional<gui::Pid> expectedPid);
    /** Wrap call with ASSERT_NO_FATAL_FAILURE() to ensure the return value is valid. */
    sp<IBinder> getUnresponsiveWindowToken(std::chrono::nanoseconds timeout);
    void assertNotifyWindowResponsiveWasCalled(const sp<IBinder>& expectedToken,
                                               std::optional<gui::Pid> expectedPid);
    /** Wrap call with ASSERT_NO_FATAL_FAILURE() to ensure the return value is valid. */
    sp<IBinder> getResponsiveWindowToken();
    void assertNotifyAnrWasNotCalled();
    PointerCaptureRequest assertSetPointerCaptureCalled(const sp<gui::WindowInfoHandle>& window,
                                                        bool enabled);
    void assertSetPointerCaptureNotCalled();
    void assertDropTargetEquals(const InputDispatcherInterface& dispatcher,
                                const sp<IBinder>& targetToken);
    void assertNotifyInputChannelBrokenWasCalled(const sp<IBinder>& token);
    /**
     * Set policy timeout. A value of zero means next key will not be intercepted.
     */
    void setInterceptKeyTimeout(std::chrono::milliseconds timeout);
    std::chrono::nanoseconds getKeyWaitingForEventsTimeout() override;
    void setStaleEventTimeout(std::chrono::nanoseconds timeout);
    void assertUserActivityNotPoked();
    /**
     * Asserts that a user activity poke has happened. The earliest recorded poke event will be
     * cleared after this call.
     *
     * If an expected UserActivityPokeEvent is provided, asserts that the given event is the
     * earliest recorded poke event.
     */
    void assertUserActivityPoked(std::optional<UserActivityPokeEvent> expectedPokeEvent = {});
    void assertNotifyDeviceInteractionWasCalled(int32_t deviceId, std::set<gui::Uid> uids);
    void assertNotifyDeviceInteractionWasNotCalled();
    void setUnhandledKeyHandler(std::function<std::optional<KeyEvent>(const KeyEvent&)> handler);
    void assertUnhandledKeyReported(int32_t keycode);
    void assertUnhandledKeyNotReported();

private:
    std::mutex mLock;
    std::unique_ptr<InputEvent> mFilteredEvent GUARDED_BY(mLock);
    std::optional<nsecs_t> mConfigurationChangedTime GUARDED_BY(mLock);
    sp<IBinder> mOnPointerDownToken GUARDED_BY(mLock);
    std::optional<NotifySwitchArgs> mLastNotifySwitch GUARDED_BY(mLock);

    std::condition_variable mPointerCaptureChangedCondition;

    std::optional<PointerCaptureRequest> mPointerCaptureRequest GUARDED_BY(mLock);
    // ANR handling
    std::queue<std::shared_ptr<InputApplicationHandle>> mAnrApplications GUARDED_BY(mLock);
    std::queue<AnrResult> mAnrWindows GUARDED_BY(mLock);
    std::queue<AnrResult> mResponsiveWindows GUARDED_BY(mLock);
    std::condition_variable mNotifyAnr;
    std::queue<sp<IBinder>> mBrokenInputChannels GUARDED_BY(mLock);
    std::condition_variable mNotifyInputChannelBroken;

    sp<IBinder> mDropTargetWindowToken GUARDED_BY(mLock);
    bool mNotifyDropWindowWasCalled GUARDED_BY(mLock) = false;

    std::condition_variable mNotifyUserActivity;
    std::queue<UserActivityPokeEvent> mUserActivityPokeEvents;

    std::chrono::milliseconds mInterceptKeyTimeout = 0ms;

    std::chrono::nanoseconds mStaleEventTimeout = 1000ms;

    BlockingQueue<std::pair<int32_t /*deviceId*/, std::set<gui::Uid>>> mNotifiedInteractions;

    std::condition_variable mNotifyUnhandledKey;
    std::queue<int32_t> mReportedUnhandledKeycodes GUARDED_BY(mLock);
    std::function<std::optional<KeyEvent>(const KeyEvent&)> mUnhandledKeyHandler GUARDED_BY(mLock);

    /**
     * All three ANR-related callbacks behave the same way, so we use this generic function to wait
     * for a specific container to become non-empty. When the container is non-empty, return the
     * first entry from the container and erase it.
     */
    template <class T>
    T getAnrTokenLockedInterruptible(std::chrono::nanoseconds timeout, std::queue<T>& storage,
                                     std::unique_lock<std::mutex>& lock) REQUIRES(mLock);

    template <class T>
    std::optional<T> getItemFromStorageLockedInterruptible(std::chrono::nanoseconds timeout,
                                                           std::queue<T>& storage,
                                                           std::unique_lock<std::mutex>& lock,
                                                           std::condition_variable& condition)
            REQUIRES(mLock);

    void notifyConfigurationChanged(nsecs_t when) override;
    void notifyWindowUnresponsive(const sp<IBinder>& connectionToken, std::optional<gui::Pid> pid,
                                  const std::string&) override;
    void notifyWindowResponsive(const sp<IBinder>& connectionToken,
                                std::optional<gui::Pid> pid) override;
    void notifyNoFocusedWindowAnr(
            const std::shared_ptr<InputApplicationHandle>& applicationHandle) override;
    void notifyInputChannelBroken(const sp<IBinder>& connectionToken) override;
    void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) override;
    void notifySensorEvent(int32_t deviceId, InputDeviceSensorType sensorType,
                           InputDeviceSensorAccuracy accuracy, nsecs_t timestamp,
                           const std::vector<float>& values) override;
    void notifySensorAccuracy(int deviceId, InputDeviceSensorType sensorType,
                              InputDeviceSensorAccuracy accuracy) override;
    void notifyVibratorState(int32_t deviceId, bool isOn) override;
    bool filterInputEvent(const InputEvent& inputEvent, uint32_t policyFlags) override;
    void interceptKeyBeforeQueueing(const KeyEvent& inputEvent, uint32_t&) override;
    void interceptMotionBeforeQueueing(ui::LogicalDisplayId, uint32_t, int32_t, nsecs_t,
                                       uint32_t&) override;
    nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent&, uint32_t) override;
    std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent& event,
                                                 uint32_t) override;
    void notifySwitch(nsecs_t when, uint32_t switchValues, uint32_t switchMask,
                      uint32_t policyFlags) override;
    void pokeUserActivity(nsecs_t eventTime, int32_t eventType,
                          ui::LogicalDisplayId displayId) override;
    bool isStaleEvent(nsecs_t currentTime, nsecs_t eventTime) override;
    void onPointerDownOutsideFocus(const sp<IBinder>& newToken) override;
    void setPointerCapture(const PointerCaptureRequest& request) override;
    void notifyDropWindow(const sp<IBinder>& token, float x, float y) override;
    void notifyDeviceInteraction(int32_t deviceId, nsecs_t timestamp,
                                 const std::set<gui::Uid>& uids) override;

    void assertFilterInputEventWasCalledInternal(
            const std::function<void(const InputEvent&)>& verify);
};

} // namespace android
