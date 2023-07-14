/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include "../dispatcher/InputDispatcher.h"
#include "../BlockingQueue.h"

#include <NotifyArgsBuilders.h>
#include <android-base/properties.h>
#include <android-base/silent_death_test.h>
#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <binder/Binder.h>
#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <linux/input.h>
#include <sys/epoll.h>

#include <cinttypes>
#include <compare>
#include <thread>
#include <unordered_set>
#include <vector>

using android::base::StringPrintf;
using android::gui::FocusRequest;
using android::gui::TouchOcclusionMode;
using android::gui::WindowInfo;
using android::gui::WindowInfoHandle;
using android::os::InputEventInjectionResult;
using android::os::InputEventInjectionSync;

namespace android::inputdispatcher {

using namespace ftl::flag_operators;
using testing::AllOf;

// An arbitrary time value.
static constexpr nsecs_t ARBITRARY_TIME = 1234;

// An arbitrary device id.
static constexpr int32_t DEVICE_ID = DEFAULT_DEVICE_ID;
static constexpr int32_t SECOND_DEVICE_ID = 2;

// An arbitrary display id.
static constexpr int32_t DISPLAY_ID = ADISPLAY_ID_DEFAULT;
static constexpr int32_t SECOND_DISPLAY_ID = 1;

// Ensure common actions are interchangeable between keys and motions for convenience.
static_assert(AMOTION_EVENT_ACTION_DOWN == AKEY_EVENT_ACTION_DOWN);
static_assert(AMOTION_EVENT_ACTION_UP == AKEY_EVENT_ACTION_UP);
static constexpr int32_t ACTION_DOWN = AMOTION_EVENT_ACTION_DOWN;
static constexpr int32_t ACTION_MOVE = AMOTION_EVENT_ACTION_MOVE;
static constexpr int32_t ACTION_UP = AMOTION_EVENT_ACTION_UP;
static constexpr int32_t ACTION_HOVER_ENTER = AMOTION_EVENT_ACTION_HOVER_ENTER;
static constexpr int32_t ACTION_HOVER_MOVE = AMOTION_EVENT_ACTION_HOVER_MOVE;
static constexpr int32_t ACTION_HOVER_EXIT = AMOTION_EVENT_ACTION_HOVER_EXIT;
static constexpr int32_t ACTION_OUTSIDE = AMOTION_EVENT_ACTION_OUTSIDE;
static constexpr int32_t ACTION_CANCEL = AMOTION_EVENT_ACTION_CANCEL;
/**
 * The POINTER_DOWN(0) is an unusual, but valid, action. It just means that the new pointer in the
 * MotionEvent is at the index 0 rather than 1 (or later). That is, the pointer id=0 (which is at
 * index 0) is the new pointer going down. The same pointer could have been placed at a different
 * index, and the action would become POINTER_1_DOWN, 2, etc..; these would all be valid. In
 * general, we try to place pointer id = 0 at the index 0. Of course, this is not possible if
 * pointer id=0 leaves but the pointer id=1 remains.
 */
static constexpr int32_t POINTER_0_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_2_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_3_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (3 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_0_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_1_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_2_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

// The default pid and uid for windows created on the primary display by the test.
static constexpr gui::Pid WINDOW_PID{999};
static constexpr gui::Uid WINDOW_UID{1001};

// The default pid and uid for the windows created on the secondary display by the test.
static constexpr gui::Pid SECONDARY_WINDOW_PID{1010};
static constexpr gui::Uid SECONDARY_WINDOW_UID{1012};

// An arbitrary pid of the gesture monitor window
static constexpr gui::Pid MONITOR_PID{2001};

static constexpr std::chrono::duration STALE_EVENT_TIMEOUT = 1000ms;

static constexpr int expectedWallpaperFlags =
        AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED | AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED;

using ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID;

struct PointF {
    float x;
    float y;
    auto operator<=>(const PointF&) const = default;
};

/**
 * Return a DOWN key event with KEYCODE_A.
 */
static KeyEvent getTestKeyEvent() {
    KeyEvent event;

    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
                     INVALID_HMAC, AKEY_EVENT_ACTION_DOWN, 0, AKEYCODE_A, KEY_A, AMETA_NONE, 0,
                     ARBITRARY_TIME, ARBITRARY_TIME);
    return event;
}

static void assertMotionAction(int32_t expectedAction, int32_t receivedAction) {
    ASSERT_EQ(expectedAction, receivedAction)
            << "expected " << MotionEvent::actionToString(expectedAction) << ", got "
            << MotionEvent::actionToString(receivedAction);
}

MATCHER_P(WithMotionAction, action, "MotionEvent with specified action") {
    bool matches = action == arg.getAction();
    if (!matches) {
        *result_listener << "expected action " << MotionEvent::actionToString(action)
                         << ", but got " << MotionEvent::actionToString(arg.getAction());
    }
    if (action == AMOTION_EVENT_ACTION_DOWN) {
        if (!matches) {
            *result_listener << "; ";
        }
        *result_listener << "downTime should match eventTime for ACTION_DOWN events";
        matches &= arg.getDownTime() == arg.getEventTime();
    }
    if (action == AMOTION_EVENT_ACTION_CANCEL) {
        if (!matches) {
            *result_listener << "; ";
        }
        *result_listener << "expected FLAG_CANCELED to be set with ACTION_CANCEL, but was not set";
        matches &= (arg.getFlags() & AMOTION_EVENT_FLAG_CANCELED) != 0;
    }
    return matches;
}

MATCHER_P(WithDownTime, downTime, "InputEvent with specified downTime") {
    return arg.getDownTime() == downTime;
}

MATCHER_P(WithDisplayId, displayId, "InputEvent with specified displayId") {
    return arg.getDisplayId() == displayId;
}

MATCHER_P(WithDeviceId, deviceId, "InputEvent with specified deviceId") {
    return arg.getDeviceId() == deviceId;
}

MATCHER_P(WithSource, source, "InputEvent with specified source") {
    *result_listener << "expected source " << inputEventSourceToString(source) << ", but got "
                     << inputEventSourceToString(arg.getSource());
    return arg.getSource() == source;
}

MATCHER_P(WithFlags, flags, "InputEvent with specified flags") {
    return arg.getFlags() == flags;
}

MATCHER_P2(WithCoords, x, y, "MotionEvent with specified coordinates") {
    if (arg.getPointerCount() != 1) {
        *result_listener << "Expected 1 pointer, got " << arg.getPointerCount();
        return false;
    }
    return arg.getX(/*pointerIndex=*/0) == x && arg.getY(/*pointerIndex=*/0) == y;
}

MATCHER_P(WithPointerCount, pointerCount, "MotionEvent with specified number of pointers") {
    return arg.getPointerCount() == pointerCount;
}

MATCHER_P(WithPointers, pointers, "MotionEvent with specified pointers") {
    // Build a map for the received pointers, by pointer id
    std::map<int32_t /*pointerId*/, PointF> actualPointers;
    for (size_t pointerIndex = 0; pointerIndex < arg.getPointerCount(); pointerIndex++) {
        const int32_t pointerId = arg.getPointerId(pointerIndex);
        actualPointers[pointerId] = {arg.getX(pointerIndex), arg.getY(pointerIndex)};
    }
    return pointers == actualPointers;
}

// --- FakeInputDispatcherPolicy ---

class FakeInputDispatcherPolicy : public InputDispatcherPolicyInterface {
    InputDispatcherConfiguration mConfig;

    struct AnrResult {
        sp<IBinder> token{};
        gui::Pid pid{-1};
    };

public:
    FakeInputDispatcherPolicy() = default;
    virtual ~FakeInputDispatcherPolicy() = default;

    void assertFilterInputEventWasCalled(const NotifyKeyArgs& args) {
        assertFilterInputEventWasCalledInternal([&args](const InputEvent& event) {
            ASSERT_EQ(event.getType(), InputEventType::KEY);
            EXPECT_EQ(event.getDisplayId(), args.displayId);

            const auto& keyEvent = static_cast<const KeyEvent&>(event);
            EXPECT_EQ(keyEvent.getEventTime(), args.eventTime);
            EXPECT_EQ(keyEvent.getAction(), args.action);
        });
    }

    void assertFilterInputEventWasCalled(const NotifyMotionArgs& args, vec2 point) {
        assertFilterInputEventWasCalledInternal([&](const InputEvent& event) {
            ASSERT_EQ(event.getType(), InputEventType::MOTION);
            EXPECT_EQ(event.getDisplayId(), args.displayId);

            const auto& motionEvent = static_cast<const MotionEvent&>(event);
            EXPECT_EQ(motionEvent.getEventTime(), args.eventTime);
            EXPECT_EQ(motionEvent.getAction(), args.action);
            EXPECT_NEAR(motionEvent.getX(0), point.x, MotionEvent::ROUNDING_PRECISION);
            EXPECT_NEAR(motionEvent.getY(0), point.y, MotionEvent::ROUNDING_PRECISION);
            EXPECT_NEAR(motionEvent.getRawX(0), point.x, MotionEvent::ROUNDING_PRECISION);
            EXPECT_NEAR(motionEvent.getRawY(0), point.y, MotionEvent::ROUNDING_PRECISION);
        });
    }

    void assertFilterInputEventWasNotCalled() {
        std::scoped_lock lock(mLock);
        ASSERT_EQ(nullptr, mFilteredEvent);
    }

    void assertNotifyConfigurationChangedWasCalled(nsecs_t when) {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mConfigurationChangedTime)
                << "Timed out waiting for configuration changed call";
        ASSERT_EQ(*mConfigurationChangedTime, when);
        mConfigurationChangedTime = std::nullopt;
    }

    void assertNotifySwitchWasCalled(const NotifySwitchArgs& args) {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mLastNotifySwitch);
        // We do not check id because it is not exposed to the policy
        EXPECT_EQ(args.eventTime, mLastNotifySwitch->eventTime);
        EXPECT_EQ(args.policyFlags, mLastNotifySwitch->policyFlags);
        EXPECT_EQ(args.switchValues, mLastNotifySwitch->switchValues);
        EXPECT_EQ(args.switchMask, mLastNotifySwitch->switchMask);
        mLastNotifySwitch = std::nullopt;
    }

    void assertOnPointerDownEquals(const sp<IBinder>& touchedToken) {
        std::scoped_lock lock(mLock);
        ASSERT_EQ(touchedToken, mOnPointerDownToken);
        mOnPointerDownToken.clear();
    }

    void assertOnPointerDownWasNotCalled() {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mOnPointerDownToken == nullptr)
                << "Expected onPointerDownOutsideFocus to not have been called";
    }

    // This function must be called soon after the expected ANR timer starts,
    // because we are also checking how much time has passed.
    void assertNotifyNoFocusedWindowAnrWasCalled(
            std::chrono::nanoseconds timeout,
            const std::shared_ptr<InputApplicationHandle>& expectedApplication) {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        std::shared_ptr<InputApplicationHandle> application;
        ASSERT_NO_FATAL_FAILURE(
                application = getAnrTokenLockedInterruptible(timeout, mAnrApplications, lock));
        ASSERT_EQ(expectedApplication, application);
    }

    void assertNotifyWindowUnresponsiveWasCalled(std::chrono::nanoseconds timeout,
                                                 const sp<WindowInfoHandle>& window) {
        LOG_ALWAYS_FATAL_IF(window == nullptr, "window should not be null");
        assertNotifyWindowUnresponsiveWasCalled(timeout, window->getToken(),
                                                window->getInfo()->ownerPid);
    }

    void assertNotifyWindowUnresponsiveWasCalled(std::chrono::nanoseconds timeout,
                                                 const sp<IBinder>& expectedToken,
                                                 gui::Pid expectedPid) {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        AnrResult result;
        ASSERT_NO_FATAL_FAILURE(result =
                                        getAnrTokenLockedInterruptible(timeout, mAnrWindows, lock));
        ASSERT_EQ(expectedToken, result.token);
        ASSERT_EQ(expectedPid, result.pid);
    }

    /** Wrap call with ASSERT_NO_FATAL_FAILURE() to ensure the return value is valid. */
    sp<IBinder> getUnresponsiveWindowToken(std::chrono::nanoseconds timeout) {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        AnrResult result = getAnrTokenLockedInterruptible(timeout, mAnrWindows, lock);
        const auto& [token, _] = result;
        return token;
    }

    void assertNotifyWindowResponsiveWasCalled(const sp<IBinder>& expectedToken,
                                               gui::Pid expectedPid) {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        AnrResult result;
        ASSERT_NO_FATAL_FAILURE(
                result = getAnrTokenLockedInterruptible(0s, mResponsiveWindows, lock));
        ASSERT_EQ(expectedToken, result.token);
        ASSERT_EQ(expectedPid, result.pid);
    }

    /** Wrap call with ASSERT_NO_FATAL_FAILURE() to ensure the return value is valid. */
    sp<IBinder> getResponsiveWindowToken() {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        AnrResult result = getAnrTokenLockedInterruptible(0s, mResponsiveWindows, lock);
        const auto& [token, _] = result;
        return token;
    }

    void assertNotifyAnrWasNotCalled() {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mAnrApplications.empty());
        ASSERT_TRUE(mAnrWindows.empty());
        ASSERT_TRUE(mResponsiveWindows.empty())
                << "ANR was not called, but please also consume the 'connection is responsive' "
                   "signal";
    }

    void setKeyRepeatConfiguration(nsecs_t timeout, nsecs_t delay) {
        mConfig.keyRepeatTimeout = timeout;
        mConfig.keyRepeatDelay = delay;
    }

    PointerCaptureRequest assertSetPointerCaptureCalled(bool enabled) {
        std::unique_lock lock(mLock);
        base::ScopedLockAssertion assumeLocked(mLock);

        if (!mPointerCaptureChangedCondition.wait_for(lock, 100ms,
                                                      [this, enabled]() REQUIRES(mLock) {
                                                          return mPointerCaptureRequest->enable ==
                                                                  enabled;
                                                      })) {
            ADD_FAILURE() << "Timed out waiting for setPointerCapture(" << enabled
                          << ") to be called.";
            return {};
        }
        auto request = *mPointerCaptureRequest;
        mPointerCaptureRequest.reset();
        return request;
    }

    void assertSetPointerCaptureNotCalled() {
        std::unique_lock lock(mLock);
        base::ScopedLockAssertion assumeLocked(mLock);

        if (mPointerCaptureChangedCondition.wait_for(lock, 100ms) != std::cv_status::timeout) {
            FAIL() << "Expected setPointerCapture(request) to not be called, but was called. "
                      "enabled = "
                   << std::to_string(mPointerCaptureRequest->enable);
        }
        mPointerCaptureRequest.reset();
    }

    void assertDropTargetEquals(const InputDispatcherInterface& dispatcher,
                                const sp<IBinder>& targetToken) {
        dispatcher.waitForIdle();
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mNotifyDropWindowWasCalled);
        ASSERT_EQ(targetToken, mDropTargetWindowToken);
        mNotifyDropWindowWasCalled = false;
    }

    void assertNotifyInputChannelBrokenWasCalled(const sp<IBinder>& token) {
        std::unique_lock lock(mLock);
        base::ScopedLockAssertion assumeLocked(mLock);
        std::optional<sp<IBinder>> receivedToken =
                getItemFromStorageLockedInterruptible(100ms, mBrokenInputChannels, lock,
                                                      mNotifyInputChannelBroken);
        ASSERT_TRUE(receivedToken.has_value());
        ASSERT_EQ(token, *receivedToken);
    }

    /**
     * Set policy timeout. A value of zero means next key will not be intercepted.
     */
    void setInterceptKeyTimeout(std::chrono::milliseconds timeout) {
        mInterceptKeyTimeout = timeout;
    }

    void assertUserActivityPoked() {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mPokedUserActivity) << "Expected user activity to have been poked";
    }

    void assertUserActivityNotPoked() {
        std::scoped_lock lock(mLock);
        ASSERT_FALSE(mPokedUserActivity) << "Expected user activity not to have been poked";
    }

    void assertNotifyDeviceInteractionWasCalled(int32_t deviceId, std::set<gui::Uid> uids) {
        ASSERT_EQ(std::make_pair(deviceId, uids), mNotifiedInteractions.popWithTimeout(100ms));
    }

    void assertNotifyDeviceInteractionWasNotCalled() {
        ASSERT_FALSE(mNotifiedInteractions.popWithTimeout(10ms));
    }

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
    bool mPokedUserActivity GUARDED_BY(mLock) = false;

    std::chrono::milliseconds mInterceptKeyTimeout = 0ms;

    BlockingQueue<std::pair<int32_t /*deviceId*/, std::set<gui::Uid>>> mNotifiedInteractions;

    // All three ANR-related callbacks behave the same way, so we use this generic function to wait
    // for a specific container to become non-empty. When the container is non-empty, return the
    // first entry from the container and erase it.
    template <class T>
    T getAnrTokenLockedInterruptible(std::chrono::nanoseconds timeout, std::queue<T>& storage,
                                     std::unique_lock<std::mutex>& lock) REQUIRES(mLock) {
        // If there is an ANR, Dispatcher won't be idle because there are still events
        // in the waitQueue that we need to check on. So we can't wait for dispatcher to be idle
        // before checking if ANR was called.
        // Since dispatcher is not guaranteed to call notifyNoFocusedWindowAnr right away, we need
        // to provide it some time to act. 100ms seems reasonable.
        std::chrono::duration timeToWait = timeout + 100ms; // provide some slack
        const std::chrono::time_point start = std::chrono::steady_clock::now();
        std::optional<T> token =
                getItemFromStorageLockedInterruptible(timeToWait, storage, lock, mNotifyAnr);
        if (!token.has_value()) {
            ADD_FAILURE() << "Did not receive the ANR callback";
            return {};
        }

        const std::chrono::duration waited = std::chrono::steady_clock::now() - start;
        // Ensure that the ANR didn't get raised too early. We can't be too strict here because
        // the dispatcher started counting before this function was called
        if (std::chrono::abs(timeout - waited) > 100ms) {
            ADD_FAILURE() << "ANR was raised too early or too late. Expected "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count()
                          << "ms, but waited "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(waited).count()
                          << "ms instead";
        }
        return *token;
    }

    template <class T>
    std::optional<T> getItemFromStorageLockedInterruptible(std::chrono::nanoseconds timeout,
                                                           std::queue<T>& storage,
                                                           std::unique_lock<std::mutex>& lock,
                                                           std::condition_variable& condition)
            REQUIRES(mLock) {
        condition.wait_for(lock, timeout,
                           [&storage]() REQUIRES(mLock) { return !storage.empty(); });
        if (storage.empty()) {
            ADD_FAILURE() << "Did not receive the expected callback";
            return std::nullopt;
        }
        T item = storage.front();
        storage.pop();
        return std::make_optional(item);
    }

    void notifyConfigurationChanged(nsecs_t when) override {
        std::scoped_lock lock(mLock);
        mConfigurationChangedTime = when;
    }

    void notifyWindowUnresponsive(const sp<IBinder>& connectionToken, std::optional<gui::Pid> pid,
                                  const std::string&) override {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(pid.has_value());
        mAnrWindows.push({connectionToken, *pid});
        mNotifyAnr.notify_all();
    }

    void notifyWindowResponsive(const sp<IBinder>& connectionToken,
                                std::optional<gui::Pid> pid) override {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(pid.has_value());
        mResponsiveWindows.push({connectionToken, *pid});
        mNotifyAnr.notify_all();
    }

    void notifyNoFocusedWindowAnr(
            const std::shared_ptr<InputApplicationHandle>& applicationHandle) override {
        std::scoped_lock lock(mLock);
        mAnrApplications.push(applicationHandle);
        mNotifyAnr.notify_all();
    }

    void notifyInputChannelBroken(const sp<IBinder>& connectionToken) override {
        std::scoped_lock lock(mLock);
        mBrokenInputChannels.push(connectionToken);
        mNotifyInputChannelBroken.notify_all();
    }

    void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) override {}

    void notifySensorEvent(int32_t deviceId, InputDeviceSensorType sensorType,
                           InputDeviceSensorAccuracy accuracy, nsecs_t timestamp,
                           const std::vector<float>& values) override {}

    void notifySensorAccuracy(int deviceId, InputDeviceSensorType sensorType,
                              InputDeviceSensorAccuracy accuracy) override {}

    void notifyVibratorState(int32_t deviceId, bool isOn) override {}

    InputDispatcherConfiguration getDispatcherConfiguration() override { return mConfig; }

    bool filterInputEvent(const InputEvent& inputEvent, uint32_t policyFlags) override {
        std::scoped_lock lock(mLock);
        switch (inputEvent.getType()) {
            case InputEventType::KEY: {
                const KeyEvent& keyEvent = static_cast<const KeyEvent&>(inputEvent);
                mFilteredEvent = std::make_unique<KeyEvent>(keyEvent);
                break;
            }

            case InputEventType::MOTION: {
                const MotionEvent& motionEvent = static_cast<const MotionEvent&>(inputEvent);
                mFilteredEvent = std::make_unique<MotionEvent>(motionEvent);
                break;
            }
            default: {
                ADD_FAILURE() << "Should only filter keys or motions";
                break;
            }
        }
        return true;
    }

    void interceptKeyBeforeQueueing(const KeyEvent& inputEvent, uint32_t&) override {
        if (inputEvent.getAction() == AKEY_EVENT_ACTION_UP) {
            // Clear intercept state when we handled the event.
            mInterceptKeyTimeout = 0ms;
        }
    }

    void interceptMotionBeforeQueueing(int32_t, nsecs_t, uint32_t&) override {}

    nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent&, uint32_t) override {
        nsecs_t delay = std::chrono::nanoseconds(mInterceptKeyTimeout).count();
        // Clear intercept state so we could dispatch the event in next wake.
        mInterceptKeyTimeout = 0ms;
        return delay;
    }

    std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent&,
                                                 uint32_t) override {
        return {};
    }

    void notifySwitch(nsecs_t when, uint32_t switchValues, uint32_t switchMask,
                      uint32_t policyFlags) override {
        std::scoped_lock lock(mLock);
        /** We simply reconstruct NotifySwitchArgs in policy because InputDispatcher is
         * essentially a passthrough for notifySwitch.
         */
        mLastNotifySwitch = NotifySwitchArgs(/*id=*/1, when, policyFlags, switchValues, switchMask);
    }

    void pokeUserActivity(nsecs_t, int32_t, int32_t) override {
        std::scoped_lock lock(mLock);
        mPokedUserActivity = true;
    }

    void onPointerDownOutsideFocus(const sp<IBinder>& newToken) override {
        std::scoped_lock lock(mLock);
        mOnPointerDownToken = newToken;
    }

    void setPointerCapture(const PointerCaptureRequest& request) override {
        std::scoped_lock lock(mLock);
        mPointerCaptureRequest = {request};
        mPointerCaptureChangedCondition.notify_all();
    }

    void notifyDropWindow(const sp<IBinder>& token, float x, float y) override {
        std::scoped_lock lock(mLock);
        mNotifyDropWindowWasCalled = true;
        mDropTargetWindowToken = token;
    }

    void notifyDeviceInteraction(int32_t deviceId, nsecs_t timestamp,
                                 const std::set<gui::Uid>& uids) override {
        ASSERT_TRUE(mNotifiedInteractions.emplace(deviceId, uids));
    }

    void assertFilterInputEventWasCalledInternal(
            const std::function<void(const InputEvent&)>& verify) {
        std::scoped_lock lock(mLock);
        ASSERT_NE(nullptr, mFilteredEvent) << "Expected filterInputEvent() to have been called.";
        verify(*mFilteredEvent);
        mFilteredEvent = nullptr;
    }
};

// --- InputDispatcherTest ---

class InputDispatcherTest : public testing::Test {
protected:
    std::unique_ptr<FakeInputDispatcherPolicy> mFakePolicy;
    std::unique_ptr<InputDispatcher> mDispatcher;

    void SetUp() override {
        mFakePolicy = std::make_unique<FakeInputDispatcherPolicy>();
        mDispatcher = std::make_unique<InputDispatcher>(*mFakePolicy, STALE_EVENT_TIMEOUT);
        mDispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
        // Start InputDispatcher thread
        ASSERT_EQ(OK, mDispatcher->start());
    }

    void TearDown() override {
        ASSERT_EQ(OK, mDispatcher->stop());
        mFakePolicy.reset();
        mDispatcher.reset();
    }

    /**
     * Used for debugging when writing the test
     */
    void dumpDispatcherState() {
        std::string dump;
        mDispatcher->dump(dump);
        std::stringstream ss(dump);
        std::string to;

        while (std::getline(ss, to, '\n')) {
            ALOGE("%s", to.c_str());
        }
    }

    void setFocusedWindow(const sp<WindowInfoHandle>& window) {
        FocusRequest request;
        request.token = window->getToken();
        request.windowName = window->getName();
        request.timestamp = systemTime(SYSTEM_TIME_MONOTONIC);
        request.displayId = window->getInfo()->displayId;
        mDispatcher->setFocusedWindow(request);
    }
};

TEST_F(InputDispatcherTest, InjectInputEvent_ValidatesKeyEvents) {
    KeyEvent event;

    // Rejects undefined key actions.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
                     INVALID_HMAC,
                     /*action*/ -1, 0, AKEYCODE_A, KEY_A, AMETA_NONE, 0, ARBITRARY_TIME,
                     ARBITRARY_TIME);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject key events with undefined action.";

    // Rejects ACTION_MULTIPLE since it is not supported despite being defined in the API.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
                     INVALID_HMAC, AKEY_EVENT_ACTION_MULTIPLE, 0, AKEYCODE_A, KEY_A, AMETA_NONE, 0,
                     ARBITRARY_TIME, ARBITRARY_TIME);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject key events with ACTION_MULTIPLE.";
}

TEST_F(InputDispatcherTest, InjectInputEvent_ValidatesMotionEvents) {
    MotionEvent event;
    PointerProperties pointerProperties[MAX_POINTERS + 1];
    PointerCoords pointerCoords[MAX_POINTERS + 1];
    for (size_t i = 0; i <= MAX_POINTERS; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerCoords[i].clear();
    }

    // Some constants commonly used below
    constexpr int32_t source = AINPUT_SOURCE_TOUCHSCREEN;
    constexpr int32_t edgeFlags = AMOTION_EVENT_EDGE_FLAG_NONE;
    constexpr int32_t metaState = AMETA_NONE;
    constexpr MotionClassification classification = MotionClassification::NONE;

    ui::Transform identityTransform;
    // Rejects undefined motion actions.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     /*action*/ -1, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with undefined action.";

    // Rejects pointer down with invalid index.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     POINTER_1_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with pointer down index too large.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, identityTransform, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     identityTransform, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with pointer down index too small.";

    // Rejects pointer up with invalid index.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     POINTER_1_UP, 0, 0, edgeFlags, metaState, 0, classification, identityTransform,
                     0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with pointer up index too large.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_UP |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, identityTransform, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     identityTransform, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with pointer up index too small.";

    // Rejects motion events with invalid number of pointers.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ 0, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with 0 pointers.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ MAX_POINTERS + 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with more than MAX_POINTERS pointers.";

    // Rejects motion events with invalid pointer ids.
    pointerProperties[0].id = -1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with pointer ids less than 0.";

    pointerProperties[0].id = MAX_POINTER_ID + 1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with pointer ids greater than MAX_POINTER_ID.";

    // Rejects motion events with duplicate pointer ids.
    pointerProperties[0].id = 1;
    pointerProperties[1].id = 1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, ARBITRARY_TIME,
                     ARBITRARY_TIME,
                     /*pointerCount*/ 2, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                            0ms, 0))
            << "Should reject motion events with duplicate pointer ids.";
}

/* Test InputDispatcher for notifyConfigurationChanged and notifySwitch events */

TEST_F(InputDispatcherTest, NotifyConfigurationChanged_CallsPolicy) {
    constexpr nsecs_t eventTime = 20;
    mDispatcher->notifyConfigurationChanged({/*id=*/10, eventTime});
    ASSERT_TRUE(mDispatcher->waitForIdle());

    mFakePolicy->assertNotifyConfigurationChangedWasCalled(eventTime);
}

TEST_F(InputDispatcherTest, NotifySwitch_CallsPolicy) {
    NotifySwitchArgs args(/*id=*/10, /*eventTime=*/20, /*policyFlags=*/0, /*switchValues=*/1,
                          /*switchMask=*/2);
    mDispatcher->notifySwitch(args);

    // InputDispatcher adds POLICY_FLAG_TRUSTED because the event went through InputListener
    args.policyFlags |= POLICY_FLAG_TRUSTED;
    mFakePolicy->assertNotifySwitchWasCalled(args);
}

namespace {

// --- InputDispatcherTest SetInputWindowTest ---
static constexpr std::chrono::duration INJECT_EVENT_TIMEOUT = 500ms;
// Default input dispatching timeout if there is no focused application or paused window
// from which to determine an appropriate dispatching timeout.
static const std::chrono::duration DISPATCHING_TIMEOUT = std::chrono::milliseconds(
        android::os::IInputConstants::UNMULTIPLIED_DEFAULT_DISPATCHING_TIMEOUT_MILLIS *
        android::base::HwTimeoutMultiplier());

class FakeApplicationHandle : public InputApplicationHandle {
public:
    FakeApplicationHandle() {
        mInfo.name = "Fake Application";
        mInfo.token = sp<BBinder>::make();
        mInfo.dispatchingTimeoutMillis =
                std::chrono::duration_cast<std::chrono::milliseconds>(DISPATCHING_TIMEOUT).count();
    }
    virtual ~FakeApplicationHandle() {}

    virtual bool updateInfo() override { return true; }

    void setDispatchingTimeout(std::chrono::milliseconds timeout) {
        mInfo.dispatchingTimeoutMillis = timeout.count();
    }
};

class FakeInputReceiver {
public:
    explicit FakeInputReceiver(std::unique_ptr<InputChannel> clientChannel, const std::string name)
          : mName(name) {
        mConsumer = std::make_unique<InputConsumer>(std::move(clientChannel));
    }

    InputEvent* consume() {
        InputEvent* event;
        std::optional<uint32_t> consumeSeq = receiveEvent(&event);
        if (!consumeSeq) {
            return nullptr;
        }
        finishEvent(*consumeSeq);
        return event;
    }

    /**
     * Receive an event without acknowledging it.
     * Return the sequence number that could later be used to send finished signal.
     */
    std::optional<uint32_t> receiveEvent(InputEvent** outEvent = nullptr) {
        uint32_t consumeSeq;
        InputEvent* event;

        std::chrono::time_point start = std::chrono::steady_clock::now();
        status_t status = WOULD_BLOCK;
        while (status == WOULD_BLOCK) {
            status = mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq,
                                        &event);
            std::chrono::duration elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > 100ms) {
                break;
            }
        }

        if (status == WOULD_BLOCK) {
            // Just means there's no event available.
            return std::nullopt;
        }

        if (status != OK) {
            ADD_FAILURE() << mName.c_str() << ": consumer consume should return OK.";
            return std::nullopt;
        }
        if (event == nullptr) {
            ADD_FAILURE() << "Consumed correctly, but received NULL event from consumer";
            return std::nullopt;
        }
        if (outEvent != nullptr) {
            *outEvent = event;
        }
        return consumeSeq;
    }

    /**
     * To be used together with "receiveEvent" to complete the consumption of an event.
     */
    void finishEvent(uint32_t consumeSeq) {
        const status_t status = mConsumer->sendFinishedSignal(consumeSeq, true);
        ASSERT_EQ(OK, status) << mName.c_str() << ": consumer sendFinishedSignal should return OK.";
    }

    void sendTimeline(int32_t inputEventId, std::array<nsecs_t, GraphicsTimeline::SIZE> timeline) {
        const status_t status = mConsumer->sendTimeline(inputEventId, timeline);
        ASSERT_EQ(OK, status);
    }

    void consumeEvent(InputEventType expectedEventType, int32_t expectedAction,
                      std::optional<int32_t> expectedDisplayId,
                      std::optional<int32_t> expectedFlags) {
        InputEvent* event = consume();

        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(expectedEventType, event->getType())
                << mName.c_str() << " expected " << ftl::enum_string(expectedEventType)
                << " event, got " << *event;

        if (expectedDisplayId.has_value()) {
            EXPECT_EQ(expectedDisplayId, event->getDisplayId());
        }

        switch (expectedEventType) {
            case InputEventType::KEY: {
                const KeyEvent& keyEvent = static_cast<const KeyEvent&>(*event);
                EXPECT_EQ(expectedAction, keyEvent.getAction());
                if (expectedFlags.has_value()) {
                    EXPECT_EQ(expectedFlags.value(), keyEvent.getFlags());
                }
                break;
            }
            case InputEventType::MOTION: {
                const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*event);
                assertMotionAction(expectedAction, motionEvent.getAction());

                if (expectedFlags.has_value()) {
                    EXPECT_EQ(expectedFlags.value(), motionEvent.getFlags());
                }
                break;
            }
            case InputEventType::FOCUS: {
                FAIL() << "Use 'consumeFocusEvent' for FOCUS events";
            }
            case InputEventType::CAPTURE: {
                FAIL() << "Use 'consumeCaptureEvent' for CAPTURE events";
            }
            case InputEventType::TOUCH_MODE: {
                FAIL() << "Use 'consumeTouchModeEvent' for TOUCH_MODE events";
            }
            case InputEventType::DRAG: {
                FAIL() << "Use 'consumeDragEvent' for DRAG events";
            }
        }
    }

    MotionEvent* consumeMotion() {
        InputEvent* event = consume();

        if (event == nullptr) {
            ADD_FAILURE() << mName << ": expected a MotionEvent, but didn't get one.";
            return nullptr;
        }

        if (event->getType() != InputEventType::MOTION) {
            ADD_FAILURE() << mName << " expected a MotionEvent, got " << *event;
            return nullptr;
        }
        return static_cast<MotionEvent*>(event);
    }

    void consumeMotionEvent(const ::testing::Matcher<MotionEvent>& matcher) {
        MotionEvent* motionEvent = consumeMotion();
        ASSERT_NE(nullptr, motionEvent) << "Did not get a motion event, but expected " << matcher;
        ASSERT_THAT(*motionEvent, matcher);
    }

    void consumeFocusEvent(bool hasFocus, bool inTouchMode) {
        InputEvent* event = consume();
        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(InputEventType::FOCUS, event->getType())
                << "Instead of FocusEvent, got " << *event;

        ASSERT_EQ(ADISPLAY_ID_NONE, event->getDisplayId())
                << mName.c_str() << ": event displayId should always be NONE.";

        FocusEvent* focusEvent = static_cast<FocusEvent*>(event);
        EXPECT_EQ(hasFocus, focusEvent->getHasFocus());
    }

    void consumeCaptureEvent(bool hasCapture) {
        const InputEvent* event = consume();
        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(InputEventType::CAPTURE, event->getType())
                << "Instead of CaptureEvent, got " << *event;

        ASSERT_EQ(ADISPLAY_ID_NONE, event->getDisplayId())
                << mName.c_str() << ": event displayId should always be NONE.";

        const auto& captureEvent = static_cast<const CaptureEvent&>(*event);
        EXPECT_EQ(hasCapture, captureEvent.getPointerCaptureEnabled());
    }

    void consumeDragEvent(bool isExiting, float x, float y) {
        const InputEvent* event = consume();
        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(InputEventType::DRAG, event->getType()) << "Instead of DragEvent, got " << *event;

        EXPECT_EQ(ADISPLAY_ID_NONE, event->getDisplayId())
                << mName.c_str() << ": event displayId should always be NONE.";

        const auto& dragEvent = static_cast<const DragEvent&>(*event);
        EXPECT_EQ(isExiting, dragEvent.isExiting());
        EXPECT_EQ(x, dragEvent.getX());
        EXPECT_EQ(y, dragEvent.getY());
    }

    void consumeTouchModeEvent(bool inTouchMode) {
        const InputEvent* event = consume();
        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(InputEventType::TOUCH_MODE, event->getType())
                << "Instead of TouchModeEvent, got " << *event;

        ASSERT_EQ(ADISPLAY_ID_NONE, event->getDisplayId())
                << mName.c_str() << ": event displayId should always be NONE.";
        const auto& touchModeEvent = static_cast<const TouchModeEvent&>(*event);
        EXPECT_EQ(inTouchMode, touchModeEvent.isInTouchMode());
    }

    void assertNoEvents() {
        InputEvent* event = consume();
        if (event == nullptr) {
            return;
        }
        if (event->getType() == InputEventType::KEY) {
            KeyEvent& keyEvent = static_cast<KeyEvent&>(*event);
            ADD_FAILURE() << "Received key event "
                          << KeyEvent::actionToString(keyEvent.getAction());
        } else if (event->getType() == InputEventType::MOTION) {
            MotionEvent& motionEvent = static_cast<MotionEvent&>(*event);
            ADD_FAILURE() << "Received motion event "
                          << MotionEvent::actionToString(motionEvent.getAction());
        } else if (event->getType() == InputEventType::FOCUS) {
            FocusEvent& focusEvent = static_cast<FocusEvent&>(*event);
            ADD_FAILURE() << "Received focus event, hasFocus = "
                          << (focusEvent.getHasFocus() ? "true" : "false");
        } else if (event->getType() == InputEventType::CAPTURE) {
            const auto& captureEvent = static_cast<CaptureEvent&>(*event);
            ADD_FAILURE() << "Received capture event, pointerCaptureEnabled = "
                          << (captureEvent.getPointerCaptureEnabled() ? "true" : "false");
        } else if (event->getType() == InputEventType::TOUCH_MODE) {
            const auto& touchModeEvent = static_cast<TouchModeEvent&>(*event);
            ADD_FAILURE() << "Received touch mode event, inTouchMode = "
                          << (touchModeEvent.isInTouchMode() ? "true" : "false");
        }
        FAIL() << mName.c_str()
               << ": should not have received any events, so consume() should return NULL";
    }

    sp<IBinder> getToken() { return mConsumer->getChannel()->getConnectionToken(); }

    int getChannelFd() { return mConsumer->getChannel()->getFd().get(); }

protected:
    std::unique_ptr<InputConsumer> mConsumer;
    PreallocatedInputEventFactory mEventFactory;

    std::string mName;
};

class FakeWindowHandle : public WindowInfoHandle {
public:
    static const int32_t WIDTH = 600;
    static const int32_t HEIGHT = 800;

    FakeWindowHandle(const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle,
                     const std::unique_ptr<InputDispatcher>& dispatcher, const std::string name,
                     int32_t displayId, std::optional<sp<IBinder>> token = std::nullopt)
          : mName(name) {
        if (token == std::nullopt) {
            base::Result<std::unique_ptr<InputChannel>> channel =
                    dispatcher->createInputChannel(name);
            token = (*channel)->getConnectionToken();
            mInputReceiver = std::make_unique<FakeInputReceiver>(std::move(*channel), name);
        }

        inputApplicationHandle->updateInfo();
        mInfo.applicationInfo = *inputApplicationHandle->getInfo();

        mInfo.token = *token;
        mInfo.id = sId++;
        mInfo.name = name;
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT;
        mInfo.alpha = 1.0;
        mInfo.frameLeft = 0;
        mInfo.frameTop = 0;
        mInfo.frameRight = WIDTH;
        mInfo.frameBottom = HEIGHT;
        mInfo.transform.set(0, 0);
        mInfo.globalScaleFactor = 1.0;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(Rect(0, 0, WIDTH, HEIGHT));
        mInfo.ownerPid = WINDOW_PID;
        mInfo.ownerUid = WINDOW_UID;
        mInfo.displayId = displayId;
        mInfo.inputConfig = WindowInfo::InputConfig::DEFAULT;
    }

    sp<FakeWindowHandle> clone(int32_t displayId) {
        sp<FakeWindowHandle> handle = sp<FakeWindowHandle>::make(mInfo.name + "(Mirror)");
        handle->mInfo = mInfo;
        handle->mInfo.displayId = displayId;
        handle->mInfo.id = sId++;
        handle->mInputReceiver = mInputReceiver;
        return handle;
    }

    /**
     * This is different from clone, because clone will make a "mirror" window - a window with the
     * same token, but a different ID. The original window and the clone window are allowed to be
     * sent to the dispatcher at the same time - they can coexist inside the dispatcher.
     * This function will create a different object of WindowInfoHandle, but with the same
     * properties as the original object - including the ID.
     * You can use either the old or the new object to consume the events.
     * IMPORTANT: The duplicated object is supposed to replace the original object, and not appear
     * at the same time inside dispatcher.
     */
    sp<FakeWindowHandle> duplicate() {
        sp<FakeWindowHandle> handle = sp<FakeWindowHandle>::make(mName);
        handle->mInfo = mInfo;
        handle->mInputReceiver = mInputReceiver;
        return handle;
    }

    void setTouchable(bool touchable) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, !touchable);
    }

    void setFocusable(bool focusable) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NOT_FOCUSABLE, !focusable);
    }

    void setVisible(bool visible) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NOT_VISIBLE, !visible);
    }

    void setDispatchingTimeout(std::chrono::nanoseconds timeout) {
        mInfo.dispatchingTimeout = timeout;
    }

    void setPaused(bool paused) {
        mInfo.setInputConfig(WindowInfo::InputConfig::PAUSE_DISPATCHING, paused);
    }

    void setPreventSplitting(bool preventSplitting) {
        mInfo.setInputConfig(WindowInfo::InputConfig::PREVENT_SPLITTING, preventSplitting);
    }

    void setSlippery(bool slippery) {
        mInfo.setInputConfig(WindowInfo::InputConfig::SLIPPERY, slippery);
    }

    void setWatchOutsideTouch(bool watchOutside) {
        mInfo.setInputConfig(WindowInfo::InputConfig::WATCH_OUTSIDE_TOUCH, watchOutside);
    }

    void setSpy(bool spy) { mInfo.setInputConfig(WindowInfo::InputConfig::SPY, spy); }

    void setInterceptsStylus(bool interceptsStylus) {
        mInfo.setInputConfig(WindowInfo::InputConfig::INTERCEPTS_STYLUS, interceptsStylus);
    }

    void setDropInput(bool dropInput) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DROP_INPUT, dropInput);
    }

    void setDropInputIfObscured(bool dropInputIfObscured) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED, dropInputIfObscured);
    }

    void setNoInputChannel(bool noInputChannel) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NO_INPUT_CHANNEL, noInputChannel);
    }

    void setDisableUserActivity(bool disableUserActivity) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DISABLE_USER_ACTIVITY, disableUserActivity);
    }

    void setAlpha(float alpha) { mInfo.alpha = alpha; }

    void setTouchOcclusionMode(TouchOcclusionMode mode) { mInfo.touchOcclusionMode = mode; }

    void setApplicationToken(sp<IBinder> token) { mInfo.applicationInfo.token = token; }

    void setFrame(const Rect& frame, const ui::Transform& displayTransform = ui::Transform()) {
        mInfo.frameLeft = frame.left;
        mInfo.frameTop = frame.top;
        mInfo.frameRight = frame.right;
        mInfo.frameBottom = frame.bottom;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(frame);

        const Rect logicalDisplayFrame = displayTransform.transform(frame);
        ui::Transform translate;
        translate.set(-logicalDisplayFrame.left, -logicalDisplayFrame.top);
        mInfo.transform = translate * displayTransform;
    }

    void setTouchableRegion(const Region& region) { mInfo.touchableRegion = region; }

    void setIsWallpaper(bool isWallpaper) {
        mInfo.setInputConfig(WindowInfo::InputConfig::IS_WALLPAPER, isWallpaper);
    }

    void setDupTouchToWallpaper(bool hasWallpaper) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER, hasWallpaper);
    }

    void setTrustedOverlay(bool trustedOverlay) {
        mInfo.setInputConfig(WindowInfo::InputConfig::TRUSTED_OVERLAY, trustedOverlay);
    }

    void setWindowTransform(float dsdx, float dtdx, float dtdy, float dsdy) {
        mInfo.transform.set(dsdx, dtdx, dtdy, dsdy);
    }

    void setWindowScale(float xScale, float yScale) { setWindowTransform(xScale, 0, 0, yScale); }

    void setWindowOffset(float offsetX, float offsetY) { mInfo.transform.set(offsetX, offsetY); }

    void consumeKeyDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeEvent(InputEventType::KEY, AKEY_EVENT_ACTION_DOWN, expectedDisplayId, expectedFlags);
    }

    void consumeKeyUp(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeEvent(InputEventType::KEY, AKEY_EVENT_ACTION_UP, expectedDisplayId, expectedFlags);
    }

    void consumeMotionCancel(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                             int32_t expectedFlags = 0) {
        consumeMotionEvent(AllOf(WithMotionAction(ACTION_CANCEL), WithDisplayId(expectedDisplayId),
                                 WithFlags(expectedFlags | AMOTION_EVENT_FLAG_CANCELED)));
    }

    void consumeMotionMove(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                           int32_t expectedFlags = 0) {
        consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                                 WithDisplayId(expectedDisplayId), WithFlags(expectedFlags)));
    }

    void consumeMotionDown(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                           int32_t expectedFlags = 0) {
        consumeAnyMotionDown(expectedDisplayId, expectedFlags);
    }

    void consumeAnyMotionDown(std::optional<int32_t> expectedDisplayId = std::nullopt,
                              std::optional<int32_t> expectedFlags = std::nullopt) {
        consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_DOWN, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionPointerDown(int32_t pointerIdx,
                                  int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                  int32_t expectedFlags = 0) {
        int32_t action = AMOTION_EVENT_ACTION_POINTER_DOWN |
                (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeEvent(InputEventType::MOTION, action, expectedDisplayId, expectedFlags);
    }

    void consumeMotionPointerUp(int32_t pointerIdx, int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                int32_t expectedFlags = 0) {
        int32_t action = AMOTION_EVENT_ACTION_POINTER_UP |
                (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeEvent(InputEventType::MOTION, action, expectedDisplayId, expectedFlags);
    }

    void consumeMotionUp(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                         int32_t expectedFlags = 0) {
        consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_UP, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionOutside(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                              int32_t expectedFlags = 0) {
        consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_OUTSIDE, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionOutsideWithZeroedCoords(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                              int32_t expectedFlags = 0) {
        InputEvent* event = consume();
        ASSERT_NE(nullptr, event);
        ASSERT_EQ(InputEventType::MOTION, event->getType());
        const MotionEvent& motionEvent = static_cast<MotionEvent&>(*event);
        EXPECT_EQ(AMOTION_EVENT_ACTION_OUTSIDE, motionEvent.getActionMasked());
        EXPECT_EQ(0.f, motionEvent.getRawPointerCoords(0)->getX());
        EXPECT_EQ(0.f, motionEvent.getRawPointerCoords(0)->getY());
    }

    void consumeFocusEvent(bool hasFocus, bool inTouchMode = true) {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Cannot consume events from a window with no receiver";
        mInputReceiver->consumeFocusEvent(hasFocus, inTouchMode);
    }

    void consumeCaptureEvent(bool hasCapture) {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Cannot consume events from a window with no receiver";
        mInputReceiver->consumeCaptureEvent(hasCapture);
    }

    void consumeMotionEvent(const ::testing::Matcher<MotionEvent>& matcher) {
        MotionEvent* motionEvent = consumeMotion();
        ASSERT_NE(nullptr, motionEvent) << "Did not get a motion event, but expected " << matcher;
        ASSERT_THAT(*motionEvent, matcher);
    }

    void consumeEvent(InputEventType expectedEventType, int32_t expectedAction,
                      std::optional<int32_t> expectedDisplayId,
                      std::optional<int32_t> expectedFlags) {
        ASSERT_NE(mInputReceiver, nullptr) << "Invalid consume event on window with no receiver";
        mInputReceiver->consumeEvent(expectedEventType, expectedAction, expectedDisplayId,
                                     expectedFlags);
    }

    void consumeDragEvent(bool isExiting, float x, float y) {
        mInputReceiver->consumeDragEvent(isExiting, x, y);
    }

    void consumeTouchModeEvent(bool inTouchMode) {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Cannot consume events from a window with no receiver";
        mInputReceiver->consumeTouchModeEvent(inTouchMode);
    }

    std::optional<uint32_t> receiveEvent(InputEvent** outEvent = nullptr) {
        if (mInputReceiver == nullptr) {
            ADD_FAILURE() << "Invalid receive event on window with no receiver";
            return std::nullopt;
        }
        return mInputReceiver->receiveEvent(outEvent);
    }

    void finishEvent(uint32_t sequenceNum) {
        ASSERT_NE(mInputReceiver, nullptr) << "Invalid receive event on window with no receiver";
        mInputReceiver->finishEvent(sequenceNum);
    }

    void sendTimeline(int32_t inputEventId, std::array<nsecs_t, GraphicsTimeline::SIZE> timeline) {
        ASSERT_NE(mInputReceiver, nullptr) << "Invalid receive event on window with no receiver";
        mInputReceiver->sendTimeline(inputEventId, timeline);
    }

    InputEvent* consume() {
        if (mInputReceiver == nullptr) {
            return nullptr;
        }
        return mInputReceiver->consume();
    }

    MotionEvent* consumeMotion() {
        InputEvent* event = consume();
        if (event == nullptr) {
            ADD_FAILURE() << "Consume failed : no event";
            return nullptr;
        }
        if (event->getType() != InputEventType::MOTION) {
            ADD_FAILURE() << "Instead of motion event, got " << *event;
            return nullptr;
        }
        return static_cast<MotionEvent*>(event);
    }

    void assertNoEvents() {
        if (mInputReceiver == nullptr &&
            mInfo.inputConfig.test(WindowInfo::InputConfig::NO_INPUT_CHANNEL)) {
            return; // Can't receive events if the window does not have input channel
        }
        ASSERT_NE(nullptr, mInputReceiver)
                << "Window without InputReceiver must specify feature NO_INPUT_CHANNEL";
        mInputReceiver->assertNoEvents();
    }

    sp<IBinder> getToken() { return mInfo.token; }

    const std::string& getName() { return mName; }

    void setOwnerInfo(gui::Pid ownerPid, gui::Uid ownerUid) {
        mInfo.ownerPid = ownerPid;
        mInfo.ownerUid = ownerUid;
    }

    gui::Pid getPid() const { return mInfo.ownerPid; }

    void destroyReceiver() { mInputReceiver = nullptr; }

    int getChannelFd() { return mInputReceiver->getChannelFd(); }

private:
    FakeWindowHandle(std::string name) : mName(name){};
    const std::string mName;
    std::shared_ptr<FakeInputReceiver> mInputReceiver;
    static std::atomic<int32_t> sId; // each window gets a unique id, like in surfaceflinger
    friend class sp<FakeWindowHandle>;
};

std::atomic<int32_t> FakeWindowHandle::sId{1};

static InputEventInjectionResult injectKey(
        const std::unique_ptr<InputDispatcher>& dispatcher, int32_t action, int32_t repeatCount,
        int32_t displayId = ADISPLAY_ID_NONE,
        InputEventInjectionSync syncMode = InputEventInjectionSync::WAIT_FOR_RESULT,
        std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT,
        bool allowKeyRepeat = true, std::optional<gui::Uid> targetUid = {},
        uint32_t policyFlags = DEFAULT_POLICY_FLAGS) {
    KeyEvent event;
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);

    // Define a valid key down event.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, displayId,
                     INVALID_HMAC, action, /*flags=*/0, AKEYCODE_A, KEY_A, AMETA_NONE, repeatCount,
                     currentTime, currentTime);

    if (!allowKeyRepeat) {
        policyFlags |= POLICY_FLAG_DISABLE_KEY_REPEAT;
    }
    // Inject event until dispatch out.
    return dispatcher->injectInputEvent(&event, targetUid, syncMode, injectionTimeout, policyFlags);
}

static InputEventInjectionResult injectKeyDown(const std::unique_ptr<InputDispatcher>& dispatcher,
                                               int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, displayId);
}

// Inject a down event that has key repeat disabled. This allows InputDispatcher to idle without
// sending a subsequent key up. When key repeat is enabled, the dispatcher cannot idle because it
// has to be woken up to process the repeating key.
static InputEventInjectionResult injectKeyDownNoRepeat(
        const std::unique_ptr<InputDispatcher>& dispatcher, int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, displayId,
                     InputEventInjectionSync::WAIT_FOR_RESULT, INJECT_EVENT_TIMEOUT,
                     /*allowKeyRepeat=*/false);
}

static InputEventInjectionResult injectKeyUp(const std::unique_ptr<InputDispatcher>& dispatcher,
                                             int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_UP, /*repeatCount=*/0, displayId);
}

static InputEventInjectionResult injectMotionEvent(
        const std::unique_ptr<InputDispatcher>& dispatcher, const MotionEvent& event,
        std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT,
        InputEventInjectionSync injectionMode = InputEventInjectionSync::WAIT_FOR_RESULT,
        std::optional<gui::Uid> targetUid = {}, uint32_t policyFlags = DEFAULT_POLICY_FLAGS) {
    return dispatcher->injectInputEvent(&event, targetUid, injectionMode, injectionTimeout,
                                        policyFlags);
}

static InputEventInjectionResult injectMotionEvent(
        const std::unique_ptr<InputDispatcher>& dispatcher, int32_t action, int32_t source,
        int32_t displayId, const PointF& position = {100, 200},
        const PointF& cursorPosition = {AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                        AMOTION_EVENT_INVALID_CURSOR_POSITION},
        std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT,
        InputEventInjectionSync injectionMode = InputEventInjectionSync::WAIT_FOR_RESULT,
        nsecs_t eventTime = systemTime(SYSTEM_TIME_MONOTONIC),
        std::optional<gui::Uid> targetUid = {}, uint32_t policyFlags = DEFAULT_POLICY_FLAGS) {
    MotionEventBuilder motionBuilder =
            MotionEventBuilder(action, source)
                    .displayId(displayId)
                    .eventTime(eventTime)
                    .rawXCursorPosition(cursorPosition.x)
                    .rawYCursorPosition(cursorPosition.y)
                    .pointer(
                            PointerBuilder(/*id=*/0, ToolType::FINGER).x(position.x).y(position.y));
    if (MotionEvent::getActionMasked(action) == ACTION_DOWN) {
        motionBuilder.downTime(eventTime);
    }

    // Inject event until dispatch out.
    return injectMotionEvent(dispatcher, motionBuilder.build(), injectionTimeout, injectionMode,
                             targetUid, policyFlags);
}

static InputEventInjectionResult injectMotionDown(
        const std::unique_ptr<InputDispatcher>& dispatcher, int32_t source, int32_t displayId,
        const PointF& location = {100, 200}) {
    return injectMotionEvent(dispatcher, AMOTION_EVENT_ACTION_DOWN, source, displayId, location);
}

static InputEventInjectionResult injectMotionUp(const std::unique_ptr<InputDispatcher>& dispatcher,
                                                int32_t source, int32_t displayId,
                                                const PointF& location = {100, 200}) {
    return injectMotionEvent(dispatcher, AMOTION_EVENT_ACTION_UP, source, displayId, location);
}

static NotifyKeyArgs generateKeyArgs(int32_t action, int32_t displayId = ADISPLAY_ID_NONE) {
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid key event.
    NotifyKeyArgs args(/*id=*/0, currentTime, /*readTime=*/0, DEVICE_ID, AINPUT_SOURCE_KEYBOARD,
                       displayId, POLICY_FLAG_PASS_TO_USER, action, /* flags */ 0, AKEYCODE_A,
                       KEY_A, AMETA_NONE, currentTime);

    return args;
}

static NotifyKeyArgs generateSystemShortcutArgs(int32_t action,
                                                int32_t displayId = ADISPLAY_ID_NONE) {
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid key event.
    NotifyKeyArgs args(/*id=*/0, currentTime, /*readTime=*/0, DEVICE_ID, AINPUT_SOURCE_KEYBOARD,
                       displayId, 0, action, /* flags */ 0, AKEYCODE_C, KEY_C, AMETA_META_ON,
                       currentTime);

    return args;
}

static NotifyKeyArgs generateAssistantKeyArgs(int32_t action,
                                              int32_t displayId = ADISPLAY_ID_NONE) {
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid key event.
    NotifyKeyArgs args(/*id=*/0, currentTime, /*readTime=*/0, DEVICE_ID, AINPUT_SOURCE_KEYBOARD,
                       displayId, 0, action, /* flags */ 0, AKEYCODE_ASSIST, KEY_ASSISTANT,
                       AMETA_NONE, currentTime);

    return args;
}

[[nodiscard]] static NotifyMotionArgs generateMotionArgs(int32_t action, int32_t source,
                                                         int32_t displayId,
                                                         const std::vector<PointF>& points) {
    size_t pointerCount = points.size();
    if (action == AMOTION_EVENT_ACTION_DOWN || action == AMOTION_EVENT_ACTION_UP) {
        EXPECT_EQ(1U, pointerCount) << "Actions DOWN and UP can only contain a single pointer";
    }

    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];

    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerProperties[i].id = i;
        pointerProperties[i].toolType = ToolType::FINGER;

        pointerCoords[i].clear();
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X, points[i].x);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y, points[i].y);
    }

    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid motion event.
    NotifyMotionArgs args(/*id=*/0, currentTime, /*readTime=*/0, DEVICE_ID, source, displayId,
                          POLICY_FLAG_PASS_TO_USER, action, /* actionButton */ 0, /* flags */ 0,
                          AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                          AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount, pointerProperties,
                          pointerCoords, /* xPrecision */ 0, /* yPrecision */ 0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, currentTime, /* videoFrames */ {});

    return args;
}

static NotifyMotionArgs generateTouchArgs(int32_t action, const std::vector<PointF>& points) {
    return generateMotionArgs(action, AINPUT_SOURCE_TOUCHSCREEN, DISPLAY_ID, points);
}

static NotifyMotionArgs generateMotionArgs(int32_t action, int32_t source, int32_t displayId) {
    return generateMotionArgs(action, source, displayId, {PointF{100, 200}});
}

static NotifyPointerCaptureChangedArgs generatePointerCaptureChangedArgs(
        const PointerCaptureRequest& request) {
    return NotifyPointerCaptureChangedArgs(/*id=*/0, systemTime(SYSTEM_TIME_MONOTONIC), request);
}

} // namespace

/**
 * When a window unexpectedly disposes of its input channel, policy should be notified about the
 * broken channel.
 */
TEST_F(InputDispatcherTest, WhenInputChannelBreaks_PolicyIsNotified) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher,
                                       "Window that breaks its input channel", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Window closes its channel, but the window remains.
    window->destroyReceiver();
    mFakePolicy->assertNotifyInputChannelBrokenWasCalled(window->getInfo()->token);
}

TEST_F(InputDispatcherTest, SetInputWindow_SingleWindowTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Window should receive motion event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, WhenDisplayNotSpecified_InjectMotionToDefaultDisplay) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    // Inject a MotionEvent to an unknown display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_NONE))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Window should receive motion event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

/**
 * Calling setInputWindows once should not cause any issues.
 * This test serves as a sanity check for the next test, where setInputWindows is
 * called twice.
 */
TEST_F(InputDispatcherTest, SetInputWindowOnceWithSingleTouchWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Window should receive motion event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

/**
 * Calling setInputWindows twice, with the same info, should not cause any issues.
 */
TEST_F(InputDispatcherTest, SetInputWindowTwice_SingleWindowTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Window should receive motion event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

// The foreground window should receive the first touch down event.
TEST_F(InputDispatcherTest, SetInputWindow_MultiWindowsTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowTop =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Top window should receive the touch down event. Second window should not receive anything.
    windowTop->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowSecond->assertNoEvents();
}

/**
 * Two windows: A top window, and a wallpaper behind the window.
 * Touch goes to the top window, and then top window disappears. Ensure that wallpaper window
 * gets ACTION_CANCEL.
 * 1. foregroundWindow <-- dup touch to wallpaper
 * 2. wallpaperWindow <-- is wallpaper
 */
TEST_F(InputDispatcherTest, WhenForegroundWindowDisappears_WallpaperTouchIsCanceled) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> foregroundWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Foreground", ADISPLAY_ID_DEFAULT);
    foregroundWindow->setDupTouchToWallpaper(true);
    sp<FakeWindowHandle> wallpaperWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper", ADISPLAY_ID_DEFAULT);
    wallpaperWindow->setIsWallpaper(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {foregroundWindow, wallpaperWindow}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Both foreground window and its wallpaper should receive the touch down
    foregroundWindow->consumeMotionDown();
    wallpaperWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {110, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    foregroundWindow->consumeMotionMove();
    wallpaperWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Now the foreground window goes away, but the wallpaper stays
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {wallpaperWindow}}});
    foregroundWindow->consumeMotionCancel();
    // Since the "parent" window of the wallpaper is gone, wallpaper should receive cancel, too.
    wallpaperWindow->consumeMotionCancel(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);
}

/**
 * Two fingers down on the window, and lift off the first finger.
 * Next, cancel the gesture to the window by removing the window. Make sure that the CANCEL event
 * contains a single pointer.
 */
TEST_F(InputDispatcherTest, CancelAfterPointer0Up) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    // First touch pointer down on right window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .build());
    // Second touch pointer down
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(110).y(100))
                                      .build());
    // First touch pointer lifts. The second one remains down
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_0_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(110).y(100))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    window->consumeMotionEvent(WithMotionAction(POINTER_1_DOWN));
    window->consumeMotionEvent(WithMotionAction(POINTER_0_UP));

    // Remove the window. The gesture should be canceled
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {}}});
    const std::map<int32_t, PointF> expectedPointers{{1, PointF{110, 100}}};
    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_CANCEL), WithPointers(expectedPointers)));
}

/**
 * Same test as WhenForegroundWindowDisappears_WallpaperTouchIsCanceled above,
 * with the following differences:
 * After ACTION_DOWN, Wallpaper window hangs up its channel, which forces the dispatcher to
 * clean up the connection.
 * This later may crash dispatcher during ACTION_CANCEL synthesis, if the dispatcher is not careful.
 * Ensure that there's no crash in the dispatcher.
 */
TEST_F(InputDispatcherTest, WhenWallpaperDisappears_NoCrash) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> foregroundWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Foreground", ADISPLAY_ID_DEFAULT);
    foregroundWindow->setDupTouchToWallpaper(true);
    sp<FakeWindowHandle> wallpaperWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper", ADISPLAY_ID_DEFAULT);
    wallpaperWindow->setIsWallpaper(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {foregroundWindow, wallpaperWindow}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Both foreground window and its wallpaper should receive the touch down
    foregroundWindow->consumeMotionDown();
    wallpaperWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {110, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    foregroundWindow->consumeMotionMove();
    wallpaperWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Wallpaper closes its channel, but the window remains.
    wallpaperWindow->destroyReceiver();
    mFakePolicy->assertNotifyInputChannelBrokenWasCalled(wallpaperWindow->getInfo()->token);

    // Now the foreground window goes away, but the wallpaper stays, even though its channel
    // is no longer valid.
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {wallpaperWindow}}});
    foregroundWindow->consumeMotionCancel();
}

class ShouldSplitTouchFixture : public InputDispatcherTest,
                                public ::testing::WithParamInterface<bool> {};
INSTANTIATE_TEST_SUITE_P(InputDispatcherTest, ShouldSplitTouchFixture,
                         ::testing::Values(true, false));
/**
 * A single window that receives touch (on top), and a wallpaper window underneath it.
 * The top window gets a multitouch gesture.
 * Ensure that wallpaper gets the same gesture.
 */
TEST_P(ShouldSplitTouchFixture, WallpaperWindowReceivesMultiTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> foregroundWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Foreground", ADISPLAY_ID_DEFAULT);
    foregroundWindow->setDupTouchToWallpaper(true);
    foregroundWindow->setPreventSplitting(GetParam());

    sp<FakeWindowHandle> wallpaperWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper", ADISPLAY_ID_DEFAULT);
    wallpaperWindow->setIsWallpaper(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {foregroundWindow, wallpaperWindow}}});

    // Touch down on top window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 100}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Both top window and its wallpaper should receive the touch down
    foregroundWindow->consumeMotionDown();
    wallpaperWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Second finger down on the top window
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(100))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(150).y(150))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    foregroundWindow->consumeMotionPointerDown(/*pointerIndex=*/1);
    wallpaperWindow->consumeMotionPointerDown(/*pointerIndex=*/1, ADISPLAY_ID_DEFAULT,
                                              expectedWallpaperFlags);

    const MotionEvent secondFingerUpEvent =
            MotionEventBuilder(POINTER_0_UP, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(100))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(150).y(150))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerUpEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    foregroundWindow->consumeMotionPointerUp(0);
    wallpaperWindow->consumeMotionPointerUp(0, ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .displayId(ADISPLAY_ID_DEFAULT)
                                        .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                                        .pointer(PointerBuilder(/* id */ 1,
                                                                ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build(),
                                INJECT_EVENT_TIMEOUT, InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    foregroundWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    wallpaperWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);
}

/**
 * Two windows: a window on the left and window on the right.
 * A third window, wallpaper, is behind both windows, and spans both top windows.
 * The first touch down goes to the left window. A second pointer touches down on the right window.
 * The touch is split, so both left and right windows should receive ACTION_DOWN.
 * The wallpaper will get the full event, so it should receive ACTION_DOWN followed by
 * ACTION_POINTER_DOWN(1).
 */
TEST_F(InputDispatcherTest, TwoWindows_SplitWallpaperTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> leftWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    leftWindow->setFrame(Rect(0, 0, 200, 200));
    leftWindow->setDupTouchToWallpaper(true);

    sp<FakeWindowHandle> rightWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    rightWindow->setFrame(Rect(200, 0, 400, 200));
    rightWindow->setDupTouchToWallpaper(true);

    sp<FakeWindowHandle> wallpaperWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper", ADISPLAY_ID_DEFAULT);
    wallpaperWindow->setFrame(Rect(0, 0, 400, 200));
    wallpaperWindow->setIsWallpaper(true);

    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {leftWindow, rightWindow, wallpaperWindow}}});

    // Touch down on left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 100}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Both foreground window and its wallpaper should receive the touch down
    leftWindow->consumeMotionDown();
    wallpaperWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Second finger down on the right window
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(100))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(300).y(100))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    leftWindow->consumeMotionMove();
    // Since the touch is split, right window gets ACTION_DOWN
    rightWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    wallpaperWindow->consumeMotionPointerDown(/*pointerIndex=*/1, ADISPLAY_ID_DEFAULT,
                                              expectedWallpaperFlags);

    // Now, leftWindow, which received the first finger, disappears.
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {rightWindow, wallpaperWindow}}});
    leftWindow->consumeMotionCancel();
    // Since a "parent" window of the wallpaper is gone, wallpaper should receive cancel, too.
    wallpaperWindow->consumeMotionCancel(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // The pointer that's still down on the right window moves, and goes to the right window only.
    // As far as the dispatcher's concerned though, both pointers are still present.
    const MotionEvent secondFingerMoveEvent =
            MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(100))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(310).y(110))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerMoveEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT));
    rightWindow->consumeMotionMove();

    leftWindow->assertNoEvents();
    rightWindow->assertNoEvents();
    wallpaperWindow->assertNoEvents();
}

/**
 * Two windows: a window on the left with dup touch to wallpaper and window on the right without it.
 * The touch slips to the right window. so left window and wallpaper should receive ACTION_CANCEL
 * The right window should receive ACTION_DOWN.
 */
TEST_F(InputDispatcherTest, WallpaperWindowWhenSlippery) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> leftWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    leftWindow->setFrame(Rect(0, 0, 200, 200));
    leftWindow->setDupTouchToWallpaper(true);
    leftWindow->setSlippery(true);

    sp<FakeWindowHandle> rightWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    rightWindow->setFrame(Rect(200, 0, 400, 200));

    sp<FakeWindowHandle> wallpaperWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper", ADISPLAY_ID_DEFAULT);
    wallpaperWindow->setIsWallpaper(true);

    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {leftWindow, rightWindow, wallpaperWindow}}});

    // Touch down on left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 100}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Both foreground window and its wallpaper should receive the touch down
    leftWindow->consumeMotionDown();
    wallpaperWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Move to right window, the left window should receive cancel.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {201, 100}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    leftWindow->consumeMotionCancel();
    rightWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    wallpaperWindow->consumeMotionCancel(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);
}

/**
 * The policy typically sets POLICY_FLAG_PASS_TO_USER to the events. But when the display is not
 * interactive, it might stop sending this flag.
 * In this test, we check that if the policy stops sending this flag mid-gesture, we still ensure
 * to have a consistent input stream.
 *
 * Test procedure:
 * DOWN -> POINTER_DOWN -> (stop sending POLICY_FLAG_PASS_TO_USER) -> CANCEL.
 * DOWN (new gesture).
 *
 * In the bad implementation, we could potentially drop the CANCEL event, and get an inconsistent
 * state in the dispatcher. This would cause the final DOWN event to not be delivered to the app.
 *
 * We technically just need a single window here, but we are using two windows (spy on top and a
 * regular window below) to emulate the actual situation where it happens on the device.
 */
TEST_F(InputDispatcherTest, TwoPointerCancelInconsistentPolicy) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> spyWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Spy", ADISPLAY_ID_DEFAULT);
    spyWindow->setFrame(Rect(0, 0, 200, 200));
    spyWindow->setTrustedOverlay(true);
    spyWindow->setSpy(true);

    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 200, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spyWindow, window}}});
    const int32_t touchDeviceId = 4;

    // Two pointers down
    mDispatcher->notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .deviceId(touchDeviceId)
                    .policyFlags(DEFAULT_POLICY_FLAGS)
                    .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                    .build());

    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .policyFlags(DEFAULT_POLICY_FLAGS)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(120).y(120))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    spyWindow->consumeMotionEvent(WithMotionAction(POINTER_1_DOWN));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    window->consumeMotionEvent(WithMotionAction(POINTER_1_DOWN));

    // Cancel the current gesture. Send the cancel without the default policy flags.
    mDispatcher->notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_CANCEL, AINPUT_SOURCE_TOUCHSCREEN)
                    .deviceId(touchDeviceId)
                    .policyFlags(0)
                    .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                    .pointer(PointerBuilder(1, ToolType::FINGER).x(120).y(120))
                    .build());
    spyWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL));

    // We don't need to reset the device to reproduce the issue, but the reset event typically
    // follows, so we keep it here to model the actual listener behaviour more closely.
    mDispatcher->notifyDeviceReset({/*id=*/1, systemTime(SYSTEM_TIME_MONOTONIC), touchDeviceId});

    // Start new gesture
    mDispatcher->notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .deviceId(touchDeviceId)
                    .policyFlags(DEFAULT_POLICY_FLAGS)
                    .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                    .build());
    spyWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));

    // No more events
    spyWindow->assertNoEvents();
    window->assertNoEvents();
}

/**
 * Two windows: a window on the left and a window on the right.
 * Mouse is hovered from the right window into the left window.
 * Next, we tap on the left window, where the cursor was last seen.
 * The second tap is done onto the right window.
 * The mouse and tap are from two different devices.
 * We technically don't need to set the downtime / eventtime for these events, but setting these
 * explicitly helps during debugging.
 * This test reproduces a crash where there is a mismatch between the downTime and eventTime.
 * In the buggy implementation, a tap on the right window would cause a crash.
 */
TEST_F(InputDispatcherTest, HoverFromLeftToRightAndTap) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> leftWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    leftWindow->setFrame(Rect(0, 0, 200, 200));

    sp<FakeWindowHandle> rightWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    rightWindow->setFrame(Rect(200, 0, 400, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {leftWindow, rightWindow}}});
    // All times need to start at the current time, otherwise the dispatcher will drop the events as
    // stale.
    const nsecs_t baseTime = systemTime(SYSTEM_TIME_MONOTONIC);
    const int32_t mouseDeviceId = 6;
    const int32_t touchDeviceId = 4;
    // Move the cursor from right
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .deviceId(mouseDeviceId)
                                        .downTime(baseTime + 10)
                                        .eventTime(baseTime + 20)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(300)
                                                         .y(100))
                                        .build()));
    rightWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // .. to the left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .deviceId(mouseDeviceId)
                                        .downTime(baseTime + 10)
                                        .eventTime(baseTime + 30)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(110)
                                                         .y(100))
                                        .build()));
    rightWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));
    // Now tap the left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .downTime(baseTime + 40)
                                        .eventTime(baseTime + 40)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build()));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));

    // release tap
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .downTime(baseTime + 40)
                                        .eventTime(baseTime + 50)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build()));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_UP));

    // Tap the window on the right
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .downTime(baseTime + 60)
                                        .eventTime(baseTime + 60)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(300)
                                                         .y(100))
                                        .build()));
    rightWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));

    // release tap
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .downTime(baseTime + 60)
                                        .eventTime(baseTime + 70)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(300)
                                                         .y(100))
                                        .build()));
    rightWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_UP));

    // No more events
    leftWindow->assertNoEvents();
    rightWindow->assertNoEvents();
}

/**
 * Start hovering in a window. While this hover is still active, make another window appear on top.
 * The top, obstructing window has no input channel, so it's not supposed to receive input.
 * While the top window is present, the hovering is stopped.
 * Later, hovering gets resumed again.
 * Ensure that new hover gesture is handled correctly.
 * This test reproduces a crash where the HOVER_EXIT event wasn't getting dispatched correctly
 * to the window that's currently being hovered over.
 */
TEST_F(InputDispatcherTest, HoverWhileWindowAppears) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 200, 200));

    // Only a single window is present at first
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Start hovering in the window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(100).y(100))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));

    // Now, an obscuring window appears!
    sp<FakeWindowHandle> obscuringWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Obscuring window",
                                       ADISPLAY_ID_DEFAULT,
                                       /*token=*/std::make_optional<sp<IBinder>>(nullptr));
    obscuringWindow->setFrame(Rect(0, 0, 200, 200));
    obscuringWindow->setTouchOcclusionMode(TouchOcclusionMode::BLOCK_UNTRUSTED);
    obscuringWindow->setOwnerInfo(SECONDARY_WINDOW_PID, SECONDARY_WINDOW_UID);
    obscuringWindow->setNoInputChannel(true);
    obscuringWindow->setFocusable(false);
    obscuringWindow->setAlpha(1.0);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {obscuringWindow, window}}});

    // While this new obscuring window is present, the hovering is stopped
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_EXIT, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(100).y(100))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));

    // Now the obscuring window goes away.
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // And a new hover gesture starts.
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(100).y(100))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));
}

/**
 * Same test as 'HoverWhileWindowAppears' above, but here, we also send some HOVER_MOVE events to
 * the obscuring window.
 */
TEST_F(InputDispatcherTest, HoverMoveWhileWindowAppears) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 200, 200));

    // Only a single window is present at first
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Start hovering in the window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(100).y(100))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));

    // Now, an obscuring window appears!
    sp<FakeWindowHandle> obscuringWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Obscuring window",
                                       ADISPLAY_ID_DEFAULT,
                                       /*token=*/std::make_optional<sp<IBinder>>(nullptr));
    obscuringWindow->setFrame(Rect(0, 0, 200, 200));
    obscuringWindow->setTouchOcclusionMode(TouchOcclusionMode::BLOCK_UNTRUSTED);
    obscuringWindow->setOwnerInfo(SECONDARY_WINDOW_PID, SECONDARY_WINDOW_UID);
    obscuringWindow->setNoInputChannel(true);
    obscuringWindow->setFocusable(false);
    obscuringWindow->setAlpha(1.0);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {obscuringWindow, window}}});

    // While this new obscuring window is present, the hovering continues. The event can't go to the
    // bottom window due to obstructed touches, so it should generate HOVER_EXIT for that window.
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_MOVE, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(100).y(100))
                                      .build());
    obscuringWindow->assertNoEvents();
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));

    // Now the obscuring window goes away.
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Hovering continues in the same position. The hovering pointer re-enters the bottom window,
    // so it should generate a HOVER_ENTER
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_MOVE, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(100).y(100))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));

    // Now the MOVE should be getting dispatched normally
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_MOVE, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(110).y(110))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_MOVE));
}

/**
 * Two windows: a window on the left and a window on the right.
 * Mouse is clicked on the left window and remains down. Touch is touched on the right and remains
 * down. Then, on the left window, also place second touch pointer down.
 * This test tries to reproduce a crash.
 * In the buggy implementation, second pointer down on the left window would cause a crash.
 */
TEST_F(InputDispatcherTest, MultiDeviceSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> leftWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    leftWindow->setFrame(Rect(0, 0, 200, 200));

    sp<FakeWindowHandle> rightWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    rightWindow->setFrame(Rect(200, 0, 400, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {leftWindow, rightWindow}}});

    const int32_t touchDeviceId = 4;
    const int32_t mouseDeviceId = 6;
    NotifyMotionArgs args;

    // Start hovering over the left window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(100).y(100))
                                      .build());
    leftWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_HOVER_ENTER), WithDeviceId(mouseDeviceId)));

    // Mouse down on left window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(100).y(100))
                                      .build());

    leftWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_HOVER_EXIT), WithDeviceId(mouseDeviceId)));
    leftWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(mouseDeviceId)));

    mDispatcher->notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS, AINPUT_SOURCE_MOUSE)
                    .deviceId(mouseDeviceId)
                    .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                    .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                    .pointer(PointerBuilder(0, ToolType::MOUSE).x(100).y(100))
                    .build());
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));

    // First touch pointer down on right window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(300).y(100))
                                      .build());
    leftWindow->consumeMotionEvent(WithMotionAction(ACTION_CANCEL));

    rightWindow->consumeMotionEvent(WithMotionAction(ACTION_DOWN));

    // Second touch pointer down on left window
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(300).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(100).y(100))
                                      .build());
    leftWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(touchDeviceId)));
    // This MOVE event is not necessary (doesn't carry any new information), but it's there in the
    // current implementation.
    const std::map<int32_t, PointF> expectedPointers{{0, PointF{100, 100}}};
    rightWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_MOVE), WithPointers(expectedPointers)));

    leftWindow->assertNoEvents();
    rightWindow->assertNoEvents();
}

/**
 * On a single window, use two different devices: mouse and touch.
 * Touch happens first, with two pointers going down, and then the first pointer leaving.
 * Mouse is clicked next, which causes the touch stream to be aborted with ACTION_CANCEL.
 * Finally, a second touch pointer goes down again. Ensure the second touch pointer is ignored,
 * because the mouse is currently down, and a POINTER_DOWN event from the touchscreen does not
 * represent a new gesture.
 */
TEST_F(InputDispatcherTest, MixedTouchAndMouseWithPointerDown) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 400, 400));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    const int32_t touchDeviceId = 4;
    const int32_t mouseDeviceId = 6;
    NotifyMotionArgs args;

    // First touch pointer down
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(300).y(100))
                                      .build());
    // Second touch pointer down
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(300).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(350).y(100))
                                      .build());
    // First touch pointer lifts. The second one remains down
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_0_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(300).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(350).y(100))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    window->consumeMotionEvent(WithMotionAction(POINTER_1_DOWN));
    window->consumeMotionEvent(WithMotionAction(POINTER_0_UP));

    // Mouse down. The touch should be canceled
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(320).y(100))
                                      .build());

    window->consumeMotionEvent(AllOf(WithMotionAction(ACTION_CANCEL), WithDeviceId(touchDeviceId),
                                     WithPointerCount(1u)));
    window->consumeMotionEvent(AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(mouseDeviceId)));

    mDispatcher->notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS, AINPUT_SOURCE_MOUSE)
                    .deviceId(mouseDeviceId)
                    .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                    .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                    .pointer(PointerBuilder(0, ToolType::MOUSE).x(320).y(100))
                    .build());
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));

    // Second touch pointer down.
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_0_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(300).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(350).y(100))
                                      .build());
    // The pointer_down event should be ignored
    window->assertNoEvents();
}

/**
 * Inject a touch down and then send a new event via 'notifyMotion'. Ensure the new event cancels
 * the injected event.
 */
TEST_F(InputDispatcherTest, UnfinishedInjectedEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 400, 400));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    const int32_t touchDeviceId = 4;
    NotifyMotionArgs args;
    // Pretend a test injects an ACTION_DOWN mouse event, but forgets to lift up the touch after
    // completion.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                        .deviceId(ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(50)
                                                         .y(50))
                                        .build()));
    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(VIRTUAL_KEYBOARD_ID)));

    // Now a real touch comes. Rather than crashing or dropping the real event, the injected pointer
    // should be canceled and the new gesture should take over.
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(300).y(100))
                                      .build());

    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_CANCEL), WithDeviceId(VIRTUAL_KEYBOARD_ID)));
    window->consumeMotionEvent(AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(touchDeviceId)));
}

/**
 * This test is similar to the test above, but the sequence of injected events is different.
 *
 * Two windows: a window on the left and a window on the right.
 * Mouse is hovered over the left window.
 * Next, we tap on the left window, where the cursor was last seen.
 *
 * After that, we inject one finger down onto the right window, and then a second finger down onto
 * the left window.
 * The touch is split, so this last gesture should cause 2 ACTION_DOWN events, one in the right
 * window (first), and then another on the left window (second).
 * This test reproduces a crash where there is a mismatch between the downTime and eventTime.
 * In the buggy implementation, second finger down on the left window would cause a crash.
 */
TEST_F(InputDispatcherTest, HoverTapAndSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> leftWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    leftWindow->setFrame(Rect(0, 0, 200, 200));

    sp<FakeWindowHandle> rightWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    rightWindow->setFrame(Rect(200, 0, 400, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {leftWindow, rightWindow}}});

    const int32_t mouseDeviceId = 6;
    const int32_t touchDeviceId = 4;
    // Hover over the left window. Keep the cursor there.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                   AINPUT_SOURCE_MOUSE)
                                        .deviceId(mouseDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(50)
                                                         .y(50))
                                        .build()));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // Tap on left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build()));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build()));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_UP));

    // First finger down on right window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(300)
                                                         .y(100))
                                        .build()));
    rightWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));

    // Second finger down on the left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(300)
                                                         .y(100))
                                        .pointer(PointerBuilder(1, ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build()));
    leftWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));
    rightWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_MOVE));

    // No more events
    leftWindow->assertNoEvents();
    rightWindow->assertNoEvents();
}

/**
 * Start hovering with a stylus device, and then tap with a touch device. Ensure no crash occurs.
 * While the touch is down, new hover events from the stylus device should be ignored. After the
 * touch is gone, stylus hovering should start working again.
 */
TEST_F(InputDispatcherTest, StylusHoverAndTouchTap) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 200, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    const int32_t stylusDeviceId = 5;
    const int32_t touchDeviceId = 4;
    // Start hovering with stylus
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                   AINPUT_SOURCE_STYLUS)
                                        .deviceId(stylusDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::STYLUS)
                                                         .x(50)
                                                         .y(50))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // Finger down on the window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_DOWN));

    // Try to continue hovering with stylus. Since we are already down, injection should fail
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_STYLUS)
                                        .deviceId(stylusDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::STYLUS)
                                                         .x(50)
                                                         .y(50))
                                        .build()));
    // No event should be sent. This event should be ignored because a pointer from another device
    // is already down.

    // Lift up the finger
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(touchDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(100)
                                                         .y(100))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_UP));

    // Now that the touch is gone, stylus hovering should start working again
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_STYLUS)
                                        .deviceId(stylusDeviceId)
                                        .pointer(PointerBuilder(0, ToolType::STYLUS)
                                                         .x(50)
                                                         .y(50))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));
    // No more events
    window->assertNoEvents();
}

/**
 * A spy window above a window with no input channel.
 * Start hovering with a stylus device, and then tap with it.
 * Ensure spy window receives the entire sequence.
 */
TEST_F(InputDispatcherTest, StylusHoverAndDownNoInputChannel) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> spyWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Spy", ADISPLAY_ID_DEFAULT);
    spyWindow->setFrame(Rect(0, 0, 200, 200));
    spyWindow->setTrustedOverlay(true);
    spyWindow->setSpy(true);
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setNoInputChannel(true);
    window->setFrame(Rect(0, 0, 200, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spyWindow, window}}});

    // Start hovering with stylus
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(50).y(50))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));
    // Stop hovering
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_EXIT, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(50).y(50))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));

    // Stylus touches down
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(50).y(50))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_DOWN));

    // Stylus goes up
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(50).y(50))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_UP));

    // Again hover
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(50).y(50))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));
    // Stop hovering
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_EXIT, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(50).y(50))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));

    // No more events
    spyWindow->assertNoEvents();
    window->assertNoEvents();
}

/**
 * Start hovering with a mouse, and then tap with a touch device. Pilfer the touch stream.
 * Next, click with the mouse device. Both windows (spy and regular) should receive the new mouse
 * ACTION_DOWN event because that's a new gesture, and pilfering should no longer be active.
 * While the mouse is down, new move events from the touch device should be ignored.
 */
TEST_F(InputDispatcherTest, TouchPilferAndMouseMove) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> spyWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Spy", ADISPLAY_ID_DEFAULT);
    spyWindow->setFrame(Rect(0, 0, 200, 200));
    spyWindow->setTrustedOverlay(true);
    spyWindow->setSpy(true);
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 200, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spyWindow, window}}});

    const int32_t mouseDeviceId = 7;
    const int32_t touchDeviceId = 4;

    // Hover a bit with mouse first
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(100).y(100))
                                      .build());
    spyWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_HOVER_ENTER), WithDeviceId(mouseDeviceId)));
    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_HOVER_ENTER), WithDeviceId(mouseDeviceId)));

    // Start touching
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(50).y(50))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));

    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(55).y(55))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_MOVE));
    window->consumeMotionEvent(WithMotionAction(ACTION_MOVE));

    // Pilfer the stream
    EXPECT_EQ(OK, mDispatcher->pilferPointers(spyWindow->getToken()));
    window->consumeMotionEvent(WithMotionAction(ACTION_CANCEL));

    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(60).y(60))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_MOVE));

    // Mouse down
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(100).y(100))
                                      .build());

    spyWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_CANCEL), WithDeviceId(touchDeviceId)));
    spyWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(mouseDeviceId)));
    window->consumeMotionEvent(AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(mouseDeviceId)));

    mDispatcher->notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS, AINPUT_SOURCE_MOUSE)
                    .deviceId(mouseDeviceId)
                    .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                    .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                    .pointer(PointerBuilder(0, ToolType::MOUSE).x(100).y(100))
                    .build());
    spyWindow->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));

    // Mouse move!
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(110).y(110))
                                      .build());
    spyWindow->consumeMotionEvent(WithMotionAction(ACTION_MOVE));
    window->consumeMotionEvent(WithMotionAction(ACTION_MOVE));

    // Touch move!
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(65).y(65))
                                      .build());

    // No more events
    spyWindow->assertNoEvents();
    window->assertNoEvents();
}

/**
 * On the display, have a single window, and also an area where there's no window.
 * First pointer touches the "no window" area of the screen. Second pointer touches the window.
 * Make sure that the window receives the second pointer, and first pointer is simply ignored.
 */
TEST_F(InputDispatcherTest, SplitWorksWhenEmptyAreaIsTouched) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", DISPLAY_ID);

    mDispatcher->setInputWindows({{DISPLAY_ID, {window}}});

    // Touch down on the empty space
    mDispatcher->notifyMotion(generateTouchArgs(AMOTION_EVENT_ACTION_DOWN, {{-1, -1}}));

    mDispatcher->waitForIdle();
    window->assertNoEvents();

    // Now touch down on the window with another pointer
    mDispatcher->notifyMotion(generateTouchArgs(POINTER_1_DOWN, {{-1, -1}, {10, 10}}));
    mDispatcher->waitForIdle();
    window->consumeMotionDown();
}

/**
 * Same test as above, but instead of touching the empty space, the first touch goes to
 * non-touchable window.
 */
TEST_F(InputDispatcherTest, SplitWorksWhenNonTouchableWindowIsTouched) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window1 =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window1", DISPLAY_ID);
    window1->setTouchableRegion(Region{{0, 0, 100, 100}});
    window1->setTouchable(false);
    sp<FakeWindowHandle> window2 =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window2", DISPLAY_ID);
    window2->setTouchableRegion(Region{{100, 0, 200, 100}});

    mDispatcher->setInputWindows({{DISPLAY_ID, {window1, window2}}});

    // Touch down on the non-touchable window
    mDispatcher->notifyMotion(generateTouchArgs(AMOTION_EVENT_ACTION_DOWN, {{50, 50}}));

    mDispatcher->waitForIdle();
    window1->assertNoEvents();
    window2->assertNoEvents();

    // Now touch down on the window with another pointer
    mDispatcher->notifyMotion(generateTouchArgs(POINTER_1_DOWN, {{50, 50}, {150, 50}}));
    mDispatcher->waitForIdle();
    window2->consumeMotionDown();
}

/**
 * When splitting touch events the downTime should be adjusted such that the downTime corresponds
 * to the event time of the first ACTION_DOWN sent to the particular window.
 */
TEST_F(InputDispatcherTest, SplitTouchesSendCorrectActionDownTime) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window1 =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window1", DISPLAY_ID);
    window1->setTouchableRegion(Region{{0, 0, 100, 100}});
    sp<FakeWindowHandle> window2 =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window2", DISPLAY_ID);
    window2->setTouchableRegion(Region{{100, 0, 200, 100}});

    mDispatcher->setInputWindows({{DISPLAY_ID, {window1, window2}}});

    // Touch down on the first window
    mDispatcher->notifyMotion(generateTouchArgs(AMOTION_EVENT_ACTION_DOWN, {{50, 50}}));

    mDispatcher->waitForIdle();
    InputEvent* inputEvent1 = window1->consume();
    ASSERT_NE(inputEvent1, nullptr);
    window2->assertNoEvents();
    MotionEvent& motionEvent1 = static_cast<MotionEvent&>(*inputEvent1);
    nsecs_t downTimeForWindow1 = motionEvent1.getDownTime();
    ASSERT_EQ(motionEvent1.getDownTime(), motionEvent1.getEventTime());

    // Now touch down on the window with another pointer
    mDispatcher->notifyMotion(generateTouchArgs(POINTER_1_DOWN, {{50, 50}, {150, 50}}));
    mDispatcher->waitForIdle();
    InputEvent* inputEvent2 = window2->consume();
    ASSERT_NE(inputEvent2, nullptr);
    MotionEvent& motionEvent2 = static_cast<MotionEvent&>(*inputEvent2);
    nsecs_t downTimeForWindow2 = motionEvent2.getDownTime();
    ASSERT_NE(downTimeForWindow1, downTimeForWindow2);
    ASSERT_EQ(motionEvent2.getDownTime(), motionEvent2.getEventTime());

    // Now move the pointer on the second window
    mDispatcher->notifyMotion(generateTouchArgs(AMOTION_EVENT_ACTION_MOVE, {{50, 50}, {151, 51}}));
    mDispatcher->waitForIdle();
    window2->consumeMotionEvent(WithDownTime(downTimeForWindow2));

    // Now add new touch down on the second window
    mDispatcher->notifyMotion(generateTouchArgs(POINTER_2_DOWN, {{50, 50}, {151, 51}, {150, 50}}));
    mDispatcher->waitForIdle();
    window2->consumeMotionEvent(WithDownTime(downTimeForWindow2));

    // TODO(b/232530217): do not send the unnecessary MOVE event and delete the next line
    window1->consumeMotionMove();
    window1->assertNoEvents();

    // Now move the pointer on the first window
    mDispatcher->notifyMotion(
            generateTouchArgs(AMOTION_EVENT_ACTION_MOVE, {{51, 51}, {151, 51}, {150, 50}}));
    mDispatcher->waitForIdle();
    window1->consumeMotionEvent(WithDownTime(downTimeForWindow1));

    mDispatcher->notifyMotion(
            generateTouchArgs(POINTER_3_DOWN, {{51, 51}, {151, 51}, {150, 50}, {50, 50}}));
    mDispatcher->waitForIdle();
    window1->consumeMotionEvent(WithDownTime(downTimeForWindow1));
}

TEST_F(InputDispatcherTest, HoverMoveEnterMouseClickAndHoverMoveExit) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowLeft =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    windowLeft->setFrame(Rect(0, 0, 600, 800));
    sp<FakeWindowHandle> windowRight =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    windowRight->setFrame(Rect(600, 0, 1200, 800));

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowLeft, windowRight}}});

    // Start cursor position in right window so that we can move the cursor to left window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(900).y(400))
                                        .build()));
    windowRight->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // Move cursor into left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    windowRight->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT));
    windowLeft->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // Inject a series of mouse events for a mouse click
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    windowLeft->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));
    windowLeft->consumeMotionEvent(WithMotionAction(ACTION_DOWN));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    windowLeft->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    windowLeft->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    windowLeft->consumeMotionUp(ADISPLAY_ID_DEFAULT);

    // Move mouse cursor back to right window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(900).y(400))
                                        .build()));
    windowRight->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // No more events
    windowLeft->assertNoEvents();
    windowRight->assertNoEvents();
}

/**
 * Put two fingers down (and don't release them) and click the mouse button.
 * The clicking of mouse is a new ACTION_DOWN event. Since it's from a different device, the
 * currently active gesture should be canceled, and the new one should proceed.
 */
TEST_F(InputDispatcherTest, TwoPointersDownMouseClick) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 600, 800));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    const int32_t touchDeviceId = 4;
    const int32_t mouseDeviceId = 6;

    // Two pointers down
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .build());

    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(120).y(120))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    window->consumeMotionEvent(WithMotionAction(POINTER_1_DOWN));

    // Inject a series of mouse events for a mouse click
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                      .build());
    window->consumeMotionEvent(AllOf(WithMotionAction(ACTION_CANCEL), WithDeviceId(touchDeviceId),
                                     WithPointerCount(2u)));
    window->consumeMotionEvent(AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(mouseDeviceId)));

    mDispatcher->notifyMotion(
            MotionArgsBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS, AINPUT_SOURCE_MOUSE)
                    .deviceId(mouseDeviceId)
                    .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                    .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                    .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                    .build());
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));

    // Try to send more touch events while the mouse is down. Since it's a continuation of an
    // already canceled gesture, it should be ignored.
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(101).y(101))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(121).y(121))
                                      .build());
    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, HoverWithSpyWindows) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> spyWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Spy", ADISPLAY_ID_DEFAULT);
    spyWindow->setFrame(Rect(0, 0, 600, 800));
    spyWindow->setTrustedOverlay(true);
    spyWindow->setSpy(true);
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 600, 800));

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spyWindow, window}}});

    // Send mouse cursor to the window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(100)
                                                         .y(100))
                                        .build()));

    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                                     WithSource(AINPUT_SOURCE_MOUSE)));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                                        WithSource(AINPUT_SOURCE_MOUSE)));

    window->assertNoEvents();
    spyWindow->assertNoEvents();
}

TEST_F(InputDispatcherTest, MouseAndTouchWithSpyWindows) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> spyWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Spy", ADISPLAY_ID_DEFAULT);
    spyWindow->setFrame(Rect(0, 0, 600, 800));
    spyWindow->setTrustedOverlay(true);
    spyWindow->setSpy(true);
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 600, 800));

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spyWindow, window}}});

    // Send mouse cursor to the window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(100)
                                                         .y(100))
                                        .build()));

    // Move mouse cursor
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(110)
                                                         .y(110))
                                        .build()));

    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                                     WithSource(AINPUT_SOURCE_MOUSE)));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                                        WithSource(AINPUT_SOURCE_MOUSE)));
    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                     WithSource(AINPUT_SOURCE_MOUSE)));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                                        WithSource(AINPUT_SOURCE_MOUSE)));
    // Touch down on the window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(SECOND_DEVICE_ID)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(200)
                                                         .y(200))
                                        .build()));
    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT),
                                     WithSource(AINPUT_SOURCE_MOUSE)));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT),
                                        WithSource(AINPUT_SOURCE_MOUSE)));
    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                     WithSource(AINPUT_SOURCE_TOUCHSCREEN)));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                        WithSource(AINPUT_SOURCE_TOUCHSCREEN)));

    // pilfer the motion, retaining the gesture on the spy window.
    EXPECT_EQ(OK, mDispatcher->pilferPointers(spyWindow->getToken()));
    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL),
                                     WithSource(AINPUT_SOURCE_TOUCHSCREEN)));

    // Touch UP on the window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(SECOND_DEVICE_ID)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(200)
                                                         .y(200))
                                        .build()));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                        WithSource(AINPUT_SOURCE_TOUCHSCREEN)));

    // Previously, a touch was pilfered. However, that gesture was just finished. Now, we are going
    // to send a new gesture. It should again go to both windows (spy and the window below), just
    // like the first gesture did, before pilfering. The window configuration has not changed.

    // One more tap - DOWN
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(SECOND_DEVICE_ID)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(250)
                                                         .y(250))
                                        .build()));
    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                     WithSource(AINPUT_SOURCE_TOUCHSCREEN)));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                        WithSource(AINPUT_SOURCE_TOUCHSCREEN)));

    // Touch UP on the window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .deviceId(SECOND_DEVICE_ID)
                                        .pointer(PointerBuilder(0, ToolType::FINGER)
                                                         .x(250)
                                                         .y(250))
                                        .build()));
    window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                     WithSource(AINPUT_SOURCE_TOUCHSCREEN)));
    spyWindow->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                        WithSource(AINPUT_SOURCE_TOUCHSCREEN)));

    window->assertNoEvents();
    spyWindow->assertNoEvents();
}

// This test is different from the test above that HOVER_ENTER and HOVER_EXIT events are injected
// directly in this test.
TEST_F(InputDispatcherTest, HoverEnterMouseClickAndHoverExit) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 1200, 800));

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));
    // Inject a series of mouse events for a mouse click
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));
    window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_PRESS));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_BUTTON_RELEASE));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    window->consumeMotionUp(ADISPLAY_ID_DEFAULT);

    // We already canceled the hovering implicitly by injecting the "DOWN" event without lifting the
    // hover first. Therefore, injection of HOVER_EXIT is inconsistent, and should fail.
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_EXIT,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                                        .build()));
    window->assertNoEvents();
}

/**
 * Hover over a window, and then remove that window. Make sure that HOVER_EXIT for that event
 * is generated.
 */
TEST_F(InputDispatcherTest, HoverExitIsSentToRemovedWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 1200, 800));

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // Remove the window, but keep the channel.
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {}}});
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT));
}

/**
 * Test that invalid HOVER events sent by accessibility do not cause a fatal crash.
 */
TEST_F(InputDispatcherTest, InvalidA11yHoverStreamDoesNotCrash) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 1200, 800));
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    MotionEventBuilder hoverEnterBuilder =
            MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER, AINPUT_SOURCE_MOUSE)
                    .pointer(PointerBuilder(0, ToolType::MOUSE).x(300).y(400))
                    .addFlag(AMOTION_EVENT_FLAG_IS_ACCESSIBILITY_EVENT);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, hoverEnterBuilder.build()));
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, hoverEnterBuilder.build()));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));
    window->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));
}

/**
 * If mouse is hovering when the touch goes down, the hovering should be stopped via HOVER_EXIT.
 */
TEST_F(InputDispatcherTest, TouchDownAfterMouseHover) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    const int32_t mouseDeviceId = 7;
    const int32_t touchDeviceId = 4;

    // Start hovering with the mouse
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_MOUSE)
                                      .deviceId(mouseDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::MOUSE).x(10).y(10))
                                      .build());
    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_HOVER_ENTER), WithDeviceId(mouseDeviceId)));

    // Touch goes down
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .deviceId(touchDeviceId)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(50).y(50))
                                      .build());

    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_HOVER_EXIT), WithDeviceId(mouseDeviceId)));
    window->consumeMotionEvent(AllOf(WithMotionAction(ACTION_DOWN), WithDeviceId(touchDeviceId)));
}

/**
 * Inject a mouse hover event followed by a tap from touchscreen.
 * The tap causes a HOVER_EXIT event to be generated because the current event
 * stream's source has been switched.
 */
TEST_F(InputDispatcherTest, MouseHoverAndTouchTap) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Inject a hover_move from mouse.
    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_HOVER_MOVE, AINPUT_SOURCE_MOUSE,
                               ADISPLAY_ID_DEFAULT, {{50, 50}});
    motionArgs.xCursorPosition = 50;
    motionArgs.yCursorPosition = 50;
    mDispatcher->notifyMotion(motionArgs);
    ASSERT_NO_FATAL_FAILURE(
            window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER),
                                             WithSource(AINPUT_SOURCE_MOUSE))));

    // Tap on the window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {{10, 10}}));
    ASSERT_NO_FATAL_FAILURE(
            window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_EXIT),
                                             WithSource(AINPUT_SOURCE_MOUSE))));

    ASSERT_NO_FATAL_FAILURE(
            window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                                             WithSource(AINPUT_SOURCE_TOUCHSCREEN))));

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT, {{10, 10}}));
    ASSERT_NO_FATAL_FAILURE(
            window->consumeMotionEvent(AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                             WithSource(AINPUT_SOURCE_TOUCHSCREEN))));
}

TEST_F(InputDispatcherTest, HoverEnterMoveRemoveWindowsInSecondDisplay) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowDefaultDisplay =
            sp<FakeWindowHandle>::make(application, mDispatcher, "DefaultDisplay",
                                       ADISPLAY_ID_DEFAULT);
    windowDefaultDisplay->setFrame(Rect(0, 0, 600, 800));
    sp<FakeWindowHandle> windowSecondDisplay =
            sp<FakeWindowHandle>::make(application, mDispatcher, "SecondDisplay",
                                       SECOND_DISPLAY_ID);
    windowSecondDisplay->setFrame(Rect(0, 0, 600, 800));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowDefaultDisplay}},
                                  {SECOND_DISPLAY_ID, {windowSecondDisplay}}});

    // Set cursor position in window in default display and check that hover enter and move
    // events are generated.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .displayId(ADISPLAY_ID_DEFAULT)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(300)
                                                         .y(600))
                                        .build()));
    windowDefaultDisplay->consumeMotionEvent(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_ENTER));

    // Remove all windows in secondary display and check that no event happens on window in
    // primary display.
    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {windowDefaultDisplay}}, {SECOND_DISPLAY_ID, {}}});
    windowDefaultDisplay->assertNoEvents();

    // Move cursor position in window in default display and check that only hover move
    // event is generated and not hover enter event.
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowDefaultDisplay}},
                                  {SECOND_DISPLAY_ID, {windowSecondDisplay}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .displayId(ADISPLAY_ID_DEFAULT)
                                        .pointer(PointerBuilder(0, ToolType::MOUSE)
                                                         .x(400)
                                                         .y(700))
                                        .build()));
    windowDefaultDisplay->consumeMotionEvent(
            AllOf(WithMotionAction(AMOTION_EVENT_ACTION_HOVER_MOVE),
                  WithSource(AINPUT_SOURCE_MOUSE)));
    windowDefaultDisplay->assertNoEvents();
}

TEST_F(InputDispatcherTest, DispatchMouseEventsUnderCursor) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> windowLeft =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    windowLeft->setFrame(Rect(0, 0, 600, 800));
    sp<FakeWindowHandle> windowRight =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    windowRight->setFrame(Rect(600, 0, 1200, 800));

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowLeft, windowRight}}});

    // Inject an event with coordinate in the area of right window, with mouse cursor in the area of
    // left window. This event should be dispatched to the left window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE,
                                ADISPLAY_ID_DEFAULT, {610, 400}, {599, 400}));
    windowLeft->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowRight->assertNoEvents();
}

TEST_F(InputDispatcherTest, NotifyDeviceReset_CancelsKeyStream) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));

    // Window should receive key down event.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    // When device reset happens, that key stream should be terminated with FLAG_CANCELED
    // on the app side.
    mDispatcher->notifyDeviceReset({/*id=*/10, /*eventTime=*/20, DEVICE_ID});
    window->consumeEvent(InputEventType::KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT,
                         AKEY_EVENT_FLAG_CANCELED);
}

TEST_F(InputDispatcherTest, NotifyDeviceReset_CancelsMotionStream) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));

    // Window should receive motion down event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // When device reset happens, that motion stream should be terminated with ACTION_CANCEL
    // on the app side.
    mDispatcher->notifyDeviceReset({/*id=*/10, /*eventTime=*/20, DEVICE_ID});
    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_CANCEL), WithDisplayId(ADISPLAY_ID_DEFAULT)));
}

TEST_F(InputDispatcherTest, NotifyDeviceResetCancelsHoveringStream) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(10).y(10))
                                      .build());

    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));

    // When device reset happens, that hover stream should be terminated with ACTION_HOVER_EXIT
    mDispatcher->notifyDeviceReset({/*id=*/10, /*eventTime=*/20, DEVICE_ID});
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_EXIT));

    // After the device has been reset, a new hovering stream can be sent to the window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_HOVER_ENTER, AINPUT_SOURCE_STYLUS)
                                      .pointer(PointerBuilder(0, ToolType::STYLUS).x(15).y(15))
                                      .build());
    window->consumeMotionEvent(WithMotionAction(ACTION_HOVER_ENTER));
}

TEST_F(InputDispatcherTest, InterceptKeyByPolicy) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    const NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    const std::chrono::milliseconds interceptKeyTimeout = 50ms;
    const nsecs_t injectTime = keyArgs.eventTime;
    mFakePolicy->setInterceptKeyTimeout(interceptKeyTimeout);
    mDispatcher->notifyKey(keyArgs);
    // The dispatching time should be always greater than or equal to intercept key timeout.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    ASSERT_TRUE((systemTime(SYSTEM_TIME_MONOTONIC) - injectTime) >=
                std::chrono::nanoseconds(interceptKeyTimeout).count());
}

/**
 * Keys with ACTION_UP are delivered immediately, even if a long 'intercept key timeout' is set.
 */
TEST_F(InputDispatcherTest, InterceptKeyIfKeyUp) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    // Set a value that's significantly larger than the default consumption timeout. If the
    // implementation is correct, the actual value doesn't matter; it won't slow down the test.
    mFakePolicy->setInterceptKeyTimeout(600ms);
    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT));
    // Window should receive key event immediately when same key up.
    window->consumeKeyUp(ADISPLAY_ID_DEFAULT);
}

/**
 * Two windows. First is a regular window. Second does not overlap with the first, and has
 * WATCH_OUTSIDE_TOUCH.
 * Both windows are owned by the same UID.
 * Tap first window. Make sure that the second window receives ACTION_OUTSIDE with correct, non-zero
 * coordinates. The coordinates are not zeroed out because both windows are owned by the same UID.
 */
TEST_F(InputDispatcherTest, ActionOutsideForOwnedWindowHasValidCoordinates) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "First Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect{0, 0, 100, 100});

    sp<FakeWindowHandle> outsideWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    outsideWindow->setFrame(Rect{100, 100, 200, 200});
    outsideWindow->setWatchOutsideTouch(true);
    // outsideWindow must be above 'window' to receive ACTION_OUTSIDE events when 'window' is tapped
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {outsideWindow, window}}});

    // Tap on first window.
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {PointF{50, 50}}));
    window->consumeMotionDown();
    // The coordinates of the tap in 'outsideWindow' are relative to its top left corner.
    // Therefore, we should offset them by (100, 100) relative to the screen's top left corner.
    outsideWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_OUTSIDE), WithCoords(-50, -50)));
}

/**
 * This test documents the behavior of WATCH_OUTSIDE_TOUCH. The window will get ACTION_OUTSIDE when
 * a another pointer causes ACTION_DOWN to be sent to another window for the first time. Only one
 * ACTION_OUTSIDE event is sent per gesture.
 */
TEST_F(InputDispatcherTest, ActionOutsideSentOnlyWhenAWindowIsTouched) {
    // There are three windows that do not overlap. `window` wants to WATCH_OUTSIDE_TOUCH.
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "First Window", ADISPLAY_ID_DEFAULT);
    window->setWatchOutsideTouch(true);
    window->setFrame(Rect{0, 0, 100, 100});
    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect{100, 100, 200, 200});
    sp<FakeWindowHandle> thirdWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Third Window",
                                       ADISPLAY_ID_DEFAULT);
    thirdWindow->setFrame(Rect{200, 200, 300, 300});
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window, secondWindow, thirdWindow}}});

    // First pointer lands outside all windows. `window` does not get ACTION_OUTSIDE.
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {PointF{-10, -10}}));
    window->assertNoEvents();
    secondWindow->assertNoEvents();

    // The second pointer lands inside `secondWindow`, which should receive a DOWN event.
    // Now, `window` should get ACTION_OUTSIDE.
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT,
                                                 {PointF{-10, -10}, PointF{105, 105}}));
    const std::map<int32_t, PointF> expectedPointers{{0, PointF{-10, -10}}, {1, PointF{105, 105}}};
    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_OUTSIDE), WithPointers(expectedPointers)));
    secondWindow->consumeMotionDown();
    thirdWindow->assertNoEvents();

    // The third pointer lands inside `thirdWindow`, which should receive a DOWN event. There is
    // no ACTION_OUTSIDE sent to `window` because one has already been sent for this gesture.
    mDispatcher->notifyMotion(
            generateMotionArgs(POINTER_2_DOWN, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {PointF{-10, -10}, PointF{105, 105}, PointF{205, 205}}));
    window->assertNoEvents();
    secondWindow->consumeMotionMove();
    thirdWindow->consumeMotionDown();
}

TEST_F(InputDispatcherTest, OnWindowInfosChanged_RemoveAllWindowsOnDisplay) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFocusable(true);

    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    const NotifyKeyArgs keyDown = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    const NotifyKeyArgs keyUp = generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyKey(keyDown);
    mDispatcher->notifyKey(keyUp);

    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    window->consumeKeyUp(ADISPLAY_ID_DEFAULT);

    // All windows are removed from the display. Ensure that we can no longer dispatch to it.
    mDispatcher->onWindowInfosChanged({{}, {}, 0, 0});

    window->consumeFocusEvent(false);

    mDispatcher->notifyKey(keyDown);
    mDispatcher->notifyKey(keyUp);
    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, NonSplitTouchableWindowReceivesMultiTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    // Ensure window is non-split and have some transform.
    window->setPreventSplitting(true);
    window->setWindowOffset(20, 40);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(50).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(-30).y(-50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    const MotionEvent* event = window->consumeMotion();
    EXPECT_EQ(POINTER_1_DOWN, event->getAction());
    EXPECT_EQ(70, event->getX(0));  // 50 + 20
    EXPECT_EQ(90, event->getY(0));  // 50 + 40
    EXPECT_EQ(-10, event->getX(1)); // -30 + 20
    EXPECT_EQ(-10, event->getY(1)); // -50 + 40
}

TEST_F(InputDispatcherTest, TouchpadThreeFingerSwipeOnlySentToTrustedOverlays) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 400, 400));
    sp<FakeWindowHandle> trustedOverlay =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Trusted Overlay",
                                       ADISPLAY_ID_DEFAULT);
    trustedOverlay->setSpy(true);
    trustedOverlay->setTrustedOverlay(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {trustedOverlay, window}}});

    // Start a three-finger touchpad swipe
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(100))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(100))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_2_DOWN, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(100))
                                      .pointer(PointerBuilder(2, ToolType::FINGER).x(300).y(100))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());

    trustedOverlay->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    trustedOverlay->consumeMotionEvent(WithMotionAction(POINTER_1_DOWN));
    trustedOverlay->consumeMotionEvent(WithMotionAction(POINTER_2_DOWN));

    // Move the swipe a bit
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(105))
                                      .pointer(PointerBuilder(2, ToolType::FINGER).x(300).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());

    trustedOverlay->consumeMotionEvent(WithMotionAction(ACTION_MOVE));

    // End the swipe
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_2_UP, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(105))
                                      .pointer(PointerBuilder(2, ToolType::FINGER).x(300).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_UP, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());

    trustedOverlay->consumeMotionEvent(WithMotionAction(POINTER_2_UP));
    trustedOverlay->consumeMotionEvent(WithMotionAction(POINTER_1_UP));
    trustedOverlay->consumeMotionEvent(WithMotionAction(ACTION_UP));

    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, TouchpadThreeFingerSwipeNotSentToSingleWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 400, 400));
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Start a three-finger touchpad swipe
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(100))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(100))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_2_DOWN, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(100))
                                      .pointer(PointerBuilder(2, ToolType::FINGER).x(300).y(100))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());

    // Move the swipe a bit
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(105))
                                      .pointer(PointerBuilder(2, ToolType::FINGER).x(300).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());

    // End the swipe
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_2_UP, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(105))
                                      .pointer(PointerBuilder(2, ToolType::FINGER).x(300).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_UP, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(250).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_MOUSE)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(200).y(105))
                                      .classification(MotionClassification::MULTI_FINGER_SWIPE)
                                      .build());

    window->assertNoEvents();
}

/**
 * Send a two-pointer gesture to a single window. The window's orientation changes in response to
 * the first pointer.
 * Ensure that the second pointer is not sent to the window.
 *
 * The subsequent gesture should be correctly delivered to the window.
 */
TEST_F(InputDispatcherTest, MultiplePointersWithRotatingWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 400, 400));
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    const nsecs_t baseTime = systemTime(SYSTEM_TIME_MONOTONIC);
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .downTime(baseTime + 10)
                                      .eventTime(baseTime + 10)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .build());

    window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));

    // We need a new window object for the same window, because dispatcher will store objects by
    // reference. That means that the testing code and the dispatcher will refer to the same shared
    // object. Calling window->setTransform here would affect dispatcher's comparison
    // of the old window to the new window, since both the old window and the new window would be
    // updated to the same value.
    sp<FakeWindowHandle> windowDup = window->duplicate();

    // Change the transform so that the orientation is now different from original.
    windowDup->setWindowTransform(0, -1, 1, 0);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowDup}}});

    window->consumeMotionEvent(WithMotionAction(ACTION_CANCEL));

    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .downTime(baseTime + 10)
                                      .eventTime(baseTime + 30)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(200).y(200))
                                      .build());

    // Finish the gesture and start a new one. Ensure the new gesture is sent to the window
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .downTime(baseTime + 10)
                                      .eventTime(baseTime + 40)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(200).y(200))
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .downTime(baseTime + 10)
                                      .eventTime(baseTime + 50)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                      .build());

    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .downTime(baseTime + 60)
                                      .eventTime(baseTime + 60)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(40).y(40))
                                      .build());

    windowDup->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
}

/**
 * Ensure the correct coordinate spaces are used by InputDispatcher.
 *
 * InputDispatcher works in the display space, so its coordinate system is relative to the display
 * panel. Windows get events in the window space, and get raw coordinates in the logical display
 * space.
 */
class InputDispatcherDisplayProjectionTest : public InputDispatcherTest {
public:
    void SetUp() override {
        InputDispatcherTest::SetUp();
        removeAllWindowsAndDisplays();
    }

    void addDisplayInfo(int displayId, const ui::Transform& transform) {
        gui::DisplayInfo info;
        info.displayId = displayId;
        info.transform = transform;
        mDisplayInfos.push_back(std::move(info));
        mDispatcher->onWindowInfosChanged({mWindowInfos, mDisplayInfos, 0, 0});
    }

    void addWindow(const sp<WindowInfoHandle>& windowHandle) {
        mWindowInfos.push_back(*windowHandle->getInfo());
        mDispatcher->onWindowInfosChanged({mWindowInfos, mDisplayInfos, 0, 0});
    }

    void removeAllWindowsAndDisplays() {
        mDisplayInfos.clear();
        mWindowInfos.clear();
    }

    // Set up a test scenario where the display has a scaled projection and there are two windows
    // on the display.
    std::pair<sp<FakeWindowHandle>, sp<FakeWindowHandle>> setupScaledDisplayScenario() {
        // The display has a projection that has a scale factor of 2 and 4 in the x and y directions
        // respectively.
        ui::Transform displayTransform;
        displayTransform.set(2, 0, 0, 4);
        addDisplayInfo(ADISPLAY_ID_DEFAULT, displayTransform);

        std::shared_ptr<FakeApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();

        // Add two windows to the display. Their frames are represented in the display space.
        sp<FakeWindowHandle> firstWindow =
                sp<FakeWindowHandle>::make(application, mDispatcher, "First Window",
                                           ADISPLAY_ID_DEFAULT);
        firstWindow->setFrame(Rect(0, 0, 100, 200), displayTransform);
        addWindow(firstWindow);

        sp<FakeWindowHandle> secondWindow =
                sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                           ADISPLAY_ID_DEFAULT);
        secondWindow->setFrame(Rect(100, 200, 200, 400), displayTransform);
        addWindow(secondWindow);
        return {std::move(firstWindow), std::move(secondWindow)};
    }

private:
    std::vector<gui::DisplayInfo> mDisplayInfos;
    std::vector<gui::WindowInfo> mWindowInfos;
};

TEST_F(InputDispatcherDisplayProjectionTest, HitTestCoordinateSpaceConsistency) {
    auto [firstWindow, secondWindow] = setupScaledDisplayScenario();
    // Send down to the first window. The point is represented in the display space. The point is
    // selected so that if the hit test was performed with the point and the bounds being in
    // different coordinate spaces, the event would end up in the incorrect window.
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {PointF{75, 55}}));

    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();
}

// Ensure that when a MotionEvent is injected through the InputDispatcher::injectInputEvent() API,
// the event should be treated as being in the logical display space.
TEST_F(InputDispatcherDisplayProjectionTest, InjectionInLogicalDisplaySpace) {
    auto [firstWindow, secondWindow] = setupScaledDisplayScenario();
    // Send down to the first window. The point is represented in the logical display space. The
    // point is selected so that if the hit test was done in logical display space, then it would
    // end up in the incorrect window.
    injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                     PointF{75 * 2, 55 * 4});

    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();
}

// Ensure that when a MotionEvent that has a custom transform is injected, the post-transformed
// event should be treated as being in the logical display space.
TEST_F(InputDispatcherDisplayProjectionTest, InjectionWithTransformInLogicalDisplaySpace) {
    auto [firstWindow, secondWindow] = setupScaledDisplayScenario();

    const std::array<float, 9> matrix = {1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 0.0, 0.0, 1.0};
    ui::Transform injectedEventTransform;
    injectedEventTransform.set(matrix);
    const vec2 expectedPoint{75, 55}; // The injected point in the logical display space.
    const vec2 untransformedPoint = injectedEventTransform.inverse().transform(expectedPoint);

    MotionEvent event = MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                .displayId(ADISPLAY_ID_DEFAULT)
                                .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                                .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER)
                                                 .x(untransformedPoint.x)
                                                 .y(untransformedPoint.y))
                                .build();
    event.transform(matrix);

    injectMotionEvent(mDispatcher, event, INJECT_EVENT_TIMEOUT,
                      InputEventInjectionSync::WAIT_FOR_RESULT);

    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDisplayProjectionTest, WindowGetsEventsInCorrectCoordinateSpace) {
    auto [firstWindow, secondWindow] = setupScaledDisplayScenario();

    // Send down to the second window.
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {PointF{150, 220}}));

    firstWindow->assertNoEvents();
    const MotionEvent* event = secondWindow->consumeMotion();
    ASSERT_NE(nullptr, event);
    EXPECT_EQ(AMOTION_EVENT_ACTION_DOWN, event->getAction());

    // Ensure that the events from the "getRaw" API are in logical display coordinates.
    EXPECT_EQ(300, event->getRawX(0));
    EXPECT_EQ(880, event->getRawY(0));

    // Ensure that the x and y values are in the window's coordinate space.
    // The left-top of the second window is at (100, 200) in display space, which is (200, 800) in
    // the logical display space. This will be the origin of the window space.
    EXPECT_EQ(100, event->getX(0));
    EXPECT_EQ(80, event->getY(0));
}

/** Ensure consistent behavior of InputDispatcher in all orientations. */
class InputDispatcherDisplayOrientationFixture
      : public InputDispatcherDisplayProjectionTest,
        public ::testing::WithParamInterface<ui::Rotation> {};

// This test verifies the touchable region of a window for all rotations of the display by tapping
// in different locations on the display, specifically points close to the four corners of a
// window.
TEST_P(InputDispatcherDisplayOrientationFixture, HitTestInDifferentOrientations) {
    constexpr static int32_t displayWidth = 400;
    constexpr static int32_t displayHeight = 800;

    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    const auto rotation = GetParam();

    // Set up the display with the specified rotation.
    const bool isRotated = rotation == ui::ROTATION_90 || rotation == ui::ROTATION_270;
    const int32_t logicalDisplayWidth = isRotated ? displayHeight : displayWidth;
    const int32_t logicalDisplayHeight = isRotated ? displayWidth : displayHeight;
    const ui::Transform displayTransform(ui::Transform::toRotationFlags(rotation),
                                         logicalDisplayWidth, logicalDisplayHeight);
    addDisplayInfo(ADISPLAY_ID_DEFAULT, displayTransform);

    // Create a window with its bounds determined in the logical display.
    const Rect frameInLogicalDisplay(100, 100, 200, 300);
    const Rect frameInDisplay = displayTransform.inverse().transform(frameInLogicalDisplay);
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(frameInDisplay, displayTransform);
    addWindow(window);

    // The following points in logical display space should be inside the window.
    static const std::array<vec2, 4> insidePoints{
            {{100, 100}, {199.99, 100}, {100, 299.99}, {199.99, 299.99}}};
    for (const auto pointInsideWindow : insidePoints) {
        const vec2 p = displayTransform.inverse().transform(pointInsideWindow);
        const PointF pointInDisplaySpace{p.x, p.y};
        mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                     AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                     {pointInDisplaySpace}));
        window->consumeMotionDown();

        mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP,
                                                     AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                     {pointInDisplaySpace}));
        window->consumeMotionUp();
    }

    // The following points in logical display space should be outside the window.
    static const std::array<vec2, 5> outsidePoints{
            {{200, 100}, {100, 300}, {200, 300}, {100, 99.99}, {99.99, 100}}};
    for (const auto pointOutsideWindow : outsidePoints) {
        const vec2 p = displayTransform.inverse().transform(pointOutsideWindow);
        const PointF pointInDisplaySpace{p.x, p.y};
        mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                     AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                     {pointInDisplaySpace}));

        mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP,
                                                     AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                     {pointInDisplaySpace}));
    }
    window->assertNoEvents();
}

// Run the precision tests for all rotations.
INSTANTIATE_TEST_SUITE_P(InputDispatcherDisplayOrientationTests,
                         InputDispatcherDisplayOrientationFixture,
                         ::testing::Values(ui::ROTATION_0, ui::ROTATION_90, ui::ROTATION_180,
                                           ui::ROTATION_270),
                         [](const testing::TestParamInfo<ui::Rotation>& testParamInfo) {
                             return ftl::enum_string(testParamInfo.param);
                         });

using TransferFunction = std::function<bool(const std::unique_ptr<InputDispatcher>& dispatcher,
                                            sp<IBinder>, sp<IBinder>)>;

class TransferTouchFixture : public InputDispatcherTest,
                             public ::testing::WithParamInterface<TransferFunction> {};

TEST_P(TransferTouchFixture, TransferTouch_OnePointer) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    // Create a couple of windows
    sp<FakeWindowHandle> firstWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "First Window",
                                       ADISPLAY_ID_DEFAULT);
    firstWindow->setDupTouchToWallpaper(true);
    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> wallpaper =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper", ADISPLAY_ID_DEFAULT);
    wallpaper->setIsWallpaper(true);
    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow, wallpaper}}});

    // Send down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));

    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();
    wallpaper->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Transfer touch to the second window
    TransferFunction f = GetParam();
    const bool success = f(mDispatcher, firstWindow->getToken(), secondWindow->getToken());
    ASSERT_TRUE(success);
    // The first window gets cancel and the second gets down
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionDown();
    wallpaper->consumeMotionCancel(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Send up event to the second window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    // The first  window gets no events and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
    wallpaper->assertNoEvents();
}

/**
 * When 'transferTouch' API is invoked, dispatcher needs to find the "best" window to take touch
 * from. When we have spy windows, there are several windows to choose from: either spy, or the
 * 'real' (non-spy) window. Always prefer the 'real' window because that's what would be most
 * natural to the user.
 * In this test, we are sending a pointer to both spy window and first window. We then try to
 * transfer touch to the second window. The dispatcher should identify the first window as the
 * one that should lose the gesture, and therefore the action should be to move the gesture from
 * the first window to the second.
 * The main goal here is to test the behaviour of 'transferTouch' API, but it's still valid to test
 * the other API, as well.
 */
TEST_P(TransferTouchFixture, TransferTouch_MultipleWindowsWithSpy) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    // Create a couple of windows + a spy window
    sp<FakeWindowHandle> spyWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Spy", ADISPLAY_ID_DEFAULT);
    spyWindow->setTrustedOverlay(true);
    spyWindow->setSpy(true);
    sp<FakeWindowHandle> firstWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "First", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spyWindow, firstWindow, secondWindow}}});

    // Send down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    // Only the first window and spy should get the down event
    spyWindow->consumeMotionDown();
    firstWindow->consumeMotionDown();

    // Transfer touch to the second window. Non-spy window should be preferred over the spy window
    // if f === 'transferTouch'.
    TransferFunction f = GetParam();
    const bool success = f(mDispatcher, firstWindow->getToken(), secondWindow->getToken());
    ASSERT_TRUE(success);
    // The first window gets cancel and the second gets down
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionDown();

    // Send up event to the second window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    // The first  window gets no events and the second+spy get up
    firstWindow->assertNoEvents();
    spyWindow->consumeMotionUp();
    secondWindow->consumeMotionUp();
}

TEST_P(TransferTouchFixture, TransferTouch_TwoPointersNonSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    PointF touchPoint = {10, 10};

    // Create a couple of windows
    sp<FakeWindowHandle> firstWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "First Window",
                                       ADISPLAY_ID_DEFAULT);
    firstWindow->setPreventSplitting(true);
    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    secondWindow->setPreventSplitting(true);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    // Send down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {touchPoint}));
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send pointer down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT, {touchPoint, touchPoint}));
    // Only the first window should get the pointer down event
    firstWindow->consumeMotionPointerDown(1);
    secondWindow->assertNoEvents();

    // Transfer touch focus to the second window
    TransferFunction f = GetParam();
    bool success = f(mDispatcher, firstWindow->getToken(), secondWindow->getToken());
    ASSERT_TRUE(success);
    // The first window gets cancel and the second gets down and pointer down
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionDown();
    secondWindow->consumeMotionPointerDown(1);

    // Send pointer up to the second window
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT, {touchPoint, touchPoint}));
    // The first window gets nothing and the second gets pointer up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionPointerUp(1);

    // Send up event to the second window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    // The first window gets nothing and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
}

TEST_P(TransferTouchFixture, TransferTouch_MultipleWallpapers) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    // Create a couple of windows
    sp<FakeWindowHandle> firstWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "First Window",
                                       ADISPLAY_ID_DEFAULT);
    firstWindow->setDupTouchToWallpaper(true);
    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    secondWindow->setDupTouchToWallpaper(true);

    sp<FakeWindowHandle> wallpaper1 =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper1", ADISPLAY_ID_DEFAULT);
    wallpaper1->setIsWallpaper(true);

    sp<FakeWindowHandle> wallpaper2 =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Wallpaper2", ADISPLAY_ID_DEFAULT);
    wallpaper2->setIsWallpaper(true);
    // Add the windows to the dispatcher
    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {firstWindow, wallpaper1, secondWindow, wallpaper2}}});

    // Send down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));

    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();
    wallpaper1->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);
    wallpaper2->assertNoEvents();

    // Transfer touch focus to the second window
    TransferFunction f = GetParam();
    bool success = f(mDispatcher, firstWindow->getToken(), secondWindow->getToken());
    ASSERT_TRUE(success);

    // The first window gets cancel and the second gets down
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionDown();
    wallpaper1->consumeMotionCancel(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);
    wallpaper2->consumeMotionDown(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);

    // Send up event to the second window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    // The first  window gets no events and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
    wallpaper1->assertNoEvents();
    wallpaper2->consumeMotionUp(ADISPLAY_ID_DEFAULT, expectedWallpaperFlags);
}

// For the cases of single pointer touch and two pointers non-split touch, the api's
// 'transferTouch' and 'transferTouchFocus' are equivalent in behaviour. They only differ
// for the case where there are multiple pointers split across several windows.
INSTANTIATE_TEST_SUITE_P(TransferFunctionTests, TransferTouchFixture,
                         ::testing::Values(
                                 [&](const std::unique_ptr<InputDispatcher>& dispatcher,
                                     sp<IBinder> /*ignored*/, sp<IBinder> destChannelToken) {
                                     return dispatcher->transferTouch(destChannelToken,
                                                                      ADISPLAY_ID_DEFAULT);
                                 },
                                 [&](const std::unique_ptr<InputDispatcher>& dispatcher,
                                     sp<IBinder> from, sp<IBinder> to) {
                                     return dispatcher->transferTouchFocus(from, to,
                                                                           /*isDragAndDrop=*/false);
                                 }));

TEST_F(InputDispatcherTest, TransferTouchFocus_TwoPointersSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> firstWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "First Window",
                                       ADISPLAY_ID_DEFAULT);
    firstWindow->setFrame(Rect(0, 0, 600, 400));

    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect(0, 400, 600, 800));

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    PointF pointInFirst = {300, 200};
    PointF pointInSecond = {300, 600};

    // Send down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst}));
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send down to the second window
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst, pointInSecond}));
    // The first window gets a move and the second a down
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionDown();

    // Transfer touch focus to the second window
    mDispatcher->transferTouchFocus(firstWindow->getToken(), secondWindow->getToken());
    // The first window gets cancel and the new gets pointer down (it already saw down)
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionPointerDown(1);

    // Send pointer up to the second window
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst, pointInSecond}));
    // The first window gets nothing and the second gets pointer up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionPointerUp(1);

    // Send up event to the second window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    // The first window gets nothing and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
}

// Same as TransferTouchFocus_TwoPointersSplitTouch, but using 'transferTouch' api.
// Unlike 'transferTouchFocus', calling 'transferTouch' when there are two windows receiving
// touch is not supported, so the touch should continue on those windows and the transferred-to
// window should get nothing.
TEST_F(InputDispatcherTest, TransferTouch_TwoPointersSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> firstWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "First Window",
                                       ADISPLAY_ID_DEFAULT);
    firstWindow->setFrame(Rect(0, 0, 600, 400));

    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect(0, 400, 600, 800));

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    PointF pointInFirst = {300, 200};
    PointF pointInSecond = {300, 600};

    // Send down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst}));
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send down to the second window
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst, pointInSecond}));
    // The first window gets a move and the second a down
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionDown();

    // Transfer touch focus to the second window
    const bool transferred =
            mDispatcher->transferTouch(secondWindow->getToken(), ADISPLAY_ID_DEFAULT);
    // The 'transferTouch' call should not succeed, because there are 2 touched windows
    ASSERT_FALSE(transferred);
    firstWindow->assertNoEvents();
    secondWindow->assertNoEvents();

    // The rest of the dispatch should proceed as normal
    // Send pointer up to the second window
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst, pointInSecond}));
    // The first window gets MOVE and the second gets pointer up
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionUp();

    // Send up event to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    // The first window gets nothing and the second gets up
    firstWindow->consumeMotionUp();
    secondWindow->assertNoEvents();
}

// This case will create two windows and one mirrored window on the default display and mirror
// two windows on the second display. It will test if 'transferTouchFocus' works fine if we put
// the windows info of second display before default display.
TEST_F(InputDispatcherTest, TransferTouchFocus_CloneSurface) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> firstWindowInPrimary =
            sp<FakeWindowHandle>::make(application, mDispatcher, "D_1_W1", ADISPLAY_ID_DEFAULT);
    firstWindowInPrimary->setFrame(Rect(0, 0, 100, 100));
    sp<FakeWindowHandle> secondWindowInPrimary =
            sp<FakeWindowHandle>::make(application, mDispatcher, "D_1_W2", ADISPLAY_ID_DEFAULT);
    secondWindowInPrimary->setFrame(Rect(100, 0, 200, 100));

    sp<FakeWindowHandle> mirrorWindowInPrimary = firstWindowInPrimary->clone(ADISPLAY_ID_DEFAULT);
    mirrorWindowInPrimary->setFrame(Rect(0, 100, 100, 200));

    sp<FakeWindowHandle> firstWindowInSecondary = firstWindowInPrimary->clone(SECOND_DISPLAY_ID);
    firstWindowInSecondary->setFrame(Rect(0, 0, 100, 100));

    sp<FakeWindowHandle> secondWindowInSecondary = secondWindowInPrimary->clone(SECOND_DISPLAY_ID);
    secondWindowInPrimary->setFrame(Rect(100, 0, 200, 100));

    // Update window info, let it find window handle of second display first.
    mDispatcher->setInputWindows(
            {{SECOND_DISPLAY_ID, {firstWindowInSecondary, secondWindowInSecondary}},
             {ADISPLAY_ID_DEFAULT,
              {mirrorWindowInPrimary, firstWindowInPrimary, secondWindowInPrimary}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Window should receive motion event.
    firstWindowInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // Transfer touch focus
    ASSERT_TRUE(mDispatcher->transferTouchFocus(firstWindowInPrimary->getToken(),
                                                secondWindowInPrimary->getToken()));
    // The first window gets cancel.
    firstWindowInPrimary->consumeMotionCancel();
    secondWindowInPrimary->consumeMotionDown();

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    firstWindowInPrimary->assertNoEvents();
    secondWindowInPrimary->consumeMotionMove();

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                             {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    firstWindowInPrimary->assertNoEvents();
    secondWindowInPrimary->consumeMotionUp();
}

// Same as TransferTouchFocus_CloneSurface, but this touch on the secondary display and use
// 'transferTouch' api.
TEST_F(InputDispatcherTest, TransferTouch_CloneSurface) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> firstWindowInPrimary =
            sp<FakeWindowHandle>::make(application, mDispatcher, "D_1_W1", ADISPLAY_ID_DEFAULT);
    firstWindowInPrimary->setFrame(Rect(0, 0, 100, 100));
    sp<FakeWindowHandle> secondWindowInPrimary =
            sp<FakeWindowHandle>::make(application, mDispatcher, "D_1_W2", ADISPLAY_ID_DEFAULT);
    secondWindowInPrimary->setFrame(Rect(100, 0, 200, 100));

    sp<FakeWindowHandle> mirrorWindowInPrimary = firstWindowInPrimary->clone(ADISPLAY_ID_DEFAULT);
    mirrorWindowInPrimary->setFrame(Rect(0, 100, 100, 200));

    sp<FakeWindowHandle> firstWindowInSecondary = firstWindowInPrimary->clone(SECOND_DISPLAY_ID);
    firstWindowInSecondary->setFrame(Rect(0, 0, 100, 100));

    sp<FakeWindowHandle> secondWindowInSecondary = secondWindowInPrimary->clone(SECOND_DISPLAY_ID);
    secondWindowInPrimary->setFrame(Rect(100, 0, 200, 100));

    // Update window info, let it find window handle of second display first.
    mDispatcher->setInputWindows(
            {{SECOND_DISPLAY_ID, {firstWindowInSecondary, secondWindowInSecondary}},
             {ADISPLAY_ID_DEFAULT,
              {mirrorWindowInPrimary, firstWindowInPrimary, secondWindowInPrimary}}});

    // Touch on second display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Window should receive motion event.
    firstWindowInPrimary->consumeMotionDown(SECOND_DISPLAY_ID);

    // Transfer touch focus
    ASSERT_TRUE(mDispatcher->transferTouch(secondWindowInSecondary->getToken(), SECOND_DISPLAY_ID));

    // The first window gets cancel.
    firstWindowInPrimary->consumeMotionCancel(SECOND_DISPLAY_ID);
    secondWindowInPrimary->consumeMotionDown(SECOND_DISPLAY_ID);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                SECOND_DISPLAY_ID, {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    firstWindowInPrimary->assertNoEvents();
    secondWindowInPrimary->consumeMotionMove(SECOND_DISPLAY_ID);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID, {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    firstWindowInPrimary->assertNoEvents();
    secondWindowInPrimary->consumeMotionUp(SECOND_DISPLAY_ID);
}

TEST_F(InputDispatcherTest, FocusedWindow_ReceivesFocusEventAndKeyEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));

    // Window should receive key down event.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    // Should have poked user activity
    mDispatcher->waitForIdle();
    mFakePolicy->assertUserActivityPoked();
}

TEST_F(InputDispatcherTest, FocusedWindow_DisableUserActivity) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    window->setDisableUserActivity(true);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));

    // Window should receive key down event.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    // Should have poked user activity
    mDispatcher->waitForIdle();
    mFakePolicy->assertUserActivityNotPoked();
}

TEST_F(InputDispatcherTest, FocusedWindow_DoesNotReceiveSystemShortcut) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    mDispatcher->notifyKey(generateSystemShortcutArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    mDispatcher->waitForIdle();

    // System key is not passed down
    window->assertNoEvents();

    // Should have poked user activity
    mFakePolicy->assertUserActivityPoked();
}

TEST_F(InputDispatcherTest, FocusedWindow_DoesNotReceiveAssistantKey) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    mDispatcher->notifyKey(generateAssistantKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    mDispatcher->waitForIdle();

    // System key is not passed down
    window->assertNoEvents();

    // Should have poked user activity
    mFakePolicy->assertUserActivityPoked();
}

TEST_F(InputDispatcherTest, FocusedWindow_SystemKeyIgnoresDisableUserActivity) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    window->setDisableUserActivity(true);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    mDispatcher->notifyKey(generateSystemShortcutArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    mDispatcher->waitForIdle();

    // System key is not passed down
    window->assertNoEvents();

    // Should have poked user activity
    mFakePolicy->assertUserActivityPoked();
}

TEST_F(InputDispatcherTest, InjectedTouchesPokeUserActivity) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {100, 100}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    window->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_DOWN), WithDisplayId(ADISPLAY_ID_DEFAULT)));

    // Should have poked user activity
    mDispatcher->waitForIdle();
    mFakePolicy->assertUserActivityPoked();
}

TEST_F(InputDispatcherTest, UnfocusedWindow_DoesNotReceiveFocusEventOrKeyEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    mDispatcher->waitForIdle();

    window->assertNoEvents();
}

// If a window is touchable, but does not have focus, it should receive motion events, but not keys
TEST_F(InputDispatcherTest, UnfocusedWindow_ReceivesMotionsButNotKeys) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Send key
    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    // Send motion
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));

    // Window should receive only the motion event
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    window->assertNoEvents(); // Key event or focus event will not be received
}

TEST_F(InputDispatcherTest, PointerCancel_SendCancelWhenSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> firstWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "First Window",
                                       ADISPLAY_ID_DEFAULT);
    firstWindow->setFrame(Rect(0, 0, 600, 400));

    sp<FakeWindowHandle> secondWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second Window",
                                       ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect(0, 400, 600, 800));

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    PointF pointInFirst = {300, 200};
    PointF pointInSecond = {300, 600};

    // Send down to the first window
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst}));
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send down to the second window
    mDispatcher->notifyMotion(generateMotionArgs(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT,
                                                 {pointInFirst, pointInSecond}));
    // The first window gets a move and the second a down
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionDown();

    // Send pointer cancel to the second window
    NotifyMotionArgs pointerUpMotionArgs =
            generateMotionArgs(POINTER_1_UP, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {pointInFirst, pointInSecond});
    pointerUpMotionArgs.flags |= AMOTION_EVENT_FLAG_CANCELED;
    mDispatcher->notifyMotion(pointerUpMotionArgs);
    // The first window gets move and the second gets cancel.
    firstWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_CANCELED);
    secondWindow->consumeMotionCancel(ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_CANCELED);

    // Send up event.
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    // The first window gets up and the second gets nothing.
    firstWindow->consumeMotionUp();
    secondWindow->assertNoEvents();
}

TEST_F(InputDispatcherTest, SendTimeline_DoesNotCrashDispatcher) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;
    graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME] = 2;
    graphicsTimeline[GraphicsTimeline::PRESENT_TIME] = 3;

    window->sendTimeline(/*inputEventId=*/1, graphicsTimeline);
    window->assertNoEvents();
    mDispatcher->waitForIdle();
}

class FakeMonitorReceiver {
public:
    FakeMonitorReceiver(const std::unique_ptr<InputDispatcher>& dispatcher, const std::string name,
                        int32_t displayId) {
        base::Result<std::unique_ptr<InputChannel>> channel =
                dispatcher->createInputMonitor(displayId, name, MONITOR_PID);
        mInputReceiver = std::make_unique<FakeInputReceiver>(std::move(*channel), name);
    }

    sp<IBinder> getToken() { return mInputReceiver->getToken(); }

    void consumeKeyDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeEvent(InputEventType::KEY, AKEY_EVENT_ACTION_DOWN, expectedDisplayId,
                                     expectedFlags);
    }

    std::optional<int32_t> receiveEvent() { return mInputReceiver->receiveEvent(); }

    void finishEvent(uint32_t consumeSeq) { return mInputReceiver->finishEvent(consumeSeq); }

    void consumeMotionDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_DOWN,
                                     expectedDisplayId, expectedFlags);
    }

    void consumeMotionMove(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_MOVE,
                                     expectedDisplayId, expectedFlags);
    }

    void consumeMotionUp(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_UP,
                                     expectedDisplayId, expectedFlags);
    }

    void consumeMotionCancel(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeMotionEvent(
                AllOf(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL),
                      WithDisplayId(expectedDisplayId),
                      WithFlags(expectedFlags | AMOTION_EVENT_FLAG_CANCELED)));
    }

    void consumeMotionPointerDown(int32_t pointerIdx) {
        int32_t action = AMOTION_EVENT_ACTION_POINTER_DOWN |
                (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        mInputReceiver->consumeEvent(InputEventType::MOTION, action, ADISPLAY_ID_DEFAULT,
                                     /*expectedFlags=*/0);
    }

    MotionEvent* consumeMotion() {
        InputEvent* event = mInputReceiver->consume();
        if (!event) {
            ADD_FAILURE() << "No event was produced";
            return nullptr;
        }
        if (event->getType() != InputEventType::MOTION) {
            ADD_FAILURE() << "Expected MotionEvent, got " << *event;
            return nullptr;
        }
        return static_cast<MotionEvent*>(event);
    }

    void assertNoEvents() { mInputReceiver->assertNoEvents(); }

private:
    std::unique_ptr<FakeInputReceiver> mInputReceiver;
};

using InputDispatcherMonitorTest = InputDispatcherTest;

/**
 * Two entities that receive touch: A window, and a global monitor.
 * The touch goes to the window, and then the window disappears.
 * The monitor does not get cancel right away. But if more events come in, the touch gets canceled
 * for the monitor, as well.
 * 1. foregroundWindow
 * 2. monitor <-- global monitor (doesn't observe z order, receives all events)
 */
TEST_F(InputDispatcherMonitorTest, MonitorTouchIsCanceledWhenForegroundWindowDisappears) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Foreground", ADISPLAY_ID_DEFAULT);

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Both the foreground window and the global monitor should receive the touch down
    window->consumeMotionDown();
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {110, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    window->consumeMotionMove();
    monitor.consumeMotionMove(ADISPLAY_ID_DEFAULT);

    // Now the foreground window goes away
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {}}});
    window->consumeMotionCancel();
    monitor.assertNoEvents(); // Global monitor does not get a cancel yet

    // If more events come in, there will be no more foreground window to send them to. This will
    // cause a cancel for the monitor, as well.
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {120, 200}))
            << "Injection should fail because the window was removed";
    window->assertNoEvents();
    // Global monitor now gets the cancel
    monitor.consumeMotionCancel(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherMonitorTest, ReceivesMotionEvents) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherMonitorTest, MonitorCannotPilferPointers) {
    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);

    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // Pilfer pointers from the monitor.
    // This should not do anything and the window should continue to receive events.
    EXPECT_NE(OK, mDispatcher->pilferPointers(monitor.getToken()));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    monitor.consumeMotionMove(ADISPLAY_ID_DEFAULT);
    window->consumeMotionMove(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherMonitorTest, NoWindowTransform) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->setWindowOffset(20, 40);
    window->setWindowTransform(0, 1, -1, 0);

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    MotionEvent* event = monitor.consumeMotion();
    // Even though window has transform, gesture monitor must not.
    ASSERT_EQ(ui::Transform(), event->getTransform());
}

TEST_F(InputDispatcherMonitorTest, InjectionFailsWithNoWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Injection should fail if there is a monitor, but no touchable window";
    monitor.assertNoEvents();
}

TEST_F(InputDispatcherTest, TestMoveEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);

    mDispatcher->notifyMotion(motionArgs);
    // Window should receive motion down event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    motionArgs.action = AMOTION_EVENT_ACTION_MOVE;
    motionArgs.id += 1;
    motionArgs.eventTime = systemTime(SYSTEM_TIME_MONOTONIC);
    motionArgs.pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                             motionArgs.pointerCoords[0].getX() - 10);

    mDispatcher->notifyMotion(motionArgs);
    window->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_MOVE, ADISPLAY_ID_DEFAULT,
                         /*expectedFlags=*/0);
}

/**
 * Dispatcher has touch mode enabled by default. Typically, the policy overrides that value to
 * the device default right away. In the test scenario, we check both the default value,
 * and the action of enabling / disabling.
 */
TEST_F(InputDispatcherTest, TouchModeState_IsSentToApps) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Test window", ADISPLAY_ID_DEFAULT);
    const WindowInfo& windowInfo = *window->getInfo();

    // Set focused application.
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);

    SCOPED_TRACE("Check default value of touch mode");
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/true);

    SCOPED_TRACE("Remove the window to trigger focus loss");
    window->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(/*hasFocus=*/false, /*inTouchMode=*/true);

    SCOPED_TRACE("Disable touch mode");
    mDispatcher->setInTouchMode(false, windowInfo.ownerPid, windowInfo.ownerUid,
                                /*hasPermission=*/true, ADISPLAY_ID_DEFAULT);
    window->consumeTouchModeEvent(false);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/false);

    SCOPED_TRACE("Remove the window to trigger focus loss");
    window->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(/*hasFocus=*/false, /*inTouchMode=*/false);

    SCOPED_TRACE("Enable touch mode again");
    mDispatcher->setInTouchMode(true, windowInfo.ownerPid, windowInfo.ownerUid,
                                /*hasPermission=*/true, ADISPLAY_ID_DEFAULT);
    window->consumeTouchModeEvent(true);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/true);

    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, VerifyInputEvent_KeyEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Test window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/true);

    const NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN);
    mDispatcher->notifyKey(keyArgs);

    InputEvent* event = window->consume();
    ASSERT_NE(event, nullptr);

    std::unique_ptr<VerifiedInputEvent> verified = mDispatcher->verifyInputEvent(*event);
    ASSERT_NE(verified, nullptr);
    ASSERT_EQ(verified->type, VerifiedInputEvent::Type::KEY);

    ASSERT_EQ(keyArgs.eventTime, verified->eventTimeNanos);
    ASSERT_EQ(keyArgs.deviceId, verified->deviceId);
    ASSERT_EQ(keyArgs.source, verified->source);
    ASSERT_EQ(keyArgs.displayId, verified->displayId);

    const VerifiedKeyEvent& verifiedKey = static_cast<const VerifiedKeyEvent&>(*verified);

    ASSERT_EQ(keyArgs.action, verifiedKey.action);
    ASSERT_EQ(keyArgs.flags & VERIFIED_KEY_EVENT_FLAGS, verifiedKey.flags);
    ASSERT_EQ(keyArgs.downTime, verifiedKey.downTimeNanos);
    ASSERT_EQ(keyArgs.keyCode, verifiedKey.keyCode);
    ASSERT_EQ(keyArgs.scanCode, verifiedKey.scanCode);
    ASSERT_EQ(keyArgs.metaState, verifiedKey.metaState);
    ASSERT_EQ(0, verifiedKey.repeatCount);
}

TEST_F(InputDispatcherTest, VerifyInputEvent_MotionEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Test window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    ui::Transform transform;
    transform.set({1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 0, 0, 1});

    gui::DisplayInfo displayInfo;
    displayInfo.displayId = ADISPLAY_ID_DEFAULT;
    displayInfo.transform = transform;

    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {displayInfo}, 0, 0});

    const NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(motionArgs);

    InputEvent* event = window->consume();
    ASSERT_NE(event, nullptr);

    std::unique_ptr<VerifiedInputEvent> verified = mDispatcher->verifyInputEvent(*event);
    ASSERT_NE(verified, nullptr);
    ASSERT_EQ(verified->type, VerifiedInputEvent::Type::MOTION);

    EXPECT_EQ(motionArgs.eventTime, verified->eventTimeNanos);
    EXPECT_EQ(motionArgs.deviceId, verified->deviceId);
    EXPECT_EQ(motionArgs.source, verified->source);
    EXPECT_EQ(motionArgs.displayId, verified->displayId);

    const VerifiedMotionEvent& verifiedMotion = static_cast<const VerifiedMotionEvent&>(*verified);

    const vec2 rawXY =
            MotionEvent::calculateTransformedXY(motionArgs.source, transform,
                                                motionArgs.pointerCoords[0].getXYValue());
    EXPECT_EQ(rawXY.x, verifiedMotion.rawX);
    EXPECT_EQ(rawXY.y, verifiedMotion.rawY);
    EXPECT_EQ(motionArgs.action & AMOTION_EVENT_ACTION_MASK, verifiedMotion.actionMasked);
    EXPECT_EQ(motionArgs.flags & VERIFIED_MOTION_EVENT_FLAGS, verifiedMotion.flags);
    EXPECT_EQ(motionArgs.downTime, verifiedMotion.downTimeNanos);
    EXPECT_EQ(motionArgs.metaState, verifiedMotion.metaState);
    EXPECT_EQ(motionArgs.buttonState, verifiedMotion.buttonState);
}

/**
 * Ensure that separate calls to sign the same data are generating the same key.
 * We avoid asserting against INVALID_HMAC. Since the key is random, there is a non-zero chance
 * that a specific key and data combination would produce INVALID_HMAC, which would cause flaky
 * tests.
 */
TEST_F(InputDispatcherTest, GeneratedHmac_IsConsistent) {
    KeyEvent event = getTestKeyEvent();
    VerifiedKeyEvent verifiedEvent = verifiedKeyEventFromKeyEvent(event);

    std::array<uint8_t, 32> hmac1 = mDispatcher->sign(verifiedEvent);
    std::array<uint8_t, 32> hmac2 = mDispatcher->sign(verifiedEvent);
    ASSERT_EQ(hmac1, hmac2);
}

/**
 * Ensure that changes in VerifiedKeyEvent produce a different hmac.
 */
TEST_F(InputDispatcherTest, GeneratedHmac_ChangesWhenFieldsChange) {
    KeyEvent event = getTestKeyEvent();
    VerifiedKeyEvent verifiedEvent = verifiedKeyEventFromKeyEvent(event);
    std::array<uint8_t, 32> initialHmac = mDispatcher->sign(verifiedEvent);

    verifiedEvent.deviceId += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.source += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.eventTimeNanos += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.displayId += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.action += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.downTimeNanos += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.flags += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.keyCode += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.scanCode += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.metaState += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));

    verifiedEvent.repeatCount += 1;
    ASSERT_NE(initialHmac, mDispatcher->sign(verifiedEvent));
}

TEST_F(InputDispatcherTest, SetFocusedWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowTop =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    // Top window is also focusable but is not granted focus.
    windowTop->setFocusable(true);
    windowSecond->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    setFocusedWindow(windowSecond);

    windowSecond->consumeFocusEvent(true);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";

    // Focused window should receive event.
    windowSecond->consumeKeyDown(ADISPLAY_ID_NONE);
    windowTop->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetFocusedWindow_DropRequestInvalidChannel) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    window->setFocusable(true);
    // Release channel for window is no longer valid.
    window->releaseChannel();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    // Test inject a key down, should timeout.
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";

    // window channel is invalid, so it should not receive any input event.
    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetFocusedWindow_DropRequestNoFocusableWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
    window->setFocusable(false);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    // Test inject a key down, should timeout.
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";

    // window is not focusable, so it should not receive any input event.
    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetFocusedWindow_CheckFocusedToken) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowTop =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    windowTop->setFocusable(true);
    windowSecond->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    setFocusedWindow(windowTop);
    windowTop->consumeFocusEvent(true);

    windowTop->editInfo()->focusTransferTarget = windowSecond->getToken();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    windowSecond->consumeFocusEvent(true);
    windowTop->consumeFocusEvent(false);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";

    // Focused window should receive event.
    windowSecond->consumeKeyDown(ADISPLAY_ID_NONE);
}

TEST_F(InputDispatcherTest, SetFocusedWindow_TransferFocusTokenNotFocusable) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowTop =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    windowTop->setFocusable(true);
    windowSecond->setFocusable(false);
    windowTop->editInfo()->focusTransferTarget = windowSecond->getToken();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    setFocusedWindow(windowTop);
    windowTop->consumeFocusEvent(true);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";

    // Event should be dropped.
    windowTop->consumeKeyDown(ADISPLAY_ID_NONE);
    windowSecond->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetFocusedWindow_DeferInvisibleWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> previousFocusedWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "previousFocusedWindow",
                                       ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    window->setFocusable(true);
    previousFocusedWindow->setFocusable(true);
    window->setVisible(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window, previousFocusedWindow}}});
    setFocusedWindow(previousFocusedWindow);
    previousFocusedWindow->consumeFocusEvent(true);

    // Requesting focus on invisible window takes focus from currently focused window.
    setFocusedWindow(window);
    previousFocusedWindow->consumeFocusEvent(false);

    // Injected key goes to pending queue.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                        InputEventInjectionSync::NONE));

    // Window does not get focus event or key down.
    window->assertNoEvents();

    // Window becomes visible.
    window->setVisible(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Window receives focus event.
    window->consumeFocusEvent(true);
    // Focused window receives key down.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, DisplayRemoved) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    // window is granted focus.
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    // When a display is removed window loses focus.
    mDispatcher->displayRemoved(ADISPLAY_ID_DEFAULT);
    window->consumeFocusEvent(false);
}

/**
 * Launch two windows, with different owners. One window (slipperyExitWindow) has Flag::SLIPPERY,
 * and overlaps the other window, slipperyEnterWindow. The window 'slipperyExitWindow' is on top
 * of the 'slipperyEnterWindow'.
 *
 * Inject touch down into the top window. Upon receipt of the DOWN event, move the window in such
 * a way so that the touched location is no longer covered by the top window.
 *
 * Next, inject a MOVE event. Because the top window already moved earlier, this event is now
 * positioned over the bottom (slipperyEnterWindow) only. And because the top window had
 * Flag::SLIPPERY, this will cause the top window to lose the touch event (it will receive
 * ACTION_CANCEL instead), and the bottom window will receive a newly generated gesture (starting
 * with ACTION_DOWN).
 * Thus, the touch has been transferred from the top window into the bottom window, because the top
 * window moved itself away from the touched location and had Flag::SLIPPERY.
 *
 * Even though the top window moved away from the touched location, it is still obscuring the bottom
 * window. It's just not obscuring it at the touched location. That means, FLAG_WINDOW_IS_PARTIALLY_
 * OBSCURED should be set for the MotionEvent that reaches the bottom window.
 *
 * In this test, we ensure that the event received by the bottom window has
 * FLAG_WINDOW_IS_PARTIALLY_OBSCURED.
 */
TEST_F(InputDispatcherTest, SlipperyWindow_SetsFlagPartiallyObscured) {
    constexpr gui::Pid SLIPPERY_PID{WINDOW_PID.val() + 1};
    constexpr gui::Uid SLIPPERY_UID{WINDOW_UID.val() + 1};

    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    sp<FakeWindowHandle> slipperyExitWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    slipperyExitWindow->setSlippery(true);
    // Make sure this one overlaps the bottom window
    slipperyExitWindow->setFrame(Rect(25, 25, 75, 75));
    // Change the owner uid/pid of the window so that it is considered to be occluding the bottom
    // one. Windows with the same owner are not considered to be occluding each other.
    slipperyExitWindow->setOwnerInfo(SLIPPERY_PID, SLIPPERY_UID);

    sp<FakeWindowHandle> slipperyEnterWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
    slipperyExitWindow->setFrame(Rect(0, 0, 100, 100));

    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {slipperyExitWindow, slipperyEnterWindow}}});

    // Use notifyMotion instead of injecting to avoid dealing with injection permissions
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {{50, 50}}));
    slipperyExitWindow->consumeMotionDown();
    slipperyExitWindow->setFrame(Rect(70, 70, 100, 100));
    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {slipperyExitWindow, slipperyEnterWindow}}});

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_MOVE,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {{51, 51}}));

    slipperyExitWindow->consumeMotionCancel();

    slipperyEnterWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT,
                                           AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED);
}

/**
 * Two windows, one on the left and another on the right. The left window is slippery. The right
 * window isn't eligible to receive touch because it specifies InputConfig::DROP_INPUT. When the
 * touch moves from the left window into the right window, the gesture should continue to go to the
 * left window. Touch shouldn't slip because the right window can't receive touches. This test
 * reproduces a crash.
 */
TEST_F(InputDispatcherTest, TouchSlippingIntoWindowThatDropsTouches) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> leftSlipperyWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    leftSlipperyWindow->setSlippery(true);
    leftSlipperyWindow->setFrame(Rect(0, 0, 100, 100));

    sp<FakeWindowHandle> rightDropTouchesWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    rightDropTouchesWindow->setFrame(Rect(100, 0, 200, 100));
    rightDropTouchesWindow->setDropInput(true);

    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {leftSlipperyWindow, rightDropTouchesWindow}}});

    // Start touch in the left window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(50).y(50))
                                      .build());
    leftSlipperyWindow->consumeMotionDown();

    // And move it into the right window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(150).y(50))
                                      .build());

    // Since the right window isn't eligible to receive input, touch does not slip.
    // The left window continues to receive the gesture.
    leftSlipperyWindow->consumeMotionEvent(WithMotionAction(ACTION_MOVE));
    rightDropTouchesWindow->assertNoEvents();
}

TEST_F(InputDispatcherTest, NotifiesDeviceInteractionsWithMotions) {
    using Uid = gui::Uid;
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> leftWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    leftWindow->setFrame(Rect(0, 0, 100, 100));
    leftWindow->setOwnerInfo(gui::Pid{1}, Uid{101});

    sp<FakeWindowHandle> rightSpy =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right spy", ADISPLAY_ID_DEFAULT);
    rightSpy->setFrame(Rect(100, 0, 200, 100));
    rightSpy->setOwnerInfo(gui::Pid{2}, Uid{102});
    rightSpy->setSpy(true);
    rightSpy->setTrustedOverlay(true);

    sp<FakeWindowHandle> rightWindow =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    rightWindow->setFrame(Rect(100, 0, 200, 100));
    rightWindow->setOwnerInfo(gui::Pid{3}, Uid{103});

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {rightSpy, rightWindow, leftWindow}}});

    // Touch in the left window
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(50).y(50))
                                      .build());
    ASSERT_NO_FATAL_FAILURE(leftWindow->consumeMotionDown());
    mDispatcher->waitForIdle();
    ASSERT_NO_FATAL_FAILURE(
            mFakePolicy->assertNotifyDeviceInteractionWasCalled(DEVICE_ID, {Uid{101}}));

    // Touch another finger over the right windows
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(50).y(50))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(150).y(50))
                                      .build());
    ASSERT_NO_FATAL_FAILURE(rightSpy->consumeMotionDown());
    ASSERT_NO_FATAL_FAILURE(rightWindow->consumeMotionDown());
    ASSERT_NO_FATAL_FAILURE(leftWindow->consumeMotionMove());
    mDispatcher->waitForIdle();
    ASSERT_NO_FATAL_FAILURE(
            mFakePolicy->assertNotifyDeviceInteractionWasCalled(DEVICE_ID,
                                                                {Uid{101}, Uid{102}, Uid{103}}));

    // Release finger over left window. The UP actions are not treated as device interaction.
    // The windows that did not receive the UP pointer will receive MOVE events, but since this
    // is part of the UP action, we do not treat this as device interaction.
    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_0_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(50).y(50))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(150).y(50))
                                      .build());
    ASSERT_NO_FATAL_FAILURE(leftWindow->consumeMotionUp());
    ASSERT_NO_FATAL_FAILURE(rightSpy->consumeMotionMove());
    ASSERT_NO_FATAL_FAILURE(rightWindow->consumeMotionMove());
    mDispatcher->waitForIdle();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertNotifyDeviceInteractionWasNotCalled());

    // Move remaining finger
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(150).y(50))
                                      .build());
    ASSERT_NO_FATAL_FAILURE(rightSpy->consumeMotionMove());
    ASSERT_NO_FATAL_FAILURE(rightWindow->consumeMotionMove());
    mDispatcher->waitForIdle();
    ASSERT_NO_FATAL_FAILURE(
            mFakePolicy->assertNotifyDeviceInteractionWasCalled(DEVICE_ID, {Uid{102}, Uid{103}}));

    // Release all fingers
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(150).y(50))
                                      .build());
    ASSERT_NO_FATAL_FAILURE(rightSpy->consumeMotionUp());
    ASSERT_NO_FATAL_FAILURE(rightWindow->consumeMotionUp());
    mDispatcher->waitForIdle();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertNotifyDeviceInteractionWasNotCalled());
}

TEST_F(InputDispatcherTest, NotifiesDeviceInteractionsWithKeys) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));
    window->setOwnerInfo(gui::Pid{1}, gui::Uid{101});

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    ASSERT_NO_FATAL_FAILURE(window->consumeFocusEvent(true));

    mDispatcher->notifyKey(KeyArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_KEYBOARD).build());
    ASSERT_NO_FATAL_FAILURE(window->consumeKeyDown(ADISPLAY_ID_DEFAULT));
    mDispatcher->waitForIdle();
    ASSERT_NO_FATAL_FAILURE(
            mFakePolicy->assertNotifyDeviceInteractionWasCalled(DEVICE_ID, {gui::Uid{101}}));

    // The UP actions are not treated as device interaction.
    mDispatcher->notifyKey(KeyArgsBuilder(ACTION_UP, AINPUT_SOURCE_KEYBOARD).build());
    ASSERT_NO_FATAL_FAILURE(window->consumeKeyUp(ADISPLAY_ID_DEFAULT));
    mDispatcher->waitForIdle();
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertNotifyDeviceInteractionWasNotCalled());
}

class InputDispatcherKeyRepeatTest : public InputDispatcherTest {
protected:
    static constexpr nsecs_t KEY_REPEAT_TIMEOUT = 40 * 1000000; // 40 ms
    static constexpr nsecs_t KEY_REPEAT_DELAY = 40 * 1000000;   // 40 ms

    std::shared_ptr<FakeApplicationHandle> mApp;
    sp<FakeWindowHandle> mWindow;

    virtual void SetUp() override {
        mFakePolicy = std::make_unique<FakeInputDispatcherPolicy>();
        mFakePolicy->setKeyRepeatConfiguration(KEY_REPEAT_TIMEOUT, KEY_REPEAT_DELAY);
        mDispatcher = std::make_unique<InputDispatcher>(*mFakePolicy);
        mDispatcher->requestRefreshConfiguration();
        mDispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
        ASSERT_EQ(OK, mDispatcher->start());

        setUpWindow();
    }

    void setUpWindow() {
        mApp = std::make_shared<FakeApplicationHandle>();
        mWindow = sp<FakeWindowHandle>::make(mApp, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

        mWindow->setFocusable(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
        setFocusedWindow(mWindow);
        mWindow->consumeFocusEvent(true);
    }

    void sendAndConsumeKeyDown(int32_t deviceId) {
        NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
        keyArgs.deviceId = deviceId;
        keyArgs.policyFlags |= POLICY_FLAG_TRUSTED; // Otherwise it won't generate repeat event
        mDispatcher->notifyKey(keyArgs);

        // Window should receive key down event.
        mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    }

    void expectKeyRepeatOnce(int32_t repeatCount) {
        SCOPED_TRACE(StringPrintf("Checking event with repeat count %" PRId32, repeatCount));
        InputEvent* repeatEvent = mWindow->consume();
        ASSERT_NE(nullptr, repeatEvent);

        ASSERT_EQ(InputEventType::KEY, repeatEvent->getType());

        KeyEvent* repeatKeyEvent = static_cast<KeyEvent*>(repeatEvent);
        uint32_t eventAction = repeatKeyEvent->getAction();
        EXPECT_EQ(AKEY_EVENT_ACTION_DOWN, eventAction);
        EXPECT_EQ(repeatCount, repeatKeyEvent->getRepeatCount());
    }

    void sendAndConsumeKeyUp(int32_t deviceId) {
        NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT);
        keyArgs.deviceId = deviceId;
        keyArgs.policyFlags |= POLICY_FLAG_TRUSTED; // Unless it won't generate repeat event
        mDispatcher->notifyKey(keyArgs);

        // Window should receive key down event.
        mWindow->consumeEvent(InputEventType::KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT,
                              /*expectedFlags=*/0);
    }
};

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_ReceivesKeyRepeat) {
    sendAndConsumeKeyDown(/*deviceId=*/1);
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        expectKeyRepeatOnce(repeatCount);
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_ReceivesKeyRepeatFromTwoDevices) {
    sendAndConsumeKeyDown(/*deviceId=*/1);
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        expectKeyRepeatOnce(repeatCount);
    }
    sendAndConsumeKeyDown(/*deviceId=*/2);
    /* repeatCount will start from 1 for deviceId 2 */
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        expectKeyRepeatOnce(repeatCount);
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_StopsKeyRepeatAfterUp) {
    sendAndConsumeKeyDown(/*deviceId=*/1);
    expectKeyRepeatOnce(/*repeatCount=*/1);
    sendAndConsumeKeyUp(/*deviceId=*/1);
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_KeyRepeatAfterStaleDeviceKeyUp) {
    sendAndConsumeKeyDown(/*deviceId=*/1);
    expectKeyRepeatOnce(/*repeatCount=*/1);
    sendAndConsumeKeyDown(/*deviceId=*/2);
    expectKeyRepeatOnce(/*repeatCount=*/1);
    // Stale key up from device 1.
    sendAndConsumeKeyUp(/*deviceId=*/1);
    // Device 2 is still down, keep repeating
    expectKeyRepeatOnce(/*repeatCount=*/2);
    expectKeyRepeatOnce(/*repeatCount=*/3);
    // Device 2 key up
    sendAndConsumeKeyUp(/*deviceId=*/2);
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_KeyRepeatStopsAfterRepeatingKeyUp) {
    sendAndConsumeKeyDown(/*deviceId=*/1);
    expectKeyRepeatOnce(/*repeatCount=*/1);
    sendAndConsumeKeyDown(/*deviceId=*/2);
    expectKeyRepeatOnce(/*repeatCount=*/1);
    // Device 2 which holds the key repeating goes up, expect the repeating to stop.
    sendAndConsumeKeyUp(/*deviceId=*/2);
    // Device 1 still holds key down, but the repeating was already stopped
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_StopsKeyRepeatAfterDisableInputDevice) {
    sendAndConsumeKeyDown(DEVICE_ID);
    expectKeyRepeatOnce(/*repeatCount=*/1);
    mDispatcher->notifyDeviceReset({/*id=*/10, /*eventTime=*/20, DEVICE_ID});
    mWindow->consumeKeyUp(ADISPLAY_ID_DEFAULT,
                          AKEY_EVENT_FLAG_CANCELED | AKEY_EVENT_FLAG_LONG_PRESS);
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_RepeatKeyEventsUseEventIdFromInputDispatcher) {
    GTEST_SKIP() << "Flaky test (b/270393106)";
    sendAndConsumeKeyDown(/*deviceId=*/1);
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        InputEvent* repeatEvent = mWindow->consume();
        ASSERT_NE(nullptr, repeatEvent) << "Didn't receive event with repeat count " << repeatCount;
        EXPECT_EQ(IdGenerator::Source::INPUT_DISPATCHER,
                  IdGenerator::getSource(repeatEvent->getId()));
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_RepeatKeyEventsUseUniqueEventId) {
    GTEST_SKIP() << "Flaky test (b/270393106)";
    sendAndConsumeKeyDown(/*deviceId=*/1);

    std::unordered_set<int32_t> idSet;
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        InputEvent* repeatEvent = mWindow->consume();
        ASSERT_NE(nullptr, repeatEvent) << "Didn't receive event with repeat count " << repeatCount;
        int32_t id = repeatEvent->getId();
        EXPECT_EQ(idSet.end(), idSet.find(id));
        idSet.insert(id);
    }
}

/* Test InputDispatcher for MultiDisplay */
class InputDispatcherFocusOnTwoDisplaysTest : public InputDispatcherTest {
public:
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        application1 = std::make_shared<FakeApplicationHandle>();
        windowInPrimary =
                sp<FakeWindowHandle>::make(application1, mDispatcher, "D_1", ADISPLAY_ID_DEFAULT);

        // Set focus window for primary display, but focused display would be second one.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application1);
        windowInPrimary->setFocusable(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowInPrimary}}});
        setFocusedWindow(windowInPrimary);
        windowInPrimary->consumeFocusEvent(true);

        application2 = std::make_shared<FakeApplicationHandle>();
        windowInSecondary =
                sp<FakeWindowHandle>::make(application2, mDispatcher, "D_2", SECOND_DISPLAY_ID);
        // Set focus to second display window.
        // Set focus display to second one.
        mDispatcher->setFocusedDisplay(SECOND_DISPLAY_ID);
        // Set focus window for second display.
        mDispatcher->setFocusedApplication(SECOND_DISPLAY_ID, application2);
        windowInSecondary->setFocusable(true);
        mDispatcher->setInputWindows({{SECOND_DISPLAY_ID, {windowInSecondary}}});
        setFocusedWindow(windowInSecondary);
        windowInSecondary->consumeFocusEvent(true);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();

        application1.reset();
        windowInPrimary.clear();
        application2.reset();
        windowInSecondary.clear();
    }

protected:
    std::shared_ptr<FakeApplicationHandle> application1;
    sp<FakeWindowHandle> windowInPrimary;
    std::shared_ptr<FakeApplicationHandle> application2;
    sp<FakeWindowHandle> windowInSecondary;
};

TEST_F(InputDispatcherFocusOnTwoDisplaysTest, SetInputWindow_MultiDisplayTouch) {
    // Test touch down on primary display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowInSecondary->assertNoEvents();

    // Test touch down on second display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->assertNoEvents();
    windowInSecondary->consumeMotionDown(SECOND_DISPLAY_ID);
}

TEST_F(InputDispatcherFocusOnTwoDisplaysTest, SetInputWindow_MultiDisplayFocus) {
    // Test inject a key down with display id specified.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectKeyDownNoRepeat(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    windowInSecondary->assertNoEvents();

    // Test inject a key down without display id specified.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDownNoRepeat(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->assertNoEvents();
    windowInSecondary->consumeKeyDown(ADISPLAY_ID_NONE);

    // Remove all windows in secondary display.
    mDispatcher->setInputWindows({{SECOND_DISPLAY_ID, {}}});

    // Old focus should receive a cancel event.
    windowInSecondary->consumeEvent(InputEventType::KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_NONE,
                                    AKEY_EVENT_FLAG_CANCELED);

    // Test inject a key down, should timeout because of no target window.
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDownNoRepeat(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";
    windowInPrimary->assertNoEvents();
    windowInSecondary->consumeFocusEvent(false);
    windowInSecondary->assertNoEvents();
}

// Test per-display input monitors for motion event.
TEST_F(InputDispatcherFocusOnTwoDisplaysTest, MonitorMotionEvent_MultiDisplay) {
    FakeMonitorReceiver monitorInPrimary =
            FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);
    FakeMonitorReceiver monitorInSecondary =
            FakeMonitorReceiver(mDispatcher, "M_2", SECOND_DISPLAY_ID);

    // Test touch down on primary display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitorInPrimary.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowInSecondary->assertNoEvents();
    monitorInSecondary.assertNoEvents();

    // Test touch down on second display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary.assertNoEvents();
    windowInSecondary->consumeMotionDown(SECOND_DISPLAY_ID);
    monitorInSecondary.consumeMotionDown(SECOND_DISPLAY_ID);

    // Lift up the touch from the second display
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInSecondary->consumeMotionUp(SECOND_DISPLAY_ID);
    monitorInSecondary.consumeMotionUp(SECOND_DISPLAY_ID);

    // Test inject a non-pointer motion event.
    // If specific a display, it will dispatch to the focused window of particular display,
    // or it will dispatch to the focused window of focused display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TRACKBALL, ADISPLAY_ID_NONE))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary.assertNoEvents();
    windowInSecondary->consumeMotionDown(ADISPLAY_ID_NONE);
    monitorInSecondary.consumeMotionDown(ADISPLAY_ID_NONE);
}

// Test per-display input monitors for key event.
TEST_F(InputDispatcherFocusOnTwoDisplaysTest, MonitorKeyEvent_MultiDisplay) {
    // Input monitor per display.
    FakeMonitorReceiver monitorInPrimary =
            FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);
    FakeMonitorReceiver monitorInSecondary =
            FakeMonitorReceiver(mDispatcher, "M_2", SECOND_DISPLAY_ID);

    // Test inject a key down.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary.assertNoEvents();
    windowInSecondary->consumeKeyDown(ADISPLAY_ID_NONE);
    monitorInSecondary.consumeKeyDown(ADISPLAY_ID_NONE);
}

TEST_F(InputDispatcherFocusOnTwoDisplaysTest, CanFocusWindowOnUnfocusedDisplay) {
    sp<FakeWindowHandle> secondWindowInPrimary =
            sp<FakeWindowHandle>::make(application1, mDispatcher, "D_1_W2", ADISPLAY_ID_DEFAULT);
    secondWindowInPrimary->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowInPrimary, secondWindowInPrimary}}});
    setFocusedWindow(secondWindowInPrimary);
    windowInPrimary->consumeFocusEvent(false);
    secondWindowInPrimary->consumeFocusEvent(true);

    // Test inject a key down.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->assertNoEvents();
    windowInSecondary->assertNoEvents();
    secondWindowInPrimary->consumeKeyDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherFocusOnTwoDisplaysTest, CancelTouch_MultiDisplay) {
    FakeMonitorReceiver monitorInPrimary =
            FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);
    FakeMonitorReceiver monitorInSecondary =
            FakeMonitorReceiver(mDispatcher, "M_2", SECOND_DISPLAY_ID);

    // Test touch down on primary display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitorInPrimary.consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // Test touch down on second display.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowInSecondary->consumeMotionDown(SECOND_DISPLAY_ID);
    monitorInSecondary.consumeMotionDown(SECOND_DISPLAY_ID);

    // Trigger cancel touch.
    mDispatcher->cancelCurrentTouch();
    windowInPrimary->consumeMotionCancel(ADISPLAY_ID_DEFAULT);
    monitorInPrimary.consumeMotionCancel(ADISPLAY_ID_DEFAULT);
    windowInSecondary->consumeMotionCancel(SECOND_DISPLAY_ID);
    monitorInSecondary.consumeMotionCancel(SECOND_DISPLAY_ID);

    // Test inject a move motion event, no window/monitor should receive the event.
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {110, 200}))
            << "Inject motion event should return InputEventInjectionResult::FAILED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary.assertNoEvents();

    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                SECOND_DISPLAY_ID, {110, 200}))
            << "Inject motion event should return InputEventInjectionResult::FAILED";
    windowInSecondary->assertNoEvents();
    monitorInSecondary.assertNoEvents();
}

class InputFilterTest : public InputDispatcherTest {
protected:
    void testNotifyMotion(int32_t displayId, bool expectToBeFiltered,
                          const ui::Transform& transform = ui::Transform()) {
        NotifyMotionArgs motionArgs;

        motionArgs =
                generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN, displayId);
        mDispatcher->notifyMotion(motionArgs);
        motionArgs =
                generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN, displayId);
        mDispatcher->notifyMotion(motionArgs);
        ASSERT_TRUE(mDispatcher->waitForIdle());
        if (expectToBeFiltered) {
            const auto xy = transform.transform(motionArgs.pointerCoords[0].getXYValue());
            mFakePolicy->assertFilterInputEventWasCalled(motionArgs, xy);
        } else {
            mFakePolicy->assertFilterInputEventWasNotCalled();
        }
    }

    void testNotifyKey(bool expectToBeFiltered) {
        NotifyKeyArgs keyArgs;

        keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN);
        mDispatcher->notifyKey(keyArgs);
        keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_UP);
        mDispatcher->notifyKey(keyArgs);
        ASSERT_TRUE(mDispatcher->waitForIdle());

        if (expectToBeFiltered) {
            mFakePolicy->assertFilterInputEventWasCalled(keyArgs);
        } else {
            mFakePolicy->assertFilterInputEventWasNotCalled();
        }
    }
};

// Test InputFilter for MotionEvent
TEST_F(InputFilterTest, MotionEvent_InputFilter) {
    // Since the InputFilter is disabled by default, check if touch events aren't filtered.
    testNotifyMotion(ADISPLAY_ID_DEFAULT, /*expectToBeFiltered*/ false);
    testNotifyMotion(SECOND_DISPLAY_ID, /*expectToBeFiltered*/ false);

    // Enable InputFilter
    mDispatcher->setInputFilterEnabled(true);
    // Test touch on both primary and second display, and check if both events are filtered.
    testNotifyMotion(ADISPLAY_ID_DEFAULT, /*expectToBeFiltered*/ true);
    testNotifyMotion(SECOND_DISPLAY_ID, /*expectToBeFiltered*/ true);

    // Disable InputFilter
    mDispatcher->setInputFilterEnabled(false);
    // Test touch on both primary and second display, and check if both events aren't filtered.
    testNotifyMotion(ADISPLAY_ID_DEFAULT, /*expectToBeFiltered*/ false);
    testNotifyMotion(SECOND_DISPLAY_ID, /*expectToBeFiltered*/ false);
}

// Test InputFilter for KeyEvent
TEST_F(InputFilterTest, KeyEvent_InputFilter) {
    // Since the InputFilter is disabled by default, check if key event aren't filtered.
    testNotifyKey(/*expectToBeFiltered*/ false);

    // Enable InputFilter
    mDispatcher->setInputFilterEnabled(true);
    // Send a key event, and check if it is filtered.
    testNotifyKey(/*expectToBeFiltered*/ true);

    // Disable InputFilter
    mDispatcher->setInputFilterEnabled(false);
    // Send a key event, and check if it isn't filtered.
    testNotifyKey(/*expectToBeFiltered*/ false);
}

// Ensure that MotionEvents sent to the InputFilter through InputListener are converted to the
// logical display coordinate space.
TEST_F(InputFilterTest, MotionEvent_UsesLogicalDisplayCoordinates_notifyMotion) {
    ui::Transform firstDisplayTransform;
    firstDisplayTransform.set({1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 0, 0, 1});
    ui::Transform secondDisplayTransform;
    secondDisplayTransform.set({-6.6, -5.5, -4.4, -3.3, -2.2, -1.1, 0, 0, 1});

    std::vector<gui::DisplayInfo> displayInfos(2);
    displayInfos[0].displayId = ADISPLAY_ID_DEFAULT;
    displayInfos[0].transform = firstDisplayTransform;
    displayInfos[1].displayId = SECOND_DISPLAY_ID;
    displayInfos[1].transform = secondDisplayTransform;

    mDispatcher->onWindowInfosChanged({{}, displayInfos, 0, 0});

    // Enable InputFilter
    mDispatcher->setInputFilterEnabled(true);

    // Ensure the correct transforms are used for the displays.
    testNotifyMotion(ADISPLAY_ID_DEFAULT, /*expectToBeFiltered*/ true, firstDisplayTransform);
    testNotifyMotion(SECOND_DISPLAY_ID, /*expectToBeFiltered*/ true, secondDisplayTransform);
}

class InputFilterInjectionPolicyTest : public InputDispatcherTest {
protected:
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        /**
         * We don't need to enable input filter to test the injected event policy, but we enabled it
         * here to make the tests more realistic, since this policy only matters when inputfilter is
         * on.
         */
        mDispatcher->setInputFilterEnabled(true);

        std::shared_ptr<InputApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();
        mWindow = sp<FakeWindowHandle>::make(application, mDispatcher, "Test Window",
                                             ADISPLAY_ID_DEFAULT);

        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
        mWindow->setFocusable(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
        setFocusedWindow(mWindow);
        mWindow->consumeFocusEvent(true);
    }

    void testInjectedKey(int32_t policyFlags, int32_t injectedDeviceId, int32_t resolvedDeviceId,
                         int32_t flags) {
        KeyEvent event;

        const nsecs_t eventTime = systemTime(SYSTEM_TIME_MONOTONIC);
        event.initialize(InputEvent::nextId(), injectedDeviceId, AINPUT_SOURCE_KEYBOARD,
                         ADISPLAY_ID_NONE, INVALID_HMAC, AKEY_EVENT_ACTION_DOWN, 0, AKEYCODE_A,
                         KEY_A, AMETA_NONE, /*repeatCount=*/0, eventTime, eventTime);
        const int32_t additionalPolicyFlags =
                POLICY_FLAG_PASS_TO_USER | POLICY_FLAG_DISABLE_KEY_REPEAT;
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  mDispatcher->injectInputEvent(&event, /*targetUid=*/{},
                                                InputEventInjectionSync::WAIT_FOR_RESULT, 10ms,
                                                policyFlags | additionalPolicyFlags));

        InputEvent* received = mWindow->consume();
        ASSERT_NE(nullptr, received);
        ASSERT_EQ(resolvedDeviceId, received->getDeviceId());
        ASSERT_EQ(received->getType(), InputEventType::KEY);
        KeyEvent& keyEvent = static_cast<KeyEvent&>(*received);
        ASSERT_EQ(flags, keyEvent.getFlags());
    }

    void testInjectedMotion(int32_t policyFlags, int32_t injectedDeviceId, int32_t resolvedDeviceId,
                            int32_t flags) {
        MotionEvent event;
        PointerProperties pointerProperties[1];
        PointerCoords pointerCoords[1];
        pointerProperties[0].clear();
        pointerProperties[0].id = 0;
        pointerCoords[0].clear();
        pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 300);
        pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 400);

        ui::Transform identityTransform;
        const nsecs_t eventTime = systemTime(SYSTEM_TIME_MONOTONIC);
        event.initialize(InputEvent::nextId(), injectedDeviceId, AINPUT_SOURCE_TOUCHSCREEN,
                         DISPLAY_ID, INVALID_HMAC, AMOTION_EVENT_ACTION_DOWN, 0, 0,
                         AMOTION_EVENT_EDGE_FLAG_NONE, AMETA_NONE, 0, MotionClassification::NONE,
                         identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                         AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, eventTime,
                         eventTime,
                         /*pointerCount*/ 1, pointerProperties, pointerCoords);

        const int32_t additionalPolicyFlags = POLICY_FLAG_PASS_TO_USER;
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  mDispatcher->injectInputEvent(&event, /*targetUid=*/{},
                                                InputEventInjectionSync::WAIT_FOR_RESULT, 10ms,
                                                policyFlags | additionalPolicyFlags));

        InputEvent* received = mWindow->consume();
        ASSERT_NE(nullptr, received);
        ASSERT_EQ(resolvedDeviceId, received->getDeviceId());
        ASSERT_EQ(received->getType(), InputEventType::MOTION);
        MotionEvent& motionEvent = static_cast<MotionEvent&>(*received);
        ASSERT_EQ(flags, motionEvent.getFlags());
    }

private:
    sp<FakeWindowHandle> mWindow;
};

TEST_F(InputFilterInjectionPolicyTest, TrustedFilteredEvents_KeepOriginalDeviceId) {
    // Must have POLICY_FLAG_FILTERED here to indicate that the event has gone through the input
    // filter. Without it, the event will no different from a regularly injected event, and the
    // injected device id will be overwritten.
    testInjectedKey(POLICY_FLAG_FILTERED, /*injectedDeviceId=*/3, /*resolvedDeviceId=*/3,
                    /*flags=*/0);
}

TEST_F(InputFilterInjectionPolicyTest, KeyEventsInjectedFromAccessibility_HaveAccessibilityFlag) {
    testInjectedKey(POLICY_FLAG_FILTERED | POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY,
                    /*injectedDeviceId=*/3, /*resolvedDeviceId=*/3,
                    AKEY_EVENT_FLAG_IS_ACCESSIBILITY_EVENT);
}

TEST_F(InputFilterInjectionPolicyTest,
       MotionEventsInjectedFromAccessibility_HaveAccessibilityFlag) {
    testInjectedMotion(POLICY_FLAG_FILTERED | POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY,
                       /*injectedDeviceId=*/3, /*resolvedDeviceId=*/3,
                       AMOTION_EVENT_FLAG_IS_ACCESSIBILITY_EVENT);
}

TEST_F(InputFilterInjectionPolicyTest, RegularInjectedEvents_ReceiveVirtualDeviceId) {
    testInjectedKey(/*policyFlags=*/0, /*injectedDeviceId=*/3,
                    /*resolvedDeviceId=*/VIRTUAL_KEYBOARD_ID, /*flags=*/0);
}

class InputDispatcherOnPointerDownOutsideFocus : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        std::shared_ptr<FakeApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();
        mUnfocusedWindow =
                sp<FakeWindowHandle>::make(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
        mUnfocusedWindow->setFrame(Rect(0, 0, 30, 30));

        mFocusedWindow =
                sp<FakeWindowHandle>::make(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
        mFocusedWindow->setFrame(Rect(50, 50, 100, 100));

        // Set focused application.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
        mFocusedWindow->setFocusable(true);

        // Expect one focus window exist in display.
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mUnfocusedWindow, mFocusedWindow}}});
        setFocusedWindow(mFocusedWindow);
        mFocusedWindow->consumeFocusEvent(true);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();

        mUnfocusedWindow.clear();
        mFocusedWindow.clear();
    }

protected:
    sp<FakeWindowHandle> mUnfocusedWindow;
    sp<FakeWindowHandle> mFocusedWindow;
    static constexpr PointF FOCUSED_WINDOW_TOUCH_POINT = {60, 60};
};

// Have two windows, one with focus. Inject MotionEvent with source TOUCHSCREEN and action
// DOWN on the window that doesn't have focus. Ensure the window that didn't have focus received
// the onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_Success) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {20, 20}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mUnfocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownEquals(mUnfocusedWindow->getToken());
}

// Have two windows, one with focus. Inject MotionEvent with source TRACKBALL and action
// DOWN on the window that doesn't have focus. Ensure no window received the
// onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_NonPointerSource) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TRACKBALL, ADISPLAY_ID_DEFAULT, {20, 20}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mFocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

// Have two windows, one with focus. Inject KeyEvent with action DOWN on the window that doesn't
// have focus. Ensure no window received the onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_NonMotionFailure) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectKeyDownNoRepeat(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mFocusedWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

// Have two windows, one with focus. Inject MotionEvent with source TOUCHSCREEN and action
// DOWN on the window that already has focus. Ensure no window received the
// onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_OnAlreadyFocusedWindow) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_TOUCH_POINT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mFocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

// Have two windows, one with focus. Injecting a trusted DOWN MotionEvent with the flag
// NO_FOCUS_CHANGE on the unfocused window should not call the onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, NoFocusChangeFlag) {
    const MotionEvent event =
            MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(20).y(20))
                    .addFlag(AMOTION_EVENT_FLAG_NO_FOCUS_CHANGE)
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectMotionEvent(mDispatcher, event))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mUnfocusedWindow->consumeAnyMotionDown(ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_NO_FOCUS_CHANGE);

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
    // Ensure that the unfocused window did not receive any FOCUS events.
    mUnfocusedWindow->assertNoEvents();
}

// These tests ensures we can send touch events to a single client when there are multiple input
// windows that point to the same client token.
class InputDispatcherMultiWindowSameTokenTests : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        std::shared_ptr<FakeApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();
        mWindow1 = sp<FakeWindowHandle>::make(application, mDispatcher, "Fake Window 1",
                                              ADISPLAY_ID_DEFAULT);
        mWindow1->setFrame(Rect(0, 0, 100, 100));

        mWindow2 = sp<FakeWindowHandle>::make(application, mDispatcher, "Fake Window 2",
                                              ADISPLAY_ID_DEFAULT, mWindow1->getToken());
        mWindow2->setFrame(Rect(100, 100, 200, 200));

        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow1, mWindow2}}});
    }

protected:
    sp<FakeWindowHandle> mWindow1;
    sp<FakeWindowHandle> mWindow2;

    // Helper function to convert the point from screen coordinates into the window's space
    static PointF getPointInWindow(const WindowInfo* windowInfo, const PointF& point) {
        vec2 vals = windowInfo->transform.transform(point.x, point.y);
        return {vals.x, vals.y};
    }

    void consumeMotionEvent(const sp<FakeWindowHandle>& window, int32_t expectedAction,
                            const std::vector<PointF>& points) {
        const std::string name = window->getName();
        InputEvent* event = window->consume();

        ASSERT_NE(nullptr, event) << name.c_str()
                                  << ": consumer should have returned non-NULL event.";

        ASSERT_EQ(InputEventType::MOTION, event->getType())
                << name.c_str() << ": expected MotionEvent, got " << *event;

        const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*event);
        assertMotionAction(expectedAction, motionEvent.getAction());
        ASSERT_EQ(points.size(), motionEvent.getPointerCount());

        for (size_t i = 0; i < points.size(); i++) {
            float expectedX = points[i].x;
            float expectedY = points[i].y;

            EXPECT_EQ(expectedX, motionEvent.getX(i))
                    << "expected " << expectedX << " for x[" << i << "] coord of " << name.c_str()
                    << ", got " << motionEvent.getX(i);
            EXPECT_EQ(expectedY, motionEvent.getY(i))
                    << "expected " << expectedY << " for y[" << i << "] coord of " << name.c_str()
                    << ", got " << motionEvent.getY(i);
        }
    }

    void touchAndAssertPositions(int32_t action, const std::vector<PointF>& touchedPoints,
                                 std::vector<PointF> expectedPoints) {
        mDispatcher->notifyMotion(generateMotionArgs(action, AINPUT_SOURCE_TOUCHSCREEN,
                                                     ADISPLAY_ID_DEFAULT, touchedPoints));

        // Always consume from window1 since it's the window that has the InputReceiver
        consumeMotionEvent(mWindow1, action, expectedPoints);
    }
};

TEST_F(InputDispatcherMultiWindowSameTokenTests, SingleTouchSameScale) {
    // Touch Window 1
    PointF touchedPoint = {10, 10};
    PointF expectedPoint = getPointInWindow(mWindow1->getInfo(), touchedPoint);
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, {touchedPoint}, {expectedPoint});

    // Release touch on Window 1
    touchAndAssertPositions(AMOTION_EVENT_ACTION_UP, {touchedPoint}, {expectedPoint});

    // Touch Window 2
    touchedPoint = {150, 150};
    expectedPoint = getPointInWindow(mWindow2->getInfo(), touchedPoint);
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, {touchedPoint}, {expectedPoint});
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, SingleTouchDifferentTransform) {
    // Set scale value for window2
    mWindow2->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    PointF touchedPoint = {10, 10};
    PointF expectedPoint = getPointInWindow(mWindow1->getInfo(), touchedPoint);
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, {touchedPoint}, {expectedPoint});
    // Release touch on Window 1
    touchAndAssertPositions(AMOTION_EVENT_ACTION_UP, {touchedPoint}, {expectedPoint});

    // Touch Window 2
    touchedPoint = {150, 150};
    expectedPoint = getPointInWindow(mWindow2->getInfo(), touchedPoint);
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, {touchedPoint}, {expectedPoint});
    touchAndAssertPositions(AMOTION_EVENT_ACTION_UP, {touchedPoint}, {expectedPoint});

    // Update the transform so rotation is set
    mWindow2->setWindowTransform(0, -1, 1, 0);
    expectedPoint = getPointInWindow(mWindow2->getInfo(), touchedPoint);
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, {touchedPoint}, {expectedPoint});
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, MultipleTouchDifferentTransform) {
    mWindow2->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    std::vector<PointF> touchedPoints = {PointF{10, 10}};
    std::vector<PointF> expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0])};
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, touchedPoints, expectedPoints);

    // Touch Window 2
    touchedPoints.push_back(PointF{150, 150});
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));
    touchAndAssertPositions(POINTER_1_DOWN, touchedPoints, expectedPoints);

    // Release Window 2
    touchAndAssertPositions(POINTER_1_UP, touchedPoints, expectedPoints);
    expectedPoints.pop_back();

    // Update the transform so rotation is set for Window 2
    mWindow2->setWindowTransform(0, -1, 1, 0);
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));
    touchAndAssertPositions(POINTER_1_DOWN, touchedPoints, expectedPoints);
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, MultipleTouchMoveDifferentTransform) {
    mWindow2->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    std::vector<PointF> touchedPoints = {PointF{10, 10}};
    std::vector<PointF> expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0])};
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, touchedPoints, expectedPoints);

    // Touch Window 2
    touchedPoints.push_back(PointF{150, 150});
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));

    touchAndAssertPositions(POINTER_1_DOWN, touchedPoints, expectedPoints);

    // Move both windows
    touchedPoints = {{20, 20}, {175, 175}};
    expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0]),
                      getPointInWindow(mWindow2->getInfo(), touchedPoints[1])};

    touchAndAssertPositions(AMOTION_EVENT_ACTION_MOVE, touchedPoints, expectedPoints);

    // Release Window 2
    touchAndAssertPositions(POINTER_1_UP, touchedPoints, expectedPoints);
    expectedPoints.pop_back();

    // Touch Window 2
    mWindow2->setWindowTransform(0, -1, 1, 0);
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));
    touchAndAssertPositions(POINTER_1_DOWN, touchedPoints, expectedPoints);

    // Move both windows
    touchedPoints = {{20, 20}, {175, 175}};
    expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0]),
                      getPointInWindow(mWindow2->getInfo(), touchedPoints[1])};

    touchAndAssertPositions(AMOTION_EVENT_ACTION_MOVE, touchedPoints, expectedPoints);
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, MultipleWindowsFirstTouchWithScale) {
    mWindow1->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    std::vector<PointF> touchedPoints = {PointF{10, 10}};
    std::vector<PointF> expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0])};
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, touchedPoints, expectedPoints);

    // Touch Window 2
    touchedPoints.push_back(PointF{150, 150});
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));

    touchAndAssertPositions(POINTER_1_DOWN, touchedPoints, expectedPoints);

    // Move both windows
    touchedPoints = {{20, 20}, {175, 175}};
    expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0]),
                      getPointInWindow(mWindow2->getInfo(), touchedPoints[1])};

    touchAndAssertPositions(AMOTION_EVENT_ACTION_MOVE, touchedPoints, expectedPoints);
}

/**
 * When one of the windows is slippery, the touch should not slip into the other window with the
 * same input channel.
 */
TEST_F(InputDispatcherMultiWindowSameTokenTests, TouchDoesNotSlipEvenIfSlippery) {
    mWindow1->setSlippery(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow1, mWindow2}}});

    // Touch down in window 1
    mDispatcher->notifyMotion(generateMotionArgs(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT, {{50, 50}}));
    consumeMotionEvent(mWindow1, ACTION_DOWN, {{50, 50}});

    // Move touch to be above window 2. Even though window 1 is slippery, touch should not slip.
    // That means the gesture should continue normally, without any ACTION_CANCEL or ACTION_DOWN
    // getting generated.
    mDispatcher->notifyMotion(generateMotionArgs(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT, {{150, 150}}));

    consumeMotionEvent(mWindow1, ACTION_MOVE, {{150, 150}});
}

/**
 * When hover starts in one window and continues into the other, there should be a HOVER_EXIT and
 * a HOVER_ENTER generated, even if the windows have the same token. This is because the new window
 * that the pointer is hovering over may have a different transform.
 */
TEST_F(InputDispatcherMultiWindowSameTokenTests, HoverIntoClone) {
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow1, mWindow2}}});

    // Start hover in window 1
    mDispatcher->notifyMotion(generateMotionArgs(ACTION_HOVER_ENTER, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT, {{50, 50}}));
    consumeMotionEvent(mWindow1, ACTION_HOVER_ENTER,
                       {getPointInWindow(mWindow1->getInfo(), PointF{50, 50})});

    // Move hover to window 2.
    mDispatcher->notifyMotion(generateMotionArgs(ACTION_HOVER_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT, {{150, 150}}));

    consumeMotionEvent(mWindow1, ACTION_HOVER_EXIT, {{50, 50}});
    consumeMotionEvent(mWindow1, ACTION_HOVER_ENTER,
                       {getPointInWindow(mWindow2->getInfo(), PointF{150, 150})});
}

class InputDispatcherSingleWindowAnr : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        mApplication = std::make_shared<FakeApplicationHandle>();
        mApplication->setDispatchingTimeout(20ms);
        mWindow = sp<FakeWindowHandle>::make(mApplication, mDispatcher, "TestWindow",
                                             ADISPLAY_ID_DEFAULT);
        mWindow->setFrame(Rect(0, 0, 30, 30));
        mWindow->setDispatchingTimeout(30ms);
        mWindow->setFocusable(true);

        // Set focused application.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApplication);

        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
        setFocusedWindow(mWindow);
        mWindow->consumeFocusEvent(true);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();
        mWindow.clear();
    }

protected:
    std::shared_ptr<FakeApplicationHandle> mApplication;
    sp<FakeWindowHandle> mWindow;
    static constexpr PointF WINDOW_LOCATION = {20, 20};

    void tapOnWindow() {
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                   WINDOW_LOCATION));
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                 WINDOW_LOCATION));
    }

    sp<FakeWindowHandle> addSpyWindow() {
        sp<FakeWindowHandle> spy =
                sp<FakeWindowHandle>::make(mApplication, mDispatcher, "Spy", ADISPLAY_ID_DEFAULT);
        spy->setTrustedOverlay(true);
        spy->setFocusable(false);
        spy->setSpy(true);
        spy->setDispatchingTimeout(30ms);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, mWindow}}});
        return spy;
    }
};

// Send a tap and respond, which should not cause an ANR.
TEST_F(InputDispatcherSingleWindowAnr, WhenTouchIsConsumed_NoAnr) {
    tapOnWindow();
    mWindow->consumeMotionDown();
    mWindow->consumeMotionUp();
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// Send a regular key and respond, which should not cause an ANR.
TEST_F(InputDispatcherSingleWindowAnr, WhenKeyIsConsumed_NoAnr) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDownNoRepeat(mDispatcher));
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

TEST_F(InputDispatcherSingleWindowAnr, WhenFocusedApplicationChanges_NoAnr) {
    mWindow->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);

    InputEventInjectionResult result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::NONE, /*injectionTimeout=*/10ms,
                      /*allowKeyRepeat=*/false);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, result);
    // Key will not go to window because we have no focused window.
    // The 'no focused window' ANR timer should start instead.

    // Now, the focused application goes away.
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, nullptr);
    // The key should get dropped and there should be no ANR.

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// Send an event to the app and have the app not respond right away.
// When ANR is raised, policy will tell the dispatcher to cancel the events for that window.
// So InputDispatcher will enqueue ACTION_CANCEL event as well.
TEST_F(InputDispatcherSingleWindowAnr, OnPointerDown_BasicAnr) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));

    std::optional<uint32_t> sequenceNum = mWindow->receiveEvent(); // ACTION_DOWN
    ASSERT_TRUE(sequenceNum);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);

    mWindow->finishEvent(*sequenceNum);
    mWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_CANCEL), WithDisplayId(ADISPLAY_ID_DEFAULT)));
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken(), mWindow->getPid());
}

// Send a key to the app and have the app not respond right away.
TEST_F(InputDispatcherSingleWindowAnr, OnKeyDown_BasicAnr) {
    // Inject a key, and don't respond - expect that ANR is called.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDownNoRepeat(mDispatcher));
    std::optional<uint32_t> sequenceNum = mWindow->receiveEvent();
    ASSERT_TRUE(sequenceNum);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

// We have a focused application, but no focused window
TEST_F(InputDispatcherSingleWindowAnr, FocusedApplication_NoFocusedWindow) {
    mWindow->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);

    // taps on the window work as normal
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));
    ASSERT_NO_FATAL_FAILURE(mWindow->consumeMotionDown());
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyAnrWasNotCalled();

    // Once a focused event arrives, we get an ANR for this application
    // We specify the injection timeout to be smaller than the application timeout, to ensure that
    // injection times out (instead of failing).
    const InputEventInjectionResult result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::WAIT_FOR_RESULT, 10ms, /*allowKeyRepeat=*/false);
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, result);
    const std::chrono::duration timeout = mApplication->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyNoFocusedWindowAnrWasCalled(timeout, mApplication);
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

/**
 * Make sure the stale key is dropped before causing an ANR. So even if there's no focused window,
 * there will not be an ANR.
 */
TEST_F(InputDispatcherSingleWindowAnr, StaleKeyEventDoesNotAnr) {
    mWindow->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);

    KeyEvent event;
    const nsecs_t eventTime = systemTime(SYSTEM_TIME_MONOTONIC) -
            std::chrono::nanoseconds(STALE_EVENT_TIMEOUT).count();

    // Define a valid key down event that is stale (too old).
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
                     INVALID_HMAC, AKEY_EVENT_ACTION_DOWN, /* flags */ 0, AKEYCODE_A, KEY_A,
                     AMETA_NONE, /*repeatCount=*/1, eventTime, eventTime);

    const int32_t policyFlags = POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER;

    InputEventInjectionResult result =
            mDispatcher->injectInputEvent(&event, /*targetUid=*/{},
                                          InputEventInjectionSync::WAIT_FOR_RESULT,
                                          INJECT_EVENT_TIMEOUT, policyFlags);
    ASSERT_EQ(InputEventInjectionResult::FAILED, result)
            << "Injection should fail because the event is stale";

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();
    mWindow->assertNoEvents();
}

// We have a focused application, but no focused window
// Make sure that we don't notify policy twice about the same ANR.
TEST_F(InputDispatcherSingleWindowAnr, NoFocusedWindow_DoesNotSendDuplicateAnr) {
    mWindow->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);

    // Once a focused event arrives, we get an ANR for this application
    // We specify the injection timeout to be smaller than the application timeout, to ensure that
    // injection times out (instead of failing).
    const InputEventInjectionResult result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::WAIT_FOR_RESULT, 10ms, /*allowKeyRepeat=*/false);
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, result);
    const std::chrono::duration appTimeout =
            mApplication->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyNoFocusedWindowAnrWasCalled(appTimeout, mApplication);

    std::this_thread::sleep_for(appTimeout);
    // ANR should not be raised again. It is up to policy to do that if it desires.
    mFakePolicy->assertNotifyAnrWasNotCalled();

    // If we now get a focused window, the ANR should stop, but the policy handles that via
    // 'notifyFocusChanged' callback. This is implemented in the policy so we can't test it here.
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

// We have a focused application, but no focused window
TEST_F(InputDispatcherSingleWindowAnr, NoFocusedWindow_DropsFocusedEvents) {
    mWindow->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);

    // Once a focused event arrives, we get an ANR for this application
    const InputEventInjectionResult result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::WAIT_FOR_RESULT, 10ms);
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, result);

    const std::chrono::duration timeout = mApplication->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyNoFocusedWindowAnrWasCalled(timeout, mApplication);

    // Future focused events get dropped right away
    ASSERT_EQ(InputEventInjectionResult::FAILED, injectKeyDown(mDispatcher));
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mWindow->assertNoEvents();
}

/**
 * Ensure that the implementation is valid. Since we are using multiset to keep track of the
 * ANR timeouts, we are allowing entries with identical timestamps in the same connection.
 * If we process 1 of the events, but ANR on the second event with the same timestamp,
 * the ANR mechanism should still work.
 *
 * In this test, we are injecting DOWN and UP events with the same timestamps, and acknowledging the
 * DOWN event, while not responding on the second one.
 */
TEST_F(InputDispatcherSingleWindowAnr, Anr_HandlesEventsWithIdenticalTimestamps) {
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                      ADISPLAY_ID_DEFAULT, WINDOW_LOCATION,
                      {AMOTION_EVENT_INVALID_CURSOR_POSITION,
                       AMOTION_EVENT_INVALID_CURSOR_POSITION},
                      500ms, InputEventInjectionSync::WAIT_FOR_RESULT, currentTime);

    // Now send ACTION_UP, with identical timestamp
    injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                      ADISPLAY_ID_DEFAULT, WINDOW_LOCATION,
                      {AMOTION_EVENT_INVALID_CURSOR_POSITION,
                       AMOTION_EVENT_INVALID_CURSOR_POSITION},
                      500ms, InputEventInjectionSync::WAIT_FOR_RESULT, currentTime);

    // We have now sent down and up. Let's consume first event and then ANR on the second.
    mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);
}

// A spy window can receive an ANR
TEST_F(InputDispatcherSingleWindowAnr, SpyWindowAnr) {
    sp<FakeWindowHandle> spy = addSpyWindow();

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));
    mWindow->consumeMotionDown();

    std::optional<uint32_t> sequenceNum = spy->receiveEvent(); // ACTION_DOWN
    ASSERT_TRUE(sequenceNum);
    const std::chrono::duration timeout = spy->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, spy);

    spy->finishEvent(*sequenceNum);
    spy->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_CANCEL), WithDisplayId(ADISPLAY_ID_DEFAULT)));
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(spy->getToken(), mWindow->getPid());
}

// If an app is not responding to a key event, spy windows should continue to receive
// new motion events
TEST_F(InputDispatcherSingleWindowAnr, SpyWindowReceivesEventsDuringAppAnrOnKey) {
    sp<FakeWindowHandle> spy = addSpyWindow();

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT));
    mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher, ADISPLAY_ID_DEFAULT));

    // Stuck on the ACTION_UP
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);

    // New tap will go to the spy window, but not to the window
    tapOnWindow();
    spy->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    spy->consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeKeyUp(ADISPLAY_ID_DEFAULT); // still the previous motion
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken(), mWindow->getPid());
    mWindow->assertNoEvents();
    spy->assertNoEvents();
}

// If an app is not responding to a motion event, spy windows should continue to receive
// new motion events
TEST_F(InputDispatcherSingleWindowAnr, SpyWindowReceivesEventsDuringAppAnrOnMotion) {
    sp<FakeWindowHandle> spy = addSpyWindow();

    tapOnWindow();
    spy->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    spy->consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeMotionDown();
    // Stuck on the ACTION_UP
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);

    // New tap will go to the spy window, but not to the window
    tapOnWindow();
    spy->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    spy->consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT); // still the previous motion
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken(), mWindow->getPid());
    mWindow->assertNoEvents();
    spy->assertNoEvents();
}

TEST_F(InputDispatcherSingleWindowAnr, UnresponsiveMonitorAnr) {
    mDispatcher->setMonitorDispatchingTimeoutForTest(30ms);

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));

    mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    const std::optional<uint32_t> consumeSeq = monitor.receiveEvent();
    ASSERT_TRUE(consumeSeq);

    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(30ms, monitor.getToken(), MONITOR_PID);

    monitor.finishEvent(*consumeSeq);
    monitor.consumeMotionCancel(ADISPLAY_ID_DEFAULT);

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(monitor.getToken(), MONITOR_PID);
}

// If a window is unresponsive, then you get anr. if the window later catches up and starts to
// process events, you don't get an anr. When the window later becomes unresponsive again, you
// get an ANR again.
// 1. tap -> block on ACTION_UP -> receive ANR
// 2. consume all pending events (= queue becomes healthy again)
// 3. tap again -> block on ACTION_UP again -> receive ANR second time
TEST_F(InputDispatcherSingleWindowAnr, SameWindow_CanReceiveAnrTwice) {
    tapOnWindow();

    mWindow->consumeMotionDown();
    // Block on ACTION_UP
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);
    mWindow->consumeMotionUp(); // Now the connection should be healthy again
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken(), mWindow->getPid());
    mWindow->assertNoEvents();

    tapOnWindow();
    mWindow->consumeMotionDown();
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);
    mWindow->consumeMotionUp();

    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken(), mWindow->getPid());
    mFakePolicy->assertNotifyAnrWasNotCalled();
    mWindow->assertNoEvents();
}

// If a connection remains unresponsive for a while, make sure policy is only notified once about
// it.
TEST_F(InputDispatcherSingleWindowAnr, Policy_DoesNotGetDuplicateAnr) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));

    const std::chrono::duration windowTimeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(windowTimeout, mWindow);
    std::this_thread::sleep_for(windowTimeout);
    // 'notifyConnectionUnresponsive' should only be called once per connection
    mFakePolicy->assertNotifyAnrWasNotCalled();
    // When the ANR happened, dispatcher should abort the current event stream via ACTION_CANCEL
    mWindow->consumeMotionDown();
    mWindow->consumeMotionEvent(
            AllOf(WithMotionAction(ACTION_CANCEL), WithDisplayId(ADISPLAY_ID_DEFAULT)));
    mWindow->assertNoEvents();
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken(), mWindow->getPid());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

/**
 * If a window is processing a motion event, and then a key event comes in, the key event should
 * not to to the focused window until the motion is processed.
 *
 * Warning!!!
 * This test depends on the value of android::inputdispatcher::KEY_WAITING_FOR_MOTION_TIMEOUT
 * and the injection timeout that we specify when injecting the key.
 * We must have the injection timeout (10ms) be smaller than
 *  KEY_WAITING_FOR_MOTION_TIMEOUT (currently 500ms).
 *
 * If that value changes, this test should also change.
 */
TEST_F(InputDispatcherSingleWindowAnr, Key_StaysPendingWhileMotionIsProcessed) {
    mWindow->setDispatchingTimeout(2s); // Set a long ANR timeout to prevent it from triggering
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});

    tapOnWindow();
    std::optional<uint32_t> downSequenceNum = mWindow->receiveEvent();
    ASSERT_TRUE(downSequenceNum);
    std::optional<uint32_t> upSequenceNum = mWindow->receiveEvent();
    ASSERT_TRUE(upSequenceNum);
    // Don't finish the events yet, and send a key
    // Injection will "succeed" because we will eventually give up and send the key to the focused
    // window even if motions are still being processed. But because the injection timeout is short,
    // we will receive INJECTION_TIMED_OUT as the result.

    InputEventInjectionResult result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::WAIT_FOR_RESULT, 10ms);
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, result);
    // Key will not be sent to the window, yet, because the window is still processing events
    // and the key remains pending, waiting for the touch events to be processed
    std::optional<uint32_t> keySequenceNum = mWindow->receiveEvent();
    ASSERT_FALSE(keySequenceNum);

    std::this_thread::sleep_for(500ms);
    // if we wait long enough though, dispatcher will give up, and still send the key
    // to the focused window, even though we have not yet finished the motion event
    mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    mWindow->finishEvent(*downSequenceNum);
    mWindow->finishEvent(*upSequenceNum);
}

/**
 * If a window is processing a motion event, and then a key event comes in, the key event should
 * not go to the focused window until the motion is processed.
 * If then a new motion comes in, then the pending key event should be going to the currently
 * focused window right away.
 */
TEST_F(InputDispatcherSingleWindowAnr,
       PendingKey_IsDroppedWhileMotionIsProcessedAndNewTouchComesIn) {
    mWindow->setDispatchingTimeout(2s); // Set a long ANR timeout to prevent it from triggering
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});

    tapOnWindow();
    std::optional<uint32_t> downSequenceNum = mWindow->receiveEvent();
    ASSERT_TRUE(downSequenceNum);
    std::optional<uint32_t> upSequenceNum = mWindow->receiveEvent();
    ASSERT_TRUE(upSequenceNum);
    // Don't finish the events yet, and send a key
    // Injection is async, so it will succeed
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                        InputEventInjectionSync::NONE));
    // At this point, key is still pending, and should not be sent to the application yet.
    std::optional<uint32_t> keySequenceNum = mWindow->receiveEvent();
    ASSERT_FALSE(keySequenceNum);

    // Now tap down again. It should cause the pending key to go to the focused window right away.
    tapOnWindow();
    mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT); // it doesn't matter that we haven't ack'd
    // the other events yet. We can finish events in any order.
    mWindow->finishEvent(*downSequenceNum); // first tap's ACTION_DOWN
    mWindow->finishEvent(*upSequenceNum);   // first tap's ACTION_UP
    mWindow->consumeMotionDown();
    mWindow->consumeMotionUp();
    mWindow->assertNoEvents();
}

/**
 * Send an event to the app and have the app not respond right away.
 * When ANR is raised, policy will tell the dispatcher to cancel the events for that window.
 * So InputDispatcher will enqueue ACTION_CANCEL event as well.
 * At some point, the window becomes responsive again.
 * Ensure that subsequent events get dropped, and the next gesture is delivered.
 */
TEST_F(InputDispatcherSingleWindowAnr, TwoGesturesWithAnr) {
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(10).y(10))
                                      .build());

    std::optional<uint32_t> sequenceNum = mWindow->receiveEvent(); // ACTION_DOWN
    ASSERT_TRUE(sequenceNum);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow);

    mWindow->finishEvent(*sequenceNum);
    mWindow->consumeMotionEvent(WithMotionAction(ACTION_CANCEL));
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken(), mWindow->getPid());

    // Now that the window is responsive, let's continue the gesture.
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(11).y(11))
                                      .build());

    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(11).y(11))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(3).y(3))
                                      .build());

    mDispatcher->notifyMotion(MotionArgsBuilder(POINTER_1_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(11).y(11))
                                      .pointer(PointerBuilder(1, ToolType::FINGER).x(3).y(3))
                                      .build());
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(11).y(11))
                                      .build());
    // We already canceled this pointer, so the window shouldn't get any new events.
    mWindow->assertNoEvents();

    // Start another one.
    mDispatcher->notifyMotion(MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                      .pointer(PointerBuilder(0, ToolType::FINGER).x(15).y(15))
                                      .build());
    mWindow->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
}

class InputDispatcherMultiWindowAnr : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        mApplication = std::make_shared<FakeApplicationHandle>();
        mApplication->setDispatchingTimeout(10ms);
        mUnfocusedWindow = sp<FakeWindowHandle>::make(mApplication, mDispatcher, "Unfocused",
                                                      ADISPLAY_ID_DEFAULT);
        mUnfocusedWindow->setFrame(Rect(0, 0, 30, 30));
        // Adding FLAG_WATCH_OUTSIDE_TOUCH to receive ACTION_OUTSIDE when another window is tapped
        mUnfocusedWindow->setWatchOutsideTouch(true);

        mFocusedWindow = sp<FakeWindowHandle>::make(mApplication, mDispatcher, "Focused",
                                                    ADISPLAY_ID_DEFAULT);
        mFocusedWindow->setDispatchingTimeout(30ms);
        mFocusedWindow->setFrame(Rect(50, 50, 100, 100));

        // Set focused application.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApplication);
        mFocusedWindow->setFocusable(true);

        // Expect one focus window exist in display.
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mUnfocusedWindow, mFocusedWindow}}});
        setFocusedWindow(mFocusedWindow);
        mFocusedWindow->consumeFocusEvent(true);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();

        mUnfocusedWindow.clear();
        mFocusedWindow.clear();
    }

protected:
    std::shared_ptr<FakeApplicationHandle> mApplication;
    sp<FakeWindowHandle> mUnfocusedWindow;
    sp<FakeWindowHandle> mFocusedWindow;
    static constexpr PointF UNFOCUSED_WINDOW_LOCATION = {20, 20};
    static constexpr PointF FOCUSED_WINDOW_LOCATION = {75, 75};
    static constexpr PointF LOCATION_OUTSIDE_ALL_WINDOWS = {40, 40};

    void tapOnFocusedWindow() { tap(FOCUSED_WINDOW_LOCATION); }

    void tapOnUnfocusedWindow() { tap(UNFOCUSED_WINDOW_LOCATION); }

private:
    void tap(const PointF& location) {
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                   location));
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                 location));
    }
};

// If we have 2 windows that are both unresponsive, the one with the shortest timeout
// should be ANR'd first.
TEST_F(InputDispatcherMultiWindowAnr, TwoWindows_BothUnresponsive) {
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_LOCATION))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mFocusedWindow->consumeMotionDown();
    mUnfocusedWindow->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_OUTSIDE,
                                   ADISPLAY_ID_DEFAULT, /*flags=*/0);
    // We consumed all events, so no ANR
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_LOCATION));
    std::optional<uint32_t> unfocusedSequenceNum = mUnfocusedWindow->receiveEvent();
    ASSERT_TRUE(unfocusedSequenceNum);

    const std::chrono::duration timeout =
            mFocusedWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mFocusedWindow);
    // Because we injected two DOWN events in a row, CANCEL is enqueued for the first event
    // sequence to make it consistent
    mFocusedWindow->consumeMotionCancel();
    mUnfocusedWindow->finishEvent(*unfocusedSequenceNum);
    mFocusedWindow->consumeMotionDown();
    // This cancel is generated because the connection was unresponsive
    mFocusedWindow->consumeMotionCancel();
    mFocusedWindow->assertNoEvents();
    mUnfocusedWindow->assertNoEvents();
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mFocusedWindow->getToken(),
                                                       mFocusedWindow->getPid());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// If we have 2 windows with identical timeouts that are both unresponsive,
// it doesn't matter which order they should have ANR.
// But we should receive ANR for both.
TEST_F(InputDispatcherMultiWindowAnr, TwoWindows_BothUnresponsiveWithSameTimeout) {
    // Set the timeout for unfocused window to match the focused window
    mUnfocusedWindow->setDispatchingTimeout(10ms);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mUnfocusedWindow, mFocusedWindow}}});

    tapOnFocusedWindow();
    // we should have ACTION_DOWN/ACTION_UP on focused window and ACTION_OUTSIDE on unfocused window
    sp<IBinder> anrConnectionToken1, anrConnectionToken2;
    ASSERT_NO_FATAL_FAILURE(anrConnectionToken1 = mFakePolicy->getUnresponsiveWindowToken(10ms));
    ASSERT_NO_FATAL_FAILURE(anrConnectionToken2 = mFakePolicy->getUnresponsiveWindowToken(0ms));

    // We don't know which window will ANR first. But both of them should happen eventually.
    ASSERT_TRUE(mFocusedWindow->getToken() == anrConnectionToken1 ||
                mFocusedWindow->getToken() == anrConnectionToken2);
    ASSERT_TRUE(mUnfocusedWindow->getToken() == anrConnectionToken1 ||
                mUnfocusedWindow->getToken() == anrConnectionToken2);

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();

    mFocusedWindow->consumeMotionDown();
    mFocusedWindow->consumeMotionUp();
    mUnfocusedWindow->consumeMotionOutside();

    sp<IBinder> responsiveToken1, responsiveToken2;
    ASSERT_NO_FATAL_FAILURE(responsiveToken1 = mFakePolicy->getResponsiveWindowToken());
    ASSERT_NO_FATAL_FAILURE(responsiveToken2 = mFakePolicy->getResponsiveWindowToken());

    // Both applications should be marked as responsive, in any order
    ASSERT_TRUE(mFocusedWindow->getToken() == responsiveToken1 ||
                mFocusedWindow->getToken() == responsiveToken2);
    ASSERT_TRUE(mUnfocusedWindow->getToken() == responsiveToken1 ||
                mUnfocusedWindow->getToken() == responsiveToken2);
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// If a window is already not responding, the second tap on the same window should be ignored.
// We should also log an error to account for the dropped event (not tested here).
// At the same time, FLAG_WATCH_OUTSIDE_TOUCH targets should not receive any events.
TEST_F(InputDispatcherMultiWindowAnr, DuringAnr_SecondTapIsIgnored) {
    tapOnFocusedWindow();
    mUnfocusedWindow->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_OUTSIDE,
                                   ADISPLAY_ID_DEFAULT, /*flags=*/0);
    // Receive the events, but don't respond
    std::optional<uint32_t> downEventSequenceNum = mFocusedWindow->receiveEvent(); // ACTION_DOWN
    ASSERT_TRUE(downEventSequenceNum);
    std::optional<uint32_t> upEventSequenceNum = mFocusedWindow->receiveEvent(); // ACTION_UP
    ASSERT_TRUE(upEventSequenceNum);
    const std::chrono::duration timeout =
            mFocusedWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mFocusedWindow);

    // Tap once again
    // We cannot use "tapOnFocusedWindow" because it asserts the injection result to be success
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_LOCATION));
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                             FOCUSED_WINDOW_LOCATION));
    // Unfocused window does not receive ACTION_OUTSIDE because the tapped window is not a
    // valid touch target
    mUnfocusedWindow->assertNoEvents();

    // Consume the first tap
    mFocusedWindow->finishEvent(*downEventSequenceNum);
    mFocusedWindow->finishEvent(*upEventSequenceNum);
    ASSERT_TRUE(mDispatcher->waitForIdle());
    // The second tap did not go to the focused window
    mFocusedWindow->assertNoEvents();
    // Since all events are finished, connection should be deemed healthy again
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mFocusedWindow->getToken(),
                                                       mFocusedWindow->getPid());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// If you tap outside of all windows, there will not be ANR
TEST_F(InputDispatcherMultiWindowAnr, TapOutsideAllWindows_DoesNotAnr) {
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               LOCATION_OUTSIDE_ALL_WINDOWS));
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// Since the focused window is paused, tapping on it should not produce any events
TEST_F(InputDispatcherMultiWindowAnr, Window_CanBePaused) {
    mFocusedWindow->setPaused(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mUnfocusedWindow, mFocusedWindow}}});

    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_LOCATION));

    std::this_thread::sleep_for(mFocusedWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT));
    ASSERT_TRUE(mDispatcher->waitForIdle());
    // Should not ANR because the window is paused, and touches shouldn't go to it
    mFakePolicy->assertNotifyAnrWasNotCalled();

    mFocusedWindow->assertNoEvents();
    mUnfocusedWindow->assertNoEvents();
}

/**
 * If a window is processing a motion event, and then a key event comes in, the key event should
 * not to to the focused window until the motion is processed.
 * If a different window becomes focused at this time, the key should go to that window instead.
 *
 * Warning!!!
 * This test depends on the value of android::inputdispatcher::KEY_WAITING_FOR_MOTION_TIMEOUT
 * and the injection timeout that we specify when injecting the key.
 * We must have the injection timeout (10ms) be smaller than
 *  KEY_WAITING_FOR_MOTION_TIMEOUT (currently 500ms).
 *
 * If that value changes, this test should also change.
 */
TEST_F(InputDispatcherMultiWindowAnr, PendingKey_GoesToNewlyFocusedWindow) {
    // Set a long ANR timeout to prevent it from triggering
    mFocusedWindow->setDispatchingTimeout(2s);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mFocusedWindow, mUnfocusedWindow}}});

    tapOnUnfocusedWindow();
    std::optional<uint32_t> downSequenceNum = mUnfocusedWindow->receiveEvent();
    ASSERT_TRUE(downSequenceNum);
    std::optional<uint32_t> upSequenceNum = mUnfocusedWindow->receiveEvent();
    ASSERT_TRUE(upSequenceNum);
    // Don't finish the events yet, and send a key
    // Injection will succeed because we will eventually give up and send the key to the focused
    // window even if motions are still being processed.

    InputEventInjectionResult result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::NONE, /*injectionTimeout=*/10ms);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, result);
    // Key will not be sent to the window, yet, because the window is still processing events
    // and the key remains pending, waiting for the touch events to be processed
    std::optional<uint32_t> keySequenceNum = mFocusedWindow->receiveEvent();
    ASSERT_FALSE(keySequenceNum);

    // Switch the focus to the "unfocused" window that we tapped. Expect the key to go there
    mFocusedWindow->setFocusable(false);
    mUnfocusedWindow->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mFocusedWindow, mUnfocusedWindow}}});
    setFocusedWindow(mUnfocusedWindow);

    // Focus events should precede the key events
    mUnfocusedWindow->consumeFocusEvent(true);
    mFocusedWindow->consumeFocusEvent(false);

    // Finish the tap events, which should unblock dispatcher
    mUnfocusedWindow->finishEvent(*downSequenceNum);
    mUnfocusedWindow->finishEvent(*upSequenceNum);

    // Now that all queues are cleared and no backlog in the connections, the key event
    // can finally go to the newly focused "mUnfocusedWindow".
    mUnfocusedWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    mFocusedWindow->assertNoEvents();
    mUnfocusedWindow->assertNoEvents();
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// When the touch stream is split across 2 windows, and one of them does not respond,
// then ANR should be raised and the touch should be canceled for the unresponsive window.
// The other window should not be affected by that.
TEST_F(InputDispatcherMultiWindowAnr, SplitTouch_SingleWindowAnr) {
    // Touch Window 1
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {FOCUSED_WINDOW_LOCATION}));
    mUnfocusedWindow->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_OUTSIDE,
                                   ADISPLAY_ID_DEFAULT, /*flags=*/0);

    // Touch Window 2
    mDispatcher->notifyMotion(
            generateMotionArgs(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {FOCUSED_WINDOW_LOCATION, UNFOCUSED_WINDOW_LOCATION}));

    const std::chrono::duration timeout =
            mFocusedWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mFocusedWindow);

    mUnfocusedWindow->consumeMotionDown();
    mFocusedWindow->consumeMotionDown();
    // Focused window may or may not receive ACTION_MOVE
    // But it should definitely receive ACTION_CANCEL due to the ANR
    InputEvent* event;
    std::optional<int32_t> moveOrCancelSequenceNum = mFocusedWindow->receiveEvent(&event);
    ASSERT_TRUE(moveOrCancelSequenceNum);
    mFocusedWindow->finishEvent(*moveOrCancelSequenceNum);
    ASSERT_NE(nullptr, event);
    ASSERT_EQ(event->getType(), InputEventType::MOTION);
    MotionEvent& motionEvent = static_cast<MotionEvent&>(*event);
    if (motionEvent.getAction() == AMOTION_EVENT_ACTION_MOVE) {
        mFocusedWindow->consumeMotionCancel();
    } else {
        ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionEvent.getAction());
    }
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mFocusedWindow->getToken(),
                                                       mFocusedWindow->getPid());

    mUnfocusedWindow->assertNoEvents();
    mFocusedWindow->assertNoEvents();
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

/**
 * If we have no focused window, and a key comes in, we start the ANR timer.
 * The focused application should add a focused window before the timer runs out to prevent ANR.
 *
 * If the user touches another application during this time, the key should be dropped.
 * Next, if a new focused window comes in, without toggling the focused application,
 * then no ANR should occur.
 *
 * Normally, we would expect the new focused window to be accompanied by 'setFocusedApplication',
 * but in some cases the policy may not update the focused application.
 */
TEST_F(InputDispatcherMultiWindowAnr, FocusedWindowWithoutSetFocusedApplication_NoAnr) {
    std::shared_ptr<FakeApplicationHandle> focusedApplication =
            std::make_shared<FakeApplicationHandle>();
    focusedApplication->setDispatchingTimeout(60ms);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, focusedApplication);
    // The application that owns 'mFocusedWindow' and 'mUnfocusedWindow' is not focused.
    mFocusedWindow->setFocusable(false);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mFocusedWindow, mUnfocusedWindow}}});
    mFocusedWindow->consumeFocusEvent(false);

    // Send a key. The ANR timer should start because there is no focused window.
    // 'focusedApplication' will get blamed if this timer completes.
    // Key will not be sent anywhere because we have no focused window. It will remain pending.
    InputEventInjectionResult result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::NONE, /*injectionTimeout=*/10ms,
                      /*allowKeyRepeat=*/false);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, result);

    // Wait until dispatcher starts the "no focused window" timer. If we don't wait here,
    // then the injected touches won't cause the focused event to get dropped.
    // The dispatcher only checks for whether the queue should be pruned upon queueing.
    // If we inject the touch right away and the ANR timer hasn't started, the touch event would
    // simply be added to the queue without 'shouldPruneInboundQueueLocked' returning 'true'.
    // For this test, it means that the key would get delivered to the window once it becomes
    // focused.
    std::this_thread::sleep_for(10ms);

    // Touch unfocused window. This should force the pending key to get dropped.
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {UNFOCUSED_WINDOW_LOCATION}));

    // We do not consume the motion right away, because that would require dispatcher to first
    // process (== drop) the key event, and by that time, ANR will be raised.
    // Set the focused window first.
    mFocusedWindow->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mFocusedWindow, mUnfocusedWindow}}});
    setFocusedWindow(mFocusedWindow);
    mFocusedWindow->consumeFocusEvent(true);
    // We do not call "setFocusedApplication" here, even though the newly focused window belongs
    // to another application. This could be a bug / behaviour in the policy.

    mUnfocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    // Should not ANR because we actually have a focused window. It was just added too slowly.
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertNotifyAnrWasNotCalled());
}

// These tests ensure we cannot send touch events to a window that's positioned behind a window
// that has feature NO_INPUT_CHANNEL.
// Layout:
//   Top (closest to user)
//       mNoInputWindow (above all windows)
//       mBottomWindow
//   Bottom (furthest from user)
class InputDispatcherMultiWindowOcclusionTests : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        mApplication = std::make_shared<FakeApplicationHandle>();
        mNoInputWindow =
                sp<FakeWindowHandle>::make(mApplication, mDispatcher,
                                           "Window without input channel", ADISPLAY_ID_DEFAULT,
                                           /*token=*/std::make_optional<sp<IBinder>>(nullptr));
        mNoInputWindow->setNoInputChannel(true);
        mNoInputWindow->setFrame(Rect(0, 0, 100, 100));
        // It's perfectly valid for this window to not have an associated input channel

        mBottomWindow = sp<FakeWindowHandle>::make(mApplication, mDispatcher, "Bottom window",
                                                   ADISPLAY_ID_DEFAULT);
        mBottomWindow->setFrame(Rect(0, 0, 100, 100));

        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mNoInputWindow, mBottomWindow}}});
    }

protected:
    std::shared_ptr<FakeApplicationHandle> mApplication;
    sp<FakeWindowHandle> mNoInputWindow;
    sp<FakeWindowHandle> mBottomWindow;
};

TEST_F(InputDispatcherMultiWindowOcclusionTests, NoInputChannelFeature_DropsTouches) {
    PointF touchedPoint = {10, 10};

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {touchedPoint}));

    mNoInputWindow->assertNoEvents();
    // Even though the window 'mNoInputWindow' positioned above 'mBottomWindow' does not have
    // an input channel, it is not marked as FLAG_NOT_TOUCHABLE,
    // and therefore should prevent mBottomWindow from receiving touches
    mBottomWindow->assertNoEvents();
}

/**
 * If a window has feature NO_INPUT_CHANNEL, and somehow (by mistake) still has an input channel,
 * ensure that this window does not receive any touches, and blocks touches to windows underneath.
 */
TEST_F(InputDispatcherMultiWindowOcclusionTests,
       NoInputChannelFeature_DropsTouchesWithValidChannel) {
    mNoInputWindow = sp<FakeWindowHandle>::make(mApplication, mDispatcher,
                                                "Window with input channel and NO_INPUT_CHANNEL",
                                                ADISPLAY_ID_DEFAULT);

    mNoInputWindow->setNoInputChannel(true);
    mNoInputWindow->setFrame(Rect(0, 0, 100, 100));
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mNoInputWindow, mBottomWindow}}});

    PointF touchedPoint = {10, 10};

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                 {touchedPoint}));

    mNoInputWindow->assertNoEvents();
    mBottomWindow->assertNoEvents();
}

class InputDispatcherMirrorWindowFocusTests : public InputDispatcherTest {
protected:
    std::shared_ptr<FakeApplicationHandle> mApp;
    sp<FakeWindowHandle> mWindow;
    sp<FakeWindowHandle> mMirror;

    virtual void SetUp() override {
        InputDispatcherTest::SetUp();
        mApp = std::make_shared<FakeApplicationHandle>();
        mWindow = sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mMirror = sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindowMirror",
                                             ADISPLAY_ID_DEFAULT, mWindow->getToken());
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApp);
        mWindow->setFocusable(true);
        mMirror->setFocusable(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mMirror}}});
    }
};

TEST_F(InputDispatcherMirrorWindowFocusTests, CanGetFocus) {
    // Request focus on a mirrored window
    setFocusedWindow(mMirror);

    // window gets focused
    mWindow->consumeFocusEvent(true);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
}

// A focused & mirrored window remains focused only if the window and its mirror are both
// focusable.
TEST_F(InputDispatcherMirrorWindowFocusTests, FocusedIfAllWindowsFocusable) {
    setFocusedWindow(mMirror);

    // window gets focused
    mWindow->consumeFocusEvent(true);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyUp(ADISPLAY_ID_NONE);

    mMirror->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mMirror}}});

    // window loses focus since one of the windows associated with the token in not focusable
    mWindow->consumeFocusEvent(false);

    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";
    mWindow->assertNoEvents();
}

// A focused & mirrored window remains focused until the window and its mirror both become
// invisible.
TEST_F(InputDispatcherMirrorWindowFocusTests, FocusedIfAnyWindowVisible) {
    setFocusedWindow(mMirror);

    // window gets focused
    mWindow->consumeFocusEvent(true);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyUp(ADISPLAY_ID_NONE);

    mMirror->setVisible(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mMirror}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyUp(ADISPLAY_ID_NONE);

    mWindow->setVisible(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mMirror}}});

    // window loses focus only after all windows associated with the token become invisible.
    mWindow->consumeFocusEvent(false);

    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";
    mWindow->assertNoEvents();
}

// A focused & mirrored window remains focused until both windows are removed.
TEST_F(InputDispatcherMirrorWindowFocusTests, FocusedWhileWindowsAlive) {
    setFocusedWindow(mMirror);

    // window gets focused
    mWindow->consumeFocusEvent(true);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyUp(ADISPLAY_ID_NONE);

    // single window is removed but the window token remains focused
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mMirror}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyUp(ADISPLAY_ID_NONE);

    // Both windows are removed
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {}}});
    mWindow->consumeFocusEvent(false);

    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";
    mWindow->assertNoEvents();
}

// Focus request can be pending until one window becomes visible.
TEST_F(InputDispatcherMirrorWindowFocusTests, DeferFocusWhenInvisible) {
    // Request focus on an invisible mirror.
    mWindow->setVisible(false);
    mMirror->setVisible(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mMirror}}});
    setFocusedWindow(mMirror);

    // Injected key goes to pending queue.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, /*repeatCount=*/0, ADISPLAY_ID_DEFAULT,
                        InputEventInjectionSync::NONE));

    mMirror->setVisible(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mMirror}}});

    // window gets focused
    mWindow->consumeFocusEvent(true);
    // window gets the pending key event
    mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
}

class InputDispatcherPointerCaptureTests : public InputDispatcherTest {
protected:
    std::shared_ptr<FakeApplicationHandle> mApp;
    sp<FakeWindowHandle> mWindow;
    sp<FakeWindowHandle> mSecondWindow;

    void SetUp() override {
        InputDispatcherTest::SetUp();
        mApp = std::make_shared<FakeApplicationHandle>();
        mWindow = sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mWindow->setFocusable(true);
        mSecondWindow =
                sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindow2", ADISPLAY_ID_DEFAULT);
        mSecondWindow->setFocusable(true);

        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApp);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mSecondWindow}}});

        setFocusedWindow(mWindow);
        mWindow->consumeFocusEvent(true);
    }

    void notifyPointerCaptureChanged(const PointerCaptureRequest& request) {
        mDispatcher->notifyPointerCaptureChanged(generatePointerCaptureChangedArgs(request));
    }

    PointerCaptureRequest requestAndVerifyPointerCapture(const sp<FakeWindowHandle>& window,
                                                         bool enabled) {
        mDispatcher->requestPointerCapture(window->getToken(), enabled);
        auto request = mFakePolicy->assertSetPointerCaptureCalled(enabled);
        notifyPointerCaptureChanged(request);
        window->consumeCaptureEvent(enabled);
        return request;
    }
};

TEST_F(InputDispatcherPointerCaptureTests, EnablePointerCaptureWhenFocused) {
    // Ensure that capture cannot be obtained for unfocused windows.
    mDispatcher->requestPointerCapture(mSecondWindow->getToken(), true);
    mFakePolicy->assertSetPointerCaptureNotCalled();
    mSecondWindow->assertNoEvents();

    // Ensure that capture can be enabled from the focus window.
    requestAndVerifyPointerCapture(mWindow, true);

    // Ensure that capture cannot be disabled from a window that does not have capture.
    mDispatcher->requestPointerCapture(mSecondWindow->getToken(), false);
    mFakePolicy->assertSetPointerCaptureNotCalled();

    // Ensure that capture can be disabled from the window with capture.
    requestAndVerifyPointerCapture(mWindow, false);
}

TEST_F(InputDispatcherPointerCaptureTests, DisablesPointerCaptureAfterWindowLosesFocus) {
    auto request = requestAndVerifyPointerCapture(mWindow, true);

    setFocusedWindow(mSecondWindow);

    // Ensure that the capture disabled event was sent first.
    mWindow->consumeCaptureEvent(false);
    mWindow->consumeFocusEvent(false);
    mSecondWindow->consumeFocusEvent(true);
    mFakePolicy->assertSetPointerCaptureCalled(false);

    // Ensure that additional state changes from InputReader are not sent to the window.
    notifyPointerCaptureChanged({});
    notifyPointerCaptureChanged(request);
    notifyPointerCaptureChanged({});
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
    mFakePolicy->assertSetPointerCaptureNotCalled();
}

TEST_F(InputDispatcherPointerCaptureTests, UnexpectedStateChangeDisablesPointerCapture) {
    auto request = requestAndVerifyPointerCapture(mWindow, true);

    // InputReader unexpectedly disables and enables pointer capture.
    notifyPointerCaptureChanged({});
    notifyPointerCaptureChanged(request);

    // Ensure that Pointer Capture is disabled.
    mFakePolicy->assertSetPointerCaptureCalled(false);
    mWindow->consumeCaptureEvent(false);
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherPointerCaptureTests, OutOfOrderRequests) {
    requestAndVerifyPointerCapture(mWindow, true);

    // The first window loses focus.
    setFocusedWindow(mSecondWindow);
    mFakePolicy->assertSetPointerCaptureCalled(false);
    mWindow->consumeCaptureEvent(false);

    // Request Pointer Capture from the second window before the notification from InputReader
    // arrives.
    mDispatcher->requestPointerCapture(mSecondWindow->getToken(), true);
    auto request = mFakePolicy->assertSetPointerCaptureCalled(true);

    // InputReader notifies Pointer Capture was disabled (because of the focus change).
    notifyPointerCaptureChanged({});

    // InputReader notifies Pointer Capture was enabled (because of mSecondWindow's request).
    notifyPointerCaptureChanged(request);

    mSecondWindow->consumeFocusEvent(true);
    mSecondWindow->consumeCaptureEvent(true);
}

TEST_F(InputDispatcherPointerCaptureTests, EnableRequestFollowsSequenceNumbers) {
    // App repeatedly enables and disables capture.
    mDispatcher->requestPointerCapture(mWindow->getToken(), true);
    auto firstRequest = mFakePolicy->assertSetPointerCaptureCalled(true);
    mDispatcher->requestPointerCapture(mWindow->getToken(), false);
    mFakePolicy->assertSetPointerCaptureCalled(false);
    mDispatcher->requestPointerCapture(mWindow->getToken(), true);
    auto secondRequest = mFakePolicy->assertSetPointerCaptureCalled(true);

    // InputReader notifies that PointerCapture has been enabled for the first request. Since the
    // first request is now stale, this should do nothing.
    notifyPointerCaptureChanged(firstRequest);
    mWindow->assertNoEvents();

    // InputReader notifies that the second request was enabled.
    notifyPointerCaptureChanged(secondRequest);
    mWindow->consumeCaptureEvent(true);
}

TEST_F(InputDispatcherPointerCaptureTests, RapidToggleRequests) {
    requestAndVerifyPointerCapture(mWindow, true);

    // App toggles pointer capture off and on.
    mDispatcher->requestPointerCapture(mWindow->getToken(), false);
    mFakePolicy->assertSetPointerCaptureCalled(false);

    mDispatcher->requestPointerCapture(mWindow->getToken(), true);
    auto enableRequest = mFakePolicy->assertSetPointerCaptureCalled(true);

    // InputReader notifies that the latest "enable" request was processed, while skipping over the
    // preceding "disable" request.
    notifyPointerCaptureChanged(enableRequest);

    // Since pointer capture was never disabled during the rapid toggle, the window does not receive
    // any notifications.
    mWindow->assertNoEvents();
}

class InputDispatcherUntrustedTouchesTest : public InputDispatcherTest {
protected:
    constexpr static const float MAXIMUM_OBSCURING_OPACITY = 0.8;

    constexpr static const float OPACITY_ABOVE_THRESHOLD = 0.9;
    static_assert(OPACITY_ABOVE_THRESHOLD > MAXIMUM_OBSCURING_OPACITY);

    constexpr static const float OPACITY_BELOW_THRESHOLD = 0.7;
    static_assert(OPACITY_BELOW_THRESHOLD < MAXIMUM_OBSCURING_OPACITY);

    // When combined twice, ie 1 - (1 - 0.5)*(1 - 0.5) = 0.75 < 8, is still below the threshold
    constexpr static const float OPACITY_FAR_BELOW_THRESHOLD = 0.5;
    static_assert(OPACITY_FAR_BELOW_THRESHOLD < MAXIMUM_OBSCURING_OPACITY);
    static_assert(1 - (1 - OPACITY_FAR_BELOW_THRESHOLD) * (1 - OPACITY_FAR_BELOW_THRESHOLD) <
                  MAXIMUM_OBSCURING_OPACITY);

    static constexpr gui::Uid TOUCHED_APP_UID{10001};
    static constexpr gui::Uid APP_B_UID{10002};
    static constexpr gui::Uid APP_C_UID{10003};

    sp<FakeWindowHandle> mTouchWindow;

    virtual void SetUp() override {
        InputDispatcherTest::SetUp();
        mTouchWindow = getWindow(TOUCHED_APP_UID, "Touched");
        mDispatcher->setMaximumObscuringOpacityForTouch(MAXIMUM_OBSCURING_OPACITY);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();
        mTouchWindow.clear();
    }

    sp<FakeWindowHandle> getOccludingWindow(gui::Uid uid, std::string name, TouchOcclusionMode mode,
                                            float alpha = 1.0f) {
        sp<FakeWindowHandle> window = getWindow(uid, name);
        window->setTouchable(false);
        window->setTouchOcclusionMode(mode);
        window->setAlpha(alpha);
        return window;
    }

    sp<FakeWindowHandle> getWindow(gui::Uid uid, std::string name) {
        std::shared_ptr<FakeApplicationHandle> app = std::make_shared<FakeApplicationHandle>();
        sp<FakeWindowHandle> window =
                sp<FakeWindowHandle>::make(app, mDispatcher, name, ADISPLAY_ID_DEFAULT);
        // Generate an arbitrary PID based on the UID
        window->setOwnerInfo(gui::Pid{static_cast<pid_t>(1777 + (uid.val() % 10000))}, uid);
        return window;
    }

    void touch(const std::vector<PointF>& points = {PointF{100, 200}}) {
        mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                     AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                                     points));
    }
};

TEST_F(InputDispatcherUntrustedTouchesTest, WindowWithBlockUntrustedOcclusionMode_BlocksTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithBlockUntrustedOcclusionModeWithOpacityBelowThreshold_BlocksTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED, 0.7f);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithBlockUntrustedOcclusionMode_DoesNotReceiveTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    w->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowWithAllowOcclusionMode_AllowsTouch) {
    const sp<FakeWindowHandle>& w = getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::ALLOW);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, TouchOutsideOccludingWindow_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED);
    w->setFrame(Rect(0, 0, 50, 50));
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch({PointF{100, 100}});

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowFromSameUid_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(TOUCHED_APP_UID, "A", TouchOcclusionMode::BLOCK_UNTRUSTED);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowWithZeroOpacity_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED, 0.0f);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowWithZeroOpacity_DoesNotReceiveTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED, 0.0f);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    w->assertNoEvents();
}

/**
 * This is important to make sure apps can't indirectly learn the position of touches (outside vs
 * inside) while letting them pass-through. Note that even though touch passes through the occluding
 * window, the occluding window will still receive ACTION_OUTSIDE event.
 */
TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithZeroOpacityAndWatchOutside_ReceivesOutsideEvent) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED, 0.0f);
    w->setWatchOutsideTouch(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    w->consumeMotionOutside();
}

TEST_F(InputDispatcherUntrustedTouchesTest, OutsideEvent_HasZeroCoordinates) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED, 0.0f);
    w->setWatchOutsideTouch(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    w->consumeMotionOutsideWithZeroedCoords();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowWithOpacityBelowThreshold_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowWithOpacityAtThreshold_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               MAXIMUM_OBSCURING_OPACITY);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowWithOpacityAboveThreshold_BlocksTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_ABOVE_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowsWithCombinedOpacityAboveThreshold_BlocksTouch) {
    // Resulting opacity = 1 - (1 - 0.7)*(1 - 0.7) = .91
    const sp<FakeWindowHandle>& w1 =
            getOccludingWindow(APP_B_UID, "B1", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    const sp<FakeWindowHandle>& w2 =
            getOccludingWindow(APP_B_UID, "B2", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w1, w2, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowsWithCombinedOpacityBelowThreshold_AllowsTouch) {
    // Resulting opacity = 1 - (1 - 0.5)*(1 - 0.5) = .75
    const sp<FakeWindowHandle>& w1 =
            getOccludingWindow(APP_B_UID, "B1", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_FAR_BELOW_THRESHOLD);
    const sp<FakeWindowHandle>& w2 =
            getOccludingWindow(APP_B_UID, "B2", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_FAR_BELOW_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w1, w2, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowsFromDifferentAppsEachBelowThreshold_AllowsTouch) {
    const sp<FakeWindowHandle>& wB =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    const sp<FakeWindowHandle>& wC =
            getOccludingWindow(APP_C_UID, "C", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {wB, wC, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, WindowsFromDifferentAppsOneAboveThreshold_BlocksTouch) {
    const sp<FakeWindowHandle>& wB =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    const sp<FakeWindowHandle>& wC =
            getOccludingWindow(APP_C_UID, "C", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_ABOVE_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {wB, wC, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithOpacityAboveThresholdAndSelfWindow_BlocksTouch) {
    const sp<FakeWindowHandle>& wA =
            getOccludingWindow(TOUCHED_APP_UID, "T", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    const sp<FakeWindowHandle>& wB =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_ABOVE_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {wA, wB, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithOpacityBelowThresholdAndSelfWindow_AllowsTouch) {
    const sp<FakeWindowHandle>& wA =
            getOccludingWindow(TOUCHED_APP_UID, "T", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_ABOVE_THRESHOLD);
    const sp<FakeWindowHandle>& wB =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {wA, wB, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, SelfWindowWithOpacityAboveThreshold_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(TOUCHED_APP_UID, "T", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_ABOVE_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest, SelfWindowWithBlockUntrustedMode_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(TOUCHED_APP_UID, "T", TouchOcclusionMode::BLOCK_UNTRUSTED);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       OpacityThresholdIs0AndWindowAboveThreshold_BlocksTouch) {
    mDispatcher->setMaximumObscuringOpacityForTouch(0.0f);
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY, 0.1f);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

TEST_F(InputDispatcherUntrustedTouchesTest, OpacityThresholdIs0AndWindowAtThreshold_AllowsTouch) {
    mDispatcher->setMaximumObscuringOpacityForTouch(0.0f);
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY, 0.0f);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       OpacityThresholdIs1AndWindowBelowThreshold_AllowsTouch) {
    mDispatcher->setMaximumObscuringOpacityForTouch(1.0f);
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_ABOVE_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithBlockUntrustedModeAndWindowWithOpacityBelowFromSameApp_BlocksTouch) {
    const sp<FakeWindowHandle>& w1 =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED,
                               OPACITY_BELOW_THRESHOLD);
    const sp<FakeWindowHandle>& w2 =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w1, w2, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

/**
 * Window B of BLOCK_UNTRUSTED occlusion mode is enough to block the touch, we're testing that the
 * addition of another window (C) of USE_OPACITY occlusion mode and opacity below the threshold
 * (which alone would result in allowing touches) does not affect the blocking behavior.
 */
TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithBlockUntrustedModeAndWindowWithOpacityBelowFromDifferentApps_BlocksTouch) {
    const sp<FakeWindowHandle>& wB =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED,
                               OPACITY_BELOW_THRESHOLD);
    const sp<FakeWindowHandle>& wC =
            getOccludingWindow(APP_C_UID, "C", TouchOcclusionMode::USE_OPACITY,
                               OPACITY_BELOW_THRESHOLD);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {wB, wC, mTouchWindow}}});

    touch();

    mTouchWindow->assertNoEvents();
}

/**
 * This test is testing that a window from a different UID but with same application token doesn't
 * block the touch. Apps can share the application token for close UI collaboration for example.
 */
TEST_F(InputDispatcherUntrustedTouchesTest,
       WindowWithSameApplicationTokenFromDifferentApp_AllowsTouch) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED);
    w->setApplicationToken(mTouchWindow->getApplicationToken());
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    mTouchWindow->consumeAnyMotionDown();
}

class InputDispatcherDragTests : public InputDispatcherTest {
protected:
    std::shared_ptr<FakeApplicationHandle> mApp;
    sp<FakeWindowHandle> mWindow;
    sp<FakeWindowHandle> mSecondWindow;
    sp<FakeWindowHandle> mDragWindow;
    sp<FakeWindowHandle> mSpyWindow;
    // Mouse would force no-split, set the id as non-zero to verify if drag state could track it.
    static constexpr int32_t MOUSE_POINTER_ID = 1;

    void SetUp() override {
        InputDispatcherTest::SetUp();
        mApp = std::make_shared<FakeApplicationHandle>();
        mWindow = sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mWindow->setFrame(Rect(0, 0, 100, 100));

        mSecondWindow =
                sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindow2", ADISPLAY_ID_DEFAULT);
        mSecondWindow->setFrame(Rect(100, 0, 200, 100));

        mSpyWindow =
                sp<FakeWindowHandle>::make(mApp, mDispatcher, "SpyWindow", ADISPLAY_ID_DEFAULT);
        mSpyWindow->setSpy(true);
        mSpyWindow->setTrustedOverlay(true);
        mSpyWindow->setFrame(Rect(0, 0, 200, 100));

        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApp);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mSpyWindow, mWindow, mSecondWindow}}});
    }

    void injectDown(int fromSource = AINPUT_SOURCE_TOUCHSCREEN) {
        switch (fromSource) {
            case AINPUT_SOURCE_TOUCHSCREEN:
                ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                          injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN,
                                           ADISPLAY_ID_DEFAULT, {50, 50}))
                        << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
                break;
            case AINPUT_SOURCE_STYLUS:
                ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                          injectMotionEvent(
                                  mDispatcher,
                                  MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                     AINPUT_SOURCE_STYLUS)
                                          .buttonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY)
                                          .pointer(PointerBuilder(0, ToolType::STYLUS)
                                                           .x(50)
                                                           .y(50))
                                          .build()));
                break;
            case AINPUT_SOURCE_MOUSE:
                ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                          injectMotionEvent(
                                  mDispatcher,
                                  MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                          .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                          .pointer(PointerBuilder(MOUSE_POINTER_ID,
                                                                  ToolType::MOUSE)
                                                           .x(50)
                                                           .y(50))
                                          .build()));
                break;
            default:
                FAIL() << "Source " << fromSource << " doesn't support drag and drop";
        }

        // Window should receive motion event.
        mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);
        // Spy window should also receive motion event
        mSpyWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    }

    // Start performing drag, we will create a drag window and transfer touch to it.
    // @param sendDown : if true, send a motion down on first window before perform drag and drop.
    // Returns true on success.
    bool startDrag(bool sendDown = true, int fromSource = AINPUT_SOURCE_TOUCHSCREEN) {
        if (sendDown) {
            injectDown(fromSource);
        }

        // The drag window covers the entire display
        mDragWindow =
                sp<FakeWindowHandle>::make(mApp, mDispatcher, "DragWindow", ADISPLAY_ID_DEFAULT);
        mDragWindow->setTouchableRegion(Region{{0, 0, 0, 0}});
        mDispatcher->setInputWindows(
                {{ADISPLAY_ID_DEFAULT, {mDragWindow, mSpyWindow, mWindow, mSecondWindow}}});

        // Transfer touch focus to the drag window
        bool transferred =
                mDispatcher->transferTouchFocus(mWindow->getToken(), mDragWindow->getToken(),
                                                /*isDragDrop=*/true);
        if (transferred) {
            mWindow->consumeMotionCancel();
            mDragWindow->consumeMotionDown();
        }
        return transferred;
    }
};

TEST_F(InputDispatcherDragTests, DragEnterAndDragExit) {
    startDrag();

    // Move on window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->assertNoEvents();

    // Move to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(true, 150, 50);
    mSecondWindow->consumeDragEvent(false, 50, 50);

    // Move back to original window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->consumeDragEvent(true, -50, 50);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, DragEnterAndPointerDownPilfersPointers) {
    startDrag();

    // No cancel event after drag start
    mSpyWindow->assertNoEvents();

    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(50).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(60).y(60))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Receives cancel for first pointer after next pointer down
    mSpyWindow->consumeMotionCancel();
    mSpyWindow->consumeMotionDown();

    mSpyWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, DragAndDrop) {
    startDrag();

    // Move on window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->assertNoEvents();

    // Move to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(true, 150, 50);
    mSecondWindow->consumeDragEvent(false, 50, 50);

    // drop to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                             {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mFakePolicy->assertDropTargetEquals(*mDispatcher, mSecondWindow->getToken());
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, StylusDragAndDrop) {
    startDrag(true, AINPUT_SOURCE_STYLUS);

    // Move on window and keep button pressed.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_STYLUS)
                                        .buttonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY)
                                        .pointer(PointerBuilder(0, ToolType::STYLUS).x(50).y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->assertNoEvents();

    // Move to another window and release button, expect to drop item.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_STYLUS)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(0, ToolType::STYLUS).x(150).y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
    mFakePolicy->assertDropTargetEquals(*mDispatcher, mSecondWindow->getToken());

    // nothing to the window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_STYLUS)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(0, ToolType::STYLUS).x(150).y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, DragAndDropOnInvalidWindow) {
    startDrag();

    // Set second window invisible.
    mSecondWindow->setVisible(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mDragWindow, mWindow, mSecondWindow}}});

    // Move on window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->assertNoEvents();

    // Move to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(true, 150, 50);
    mSecondWindow->assertNoEvents();

    // drop to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                             {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mFakePolicy->assertDropTargetEquals(*mDispatcher, nullptr);
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, NoDragAndDropWhenMultiFingers) {
    // Ensure window could track pointerIds if it didn't support split touch.
    mWindow->setPreventSplitting(true);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(50).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(75).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeMotionPointerDown(/*pointerIndex=*/1);

    // Should not perform drag and drop when window has multi fingers.
    ASSERT_FALSE(startDrag(false));
}

TEST_F(InputDispatcherDragTests, DragAndDropWhenSplitTouch) {
    // First down on second window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    mSecondWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // Second down on first window.
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(150).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // Perform drag and drop from first window.
    ASSERT_TRUE(startDrag(false));

    // Move on window.
    const MotionEvent secondFingerMoveEvent =
            MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(150).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerMoveEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT));
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->consumeMotionMove();

    // Release the drag pointer should perform drop.
    const MotionEvent secondFingerUpEvent =
            MotionEventBuilder(POINTER_1_UP, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(150).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerUpEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT));
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mFakePolicy->assertDropTargetEquals(*mDispatcher, mWindow->getToken());
    mWindow->assertNoEvents();
    mSecondWindow->consumeMotionMove();
}

TEST_F(InputDispatcherDragTests, DragAndDropWhenMultiDisplays) {
    startDrag();

    // Update window of second display.
    sp<FakeWindowHandle> windowInSecondary =
            sp<FakeWindowHandle>::make(mApp, mDispatcher, "D_2", SECOND_DISPLAY_ID);
    mDispatcher->setInputWindows({{SECOND_DISPLAY_ID, {windowInSecondary}}});

    // Let second display has a touch state.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                   AINPUT_SOURCE_TOUCHSCREEN)
                                        .displayId(SECOND_DISPLAY_ID)
                                        .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(100))
                                        .build()));
    windowInSecondary->consumeEvent(InputEventType::MOTION, AMOTION_EVENT_ACTION_DOWN,
                                    SECOND_DISPLAY_ID, /*expectedFlag=*/0);
    // Update window again.
    mDispatcher->setInputWindows({{SECOND_DISPLAY_ID, {windowInSecondary}}});

    // Move on window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->assertNoEvents();

    // Move to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT, {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(true, 150, 50);
    mSecondWindow->consumeDragEvent(false, 50, 50);

    // drop to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                             {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mFakePolicy->assertDropTargetEquals(*mDispatcher, mSecondWindow->getToken());
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, MouseDragAndDrop) {
    startDrag(true, AINPUT_SOURCE_MOUSE);
    // Move on window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(MOUSE_POINTER_ID,
                                                                ToolType::MOUSE)
                                                         .x(50)
                                                         .y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(false, 50, 50);
    mSecondWindow->assertNoEvents();

    // Move to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(MOUSE_POINTER_ID,
                                                                ToolType::MOUSE)
                                                         .x(150)
                                                         .y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->consumeDragEvent(true, 150, 50);
    mSecondWindow->consumeDragEvent(false, 50, 50);

    // drop to another window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(MOUSE_POINTER_ID,
                                                                ToolType::MOUSE)
                                                         .x(150)
                                                         .y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mFakePolicy->assertDropTargetEquals(*mDispatcher, mSecondWindow->getToken());
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

/**
 * Start drag and drop with a pointer whose id is not 0, cancel the current touch, and ensure drag
 * and drop is also canceled. Then inject a simple gesture, and ensure dispatcher does not crash.
 */
TEST_F(InputDispatcherDragTests, DragAndDropFinishedWhenCancelCurrentTouch) {
    // Down on second window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {150, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    ASSERT_NO_FATAL_FAILURE(mSecondWindow->consumeMotionDown());
    ASSERT_NO_FATAL_FAILURE(mSpyWindow->consumeMotionDown());

    // Down on first window
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(150).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    ASSERT_NO_FATAL_FAILURE(mWindow->consumeMotionDown());
    ASSERT_NO_FATAL_FAILURE(mSecondWindow->consumeMotionMove());
    ASSERT_NO_FATAL_FAILURE(mSpyWindow->consumeMotionPointerDown(1));

    // Start drag on first window
    ASSERT_TRUE(startDrag(/*sendDown=*/false, AINPUT_SOURCE_TOUCHSCREEN));

    // Trigger cancel
    mDispatcher->cancelCurrentTouch();
    ASSERT_NO_FATAL_FAILURE(mSecondWindow->consumeMotionCancel());
    ASSERT_NO_FATAL_FAILURE(mDragWindow->consumeMotionCancel());
    ASSERT_NO_FATAL_FAILURE(mSpyWindow->consumeMotionCancel());

    ASSERT_TRUE(mDispatcher->waitForIdle());
    // The D&D finished with nullptr
    mFakePolicy->assertDropTargetEquals(nullptr);

    // Remove drag window
    mDispatcher->onWindowInfosChanged({{*mWindow->getInfo(), *mSecondWindow->getInfo()}, {}, 0, 0});

    // Inject a simple gesture, ensure dispatcher not crashed
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               PointF{50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    ASSERT_NO_FATAL_FAILURE(mWindow->consumeMotionDown());

    const MotionEvent moveEvent =
            MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, moveEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    ASSERT_NO_FATAL_FAILURE(mWindow->consumeMotionMove());

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    ASSERT_NO_FATAL_FAILURE(mWindow->consumeMotionUp());
}

class InputDispatcherDropInputFeatureTest : public InputDispatcherTest {};

TEST_F(InputDispatcherDropInputFeatureTest, WindowDropsInput) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Test window", ADISPLAY_ID_DEFAULT);
    window->setDropInput(true);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/true);

    // With the flag set, window should not get any input
    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    window->assertNoEvents();

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    window->assertNoEvents();

    // With the flag cleared, the window should get input
    window->setDropInput(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT));
    window->consumeKeyUp(ADISPLAY_ID_DEFAULT);

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    window->assertNoEvents();
}

TEST_F(InputDispatcherDropInputFeatureTest, ObscuredWindowDropsInput) {
    std::shared_ptr<FakeApplicationHandle> obscuringApplication =
            std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> obscuringWindow =
            sp<FakeWindowHandle>::make(obscuringApplication, mDispatcher, "obscuringWindow",
                                       ADISPLAY_ID_DEFAULT);
    obscuringWindow->setFrame(Rect(0, 0, 50, 50));
    obscuringWindow->setOwnerInfo(gui::Pid{111}, gui::Uid{111});
    obscuringWindow->setTouchable(false);
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Test window", ADISPLAY_ID_DEFAULT);
    window->setDropInputIfObscured(true);
    window->setOwnerInfo(gui::Pid{222}, gui::Uid{222});
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {obscuringWindow, window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/true);

    // With the flag set, window should not get any input
    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    window->assertNoEvents();

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    window->assertNoEvents();

    // With the flag cleared, the window should get input
    window->setDropInputIfObscured(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {obscuringWindow, window}}});

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT));
    window->consumeKeyUp(ADISPLAY_ID_DEFAULT);

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED);
    window->assertNoEvents();
}

TEST_F(InputDispatcherDropInputFeatureTest, UnobscuredWindowGetsInput) {
    std::shared_ptr<FakeApplicationHandle> obscuringApplication =
            std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> obscuringWindow =
            sp<FakeWindowHandle>::make(obscuringApplication, mDispatcher, "obscuringWindow",
                                       ADISPLAY_ID_DEFAULT);
    obscuringWindow->setFrame(Rect(0, 0, 50, 50));
    obscuringWindow->setOwnerInfo(gui::Pid{111}, gui::Uid{111});
    obscuringWindow->setTouchable(false);
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                             "Test window", ADISPLAY_ID_DEFAULT);
    window->setDropInputIfObscured(true);
    window->setOwnerInfo(gui::Pid{222}, gui::Uid{222});
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {obscuringWindow, window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/true);

    // With the flag set, window should not get any input
    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT));
    window->assertNoEvents();

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                                 ADISPLAY_ID_DEFAULT));
    window->assertNoEvents();

    // When the window is no longer obscured because it went on top, it should get input
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window, obscuringWindow}}});

    mDispatcher->notifyKey(generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT));
    window->consumeKeyUp(ADISPLAY_ID_DEFAULT);

    mDispatcher->notifyMotion(generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
                                                 AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    window->assertNoEvents();
}

class InputDispatcherTouchModeChangedTests : public InputDispatcherTest {
protected:
    std::shared_ptr<FakeApplicationHandle> mApp;
    std::shared_ptr<FakeApplicationHandle> mSecondaryApp;
    sp<FakeWindowHandle> mWindow;
    sp<FakeWindowHandle> mSecondWindow;
    sp<FakeWindowHandle> mThirdWindow;

    void SetUp() override {
        InputDispatcherTest::SetUp();

        mApp = std::make_shared<FakeApplicationHandle>();
        mSecondaryApp = std::make_shared<FakeApplicationHandle>();
        mWindow = sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mWindow->setFocusable(true);
        setFocusedWindow(mWindow);
        mSecondWindow =
                sp<FakeWindowHandle>::make(mApp, mDispatcher, "TestWindow2", ADISPLAY_ID_DEFAULT);
        mSecondWindow->setFocusable(true);
        mThirdWindow =
                sp<FakeWindowHandle>::make(mSecondaryApp, mDispatcher,
                                           "TestWindow3_SecondaryDisplay", SECOND_DISPLAY_ID);
        mThirdWindow->setFocusable(true);

        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApp);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mSecondWindow}},
                                      {SECOND_DISPLAY_ID, {mThirdWindow}}});
        mThirdWindow->setOwnerInfo(SECONDARY_WINDOW_PID, SECONDARY_WINDOW_UID);
        mWindow->consumeFocusEvent(true);

        // Set main display initial touch mode to InputDispatcher::kDefaultInTouchMode.
        if (mDispatcher->setInTouchMode(InputDispatcher::kDefaultInTouchMode, WINDOW_PID,
                                        WINDOW_UID, /*hasPermission=*/true, ADISPLAY_ID_DEFAULT)) {
            mWindow->consumeTouchModeEvent(InputDispatcher::kDefaultInTouchMode);
            mSecondWindow->consumeTouchModeEvent(InputDispatcher::kDefaultInTouchMode);
            mThirdWindow->assertNoEvents();
        }

        // Set secondary display initial touch mode to InputDispatcher::kDefaultInTouchMode.
        if (mDispatcher->setInTouchMode(InputDispatcher::kDefaultInTouchMode, SECONDARY_WINDOW_PID,
                                        SECONDARY_WINDOW_UID, /*hasPermission=*/true,
                                        SECOND_DISPLAY_ID)) {
            mWindow->assertNoEvents();
            mSecondWindow->assertNoEvents();
            mThirdWindow->consumeTouchModeEvent(InputDispatcher::kDefaultInTouchMode);
        }
    }

    void changeAndVerifyTouchModeInMainDisplayOnly(bool inTouchMode, gui::Pid pid, gui::Uid uid,
                                                   bool hasPermission) {
        ASSERT_TRUE(mDispatcher->setInTouchMode(inTouchMode, pid, uid, hasPermission,
                                                ADISPLAY_ID_DEFAULT));
        mWindow->consumeTouchModeEvent(inTouchMode);
        mSecondWindow->consumeTouchModeEvent(inTouchMode);
        mThirdWindow->assertNoEvents();
    }
};

TEST_F(InputDispatcherTouchModeChangedTests, FocusedWindowCanChangeTouchMode) {
    const WindowInfo& windowInfo = *mWindow->getInfo();
    changeAndVerifyTouchModeInMainDisplayOnly(!InputDispatcher::kDefaultInTouchMode,
                                              windowInfo.ownerPid, windowInfo.ownerUid,
                                              /* hasPermission=*/false);
}

TEST_F(InputDispatcherTouchModeChangedTests, NonFocusedWindowOwnerCannotChangeTouchMode) {
    const WindowInfo& windowInfo = *mWindow->getInfo();
    gui::Pid ownerPid = windowInfo.ownerPid;
    gui::Uid ownerUid = windowInfo.ownerUid;
    mWindow->setOwnerInfo(gui::Pid::INVALID, gui::Uid::INVALID);
    ASSERT_FALSE(mDispatcher->setInTouchMode(InputDispatcher::kDefaultInTouchMode, ownerPid,
                                             ownerUid, /*hasPermission=*/false,
                                             ADISPLAY_ID_DEFAULT));
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherTouchModeChangedTests, NonWindowOwnerMayChangeTouchModeOnPermissionGranted) {
    const WindowInfo& windowInfo = *mWindow->getInfo();
    gui::Pid ownerPid = windowInfo.ownerPid;
    gui::Uid ownerUid = windowInfo.ownerUid;
    mWindow->setOwnerInfo(gui::Pid::INVALID, gui::Uid::INVALID);
    changeAndVerifyTouchModeInMainDisplayOnly(!InputDispatcher::kDefaultInTouchMode, ownerPid,
                                              ownerUid, /*hasPermission=*/true);
}

TEST_F(InputDispatcherTouchModeChangedTests, EventIsNotGeneratedIfNotChangingTouchMode) {
    const WindowInfo& windowInfo = *mWindow->getInfo();
    ASSERT_FALSE(mDispatcher->setInTouchMode(InputDispatcher::kDefaultInTouchMode,
                                             windowInfo.ownerPid, windowInfo.ownerUid,
                                             /*hasPermission=*/true, ADISPLAY_ID_DEFAULT));
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherTouchModeChangedTests, ChangeTouchOnSecondaryDisplayOnly) {
    const WindowInfo& windowInfo = *mThirdWindow->getInfo();
    ASSERT_TRUE(mDispatcher->setInTouchMode(!InputDispatcher::kDefaultInTouchMode,
                                            windowInfo.ownerPid, windowInfo.ownerUid,
                                            /*hasPermission=*/true, SECOND_DISPLAY_ID));
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
    mThirdWindow->consumeTouchModeEvent(!InputDispatcher::kDefaultInTouchMode);
}

TEST_F(InputDispatcherTouchModeChangedTests, CanChangeTouchModeWhenOwningLastInteractedWindow) {
    // Interact with the window first.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    // Then remove focus.
    mWindow->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});

    // Assert that caller can switch touch mode by owning one of the last interacted window.
    const WindowInfo& windowInfo = *mWindow->getInfo();
    ASSERT_TRUE(mDispatcher->setInTouchMode(!InputDispatcher::kDefaultInTouchMode,
                                            windowInfo.ownerPid, windowInfo.ownerUid,
                                            /*hasPermission=*/false, ADISPLAY_ID_DEFAULT));
}

class InputDispatcherSpyWindowTest : public InputDispatcherTest {
public:
    sp<FakeWindowHandle> createSpy() {
        std::shared_ptr<FakeApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();
        std::string name = "Fake Spy ";
        name += std::to_string(mSpyCount++);
        sp<FakeWindowHandle> spy = sp<FakeWindowHandle>::make(application, mDispatcher,
                                                              name.c_str(), ADISPLAY_ID_DEFAULT);
        spy->setSpy(true);
        spy->setTrustedOverlay(true);
        return spy;
    }

    sp<FakeWindowHandle> createForeground() {
        std::shared_ptr<FakeApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();
        sp<FakeWindowHandle> window =
                sp<FakeWindowHandle>::make(application, mDispatcher, "Fake Window",
                                           ADISPLAY_ID_DEFAULT);
        window->setFocusable(true);
        return window;
    }

private:
    int mSpyCount{0};
};

using InputDispatcherSpyWindowDeathTest = InputDispatcherSpyWindowTest;
/**
 * Adding a spy window that is not a trusted overlay causes Dispatcher to abort.
 */
TEST_F(InputDispatcherSpyWindowDeathTest, UntrustedSpy_AbortsDispatcher) {
    ScopedSilentDeath _silentDeath;

    auto spy = createSpy();
    spy->setTrustedOverlay(false);
    ASSERT_DEATH(mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy}}}),
                 ".* not a trusted overlay");
}

/**
 * Input injection into a display with a spy window but no foreground windows should succeed.
 */
TEST_F(InputDispatcherSpyWindowTest, NoForegroundWindow) {
    auto spy = createSpy();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy->consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

/**
 * Verify the order in which different input windows receive events. The touched foreground window
 * (if there is one) should always receive the event first. When there are multiple spy windows, the
 * spy windows will receive the event according to their Z-order, where the top-most spy window will
 * receive events before ones belows it.
 *
 * Here, we set up a scenario with four windows in the following Z order from the top:
 *    spy1, spy2, window, spy3.
 * We then inject an event and verify that the foreground "window" receives it first, followed by
 * "spy1" and "spy2". The "spy3" does not receive the event because it is underneath the foreground
 * window.
 */
TEST_F(InputDispatcherSpyWindowTest, ReceivesInputInOrder) {
    auto window = createForeground();
    auto spy1 = createSpy();
    auto spy2 = createSpy();
    auto spy3 = createSpy();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy1, spy2, window, spy3}}});
    const std::vector<sp<FakeWindowHandle>> channels{spy1, spy2, window, spy3};
    const size_t numChannels = channels.size();

    base::unique_fd epollFd(epoll_create1(EPOLL_CLOEXEC));
    if (!epollFd.ok()) {
        FAIL() << "Failed to create epoll fd";
    }

    for (size_t i = 0; i < numChannels; i++) {
        struct epoll_event event = {.events = EPOLLIN, .data.u64 = i};
        if (epoll_ctl(epollFd.get(), EPOLL_CTL_ADD, channels[i]->getChannelFd(), &event) < 0) {
            FAIL() << "Failed to add fd to epoll";
        }
    }

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    std::vector<size_t> eventOrder;
    std::vector<struct epoll_event> events(numChannels);
    for (;;) {
        const int nFds = epoll_wait(epollFd.get(), events.data(), static_cast<int>(numChannels),
                                    (100ms).count());
        if (nFds < 0) {
            FAIL() << "Failed to call epoll_wait";
        }
        if (nFds == 0) {
            break; // epoll_wait timed out
        }
        for (int i = 0; i < nFds; i++) {
            ASSERT_EQ(static_cast<uint32_t>(EPOLLIN), events[i].events);
            eventOrder.push_back(static_cast<size_t>(events[i].data.u64));
            channels[i]->consumeMotionDown();
        }
    }

    // Verify the order in which the events were received.
    EXPECT_EQ(3u, eventOrder.size());
    EXPECT_EQ(2u, eventOrder[0]); // index 2: window
    EXPECT_EQ(0u, eventOrder[1]); // index 0: spy1
    EXPECT_EQ(1u, eventOrder[2]); // index 1: spy2
}

/**
 * A spy window using the NOT_TOUCHABLE flag does not receive events.
 */
TEST_F(InputDispatcherSpyWindowTest, NotTouchable) {
    auto window = createForeground();
    auto spy = createSpy();
    spy->setTouchable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    spy->assertNoEvents();
}

/**
 * A spy window will only receive gestures that originate within its touchable region. Gestures that
 * have their ACTION_DOWN outside of the touchable region of the spy window will not be dispatched
 * to the window.
 */
TEST_F(InputDispatcherSpyWindowTest, TouchableRegion) {
    auto window = createForeground();
    auto spy = createSpy();
    spy->setTouchableRegion(Region{{0, 0, 20, 20}});
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    // Inject an event outside the spy window's touchable region.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    spy->assertNoEvents();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionUp();
    spy->assertNoEvents();

    // Inject an event inside the spy window's touchable region.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {5, 10}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    spy->consumeMotionDown();
}

/**
 * A spy window can listen for touches outside its touchable region using the WATCH_OUTSIDE_TOUCHES
 * flag, but it will get zero-ed out coordinates if the foreground has a different owner.
 */
TEST_F(InputDispatcherSpyWindowTest, WatchOutsideTouches) {
    auto window = createForeground();
    window->setOwnerInfo(gui::Pid{12}, gui::Uid{34});
    auto spy = createSpy();
    spy->setWatchOutsideTouch(true);
    spy->setOwnerInfo(gui::Pid{56}, gui::Uid{78});
    spy->setFrame(Rect{0, 0, 20, 20});
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    // Inject an event outside the spy window's frame and touchable region.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    spy->consumeMotionOutsideWithZeroedCoords();
}

/**
 * Even when a spy window spans over multiple foreground windows, the spy should receive all
 * pointers that are down within its bounds.
 */
TEST_F(InputDispatcherSpyWindowTest, ReceivesMultiplePointers) {
    auto windowLeft = createForeground();
    windowLeft->setFrame({0, 0, 100, 200});
    auto windowRight = createForeground();
    windowRight->setFrame({100, 0, 200, 200});
    auto spy = createSpy();
    spy->setFrame({0, 0, 200, 200});
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, windowLeft, windowRight}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowLeft->consumeMotionDown();
    spy->consumeMotionDown();

    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(50).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(150).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    windowRight->consumeMotionDown();
    spy->consumeMotionPointerDown(/*pointerIndex=*/1);
}

/**
 * When the first pointer lands outside the spy window and the second pointer lands inside it, the
 * the spy should receive the second pointer with ACTION_DOWN.
 */
TEST_F(InputDispatcherSpyWindowTest, ReceivesSecondPointerAsDown) {
    auto window = createForeground();
    window->setFrame({0, 0, 200, 200});
    auto spyRight = createSpy();
    spyRight->setFrame({100, 0, 200, 200});
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spyRight, window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    spyRight->assertNoEvents();

    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(50).y(50))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(150).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionPointerDown(/*pointerIndex=*/1);
    spyRight->consumeMotionDown();
}

/**
 * The spy window should not be able to affect whether or not touches are split. Only the foreground
 * windows should be allowed to control split touch.
 */
TEST_F(InputDispatcherSpyWindowTest, SplitIfNoForegroundWindowTouched) {
    // This spy window prevents touch splitting. However, we still expect to split touches
    // because a foreground window has not disabled splitting.
    auto spy = createSpy();
    spy->setPreventSplitting(true);

    auto window = createForeground();
    window->setFrame(Rect(0, 0, 100, 100));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    // First finger down, no window touched.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    window->assertNoEvents();

    // Second finger down on window, the window should receive touch down.
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(200))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    spy->consumeMotionPointerDown(/*pointerIndex=*/1);
}

/**
 * A spy window will usually be implemented as an un-focusable window. Verify that these windows
 * do not receive key events.
 */
TEST_F(InputDispatcherSpyWindowTest, UnfocusableSpyDoesNotReceiveKeyEvents) {
    auto spy = createSpy();
    spy->setFocusable(false);

    auto window = createForeground();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeKeyDown(ADISPLAY_ID_NONE);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeKeyUp(ADISPLAY_ID_NONE);

    spy->assertNoEvents();
}

using InputDispatcherPilferPointersTest = InputDispatcherSpyWindowTest;

/**
 * A spy window can pilfer pointers. When this happens, touch gestures used by the spy window that
 * are currently sent to any other windows - including other spy windows - will also be cancelled.
 */
TEST_F(InputDispatcherPilferPointersTest, PilferPointers) {
    auto window = createForeground();
    auto spy1 = createSpy();
    auto spy2 = createSpy();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy1, spy2, window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    spy1->consumeMotionDown();
    spy2->consumeMotionDown();

    // Pilfer pointers from the second spy window.
    EXPECT_EQ(OK, mDispatcher->pilferPointers(spy2->getToken()));
    spy2->assertNoEvents();
    spy1->consumeMotionCancel();
    window->consumeMotionCancel();

    // The rest of the gesture should only be sent to the second spy window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy2->consumeMotionMove();
    spy1->assertNoEvents();
    window->assertNoEvents();
}

/**
 * A spy window can pilfer pointers for a gesture even after the foreground window has been removed
 * in the middle of the gesture.
 */
TEST_F(InputDispatcherPilferPointersTest, CanPilferAfterWindowIsRemovedMidStream) {
    auto window = createForeground();
    auto spy = createSpy();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    spy->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    window->releaseChannel();

    EXPECT_EQ(OK, mDispatcher->pilferPointers(spy->getToken()));

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy->consumeMotionUp(ADISPLAY_ID_DEFAULT);
}

/**
 * After a spy window pilfers pointers, new pointers that go down in its bounds should be sent to
 * the spy, but not to any other windows.
 */
TEST_F(InputDispatcherPilferPointersTest, ContinuesToReceiveGestureAfterPilfer) {
    auto spy = createSpy();
    auto window = createForeground();

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    // First finger down on the window and the spy.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {100, 200}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy->consumeMotionDown();
    window->consumeMotionDown();

    // Spy window pilfers the pointers.
    EXPECT_EQ(OK, mDispatcher->pilferPointers(spy->getToken()));
    window->consumeMotionCancel();

    // Second finger down on the window and spy, but the window should not receive the pointer down.
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(200))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    spy->consumeMotionPointerDown(/*pointerIndex=*/1);

    // Third finger goes down outside all windows, so injection should fail.
    const MotionEvent thirdFingerDownEvent =
            MotionEventBuilder(POINTER_2_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(100).y(200))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .pointer(PointerBuilder(/*id=*/2, ToolType::FINGER).x(-5).y(-5))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              injectMotionEvent(mDispatcher, thirdFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::FAILED";

    spy->assertNoEvents();
    window->assertNoEvents();
}

/**
 * After a spy window pilfers pointers, only the pointers used by the spy should be canceled
 */
TEST_F(InputDispatcherPilferPointersTest, PartiallyPilferRequiredPointers) {
    auto spy = createSpy();
    spy->setFrame(Rect(0, 0, 100, 100));
    auto window = createForeground();
    window->setFrame(Rect(0, 0, 200, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    // First finger down on the window only
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {150, 150}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();

    // Second finger down on the spy and window
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(150).y(150))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(10).y(10))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy->consumeMotionDown();
    window->consumeMotionPointerDown(1);

    // Third finger down on the spy and window
    const MotionEvent thirdFingerDownEvent =
            MotionEventBuilder(POINTER_2_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(150).y(150))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(10).y(10))
                    .pointer(PointerBuilder(/*id=*/2, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, thirdFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy->consumeMotionPointerDown(1);
    window->consumeMotionPointerDown(2);

    // Spy window pilfers the pointers.
    EXPECT_EQ(OK, mDispatcher->pilferPointers(spy->getToken()));
    window->consumeMotionPointerUp(/* idx */ 2, ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_CANCELED);
    window->consumeMotionPointerUp(/* idx */ 1, ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_CANCELED);

    spy->assertNoEvents();
    window->assertNoEvents();
}

/**
 * After a spy window pilfers pointers, all pilfered pointers that have already been dispatched to
 * other windows should be canceled. If this results in the cancellation of all pointers for some
 * window, then that window should receive ACTION_CANCEL.
 */
TEST_F(InputDispatcherPilferPointersTest, PilferAllRequiredPointers) {
    auto spy = createSpy();
    spy->setFrame(Rect(0, 0, 100, 100));
    auto window = createForeground();
    window->setFrame(Rect(0, 0, 200, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    // First finger down on both spy and window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {10, 10}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    spy->consumeMotionDown();

    // Second finger down on the spy and window
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(10).y(10))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(50).y(50))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    spy->consumeMotionPointerDown(1);
    window->consumeMotionPointerDown(1);

    // Spy window pilfers the pointers.
    EXPECT_EQ(OK, mDispatcher->pilferPointers(spy->getToken()));
    window->consumeMotionCancel();

    spy->assertNoEvents();
    window->assertNoEvents();
}

/**
 * After a spy window pilfers pointers, new pointers that are not touching the spy window can still
 * be sent to other windows
 */
TEST_F(InputDispatcherPilferPointersTest, CanReceivePointersAfterPilfer) {
    auto spy = createSpy();
    spy->setFrame(Rect(0, 0, 100, 100));
    auto window = createForeground();
    window->setFrame(Rect(0, 0, 200, 200));

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    // First finger down on both window and spy
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {10, 10}))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    spy->consumeMotionDown();

    // Spy window pilfers the pointers.
    EXPECT_EQ(OK, mDispatcher->pilferPointers(spy->getToken()));
    window->consumeMotionCancel();

    // Second finger down on the window only
    const MotionEvent secondFingerDownEvent =
            MotionEventBuilder(POINTER_1_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                    .displayId(ADISPLAY_ID_DEFAULT)
                    .eventTime(systemTime(SYSTEM_TIME_MONOTONIC))
                    .pointer(PointerBuilder(/*id=*/0, ToolType::FINGER).x(10).y(10))
                    .pointer(PointerBuilder(/*id=*/1, ToolType::FINGER).x(150).y(150))
                    .build();
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, secondFingerDownEvent, INJECT_EVENT_TIMEOUT,
                                InputEventInjectionSync::WAIT_FOR_RESULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown();
    window->assertNoEvents();

    // TODO(b/232530217): do not send the unnecessary MOVE event and delete the next line
    spy->consumeMotionMove();
    spy->assertNoEvents();
}

class InputDispatcherStylusInterceptorTest : public InputDispatcherTest {
public:
    std::pair<sp<FakeWindowHandle>, sp<FakeWindowHandle>> setupStylusOverlayScenario() {
        std::shared_ptr<FakeApplicationHandle> overlayApplication =
                std::make_shared<FakeApplicationHandle>();
        sp<FakeWindowHandle> overlay =
                sp<FakeWindowHandle>::make(overlayApplication, mDispatcher,
                                           "Stylus interceptor window", ADISPLAY_ID_DEFAULT);
        overlay->setFocusable(false);
        overlay->setOwnerInfo(gui::Pid{111}, gui::Uid{111});
        overlay->setTouchable(false);
        overlay->setInterceptsStylus(true);
        overlay->setTrustedOverlay(true);

        std::shared_ptr<FakeApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();
        sp<FakeWindowHandle> window =
                sp<FakeWindowHandle>::make(application, mDispatcher, "Application window",
                                           ADISPLAY_ID_DEFAULT);
        window->setFocusable(true);
        window->setOwnerInfo(gui::Pid{222}, gui::Uid{222});

        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {overlay, window}}});
        setFocusedWindow(window);
        window->consumeFocusEvent(/*hasFocus=*/true, /*inTouchMode=*/true);
        return {std::move(overlay), std::move(window)};
    }

    void sendFingerEvent(int32_t action) {
        mDispatcher->notifyMotion(
                generateMotionArgs(action, AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS,
                                   ADISPLAY_ID_DEFAULT, {PointF{20, 20}}));
    }

    void sendStylusEvent(int32_t action) {
        NotifyMotionArgs motionArgs =
                generateMotionArgs(action, AINPUT_SOURCE_TOUCHSCREEN | AINPUT_SOURCE_STYLUS,
                                   ADISPLAY_ID_DEFAULT, {PointF{30, 40}});
        motionArgs.pointerProperties[0].toolType = ToolType::STYLUS;
        mDispatcher->notifyMotion(motionArgs);
    }
};

using InputDispatcherStylusInterceptorDeathTest = InputDispatcherStylusInterceptorTest;

TEST_F(InputDispatcherStylusInterceptorDeathTest, UntrustedOverlay_AbortsDispatcher) {
    testing::GTEST_FLAG(death_test_style) = "threadsafe";
    ScopedSilentDeath _silentDeath;

    auto [overlay, window] = setupStylusOverlayScenario();
    overlay->setTrustedOverlay(false);
    // Configuring an untrusted overlay as a stylus interceptor should cause Dispatcher to abort.
    ASSERT_DEATH(mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {overlay, window}}}),
                 ".* not a trusted overlay");
}

TEST_F(InputDispatcherStylusInterceptorTest, ConsmesOnlyStylusEvents) {
    auto [overlay, window] = setupStylusOverlayScenario();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {overlay, window}}});

    sendStylusEvent(AMOTION_EVENT_ACTION_DOWN);
    overlay->consumeMotionDown();
    sendStylusEvent(AMOTION_EVENT_ACTION_UP);
    overlay->consumeMotionUp();

    sendFingerEvent(AMOTION_EVENT_ACTION_DOWN);
    window->consumeMotionDown();
    sendFingerEvent(AMOTION_EVENT_ACTION_UP);
    window->consumeMotionUp();

    overlay->assertNoEvents();
    window->assertNoEvents();
}

TEST_F(InputDispatcherStylusInterceptorTest, SpyWindowStylusInterceptor) {
    auto [overlay, window] = setupStylusOverlayScenario();
    overlay->setSpy(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {overlay, window}}});

    sendStylusEvent(AMOTION_EVENT_ACTION_DOWN);
    overlay->consumeMotionDown();
    window->consumeMotionDown();
    sendStylusEvent(AMOTION_EVENT_ACTION_UP);
    overlay->consumeMotionUp();
    window->consumeMotionUp();

    sendFingerEvent(AMOTION_EVENT_ACTION_DOWN);
    window->consumeMotionDown();
    sendFingerEvent(AMOTION_EVENT_ACTION_UP);
    window->consumeMotionUp();

    overlay->assertNoEvents();
    window->assertNoEvents();
}

/**
 * Set up a scenario to test the behavior used by the stylus handwriting detection feature.
 * The scenario is as follows:
 *   - The stylus interceptor overlay is configured as a spy window.
 *   - The stylus interceptor spy receives the start of a new stylus gesture.
 *   - It pilfers pointers and then configures itself to no longer be a spy.
 *   - The stylus interceptor continues to receive the rest of the gesture.
 */
TEST_F(InputDispatcherStylusInterceptorTest, StylusHandwritingScenario) {
    auto [overlay, window] = setupStylusOverlayScenario();
    overlay->setSpy(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {overlay, window}}});

    sendStylusEvent(AMOTION_EVENT_ACTION_DOWN);
    overlay->consumeMotionDown();
    window->consumeMotionDown();

    // The interceptor pilfers the pointers.
    EXPECT_EQ(OK, mDispatcher->pilferPointers(overlay->getToken()));
    window->consumeMotionCancel();

    // The interceptor configures itself so that it is no longer a spy.
    overlay->setSpy(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {overlay, window}}});

    // It continues to receive the rest of the stylus gesture.
    sendStylusEvent(AMOTION_EVENT_ACTION_MOVE);
    overlay->consumeMotionMove();
    sendStylusEvent(AMOTION_EVENT_ACTION_UP);
    overlay->consumeMotionUp();

    window->assertNoEvents();
}

struct User {
    gui::Pid mPid;
    gui::Uid mUid;
    uint32_t mPolicyFlags{DEFAULT_POLICY_FLAGS};
    std::unique_ptr<InputDispatcher>& mDispatcher;

    User(std::unique_ptr<InputDispatcher>& dispatcher, gui::Pid pid, gui::Uid uid)
          : mPid(pid), mUid(uid), mDispatcher(dispatcher) {}

    InputEventInjectionResult injectTargetedMotion(int32_t action) const {
        return injectMotionEvent(mDispatcher, action, AINPUT_SOURCE_TOUCHSCREEN,
                                 ADISPLAY_ID_DEFAULT, {100, 200},
                                 {AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                  AMOTION_EVENT_INVALID_CURSOR_POSITION},
                                 INJECT_EVENT_TIMEOUT, InputEventInjectionSync::WAIT_FOR_RESULT,
                                 systemTime(SYSTEM_TIME_MONOTONIC), {mUid}, mPolicyFlags);
    }

    InputEventInjectionResult injectTargetedKey(int32_t action) const {
        return inputdispatcher::injectKey(mDispatcher, action, /*repeatCount=*/0, ADISPLAY_ID_NONE,
                                          InputEventInjectionSync::WAIT_FOR_RESULT,
                                          INJECT_EVENT_TIMEOUT, /*allowKeyRepeat=*/false, {mUid},
                                          mPolicyFlags);
    }

    sp<FakeWindowHandle> createWindow() const {
        std::shared_ptr<FakeApplicationHandle> overlayApplication =
                std::make_shared<FakeApplicationHandle>();
        sp<FakeWindowHandle> window =
                sp<FakeWindowHandle>::make(overlayApplication, mDispatcher, "Owned Window",
                                           ADISPLAY_ID_DEFAULT);
        window->setOwnerInfo(mPid, mUid);
        return window;
    }
};

using InputDispatcherTargetedInjectionTest = InputDispatcherTest;

TEST_F(InputDispatcherTargetedInjectionTest, CanInjectIntoOwnedWindow) {
    auto owner = User(mDispatcher, gui::Pid{10}, gui::Uid{11});
    auto window = owner.createWindow();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    EXPECT_EQ(InputEventInjectionResult::SUCCEEDED,
              owner.injectTargetedMotion(AMOTION_EVENT_ACTION_DOWN));
    window->consumeMotionDown();

    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    EXPECT_EQ(InputEventInjectionResult::SUCCEEDED,
              owner.injectTargetedKey(AKEY_EVENT_ACTION_DOWN));
    window->consumeKeyDown(ADISPLAY_ID_NONE);
}

TEST_F(InputDispatcherTargetedInjectionTest, CannotInjectIntoUnownedWindow) {
    auto owner = User(mDispatcher, gui::Pid{10}, gui::Uid{11});
    auto window = owner.createWindow();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    auto rando = User(mDispatcher, gui::Pid{20}, gui::Uid{21});
    EXPECT_EQ(InputEventInjectionResult::TARGET_MISMATCH,
              rando.injectTargetedMotion(AMOTION_EVENT_ACTION_DOWN));

    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    EXPECT_EQ(InputEventInjectionResult::TARGET_MISMATCH,
              rando.injectTargetedKey(AKEY_EVENT_ACTION_DOWN));
    window->assertNoEvents();
}

TEST_F(InputDispatcherTargetedInjectionTest, CanInjectIntoOwnedSpyWindow) {
    auto owner = User(mDispatcher, gui::Pid{10}, gui::Uid{11});
    auto window = owner.createWindow();
    auto spy = owner.createWindow();
    spy->setSpy(true);
    spy->setTrustedOverlay(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {spy, window}}});

    EXPECT_EQ(InputEventInjectionResult::SUCCEEDED,
              owner.injectTargetedMotion(AMOTION_EVENT_ACTION_DOWN));
    spy->consumeMotionDown();
    window->consumeMotionDown();
}

TEST_F(InputDispatcherTargetedInjectionTest, CannotInjectIntoUnownedSpyWindow) {
    auto owner = User(mDispatcher, gui::Pid{10}, gui::Uid{11});
    auto window = owner.createWindow();

    auto rando = User(mDispatcher, gui::Pid{20}, gui::Uid{21});
    auto randosSpy = rando.createWindow();
    randosSpy->setSpy(true);
    randosSpy->setTrustedOverlay(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {randosSpy, window}}});

    // The event is targeted at owner's window, so injection should succeed, but the spy should
    // not receive the event.
    EXPECT_EQ(InputEventInjectionResult::SUCCEEDED,
              owner.injectTargetedMotion(AMOTION_EVENT_ACTION_DOWN));
    randosSpy->assertNoEvents();
    window->consumeMotionDown();
}

TEST_F(InputDispatcherTargetedInjectionTest, CanInjectIntoAnyWindowWhenNotTargeting) {
    auto owner = User(mDispatcher, gui::Pid{10}, gui::Uid{11});
    auto window = owner.createWindow();

    auto rando = User(mDispatcher, gui::Pid{20}, gui::Uid{21});
    auto randosSpy = rando.createWindow();
    randosSpy->setSpy(true);
    randosSpy->setTrustedOverlay(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {randosSpy, window}}});

    // A user that has injection permission can inject into any window.
    EXPECT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                ADISPLAY_ID_DEFAULT));
    randosSpy->consumeMotionDown();
    window->consumeMotionDown();

    setFocusedWindow(randosSpy);
    randosSpy->consumeFocusEvent(true);

    EXPECT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher));
    randosSpy->consumeKeyDown(ADISPLAY_ID_NONE);
    window->assertNoEvents();
}

TEST_F(InputDispatcherTargetedInjectionTest, CannotGenerateActionOutsideToOtherUids) {
    auto owner = User(mDispatcher, gui::Pid{10}, gui::Uid{11});
    auto window = owner.createWindow();

    auto rando = User(mDispatcher, gui::Pid{20}, gui::Uid{21});
    auto randosWindow = rando.createWindow();
    randosWindow->setFrame(Rect{-10, -10, -5, -5});
    randosWindow->setWatchOutsideTouch(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {randosWindow, window}}});

    // Do not allow generation of ACTION_OUTSIDE events into windows owned by different uids.
    EXPECT_EQ(InputEventInjectionResult::SUCCEEDED,
              owner.injectTargetedMotion(AMOTION_EVENT_ACTION_DOWN));
    window->consumeMotionDown();
    randosWindow->assertNoEvents();
}

} // namespace android::inputdispatcher
