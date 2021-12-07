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

#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <binder/Binder.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <linux/input.h>

#include <cinttypes>
#include <thread>
#include <unordered_set>
#include <vector>

using android::base::StringPrintf;
using android::os::InputEventInjectionResult;
using android::os::InputEventInjectionSync;
using android::os::TouchOcclusionMode;
using namespace android::flag_operators;

namespace android::inputdispatcher {

// An arbitrary time value.
static const nsecs_t ARBITRARY_TIME = 1234;

// An arbitrary device id.
static const int32_t DEVICE_ID = 1;

// An arbitrary display id.
static const int32_t DISPLAY_ID = ADISPLAY_ID_DEFAULT;

// An arbitrary injector pid / uid pair that has permission to inject events.
static const int32_t INJECTOR_PID = 999;
static const int32_t INJECTOR_UID = 1001;

// An arbitrary pid of the gesture monitor window
static constexpr int32_t MONITOR_PID = 2001;

struct PointF {
    float x;
    float y;
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

// --- FakeInputDispatcherPolicy ---

class FakeInputDispatcherPolicy : public InputDispatcherPolicyInterface {
    InputDispatcherConfiguration mConfig;

protected:
    virtual ~FakeInputDispatcherPolicy() {}

public:
    FakeInputDispatcherPolicy() {}

    void assertFilterInputEventWasCalled(const NotifyKeyArgs& args) {
        assertFilterInputEventWasCalled(AINPUT_EVENT_TYPE_KEY, args.eventTime, args.action,
                                        args.displayId);
    }

    void assertFilterInputEventWasCalled(const NotifyMotionArgs& args) {
        assertFilterInputEventWasCalled(AINPUT_EVENT_TYPE_MOTION, args.eventTime, args.action,
                                        args.displayId);
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
        std::shared_ptr<InputApplicationHandle> application;
        { // acquire lock
            std::unique_lock lock(mLock);
            android::base::ScopedLockAssertion assumeLocked(mLock);
            ASSERT_NO_FATAL_FAILURE(
                    application = getAnrTokenLockedInterruptible(timeout, mAnrApplications, lock));
        } // release lock
        ASSERT_EQ(expectedApplication, application);
    }

    void assertNotifyWindowUnresponsiveWasCalled(std::chrono::nanoseconds timeout,
                                                 const sp<IBinder>& expectedConnectionToken) {
        sp<IBinder> connectionToken = getUnresponsiveWindowToken(timeout);
        ASSERT_EQ(expectedConnectionToken, connectionToken);
    }

    void assertNotifyWindowResponsiveWasCalled(const sp<IBinder>& expectedConnectionToken) {
        sp<IBinder> connectionToken = getResponsiveWindowToken();
        ASSERT_EQ(expectedConnectionToken, connectionToken);
    }

    void assertNotifyMonitorUnresponsiveWasCalled(std::chrono::nanoseconds timeout) {
        int32_t pid = getUnresponsiveMonitorPid(timeout);
        ASSERT_EQ(MONITOR_PID, pid);
    }

    void assertNotifyMonitorResponsiveWasCalled() {
        int32_t pid = getResponsiveMonitorPid();
        ASSERT_EQ(MONITOR_PID, pid);
    }

    sp<IBinder> getUnresponsiveWindowToken(std::chrono::nanoseconds timeout) {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        return getAnrTokenLockedInterruptible(timeout, mAnrWindowTokens, lock);
    }

    sp<IBinder> getResponsiveWindowToken() {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        return getAnrTokenLockedInterruptible(0s, mResponsiveWindowTokens, lock);
    }

    int32_t getUnresponsiveMonitorPid(std::chrono::nanoseconds timeout) {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        return getAnrTokenLockedInterruptible(timeout, mAnrMonitorPids, lock);
    }

    int32_t getResponsiveMonitorPid() {
        std::unique_lock lock(mLock);
        android::base::ScopedLockAssertion assumeLocked(mLock);
        return getAnrTokenLockedInterruptible(0s, mResponsiveMonitorPids, lock);
    }

    // All three ANR-related callbacks behave the same way, so we use this generic function to wait
    // for a specific container to become non-empty. When the container is non-empty, return the
    // first entry from the container and erase it.
    template <class T>
    T getAnrTokenLockedInterruptible(std::chrono::nanoseconds timeout, std::queue<T>& storage,
                                     std::unique_lock<std::mutex>& lock) REQUIRES(mLock) {
        const std::chrono::time_point start = std::chrono::steady_clock::now();
        std::chrono::duration timeToWait = timeout + 100ms; // provide some slack

        // If there is an ANR, Dispatcher won't be idle because there are still events
        // in the waitQueue that we need to check on. So we can't wait for dispatcher to be idle
        // before checking if ANR was called.
        // Since dispatcher is not guaranteed to call notifyNoFocusedWindowAnr right away, we need
        // to provide it some time to act. 100ms seems reasonable.
        mNotifyAnr.wait_for(lock, timeToWait,
                            [&storage]() REQUIRES(mLock) { return !storage.empty(); });
        const std::chrono::duration waited = std::chrono::steady_clock::now() - start;
        if (storage.empty()) {
            ADD_FAILURE() << "Did not receive the ANR callback";
            return {};
        }
        // Ensure that the ANR didn't get raised too early. We can't be too strict here because
        // the dispatcher started counting before this function was called
        if (std::chrono::abs(timeout - waited) > 100ms) {
            ADD_FAILURE() << "ANR was raised too early or too late. Expected "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count()
                          << "ms, but waited "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(waited).count()
                          << "ms instead";
        }
        T token = storage.front();
        storage.pop();
        return token;
    }

    void assertNotifyAnrWasNotCalled() {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mAnrApplications.empty());
        ASSERT_TRUE(mAnrWindowTokens.empty());
        ASSERT_TRUE(mAnrMonitorPids.empty());
        ASSERT_TRUE(mResponsiveWindowTokens.empty())
                << "ANR was not called, but please also consume the 'connection is responsive' "
                   "signal";
        ASSERT_TRUE(mResponsiveMonitorPids.empty())
                << "Monitor ANR was not called, but please also consume the 'monitor is responsive'"
                   " signal";
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

    void assertDropTargetEquals(const sp<IBinder>& targetToken) {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mNotifyDropWindowWasCalled);
        ASSERT_EQ(targetToken, mDropTargetWindowToken);
        mNotifyDropWindowWasCalled = false;
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
    std::queue<sp<IBinder>> mAnrWindowTokens GUARDED_BY(mLock);
    std::queue<sp<IBinder>> mResponsiveWindowTokens GUARDED_BY(mLock);
    std::queue<int32_t> mAnrMonitorPids GUARDED_BY(mLock);
    std::queue<int32_t> mResponsiveMonitorPids GUARDED_BY(mLock);
    std::condition_variable mNotifyAnr;

    sp<IBinder> mDropTargetWindowToken GUARDED_BY(mLock);
    bool mNotifyDropWindowWasCalled GUARDED_BY(mLock) = false;

    void notifyConfigurationChanged(nsecs_t when) override {
        std::scoped_lock lock(mLock);
        mConfigurationChangedTime = when;
    }

    void notifyWindowUnresponsive(const sp<IBinder>& connectionToken, const std::string&) override {
        std::scoped_lock lock(mLock);
        mAnrWindowTokens.push(connectionToken);
        mNotifyAnr.notify_all();
    }

    void notifyMonitorUnresponsive(int32_t pid, const std::string&) override {
        std::scoped_lock lock(mLock);
        mAnrMonitorPids.push(pid);
        mNotifyAnr.notify_all();
    }

    void notifyWindowResponsive(const sp<IBinder>& connectionToken) override {
        std::scoped_lock lock(mLock);
        mResponsiveWindowTokens.push(connectionToken);
        mNotifyAnr.notify_all();
    }

    void notifyMonitorResponsive(int32_t pid) override {
        std::scoped_lock lock(mLock);
        mResponsiveMonitorPids.push(pid);
        mNotifyAnr.notify_all();
    }

    void notifyNoFocusedWindowAnr(
            const std::shared_ptr<InputApplicationHandle>& applicationHandle) override {
        std::scoped_lock lock(mLock);
        mAnrApplications.push(applicationHandle);
        mNotifyAnr.notify_all();
    }

    void notifyInputChannelBroken(const sp<IBinder>&) override {}

    void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) override {}

    void notifyUntrustedTouch(const std::string& obscuringPackage) override {}
    void notifySensorEvent(int32_t deviceId, InputDeviceSensorType sensorType,
                           InputDeviceSensorAccuracy accuracy, nsecs_t timestamp,
                           const std::vector<float>& values) override {}

    void notifySensorAccuracy(int deviceId, InputDeviceSensorType sensorType,
                              InputDeviceSensorAccuracy accuracy) override {}

    void notifyVibratorState(int32_t deviceId, bool isOn) override {}

    void getDispatcherConfiguration(InputDispatcherConfiguration* outConfig) override {
        *outConfig = mConfig;
    }

    bool filterInputEvent(const InputEvent* inputEvent, uint32_t policyFlags) override {
        std::scoped_lock lock(mLock);
        switch (inputEvent->getType()) {
            case AINPUT_EVENT_TYPE_KEY: {
                const KeyEvent* keyEvent = static_cast<const KeyEvent*>(inputEvent);
                mFilteredEvent = std::make_unique<KeyEvent>(*keyEvent);
                break;
            }

            case AINPUT_EVENT_TYPE_MOTION: {
                const MotionEvent* motionEvent = static_cast<const MotionEvent*>(inputEvent);
                mFilteredEvent = std::make_unique<MotionEvent>(*motionEvent);
                break;
            }
        }
        return true;
    }

    void interceptKeyBeforeQueueing(const KeyEvent*, uint32_t&) override {}

    void interceptMotionBeforeQueueing(int32_t, nsecs_t, uint32_t&) override {}

    nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent*, uint32_t) override {
        return 0;
    }

    bool dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent*, uint32_t, KeyEvent*) override {
        return false;
    }

    void notifySwitch(nsecs_t when, uint32_t switchValues, uint32_t switchMask,
                      uint32_t policyFlags) override {
        std::scoped_lock lock(mLock);
        /** We simply reconstruct NotifySwitchArgs in policy because InputDispatcher is
         * essentially a passthrough for notifySwitch.
         */
        mLastNotifySwitch = NotifySwitchArgs(1 /*id*/, when, policyFlags, switchValues, switchMask);
    }

    void pokeUserActivity(nsecs_t, int32_t, int32_t) override {}

    bool checkInjectEventsPermissionNonReentrant(int32_t pid, int32_t uid) override {
        return pid == INJECTOR_PID && uid == INJECTOR_UID;
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

    void assertFilterInputEventWasCalled(int type, nsecs_t eventTime, int32_t action,
                                         int32_t displayId) {
        std::scoped_lock lock(mLock);
        ASSERT_NE(nullptr, mFilteredEvent) << "Expected filterInputEvent() to have been called.";
        ASSERT_EQ(mFilteredEvent->getType(), type);

        if (type == AINPUT_EVENT_TYPE_KEY) {
            const KeyEvent& keyEvent = static_cast<const KeyEvent&>(*mFilteredEvent);
            EXPECT_EQ(keyEvent.getEventTime(), eventTime);
            EXPECT_EQ(keyEvent.getAction(), action);
            EXPECT_EQ(keyEvent.getDisplayId(), displayId);
        } else if (type == AINPUT_EVENT_TYPE_MOTION) {
            const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*mFilteredEvent);
            EXPECT_EQ(motionEvent.getEventTime(), eventTime);
            EXPECT_EQ(motionEvent.getAction(), action);
            EXPECT_EQ(motionEvent.getDisplayId(), displayId);
        } else {
            FAIL() << "Unknown type: " << type;
        }

        mFilteredEvent = nullptr;
    }
};

// --- InputDispatcherTest ---

class InputDispatcherTest : public testing::Test {
protected:
    sp<FakeInputDispatcherPolicy> mFakePolicy;
    sp<InputDispatcher> mDispatcher;

    void SetUp() override {
        mFakePolicy = new FakeInputDispatcherPolicy();
        mDispatcher = new InputDispatcher(mFakePolicy);
        mDispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
        // Start InputDispatcher thread
        ASSERT_EQ(OK, mDispatcher->start());
    }

    void TearDown() override {
        ASSERT_EQ(OK, mDispatcher->stop());
        mFakePolicy.clear();
        mDispatcher.clear();
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

    void setFocusedWindow(const sp<InputWindowHandle>& window,
                          const sp<InputWindowHandle>& focusedWindow = nullptr) {
        FocusRequest request;
        request.token = window->getToken();
        request.windowName = window->getName();
        if (focusedWindow) {
            request.focusedToken = focusedWindow->getToken();
        }
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
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject key events with undefined action.";

    // Rejects ACTION_MULTIPLE since it is not supported despite being defined in the API.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
                     INVALID_HMAC, AKEY_EVENT_ACTION_MULTIPLE, 0, AKEYCODE_A, KEY_A, AMETA_NONE, 0,
                     ARBITRARY_TIME, ARBITRARY_TIME);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject key events with ACTION_MULTIPLE.";
}

TEST_F(InputDispatcherTest, InjectInputEvent_ValidatesMotionEvents) {
    MotionEvent event;
    PointerProperties pointerProperties[MAX_POINTERS + 1];
    PointerCoords pointerCoords[MAX_POINTERS + 1];
    for (int i = 0; i <= MAX_POINTERS; i++) {
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
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with undefined action.";

    // Rejects pointer down with invalid index.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                             (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, identityTransform, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     ARBITRARY_TIME, ARBITRARY_TIME, /*pointerCount*/ 1, pointerProperties,
                     pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with pointer down index too large.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, identityTransform, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     ARBITRARY_TIME, ARBITRARY_TIME, /*pointerCount*/ 1, pointerProperties,
                     pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with pointer down index too small.";

    // Rejects pointer up with invalid index.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_UP |
                             (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, identityTransform, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     ARBITRARY_TIME, ARBITRARY_TIME, /*pointerCount*/ 1, pointerProperties,
                     pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with pointer up index too large.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_UP |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, identityTransform, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     ARBITRARY_TIME, ARBITRARY_TIME, /*pointerCount*/ 1, pointerProperties,
                     pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with pointer up index too small.";

    // Rejects motion events with invalid number of pointers.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 0, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with 0 pointers.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ MAX_POINTERS + 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with more than MAX_POINTERS pointers.";

    // Rejects motion events with invalid pointer ids.
    pointerProperties[0].id = -1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with pointer ids less than 0.";

    pointerProperties[0].id = MAX_POINTER_ID + 1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with pointer ids greater than MAX_POINTER_ID.";

    // Rejects motion events with duplicate pointer ids.
    pointerProperties[0].id = 1;
    pointerProperties[1].id = 1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     identityTransform, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_DISPLAY_SIZE,
                     AMOTION_EVENT_INVALID_DISPLAY_SIZE, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 2, pointerProperties, pointerCoords);
    ASSERT_EQ(InputEventInjectionResult::FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            InputEventInjectionSync::NONE, 0ms, 0))
            << "Should reject motion events with duplicate pointer ids.";
}

/* Test InputDispatcher for notifyConfigurationChanged and notifySwitch events */

TEST_F(InputDispatcherTest, NotifyConfigurationChanged_CallsPolicy) {
    constexpr nsecs_t eventTime = 20;
    NotifyConfigurationChangedArgs args(10 /*id*/, eventTime);
    mDispatcher->notifyConfigurationChanged(&args);
    ASSERT_TRUE(mDispatcher->waitForIdle());

    mFakePolicy->assertNotifyConfigurationChangedWasCalled(eventTime);
}

TEST_F(InputDispatcherTest, NotifySwitch_CallsPolicy) {
    NotifySwitchArgs args(10 /*id*/, 20 /*eventTime*/, 0 /*policyFlags*/, 1 /*switchValues*/,
                          2 /*switchMask*/);
    mDispatcher->notifySwitch(&args);

    // InputDispatcher adds POLICY_FLAG_TRUSTED because the event went through InputListener
    args.policyFlags |= POLICY_FLAG_TRUSTED;
    mFakePolicy->assertNotifySwitchWasCalled(args);
}

// --- InputDispatcherTest SetInputWindowTest ---
static constexpr std::chrono::duration INJECT_EVENT_TIMEOUT = 500ms;
static constexpr std::chrono::nanoseconds DISPATCHING_TIMEOUT = 5s;

class FakeApplicationHandle : public InputApplicationHandle {
public:
    FakeApplicationHandle() {
        mInfo.name = "Fake Application";
        mInfo.token = new BBinder();
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
            status = mConsumer->consume(&mEventFactory, true /*consumeBatches*/, -1, &consumeSeq,
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

    void consumeEvent(int32_t expectedEventType, int32_t expectedAction,
                      std::optional<int32_t> expectedDisplayId,
                      std::optional<int32_t> expectedFlags) {
        InputEvent* event = consume();

        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(expectedEventType, event->getType())
                << mName.c_str() << " expected " << inputEventTypeToString(expectedEventType)
                << " event, got " << inputEventTypeToString(event->getType()) << " event";

        if (expectedDisplayId.has_value()) {
            EXPECT_EQ(expectedDisplayId, event->getDisplayId());
        }

        switch (expectedEventType) {
            case AINPUT_EVENT_TYPE_KEY: {
                const KeyEvent& keyEvent = static_cast<const KeyEvent&>(*event);
                EXPECT_EQ(expectedAction, keyEvent.getAction());
                if (expectedFlags.has_value()) {
                    EXPECT_EQ(expectedFlags.value(), keyEvent.getFlags());
                }
                break;
            }
            case AINPUT_EVENT_TYPE_MOTION: {
                const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*event);
                EXPECT_EQ(expectedAction, motionEvent.getAction());
                if (expectedFlags.has_value()) {
                    EXPECT_EQ(expectedFlags.value(), motionEvent.getFlags());
                }
                break;
            }
            case AINPUT_EVENT_TYPE_FOCUS: {
                FAIL() << "Use 'consumeFocusEvent' for FOCUS events";
            }
            case AINPUT_EVENT_TYPE_CAPTURE: {
                FAIL() << "Use 'consumeCaptureEvent' for CAPTURE events";
            }
            case AINPUT_EVENT_TYPE_DRAG: {
                FAIL() << "Use 'consumeDragEvent' for DRAG events";
            }
            default: {
                FAIL() << mName.c_str() << ": invalid event type: " << expectedEventType;
            }
        }
    }

    void consumeFocusEvent(bool hasFocus, bool inTouchMode) {
        InputEvent* event = consume();
        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(AINPUT_EVENT_TYPE_FOCUS, event->getType())
                << "Got " << inputEventTypeToString(event->getType())
                << " event instead of FOCUS event";

        ASSERT_EQ(ADISPLAY_ID_NONE, event->getDisplayId())
                << mName.c_str() << ": event displayId should always be NONE.";

        FocusEvent* focusEvent = static_cast<FocusEvent*>(event);
        EXPECT_EQ(hasFocus, focusEvent->getHasFocus());
        EXPECT_EQ(inTouchMode, focusEvent->getInTouchMode());
    }

    void consumeCaptureEvent(bool hasCapture) {
        const InputEvent* event = consume();
        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(AINPUT_EVENT_TYPE_CAPTURE, event->getType())
                << "Got " << inputEventTypeToString(event->getType())
                << " event instead of CAPTURE event";

        ASSERT_EQ(ADISPLAY_ID_NONE, event->getDisplayId())
                << mName.c_str() << ": event displayId should always be NONE.";

        const auto& captureEvent = static_cast<const CaptureEvent&>(*event);
        EXPECT_EQ(hasCapture, captureEvent.getPointerCaptureEnabled());
    }

    void consumeDragEvent(bool isExiting, float x, float y) {
        const InputEvent* event = consume();
        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(AINPUT_EVENT_TYPE_DRAG, event->getType())
                << "Got " << inputEventTypeToString(event->getType())
                << " event instead of DRAG event";

        EXPECT_EQ(ADISPLAY_ID_NONE, event->getDisplayId())
                << mName.c_str() << ": event displayId should always be NONE.";

        const auto& dragEvent = static_cast<const DragEvent&>(*event);
        EXPECT_EQ(isExiting, dragEvent.isExiting());
        EXPECT_EQ(x, dragEvent.getX());
        EXPECT_EQ(y, dragEvent.getY());
    }

    void assertNoEvents() {
        InputEvent* event = consume();
        if (event == nullptr) {
            return;
        }
        if (event->getType() == AINPUT_EVENT_TYPE_KEY) {
            KeyEvent& keyEvent = static_cast<KeyEvent&>(*event);
            ADD_FAILURE() << "Received key event "
                          << KeyEvent::actionToString(keyEvent.getAction());
        } else if (event->getType() == AINPUT_EVENT_TYPE_MOTION) {
            MotionEvent& motionEvent = static_cast<MotionEvent&>(*event);
            ADD_FAILURE() << "Received motion event "
                          << MotionEvent::actionToString(motionEvent.getAction());
        } else if (event->getType() == AINPUT_EVENT_TYPE_FOCUS) {
            FocusEvent& focusEvent = static_cast<FocusEvent&>(*event);
            ADD_FAILURE() << "Received focus event, hasFocus = "
                          << (focusEvent.getHasFocus() ? "true" : "false");
        } else if (event->getType() == AINPUT_EVENT_TYPE_CAPTURE) {
            const auto& captureEvent = static_cast<CaptureEvent&>(*event);
            ADD_FAILURE() << "Received capture event, pointerCaptureEnabled = "
                          << (captureEvent.getPointerCaptureEnabled() ? "true" : "false");
        }
        FAIL() << mName.c_str()
               << ": should not have received any events, so consume() should return NULL";
    }

    sp<IBinder> getToken() { return mConsumer->getChannel()->getConnectionToken(); }

protected:
    std::unique_ptr<InputConsumer> mConsumer;
    PreallocatedInputEventFactory mEventFactory;

    std::string mName;
};

class FakeWindowHandle : public InputWindowHandle {
public:
    static const int32_t WIDTH = 600;
    static const int32_t HEIGHT = 800;

    FakeWindowHandle(const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle,
                     const sp<InputDispatcher>& dispatcher, const std::string name,
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
        mInfo.type = InputWindowInfo::Type::APPLICATION;
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
        mInfo.visible = true;
        mInfo.focusable = false;
        mInfo.hasWallpaper = false;
        mInfo.paused = false;
        mInfo.ownerPid = INJECTOR_PID;
        mInfo.ownerUid = INJECTOR_UID;
        mInfo.displayId = displayId;
    }

    virtual bool updateInfo() { return true; }

    void setFocusable(bool focusable) { mInfo.focusable = focusable; }

    void setVisible(bool visible) { mInfo.visible = visible; }

    void setDispatchingTimeout(std::chrono::nanoseconds timeout) {
        mInfo.dispatchingTimeout = timeout;
    }

    void setPaused(bool paused) { mInfo.paused = paused; }

    void setAlpha(float alpha) { mInfo.alpha = alpha; }

    void setTouchOcclusionMode(android::os::TouchOcclusionMode mode) {
        mInfo.touchOcclusionMode = mode;
    }

    void setApplicationToken(sp<IBinder> token) { mInfo.applicationInfo.token = token; }

    void setFrame(const Rect& frame) {
        mInfo.frameLeft = frame.left;
        mInfo.frameTop = frame.top;
        mInfo.frameRight = frame.right;
        mInfo.frameBottom = frame.bottom;
        mInfo.transform.set(-frame.left, -frame.top);
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(frame);
    }

    void addFlags(Flags<InputWindowInfo::Flag> flags) { mInfo.flags |= flags; }

    void setFlags(Flags<InputWindowInfo::Flag> flags) { mInfo.flags = flags; }

    void setInputFeatures(InputWindowInfo::Feature features) { mInfo.inputFeatures = features; }

    void setWindowTransform(float dsdx, float dtdx, float dtdy, float dsdy) {
        mInfo.transform.set(dsdx, dtdx, dtdy, dsdy);
    }

    void setWindowScale(float xScale, float yScale) { setWindowTransform(xScale, 0, 0, yScale); }

    void setWindowOffset(float offsetX, float offsetY) { mInfo.transform.set(offsetX, offsetY); }

    void consumeKeyDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_DOWN, expectedDisplayId,
                     expectedFlags);
    }

    void consumeKeyUp(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, expectedDisplayId, expectedFlags);
    }

    void consumeMotionCancel(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                             int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_CANCEL, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionMove(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                           int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_MOVE, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionDown(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                           int32_t expectedFlags = 0) {
        consumeAnyMotionDown(expectedDisplayId, expectedFlags);
    }

    void consumeAnyMotionDown(std::optional<int32_t> expectedDisplayId = std::nullopt,
                              std::optional<int32_t> expectedFlags = std::nullopt) {
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_DOWN, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionPointerDown(int32_t pointerIdx,
                                  int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                  int32_t expectedFlags = 0) {
        int32_t action = AMOTION_EVENT_ACTION_POINTER_DOWN |
                (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, action, expectedDisplayId, expectedFlags);
    }

    void consumeMotionPointerUp(int32_t pointerIdx, int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                int32_t expectedFlags = 0) {
        int32_t action = AMOTION_EVENT_ACTION_POINTER_UP |
                (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, action, expectedDisplayId, expectedFlags);
    }

    void consumeMotionUp(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                         int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_UP, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionOutside(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                              int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_OUTSIDE, expectedDisplayId,
                     expectedFlags);
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

    void consumeEvent(int32_t expectedEventType, int32_t expectedAction,
                      std::optional<int32_t> expectedDisplayId,
                      std::optional<int32_t> expectedFlags) {
        ASSERT_NE(mInputReceiver, nullptr) << "Invalid consume event on window with no receiver";
        mInputReceiver->consumeEvent(expectedEventType, expectedAction, expectedDisplayId,
                                     expectedFlags);
    }

    void consumeDragEvent(bool isExiting, float x, float y) {
        mInputReceiver->consumeDragEvent(isExiting, x, y);
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
        if (event->getType() != AINPUT_EVENT_TYPE_MOTION) {
            ADD_FAILURE() << "Instead of motion event, got "
                          << inputEventTypeToString(event->getType());
            return nullptr;
        }
        return static_cast<MotionEvent*>(event);
    }

    void assertNoEvents() {
        if (mInputReceiver == nullptr &&
            mInfo.inputFeatures.test(InputWindowInfo::Feature::NO_INPUT_CHANNEL)) {
            return; // Can't receive events if the window does not have input channel
        }
        ASSERT_NE(nullptr, mInputReceiver)
                << "Window without InputReceiver must specify feature NO_INPUT_CHANNEL";
        mInputReceiver->assertNoEvents();
    }

    sp<IBinder> getToken() { return mInfo.token; }

    const std::string& getName() { return mName; }

    void setOwnerInfo(int32_t ownerPid, int32_t ownerUid) {
        mInfo.ownerPid = ownerPid;
        mInfo.ownerUid = ownerUid;
    }

private:
    const std::string mName;
    std::unique_ptr<FakeInputReceiver> mInputReceiver;
    static std::atomic<int32_t> sId; // each window gets a unique id, like in surfaceflinger
};

std::atomic<int32_t> FakeWindowHandle::sId{1};

static InputEventInjectionResult injectKey(
        const sp<InputDispatcher>& dispatcher, int32_t action, int32_t repeatCount,
        int32_t displayId = ADISPLAY_ID_NONE,
        InputEventInjectionSync syncMode = InputEventInjectionSync::WAIT_FOR_RESULT,
        std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT,
        bool allowKeyRepeat = true) {
    KeyEvent event;
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);

    // Define a valid key down event.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, displayId,
                     INVALID_HMAC, action, /* flags */ 0, AKEYCODE_A, KEY_A, AMETA_NONE,
                     repeatCount, currentTime, currentTime);

    int32_t policyFlags = POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER;
    if (!allowKeyRepeat) {
        policyFlags |= POLICY_FLAG_DISABLE_KEY_REPEAT;
    }
    // Inject event until dispatch out.
    return dispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID, syncMode,
                                        injectionTimeout, policyFlags);
}

static InputEventInjectionResult injectKeyDown(const sp<InputDispatcher>& dispatcher,
                                               int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_DOWN, /* repeatCount */ 0, displayId);
}

// Inject a down event that has key repeat disabled. This allows InputDispatcher to idle without
// sending a subsequent key up. When key repeat is enabled, the dispatcher cannot idle because it
// has to be woken up to process the repeating key.
static InputEventInjectionResult injectKeyDownNoRepeat(const sp<InputDispatcher>& dispatcher,
                                                       int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_DOWN, /* repeatCount */ 0, displayId,
                     InputEventInjectionSync::WAIT_FOR_RESULT, INJECT_EVENT_TIMEOUT,
                     /* allowKeyRepeat */ false);
}

static InputEventInjectionResult injectKeyUp(const sp<InputDispatcher>& dispatcher,
                                             int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_UP, /* repeatCount */ 0, displayId);
}

class PointerBuilder {
public:
    PointerBuilder(int32_t id, int32_t toolType) {
        mProperties.clear();
        mProperties.id = id;
        mProperties.toolType = toolType;
        mCoords.clear();
    }

    PointerBuilder& x(float x) { return axis(AMOTION_EVENT_AXIS_X, x); }

    PointerBuilder& y(float y) { return axis(AMOTION_EVENT_AXIS_Y, y); }

    PointerBuilder& axis(int32_t axis, float value) {
        mCoords.setAxisValue(axis, value);
        return *this;
    }

    PointerProperties buildProperties() const { return mProperties; }

    PointerCoords buildCoords() const { return mCoords; }

private:
    PointerProperties mProperties;
    PointerCoords mCoords;
};

class MotionEventBuilder {
public:
    MotionEventBuilder(int32_t action, int32_t source) {
        mAction = action;
        mSource = source;
        mEventTime = systemTime(SYSTEM_TIME_MONOTONIC);
    }

    MotionEventBuilder& eventTime(nsecs_t eventTime) {
        mEventTime = eventTime;
        return *this;
    }

    MotionEventBuilder& displayId(int32_t displayId) {
        mDisplayId = displayId;
        return *this;
    }

    MotionEventBuilder& actionButton(int32_t actionButton) {
        mActionButton = actionButton;
        return *this;
    }

    MotionEventBuilder& buttonState(int32_t buttonState) {
        mButtonState = buttonState;
        return *this;
    }

    MotionEventBuilder& rawXCursorPosition(float rawXCursorPosition) {
        mRawXCursorPosition = rawXCursorPosition;
        return *this;
    }

    MotionEventBuilder& rawYCursorPosition(float rawYCursorPosition) {
        mRawYCursorPosition = rawYCursorPosition;
        return *this;
    }

    MotionEventBuilder& pointer(PointerBuilder pointer) {
        mPointers.push_back(pointer);
        return *this;
    }

    MotionEventBuilder& addFlag(uint32_t flags) {
        mFlags |= flags;
        return *this;
    }

    MotionEvent build() {
        std::vector<PointerProperties> pointerProperties;
        std::vector<PointerCoords> pointerCoords;
        for (const PointerBuilder& pointer : mPointers) {
            pointerProperties.push_back(pointer.buildProperties());
            pointerCoords.push_back(pointer.buildCoords());
        }

        // Set mouse cursor position for the most common cases to avoid boilerplate.
        if (mSource == AINPUT_SOURCE_MOUSE &&
            !MotionEvent::isValidCursorPosition(mRawXCursorPosition, mRawYCursorPosition) &&
            mPointers.size() == 1) {
            mRawXCursorPosition = pointerCoords[0].getX();
            mRawYCursorPosition = pointerCoords[0].getY();
        }

        MotionEvent event;
        ui::Transform identityTransform;
        event.initialize(InputEvent::nextId(), DEVICE_ID, mSource, mDisplayId, INVALID_HMAC,
                         mAction, mActionButton, mFlags, /* edgeFlags */ 0, AMETA_NONE,
                         mButtonState, MotionClassification::NONE, identityTransform,
                         /* xPrecision */ 0, /* yPrecision */ 0, mRawXCursorPosition,
                         mRawYCursorPosition, mDisplayWidth, mDisplayHeight, mEventTime, mEventTime,
                         mPointers.size(), pointerProperties.data(), pointerCoords.data());

        return event;
    }

private:
    int32_t mAction;
    int32_t mSource;
    nsecs_t mEventTime;
    int32_t mDisplayId{ADISPLAY_ID_DEFAULT};
    int32_t mActionButton{0};
    int32_t mButtonState{0};
    int32_t mFlags{0};
    float mRawXCursorPosition{AMOTION_EVENT_INVALID_CURSOR_POSITION};
    float mRawYCursorPosition{AMOTION_EVENT_INVALID_CURSOR_POSITION};
    int32_t mDisplayWidth{AMOTION_EVENT_INVALID_DISPLAY_SIZE};
    int32_t mDisplayHeight{AMOTION_EVENT_INVALID_DISPLAY_SIZE};

    std::vector<PointerBuilder> mPointers;
};

static InputEventInjectionResult injectMotionEvent(
        const sp<InputDispatcher>& dispatcher, const MotionEvent& event,
        std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT,
        InputEventInjectionSync injectionMode = InputEventInjectionSync::WAIT_FOR_RESULT) {
    return dispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID, injectionMode,
                                        injectionTimeout,
                                        POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);
}

static InputEventInjectionResult injectMotionEvent(
        const sp<InputDispatcher>& dispatcher, int32_t action, int32_t source, int32_t displayId,
        const PointF& position,
        const PointF& cursorPosition = {AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                        AMOTION_EVENT_INVALID_CURSOR_POSITION},
        std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT,
        InputEventInjectionSync injectionMode = InputEventInjectionSync::WAIT_FOR_RESULT,
        nsecs_t eventTime = systemTime(SYSTEM_TIME_MONOTONIC)) {
    MotionEvent event = MotionEventBuilder(action, source)
                                .displayId(displayId)
                                .eventTime(eventTime)
                                .rawXCursorPosition(cursorPosition.x)
                                .rawYCursorPosition(cursorPosition.y)
                                .pointer(PointerBuilder(/* id */ 0, AMOTION_EVENT_TOOL_TYPE_FINGER)
                                                 .x(position.x)
                                                 .y(position.y))
                                .build();

    // Inject event until dispatch out.
    return injectMotionEvent(dispatcher, event, injectionTimeout, injectionMode);
}

static InputEventInjectionResult injectMotionDown(const sp<InputDispatcher>& dispatcher,
                                                  int32_t source, int32_t displayId,
                                                  const PointF& location = {100, 200}) {
    return injectMotionEvent(dispatcher, AMOTION_EVENT_ACTION_DOWN, source, displayId, location);
}

static InputEventInjectionResult injectMotionUp(const sp<InputDispatcher>& dispatcher,
                                                int32_t source, int32_t displayId,
                                                const PointF& location = {100, 200}) {
    return injectMotionEvent(dispatcher, AMOTION_EVENT_ACTION_UP, source, displayId, location);
}

static NotifyKeyArgs generateKeyArgs(int32_t action, int32_t displayId = ADISPLAY_ID_NONE) {
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid key event.
    NotifyKeyArgs args(/* id */ 0, currentTime, 0 /*readTime*/, DEVICE_ID, AINPUT_SOURCE_KEYBOARD,
                       displayId, POLICY_FLAG_PASS_TO_USER, action, /* flags */ 0, AKEYCODE_A,
                       KEY_A, AMETA_NONE, currentTime);

    return args;
}

static NotifyMotionArgs generateMotionArgs(int32_t action, int32_t source, int32_t displayId,
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
        pointerProperties[i].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

        pointerCoords[i].clear();
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X, points[i].x);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y, points[i].y);
    }

    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid motion event.
    NotifyMotionArgs args(/* id */ 0, currentTime, 0 /*readTime*/, DEVICE_ID, source, displayId,
                          POLICY_FLAG_PASS_TO_USER, action, /* actionButton */ 0, /* flags */ 0,
                          AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                          AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount, pointerProperties,
                          pointerCoords, /* xPrecision */ 0, /* yPrecision */ 0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, currentTime, /* videoFrames */ {});

    return args;
}

static NotifyMotionArgs generateMotionArgs(int32_t action, int32_t source, int32_t displayId) {
    return generateMotionArgs(action, source, displayId, {PointF{100, 200}});
}

static NotifyPointerCaptureChangedArgs generatePointerCaptureChangedArgs(
        const PointerCaptureRequest& request) {
    return NotifyPointerCaptureChangedArgs(/* id */ 0, systemTime(SYSTEM_TIME_MONOTONIC), request);
}

TEST_F(InputDispatcherTest, SetInputWindow_SingleWindowTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Window should receive motion event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

/**
 * Calling setInputWindows once with FLAG_NOT_TOUCH_MODAL should not cause any issues.
 * To ensure that window receives only events that were directly inside of it, add
 * FLAG_NOT_TOUCH_MODAL. This will enforce using the touchableRegion of the input
 * when finding touched windows.
 * This test serves as a sanity check for the next test, where setInputWindows is
 * called twice.
 */
TEST_F(InputDispatcherTest, SetInputWindowOnce_SingleWindowTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));
    window->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

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
 * To ensure that window receives only events that were directly inside of it, add
 * FLAG_NOT_TOUCH_MODAL. This will enforce using the touchableRegion of the input
 * when finding touched windows.
 */
TEST_F(InputDispatcherTest, SetInputWindowTwice_SingleWindowTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));
    window->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

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
            new FakeWindowHandle(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            new FakeWindowHandle(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

    // Top window should receive the touch down event. Second window should not receive anything.
    windowTop->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowSecond->assertNoEvents();
}

TEST_F(InputDispatcherTest, HoverMoveEnterMouseClickAndHoverMoveExit) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowLeft =
            new FakeWindowHandle(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    windowLeft->setFrame(Rect(0, 0, 600, 800));
    windowLeft->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);
    sp<FakeWindowHandle> windowRight =
            new FakeWindowHandle(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    windowRight->setFrame(Rect(600, 0, 1200, 800));
    windowRight->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowLeft, windowRight}}});

    // Start cursor position in right window so that we can move the cursor to left window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(900)
                                                         .y(400))
                                        .build()));
    windowRight->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_ENTER,
                              ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);
    windowRight->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_MOVE,
                              ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);

    // Move cursor into left window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    windowRight->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_EXIT,
                              ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);
    windowLeft->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_ENTER,
                             ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);
    windowLeft->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_MOVE,
                             ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);

    // Inject a series of mouse events for a mouse click
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    windowLeft->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    windowLeft->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_BUTTON_PRESS,
                             ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    windowLeft->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                             ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    windowLeft->consumeMotionUp(ADISPLAY_ID_DEFAULT);

    // Move mouse cursor back to right window
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_MOVE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(900)
                                                         .y(400))
                                        .build()));
    windowLeft->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_EXIT,
                             ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);
    windowRight->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_ENTER,
                              ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);
    windowRight->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_MOVE,
                              ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);
}

// This test is different from the test above that HOVER_ENTER and HOVER_EXIT events are injected
// directly in this test.
TEST_F(InputDispatcherTest, HoverEnterMouseClickAndHoverExit) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 1200, 800));
    window->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_ENTER,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    window->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_ENTER,
                         ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);

    // Inject a series of mouse events for a mouse click
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_PRESS,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    window->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_BUTTON_PRESS,
                         ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                                                   AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .actionButton(AMOTION_EVENT_BUTTON_PRIMARY)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    window->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                         ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_MOUSE)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    window->consumeMotionUp(ADISPLAY_ID_DEFAULT);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_HOVER_EXIT,
                                                   AINPUT_SOURCE_MOUSE)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_MOUSE)
                                                         .x(300)
                                                         .y(400))
                                        .build()));
    window->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_HOVER_EXIT,
                         ADISPLAY_ID_DEFAULT, 0 /* expectedFlag */);
}

TEST_F(InputDispatcherTest, DispatchMouseEventsUnderCursor) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> windowLeft =
            new FakeWindowHandle(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    windowLeft->setFrame(Rect(0, 0, 600, 800));
    windowLeft->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);
    sp<FakeWindowHandle> windowRight =
            new FakeWindowHandle(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    windowRight->setFrame(Rect(600, 0, 1200, 800));
    windowRight->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

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
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyKey(&keyArgs);

    // Window should receive key down event.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    // When device reset happens, that key stream should be terminated with FLAG_CANCELED
    // on the app side.
    NotifyDeviceResetArgs args(10 /*id*/, 20 /*eventTime*/, DEVICE_ID);
    mDispatcher->notifyDeviceReset(&args);
    window->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT,
                         AKEY_EVENT_FLAG_CANCELED);
}

TEST_F(InputDispatcherTest, NotifyDeviceReset_CancelsMotionStream) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&motionArgs);

    // Window should receive motion down event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // When device reset happens, that motion stream should be terminated with ACTION_CANCEL
    // on the app side.
    NotifyDeviceResetArgs args(10 /*id*/, 20 /*eventTime*/, DEVICE_ID);
    mDispatcher->notifyDeviceReset(&args);
    window->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_CANCEL, ADISPLAY_ID_DEFAULT,
                         0 /*expectedFlags*/);
}

using TransferFunction =
        std::function<bool(sp<InputDispatcher> dispatcher, sp<IBinder>, sp<IBinder>)>;

class TransferTouchFixture : public InputDispatcherTest,
                             public ::testing::WithParamInterface<TransferFunction> {};

TEST_P(TransferTouchFixture, TransferTouch_OnePointer) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    // Create a couple of windows
    sp<FakeWindowHandle> firstWindow =
            new FakeWindowHandle(application, mDispatcher, "First Window", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> secondWindow =
            new FakeWindowHandle(application, mDispatcher, "Second Window", ADISPLAY_ID_DEFAULT);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    // Send down to the first window
    NotifyMotionArgs downMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&downMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Transfer touch to the second window
    TransferFunction f = GetParam();
    const bool success = f(mDispatcher, firstWindow->getToken(), secondWindow->getToken());
    ASSERT_TRUE(success);
    // The first window gets cancel and the second gets down
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionDown();

    // Send up event to the second window
    NotifyMotionArgs upMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
    // The first  window gets no events and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
}

TEST_P(TransferTouchFixture, TransferTouch_TwoPointersNonSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    PointF touchPoint = {10, 10};

    // Create a couple of windows
    sp<FakeWindowHandle> firstWindow =
            new FakeWindowHandle(application, mDispatcher, "First Window", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> secondWindow =
            new FakeWindowHandle(application, mDispatcher, "Second Window", ADISPLAY_ID_DEFAULT);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    // Send down to the first window
    NotifyMotionArgs downMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {touchPoint});
    mDispatcher->notifyMotion(&downMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send pointer down to the first window
    NotifyMotionArgs pointerDownMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {touchPoint, touchPoint});
    mDispatcher->notifyMotion(&pointerDownMotionArgs);
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
    NotifyMotionArgs pointerUpMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_UP |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {touchPoint, touchPoint});
    mDispatcher->notifyMotion(&pointerUpMotionArgs);
    // The first window gets nothing and the second gets pointer up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionPointerUp(1);

    // Send up event to the second window
    NotifyMotionArgs upMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
    // The first window gets nothing and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
}

// For the cases of single pointer touch and two pointers non-split touch, the api's
// 'transferTouch' and 'transferTouchFocus' are equivalent in behaviour. They only differ
// for the case where there are multiple pointers split across several windows.
INSTANTIATE_TEST_SUITE_P(TransferFunctionTests, TransferTouchFixture,
                         ::testing::Values(
                                 [&](sp<InputDispatcher> dispatcher, sp<IBinder> /*ignored*/,
                                     sp<IBinder> destChannelToken) {
                                     return dispatcher->transferTouch(destChannelToken);
                                 },
                                 [&](sp<InputDispatcher> dispatcher, sp<IBinder> from,
                                     sp<IBinder> to) {
                                     return dispatcher->transferTouchFocus(from, to,
                                                                           false /*isDragAndDrop*/);
                                 }));

TEST_F(InputDispatcherTest, TransferTouchFocus_TwoPointersSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    // Create a non touch modal window that supports split touch
    sp<FakeWindowHandle> firstWindow =
            new FakeWindowHandle(application, mDispatcher, "First Window", ADISPLAY_ID_DEFAULT);
    firstWindow->setFrame(Rect(0, 0, 600, 400));
    firstWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                          InputWindowInfo::Flag::SPLIT_TOUCH);

    // Create a non touch modal window that supports split touch
    sp<FakeWindowHandle> secondWindow =
            new FakeWindowHandle(application, mDispatcher, "Second Window", ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect(0, 400, 600, 800));
    secondWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                           InputWindowInfo::Flag::SPLIT_TOUCH);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    PointF pointInFirst = {300, 200};
    PointF pointInSecond = {300, 600};

    // Send down to the first window
    NotifyMotionArgs firstDownMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {pointInFirst});
    mDispatcher->notifyMotion(&firstDownMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send down to the second window
    NotifyMotionArgs secondDownMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {pointInFirst, pointInSecond});
    mDispatcher->notifyMotion(&secondDownMotionArgs);
    // The first window gets a move and the second a down
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionDown();

    // Transfer touch focus to the second window
    mDispatcher->transferTouchFocus(firstWindow->getToken(), secondWindow->getToken());
    // The first window gets cancel and the new gets pointer down (it already saw down)
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionPointerDown(1);

    // Send pointer up to the second window
    NotifyMotionArgs pointerUpMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_UP |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {pointInFirst, pointInSecond});
    mDispatcher->notifyMotion(&pointerUpMotionArgs);
    // The first window gets nothing and the second gets pointer up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionPointerUp(1);

    // Send up event to the second window
    NotifyMotionArgs upMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
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

    // Create a non touch modal window that supports split touch
    sp<FakeWindowHandle> firstWindow =
            new FakeWindowHandle(application, mDispatcher, "First Window", ADISPLAY_ID_DEFAULT);
    firstWindow->setFrame(Rect(0, 0, 600, 400));
    firstWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                          InputWindowInfo::Flag::SPLIT_TOUCH);

    // Create a non touch modal window that supports split touch
    sp<FakeWindowHandle> secondWindow =
            new FakeWindowHandle(application, mDispatcher, "Second Window", ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect(0, 400, 600, 800));
    secondWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                           InputWindowInfo::Flag::SPLIT_TOUCH);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    PointF pointInFirst = {300, 200};
    PointF pointInSecond = {300, 600};

    // Send down to the first window
    NotifyMotionArgs firstDownMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {pointInFirst});
    mDispatcher->notifyMotion(&firstDownMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send down to the second window
    NotifyMotionArgs secondDownMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {pointInFirst, pointInSecond});
    mDispatcher->notifyMotion(&secondDownMotionArgs);
    // The first window gets a move and the second a down
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionDown();

    // Transfer touch focus to the second window
    const bool transferred = mDispatcher->transferTouch(secondWindow->getToken());
    // The 'transferTouch' call should not succeed, because there are 2 touched windows
    ASSERT_FALSE(transferred);
    firstWindow->assertNoEvents();
    secondWindow->assertNoEvents();

    // The rest of the dispatch should proceed as normal
    // Send pointer up to the second window
    NotifyMotionArgs pointerUpMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_UP |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {pointInFirst, pointInSecond});
    mDispatcher->notifyMotion(&pointerUpMotionArgs);
    // The first window gets MOVE and the second gets pointer up
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionUp();

    // Send up event to the first window
    NotifyMotionArgs upMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
    // The first window gets nothing and the second gets up
    firstWindow->consumeMotionUp();
    secondWindow->assertNoEvents();
}

TEST_F(InputDispatcherTest, FocusedWindow_ReceivesFocusEventAndKeyEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyKey(&keyArgs);

    // Window should receive key down event.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, UnfocusedWindow_DoesNotReceiveFocusEventOrKeyEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyKey(&keyArgs);
    mDispatcher->waitForIdle();

    window->assertNoEvents();
}

// If a window is touchable, but does not have focus, it should receive motion events, but not keys
TEST_F(InputDispatcherTest, UnfocusedWindow_ReceivesMotionsButNotKeys) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // Send key
    NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyKey(&keyArgs);
    // Send motion
    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&motionArgs);

    // Window should receive only the motion event
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    window->assertNoEvents(); // Key event or focus event will not be received
}

TEST_F(InputDispatcherTest, PointerCancel_SendCancelWhenSplitTouch) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    // Create first non touch modal window that supports split touch
    sp<FakeWindowHandle> firstWindow =
            new FakeWindowHandle(application, mDispatcher, "First Window", ADISPLAY_ID_DEFAULT);
    firstWindow->setFrame(Rect(0, 0, 600, 400));
    firstWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                          InputWindowInfo::Flag::SPLIT_TOUCH);

    // Create second non touch modal window that supports split touch
    sp<FakeWindowHandle> secondWindow =
            new FakeWindowHandle(application, mDispatcher, "Second Window", ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect(0, 400, 600, 800));
    secondWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                           InputWindowInfo::Flag::SPLIT_TOUCH);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    PointF pointInFirst = {300, 200};
    PointF pointInSecond = {300, 600};

    // Send down to the first window
    NotifyMotionArgs firstDownMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {pointInFirst});
    mDispatcher->notifyMotion(&firstDownMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send down to the second window
    NotifyMotionArgs secondDownMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_DOWN |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {pointInFirst, pointInSecond});
    mDispatcher->notifyMotion(&secondDownMotionArgs);
    // The first window gets a move and the second a down
    firstWindow->consumeMotionMove();
    secondWindow->consumeMotionDown();

    // Send pointer cancel to the second window
    NotifyMotionArgs pointerUpMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_UP |
                                       (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                               AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {pointInFirst, pointInSecond});
    pointerUpMotionArgs.flags |= AMOTION_EVENT_FLAG_CANCELED;
    mDispatcher->notifyMotion(&pointerUpMotionArgs);
    // The first window gets move and the second gets cancel.
    firstWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_CANCELED);
    secondWindow->consumeMotionCancel(ADISPLAY_ID_DEFAULT, AMOTION_EVENT_FLAG_CANCELED);

    // Send up event.
    NotifyMotionArgs upMotionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
    // The first window gets up and the second gets nothing.
    firstWindow->consumeMotionUp();
    secondWindow->assertNoEvents();
}

TEST_F(InputDispatcherTest, SendTimeline_DoesNotCrashDispatcher) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();

    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;
    graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME] = 2;
    graphicsTimeline[GraphicsTimeline::PRESENT_TIME] = 3;

    window->sendTimeline(1 /*inputEventId*/, graphicsTimeline);
    window->assertNoEvents();
    mDispatcher->waitForIdle();
}

class FakeMonitorReceiver {
public:
    FakeMonitorReceiver(const sp<InputDispatcher>& dispatcher, const std::string name,
                        int32_t displayId, bool isGestureMonitor = false) {
        base::Result<std::unique_ptr<InputChannel>> channel =
                dispatcher->createInputMonitor(displayId, isGestureMonitor, name, MONITOR_PID);
        mInputReceiver = std::make_unique<FakeInputReceiver>(std::move(*channel), name);
    }

    sp<IBinder> getToken() { return mInputReceiver->getToken(); }

    void consumeKeyDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_DOWN,
                                     expectedDisplayId, expectedFlags);
    }

    std::optional<int32_t> receiveEvent() { return mInputReceiver->receiveEvent(); }

    void finishEvent(uint32_t consumeSeq) { return mInputReceiver->finishEvent(consumeSeq); }

    void consumeMotionDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_DOWN,
                                     expectedDisplayId, expectedFlags);
    }

    void consumeMotionUp(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        mInputReceiver->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_UP,
                                     expectedDisplayId, expectedFlags);
    }

    MotionEvent* consumeMotion() {
        InputEvent* event = mInputReceiver->consume();
        if (!event) {
            ADD_FAILURE() << "No event was produced";
            return nullptr;
        }
        if (event->getType() != AINPUT_EVENT_TYPE_MOTION) {
            ADD_FAILURE() << "Received event of type " << event->getType() << " instead of motion";
            return nullptr;
        }
        return static_cast<MotionEvent*>(event);
    }

    void assertNoEvents() { mInputReceiver->assertNoEvents(); }

private:
    std::unique_ptr<FakeInputReceiver> mInputReceiver;
};

// Tests for gesture monitors
TEST_F(InputDispatcherTest, GestureMonitor_ReceivesMotionEvents) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "GM_1", ADISPLAY_ID_DEFAULT,
                                                      true /*isGestureMonitor*/);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, GestureMonitor_DoesNotReceiveKeyEvents) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true);

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "GM_1", ADISPLAY_ID_DEFAULT,
                                                      true /*isGestureMonitor*/);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    monitor.assertNoEvents();
}

TEST_F(InputDispatcherTest, GestureMonitor_CanPilferAfterWindowIsRemovedMidStream) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "GM_1", ADISPLAY_ID_DEFAULT,
                                                      true /*isGestureMonitor*/);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);

    window->releaseChannel();

    mDispatcher->pilferPointers(monitor.getToken());

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    monitor.consumeMotionUp(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, UnresponsiveGestureMonitor_GetsAnr) {
    FakeMonitorReceiver monitor =
            FakeMonitorReceiver(mDispatcher, "Gesture monitor", ADISPLAY_ID_DEFAULT,
                                true /*isGestureMonitor*/);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    std::optional<uint32_t> consumeSeq = monitor.receiveEvent();
    ASSERT_TRUE(consumeSeq);

    mFakePolicy->assertNotifyMonitorUnresponsiveWasCalled(DISPATCHING_TIMEOUT);
    monitor.finishEvent(*consumeSeq);
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyMonitorResponsiveWasCalled();
}

// Tests for gesture monitors
TEST_F(InputDispatcherTest, GestureMonitor_NoWindowTransform) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->setWindowOffset(20, 40);
    window->setWindowTransform(0, 1, -1, 0);

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "GM_1", ADISPLAY_ID_DEFAULT,
                                                      true /*isGestureMonitor*/);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    MotionEvent* event = monitor.consumeMotion();
    // Even though window has transform, gesture monitor must not.
    ASSERT_EQ(ui::Transform(), event->getTransform());
}

TEST_F(InputDispatcherTest, TestMoveEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);

    mDispatcher->notifyMotion(&motionArgs);
    // Window should receive motion down event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    motionArgs.action = AMOTION_EVENT_ACTION_MOVE;
    motionArgs.id += 1;
    motionArgs.eventTime = systemTime(SYSTEM_TIME_MONOTONIC);
    motionArgs.pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                             motionArgs.pointerCoords[0].getX() - 10);

    mDispatcher->notifyMotion(&motionArgs);
    window->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_MOVE, ADISPLAY_ID_DEFAULT,
                         0 /*expectedFlags*/);
}

/**
 * Dispatcher has touch mode enabled by default. Typically, the policy overrides that value to
 * the device default right away. In the test scenario, we check both the default value,
 * and the action of enabling / disabling.
 */
TEST_F(InputDispatcherTest, TouchModeState_IsSentToApps) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Test window", ADISPLAY_ID_DEFAULT);

    // Set focused application.
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);

    SCOPED_TRACE("Check default value of touch mode");
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true /*hasFocus*/, true /*inTouchMode*/);

    SCOPED_TRACE("Remove the window to trigger focus loss");
    window->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(false /*hasFocus*/, true /*inTouchMode*/);

    SCOPED_TRACE("Disable touch mode");
    mDispatcher->setInTouchMode(false);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(true /*hasFocus*/, false /*inTouchMode*/);

    SCOPED_TRACE("Remove the window to trigger focus loss");
    window->setFocusable(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(false /*hasFocus*/, false /*inTouchMode*/);

    SCOPED_TRACE("Enable touch mode again");
    mDispatcher->setInTouchMode(true);
    window->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);
    window->consumeFocusEvent(true /*hasFocus*/, true /*inTouchMode*/);

    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, VerifyInputEvent_KeyEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Test window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    window->consumeFocusEvent(true /*hasFocus*/, true /*inTouchMode*/);

    NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN);
    mDispatcher->notifyKey(&keyArgs);

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
    ASSERT_EQ(keyArgs.downTime, verifiedKey.downTimeNanos);
    ASSERT_EQ(keyArgs.flags & VERIFIED_KEY_EVENT_FLAGS, verifiedKey.flags);
    ASSERT_EQ(keyArgs.keyCode, verifiedKey.keyCode);
    ASSERT_EQ(keyArgs.scanCode, verifiedKey.scanCode);
    ASSERT_EQ(keyArgs.metaState, verifiedKey.metaState);
    ASSERT_EQ(0, verifiedKey.repeatCount);
}

TEST_F(InputDispatcherTest, VerifyInputEvent_MotionEvent) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Test window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&motionArgs);

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

    EXPECT_EQ(motionArgs.pointerCoords[0].getX(), verifiedMotion.rawX);
    EXPECT_EQ(motionArgs.pointerCoords[0].getY(), verifiedMotion.rawY);
    EXPECT_EQ(motionArgs.action & AMOTION_EVENT_ACTION_MASK, verifiedMotion.actionMasked);
    EXPECT_EQ(motionArgs.downTime, verifiedMotion.downTimeNanos);
    EXPECT_EQ(motionArgs.flags & VERIFIED_MOTION_EVENT_FLAGS, verifiedMotion.flags);
    EXPECT_EQ(motionArgs.metaState, verifiedMotion.metaState);
    EXPECT_EQ(motionArgs.buttonState, verifiedMotion.buttonState);
}

TEST_F(InputDispatcherTest, NonPointerMotionEvent_NotTransformed) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Test window", ADISPLAY_ID_DEFAULT);
    const std::string name = window->getName();

    // Window gets transformed by offset values.
    window->setWindowOffset(500.0f, 500.0f);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocusable(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    // First, we set focused window so that focusedWindowHandle is not null.
    setFocusedWindow(window);

    // Second, we consume focus event if it is right or wrong according to onFocusChangedLocked.
    window->consumeFocusEvent(true);

    constexpr const std::array nonPointerSources = {AINPUT_SOURCE_TRACKBALL,
                                                    AINPUT_SOURCE_MOUSE_RELATIVE,
                                                    AINPUT_SOURCE_JOYSTICK};
    for (const int source : nonPointerSources) {
        // Notify motion with a non-pointer source.
        NotifyMotionArgs motionArgs =
                generateMotionArgs(AMOTION_EVENT_ACTION_MOVE, source, ADISPLAY_ID_DEFAULT);
        mDispatcher->notifyMotion(&motionArgs);

        MotionEvent* event = window->consumeMotion();
        ASSERT_NE(event, nullptr);

        const MotionEvent& motionEvent = *event;
        EXPECT_EQ(AMOTION_EVENT_ACTION_MOVE, motionEvent.getAction());
        EXPECT_EQ(motionArgs.pointerCount, motionEvent.getPointerCount());

        float expectedX = motionArgs.pointerCoords[0].getX();
        float expectedY = motionArgs.pointerCoords[0].getY();

        // Ensure the axis values from the final motion event are not transformed.
        EXPECT_EQ(expectedX, motionEvent.getX(0))
                << "expected " << expectedX << " for x coord of " << name.c_str() << ", got "
                << motionEvent.getX(0);
        EXPECT_EQ(expectedY, motionEvent.getY(0))
                << "expected " << expectedY << " for y coord of " << name.c_str() << ", got "
                << motionEvent.getY(0);
        // Ensure the raw and transformed axis values for the motion event are the same.
        EXPECT_EQ(motionEvent.getRawX(0), motionEvent.getX(0))
                << "expected raw and transformed X-axis values to be equal";
        EXPECT_EQ(motionEvent.getRawY(0), motionEvent.getY(0))
                << "expected raw and transformed Y-axis values to be equal";
    }
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
            new FakeWindowHandle(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            new FakeWindowHandle(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
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
            new FakeWindowHandle(application, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
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
            new FakeWindowHandle(application, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    // Window is not focusable.
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    setFocusedWindow(window);

    // Test inject a key down, should timeout.
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";

    // window is invalid, so it should not receive any input event.
    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetFocusedWindow_CheckFocusedToken) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowTop =
            new FakeWindowHandle(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            new FakeWindowHandle(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    windowTop->setFocusable(true);
    windowSecond->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    setFocusedWindow(windowTop);
    windowTop->consumeFocusEvent(true);

    setFocusedWindow(windowSecond, windowTop);
    windowSecond->consumeFocusEvent(true);
    windowTop->consumeFocusEvent(false);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::SUCCEEDED";

    // Focused window should receive event.
    windowSecond->consumeKeyDown(ADISPLAY_ID_NONE);
}

TEST_F(InputDispatcherTest, SetFocusedWindow_DropRequestFocusTokenNotFocused) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> windowTop =
            new FakeWindowHandle(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond =
            new FakeWindowHandle(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    windowTop->setFocusable(true);
    windowSecond->setFocusable(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    setFocusedWindow(windowSecond, windowTop);

    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return InputEventInjectionResult::TIMED_OUT";

    // Event should be dropped.
    windowTop->assertNoEvents();
    windowSecond->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetFocusedWindow_DeferInvisibleWindow) {
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> previousFocusedWindow =
            new FakeWindowHandle(application, mDispatcher, "previousFocusedWindow",
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
              injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */,
                        ADISPLAY_ID_DEFAULT, InputEventInjectionSync::NONE));

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
            new FakeWindowHandle(application, mDispatcher, "window", ADISPLAY_ID_DEFAULT);
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
    constexpr int32_t SLIPPERY_PID = INJECTOR_PID + 1;
    constexpr int32_t SLIPPERY_UID = INJECTOR_UID + 1;

    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    sp<FakeWindowHandle> slipperyExitWindow =
            new FakeWindowHandle(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
    slipperyExitWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                                 InputWindowInfo::Flag::SLIPPERY);
    // Make sure this one overlaps the bottom window
    slipperyExitWindow->setFrame(Rect(25, 25, 75, 75));
    // Change the owner uid/pid of the window so that it is considered to be occluding the bottom
    // one. Windows with the same owner are not considered to be occluding each other.
    slipperyExitWindow->setOwnerInfo(SLIPPERY_PID, SLIPPERY_UID);

    sp<FakeWindowHandle> slipperyEnterWindow =
            new FakeWindowHandle(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
    slipperyExitWindow->setFrame(Rect(0, 0, 100, 100));

    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {slipperyExitWindow, slipperyEnterWindow}}});

    // Use notifyMotion instead of injecting to avoid dealing with injection permissions
    NotifyMotionArgs args = generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                               ADISPLAY_ID_DEFAULT, {{50, 50}});
    mDispatcher->notifyMotion(&args);
    slipperyExitWindow->consumeMotionDown();
    slipperyExitWindow->setFrame(Rect(70, 70, 100, 100));
    mDispatcher->setInputWindows(
            {{ADISPLAY_ID_DEFAULT, {slipperyExitWindow, slipperyEnterWindow}}});

    args = generateMotionArgs(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                              ADISPLAY_ID_DEFAULT, {{51, 51}});
    mDispatcher->notifyMotion(&args);

    slipperyExitWindow->consumeMotionCancel();

    slipperyEnterWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT,
                                           AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED);
}

class InputDispatcherKeyRepeatTest : public InputDispatcherTest {
protected:
    static constexpr nsecs_t KEY_REPEAT_TIMEOUT = 40 * 1000000; // 40 ms
    static constexpr nsecs_t KEY_REPEAT_DELAY = 40 * 1000000;   // 40 ms

    std::shared_ptr<FakeApplicationHandle> mApp;
    sp<FakeWindowHandle> mWindow;

    virtual void SetUp() override {
        mFakePolicy = new FakeInputDispatcherPolicy();
        mFakePolicy->setKeyRepeatConfiguration(KEY_REPEAT_TIMEOUT, KEY_REPEAT_DELAY);
        mDispatcher = new InputDispatcher(mFakePolicy);
        mDispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
        ASSERT_EQ(OK, mDispatcher->start());

        setUpWindow();
    }

    void setUpWindow() {
        mApp = std::make_shared<FakeApplicationHandle>();
        mWindow = new FakeWindowHandle(mApp, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

        mWindow->setFocusable(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
        setFocusedWindow(mWindow);
        mWindow->consumeFocusEvent(true);
    }

    void sendAndConsumeKeyDown(int32_t deviceId) {
        NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
        keyArgs.deviceId = deviceId;
        keyArgs.policyFlags |= POLICY_FLAG_TRUSTED; // Otherwise it won't generate repeat event
        mDispatcher->notifyKey(&keyArgs);

        // Window should receive key down event.
        mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    }

    void expectKeyRepeatOnce(int32_t repeatCount) {
        SCOPED_TRACE(StringPrintf("Checking event with repeat count %" PRId32, repeatCount));
        InputEvent* repeatEvent = mWindow->consume();
        ASSERT_NE(nullptr, repeatEvent);

        uint32_t eventType = repeatEvent->getType();
        ASSERT_EQ(AINPUT_EVENT_TYPE_KEY, eventType);

        KeyEvent* repeatKeyEvent = static_cast<KeyEvent*>(repeatEvent);
        uint32_t eventAction = repeatKeyEvent->getAction();
        EXPECT_EQ(AKEY_EVENT_ACTION_DOWN, eventAction);
        EXPECT_EQ(repeatCount, repeatKeyEvent->getRepeatCount());
    }

    void sendAndConsumeKeyUp(int32_t deviceId) {
        NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT);
        keyArgs.deviceId = deviceId;
        keyArgs.policyFlags |= POLICY_FLAG_TRUSTED; // Unless it won't generate repeat event
        mDispatcher->notifyKey(&keyArgs);

        // Window should receive key down event.
        mWindow->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT,
                              0 /*expectedFlags*/);
    }
};

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_ReceivesKeyRepeat) {
    sendAndConsumeKeyDown(1 /* deviceId */);
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        expectKeyRepeatOnce(repeatCount);
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_ReceivesKeyRepeatFromTwoDevices) {
    sendAndConsumeKeyDown(1 /* deviceId */);
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        expectKeyRepeatOnce(repeatCount);
    }
    sendAndConsumeKeyDown(2 /* deviceId */);
    /* repeatCount will start from 1 for deviceId 2 */
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        expectKeyRepeatOnce(repeatCount);
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_StopsKeyRepeatAfterUp) {
    sendAndConsumeKeyDown(1 /* deviceId */);
    expectKeyRepeatOnce(1 /*repeatCount*/);
    sendAndConsumeKeyUp(1 /* deviceId */);
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_KeyRepeatAfterStaleDeviceKeyUp) {
    sendAndConsumeKeyDown(1 /* deviceId */);
    expectKeyRepeatOnce(1 /*repeatCount*/);
    sendAndConsumeKeyDown(2 /* deviceId */);
    expectKeyRepeatOnce(1 /*repeatCount*/);
    // Stale key up from device 1.
    sendAndConsumeKeyUp(1 /* deviceId */);
    // Device 2 is still down, keep repeating
    expectKeyRepeatOnce(2 /*repeatCount*/);
    expectKeyRepeatOnce(3 /*repeatCount*/);
    // Device 2 key up
    sendAndConsumeKeyUp(2 /* deviceId */);
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_KeyRepeatStopsAfterRepeatingKeyUp) {
    sendAndConsumeKeyDown(1 /* deviceId */);
    expectKeyRepeatOnce(1 /*repeatCount*/);
    sendAndConsumeKeyDown(2 /* deviceId */);
    expectKeyRepeatOnce(1 /*repeatCount*/);
    // Device 2 which holds the key repeating goes up, expect the repeating to stop.
    sendAndConsumeKeyUp(2 /* deviceId */);
    // Device 1 still holds key down, but the repeating was already stopped
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_RepeatKeyEventsUseEventIdFromInputDispatcher) {
    sendAndConsumeKeyDown(1 /* deviceId */);
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        InputEvent* repeatEvent = mWindow->consume();
        ASSERT_NE(nullptr, repeatEvent) << "Didn't receive event with repeat count " << repeatCount;
        EXPECT_EQ(IdGenerator::Source::INPUT_DISPATCHER,
                  IdGenerator::getSource(repeatEvent->getId()));
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_RepeatKeyEventsUseUniqueEventId) {
    sendAndConsumeKeyDown(1 /* deviceId */);

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
    static constexpr int32_t SECOND_DISPLAY_ID = 1;
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        application1 = std::make_shared<FakeApplicationHandle>();
        windowInPrimary =
                new FakeWindowHandle(application1, mDispatcher, "D_1", ADISPLAY_ID_DEFAULT);

        // Set focus window for primary display, but focused display would be second one.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application1);
        windowInPrimary->setFocusable(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowInPrimary}}});
        setFocusedWindow(windowInPrimary);
        windowInPrimary->consumeFocusEvent(true);

        application2 = std::make_shared<FakeApplicationHandle>();
        windowInSecondary =
                new FakeWindowHandle(application2, mDispatcher, "D_2", SECOND_DISPLAY_ID);
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
    windowInSecondary->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_NONE,
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
            new FakeWindowHandle(application1, mDispatcher, "D_1_W2", ADISPLAY_ID_DEFAULT);
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

class InputFilterTest : public InputDispatcherTest {
protected:
    static constexpr int32_t SECOND_DISPLAY_ID = 1;

    void testNotifyMotion(int32_t displayId, bool expectToBeFiltered) {
        NotifyMotionArgs motionArgs;

        motionArgs =
                generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN, displayId);
        mDispatcher->notifyMotion(&motionArgs);
        motionArgs =
                generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN, displayId);
        mDispatcher->notifyMotion(&motionArgs);
        ASSERT_TRUE(mDispatcher->waitForIdle());
        if (expectToBeFiltered) {
            mFakePolicy->assertFilterInputEventWasCalled(motionArgs);
        } else {
            mFakePolicy->assertFilterInputEventWasNotCalled();
        }
    }

    void testNotifyKey(bool expectToBeFiltered) {
        NotifyKeyArgs keyArgs;

        keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN);
        mDispatcher->notifyKey(&keyArgs);
        keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_UP);
        mDispatcher->notifyKey(&keyArgs);
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
        mWindow =
                new FakeWindowHandle(application, mDispatcher, "Test Window", ADISPLAY_ID_DEFAULT);

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
                         KEY_A, AMETA_NONE, 0 /*repeatCount*/, eventTime, eventTime);
        const int32_t additionalPolicyFlags =
                POLICY_FLAG_PASS_TO_USER | POLICY_FLAG_DISABLE_KEY_REPEAT;
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                                InputEventInjectionSync::WAIT_FOR_RESULT, 10ms,
                                                policyFlags | additionalPolicyFlags));

        InputEvent* received = mWindow->consume();
        ASSERT_NE(nullptr, received);
        ASSERT_EQ(resolvedDeviceId, received->getDeviceId());
        ASSERT_EQ(received->getType(), AINPUT_EVENT_TYPE_KEY);
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
                         AMOTION_EVENT_INVALID_CURSOR_POSITION,
                         0 /*AMOTION_EVENT_INVALID_DISPLAY_SIZE*/,
                         0 /*AMOTION_EVENT_INVALID_DISPLAY_SIZE*/, eventTime, eventTime,
                         /*pointerCount*/ 1, pointerProperties, pointerCoords);

        const int32_t additionalPolicyFlags = POLICY_FLAG_PASS_TO_USER;
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                                InputEventInjectionSync::WAIT_FOR_RESULT, 10ms,
                                                policyFlags | additionalPolicyFlags));

        InputEvent* received = mWindow->consume();
        ASSERT_NE(nullptr, received);
        ASSERT_EQ(resolvedDeviceId, received->getDeviceId());
        ASSERT_EQ(received->getType(), AINPUT_EVENT_TYPE_MOTION);
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
    testInjectedKey(POLICY_FLAG_FILTERED, 3 /*injectedDeviceId*/, 3 /*resolvedDeviceId*/,
                    0 /*flags*/);
}

TEST_F(InputFilterInjectionPolicyTest, KeyEventsInjectedFromAccessibility_HaveAccessibilityFlag) {
    testInjectedKey(POLICY_FLAG_FILTERED | POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY,
                    3 /*injectedDeviceId*/, 3 /*resolvedDeviceId*/,
                    AKEY_EVENT_FLAG_IS_ACCESSIBILITY_EVENT);
}

TEST_F(InputFilterInjectionPolicyTest,
       MotionEventsInjectedFromAccessibility_HaveAccessibilityFlag) {
    testInjectedMotion(POLICY_FLAG_FILTERED | POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY,
                       3 /*injectedDeviceId*/, 3 /*resolvedDeviceId*/,
                       AMOTION_EVENT_FLAG_IS_ACCESSIBILITY_EVENT);
}

TEST_F(InputFilterInjectionPolicyTest, RegularInjectedEvents_ReceiveVirtualDeviceId) {
    testInjectedKey(0 /*policyFlags*/, 3 /*injectedDeviceId*/,
                    VIRTUAL_KEYBOARD_ID /*resolvedDeviceId*/, 0 /*flags*/);
}

class InputDispatcherOnPointerDownOutsideFocus : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        std::shared_ptr<FakeApplicationHandle> application =
                std::make_shared<FakeApplicationHandle>();
        mUnfocusedWindow =
                new FakeWindowHandle(application, mDispatcher, "Top", ADISPLAY_ID_DEFAULT);
        mUnfocusedWindow->setFrame(Rect(0, 0, 30, 30));
        // Adding FLAG_NOT_TOUCH_MODAL to ensure taps outside this window are not sent to this
        // window.
        mUnfocusedWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

        mFocusedWindow =
                new FakeWindowHandle(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
        mFocusedWindow->setFrame(Rect(50, 50, 100, 100));
        mFocusedWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

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
                    .pointer(PointerBuilder(/* id */ 0, AMOTION_EVENT_TOOL_TYPE_FINGER).x(20).y(20))
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
        mWindow1 = new FakeWindowHandle(application, mDispatcher, "Fake Window 1",
                                        ADISPLAY_ID_DEFAULT);
        // Adding FLAG_NOT_TOUCH_MODAL otherwise all taps will go to the top most window.
        // We also need FLAG_SPLIT_TOUCH or we won't be able to get touches for both windows.
        mWindow1->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                           InputWindowInfo::Flag::SPLIT_TOUCH);
        mWindow1->setFrame(Rect(0, 0, 100, 100));

        mWindow2 = new FakeWindowHandle(application, mDispatcher, "Fake Window 2",
                                        ADISPLAY_ID_DEFAULT, mWindow1->getToken());
        mWindow2->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                           InputWindowInfo::Flag::SPLIT_TOUCH);
        mWindow2->setFrame(Rect(100, 100, 200, 200));

        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow1, mWindow2}}});
    }

protected:
    sp<FakeWindowHandle> mWindow1;
    sp<FakeWindowHandle> mWindow2;

    // Helper function to convert the point from screen coordinates into the window's space
    static PointF getPointInWindow(const InputWindowInfo* windowInfo, const PointF& point) {
        vec2 vals = windowInfo->transform.transform(point.x, point.y);
        return {vals.x, vals.y};
    }

    void consumeMotionEvent(const sp<FakeWindowHandle>& window, int32_t expectedAction,
                            const std::vector<PointF>& points) {
        const std::string name = window->getName();
        InputEvent* event = window->consume();

        ASSERT_NE(nullptr, event) << name.c_str()
                                  << ": consumer should have returned non-NULL event.";

        ASSERT_EQ(AINPUT_EVENT_TYPE_MOTION, event->getType())
                << name.c_str() << "expected " << inputEventTypeToString(AINPUT_EVENT_TYPE_MOTION)
                << " event, got " << inputEventTypeToString(event->getType()) << " event";

        const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*event);
        EXPECT_EQ(expectedAction, motionEvent.getAction());

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

    void touchAndAssertPositions(int32_t action, std::vector<PointF> touchedPoints,
                                 std::vector<PointF> expectedPoints) {
        NotifyMotionArgs motionArgs = generateMotionArgs(action, AINPUT_SOURCE_TOUCHSCREEN,
                                                         ADISPLAY_ID_DEFAULT, touchedPoints);
        mDispatcher->notifyMotion(&motionArgs);

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
    int32_t actionPointerDown =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchedPoints.push_back(PointF{150, 150});
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));
    touchAndAssertPositions(actionPointerDown, touchedPoints, expectedPoints);

    // Release Window 2
    int32_t actionPointerUp =
            AMOTION_EVENT_ACTION_POINTER_UP + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchAndAssertPositions(actionPointerUp, touchedPoints, expectedPoints);
    expectedPoints.pop_back();

    // Update the transform so rotation is set for Window 2
    mWindow2->setWindowTransform(0, -1, 1, 0);
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));
    touchAndAssertPositions(actionPointerDown, touchedPoints, expectedPoints);
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, MultipleTouchMoveDifferentTransform) {
    mWindow2->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    std::vector<PointF> touchedPoints = {PointF{10, 10}};
    std::vector<PointF> expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0])};
    touchAndAssertPositions(AMOTION_EVENT_ACTION_DOWN, touchedPoints, expectedPoints);

    // Touch Window 2
    int32_t actionPointerDown =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchedPoints.push_back(PointF{150, 150});
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));

    touchAndAssertPositions(actionPointerDown, touchedPoints, expectedPoints);

    // Move both windows
    touchedPoints = {{20, 20}, {175, 175}};
    expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0]),
                      getPointInWindow(mWindow2->getInfo(), touchedPoints[1])};

    touchAndAssertPositions(AMOTION_EVENT_ACTION_MOVE, touchedPoints, expectedPoints);

    // Release Window 2
    int32_t actionPointerUp =
            AMOTION_EVENT_ACTION_POINTER_UP + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchAndAssertPositions(actionPointerUp, touchedPoints, expectedPoints);
    expectedPoints.pop_back();

    // Touch Window 2
    mWindow2->setWindowTransform(0, -1, 1, 0);
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));
    touchAndAssertPositions(actionPointerDown, touchedPoints, expectedPoints);

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
    int32_t actionPointerDown =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchedPoints.push_back(PointF{150, 150});
    expectedPoints.push_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));

    touchAndAssertPositions(actionPointerDown, touchedPoints, expectedPoints);

    // Move both windows
    touchedPoints = {{20, 20}, {175, 175}};
    expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0]),
                      getPointInWindow(mWindow2->getInfo(), touchedPoints[1])};

    touchAndAssertPositions(AMOTION_EVENT_ACTION_MOVE, touchedPoints, expectedPoints);
}

class InputDispatcherSingleWindowAnr : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        mApplication = std::make_shared<FakeApplicationHandle>();
        mApplication->setDispatchingTimeout(20ms);
        mWindow =
                new FakeWindowHandle(mApplication, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mWindow->setFrame(Rect(0, 0, 30, 30));
        mWindow->setDispatchingTimeout(30ms);
        mWindow->setFocusable(true);
        // Adding FLAG_NOT_TOUCH_MODAL to ensure taps outside this window are not sent to this
        // window.
        mWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

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
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /*repeatCount*/, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::NONE, 10ms /*injectionTimeout*/,
                      false /* allowKeyRepeat */);
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
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow->getToken());

    mWindow->finishEvent(*sequenceNum);
    mWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_CANCEL,
                          ADISPLAY_ID_DEFAULT, 0 /*flags*/);
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken());
}

// Send a key to the app and have the app not respond right away.
TEST_F(InputDispatcherSingleWindowAnr, OnKeyDown_BasicAnr) {
    // Inject a key, and don't respond - expect that ANR is called.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyDownNoRepeat(mDispatcher));
    std::optional<uint32_t> sequenceNum = mWindow->receiveEvent();
    ASSERT_TRUE(sequenceNum);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow->getToken());
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
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::WAIT_FOR_RESULT, 10ms, false /* allowKeyRepeat */);
    ASSERT_EQ(InputEventInjectionResult::TIMED_OUT, result);
    const std::chrono::duration timeout = mApplication->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyNoFocusedWindowAnrWasCalled(timeout, mApplication);
    ASSERT_TRUE(mDispatcher->waitForIdle());
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
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::WAIT_FOR_RESULT, 10ms, false /* allowKeyRepeat */);
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
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
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
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow->getToken());
}

// If an app is not responding to a key event, gesture monitors should continue to receive
// new motion events
TEST_F(InputDispatcherSingleWindowAnr, GestureMonitors_ReceiveEventsDuringAppAnrOnKey) {
    FakeMonitorReceiver monitor =
            FakeMonitorReceiver(mDispatcher, "Gesture monitor", ADISPLAY_ID_DEFAULT,
                                true /*isGestureMonitor*/);

    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT));
    mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED, injectKeyUp(mDispatcher, ADISPLAY_ID_DEFAULT));

    // Stuck on the ACTION_UP
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow->getToken());

    // New tap will go to the gesture monitor, but not to the window
    tapOnWindow();
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeKeyUp(ADISPLAY_ID_DEFAULT); // still the previous motion
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken());
    mWindow->assertNoEvents();
    monitor.assertNoEvents();
}

// If an app is not responding to a motion event, gesture monitors should continue to receive
// new motion events
TEST_F(InputDispatcherSingleWindowAnr, GestureMonitors_ReceiveEventsDuringAppAnrOnMotion) {
    FakeMonitorReceiver monitor =
            FakeMonitorReceiver(mDispatcher, "Gesture monitor", ADISPLAY_ID_DEFAULT,
                                true /*isGestureMonitor*/);

    tapOnWindow();
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeMotionDown();
    // Stuck on the ACTION_UP
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow->getToken());

    // New tap will go to the gesture monitor, but not to the window
    tapOnWindow();
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT); // still the previous motion
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken());
    mWindow->assertNoEvents();
    monitor.assertNoEvents();
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
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow->getToken());
    mWindow->consumeMotionUp(); // Now the connection should be healthy again
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken());
    mWindow->assertNoEvents();

    tapOnWindow();
    mWindow->consumeMotionDown();
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mWindow->getToken());
    mWindow->consumeMotionUp();

    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken());
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
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(windowTimeout, mWindow->getToken());
    std::this_thread::sleep_for(windowTimeout);
    // 'notifyConnectionUnresponsive' should only be called once per connection
    mFakePolicy->assertNotifyAnrWasNotCalled();
    // When the ANR happened, dispatcher should abort the current event stream via ACTION_CANCEL
    mWindow->consumeMotionDown();
    mWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_CANCEL,
                          ADISPLAY_ID_DEFAULT, 0 /*flags*/);
    mWindow->assertNoEvents();
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mWindow->getToken());
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
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
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
              injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */,
                        ADISPLAY_ID_DEFAULT, InputEventInjectionSync::NONE));
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

class InputDispatcherMultiWindowAnr : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        mApplication = std::make_shared<FakeApplicationHandle>();
        mApplication->setDispatchingTimeout(10ms);
        mUnfocusedWindow =
                new FakeWindowHandle(mApplication, mDispatcher, "Unfocused", ADISPLAY_ID_DEFAULT);
        mUnfocusedWindow->setFrame(Rect(0, 0, 30, 30));
        // Adding FLAG_NOT_TOUCH_MODAL to ensure taps outside this window are not sent to this
        // window.
        // Adding FLAG_WATCH_OUTSIDE_TOUCH to receive ACTION_OUTSIDE when another window is tapped
        mUnfocusedWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                                   InputWindowInfo::Flag::WATCH_OUTSIDE_TOUCH |
                                   InputWindowInfo::Flag::SPLIT_TOUCH);

        mFocusedWindow =
                new FakeWindowHandle(mApplication, mDispatcher, "Focused", ADISPLAY_ID_DEFAULT);
        mFocusedWindow->setDispatchingTimeout(30ms);
        mFocusedWindow->setFrame(Rect(50, 50, 100, 100));
        mFocusedWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL |
                                 InputWindowInfo::Flag::SPLIT_TOUCH);

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
    mUnfocusedWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_OUTSIDE,
                                   ADISPLAY_ID_DEFAULT, 0 /*flags*/);
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
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mFocusedWindow->getToken());
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
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mFocusedWindow->getToken());
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
    sp<IBinder> anrConnectionToken1 = mFakePolicy->getUnresponsiveWindowToken(10ms);
    sp<IBinder> anrConnectionToken2 = mFakePolicy->getUnresponsiveWindowToken(0ms);

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

    sp<IBinder> responsiveToken1 = mFakePolicy->getResponsiveWindowToken();
    sp<IBinder> responsiveToken2 = mFakePolicy->getResponsiveWindowToken();

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
    mUnfocusedWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_OUTSIDE,
                                   ADISPLAY_ID_DEFAULT, 0 /*flags*/);
    // Receive the events, but don't respond
    std::optional<uint32_t> downEventSequenceNum = mFocusedWindow->receiveEvent(); // ACTION_DOWN
    ASSERT_TRUE(downEventSequenceNum);
    std::optional<uint32_t> upEventSequenceNum = mFocusedWindow->receiveEvent(); // ACTION_UP
    ASSERT_TRUE(upEventSequenceNum);
    const std::chrono::duration timeout =
            mFocusedWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mFocusedWindow->getToken());

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
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mFocusedWindow->getToken());
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
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /*repeatCount*/, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::NONE, 10ms /*injectionTimeout*/);
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
    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {FOCUSED_WINDOW_LOCATION});
    mDispatcher->notifyMotion(&motionArgs);
    mUnfocusedWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_OUTSIDE,
                                   ADISPLAY_ID_DEFAULT, 0 /*flags*/);

    // Touch Window 2
    int32_t actionPointerDown =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

    motionArgs =
            generateMotionArgs(actionPointerDown, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {FOCUSED_WINDOW_LOCATION, UNFOCUSED_WINDOW_LOCATION});
    mDispatcher->notifyMotion(&motionArgs);

    const std::chrono::duration timeout =
            mFocusedWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyWindowUnresponsiveWasCalled(timeout, mFocusedWindow->getToken());

    mUnfocusedWindow->consumeMotionDown();
    mFocusedWindow->consumeMotionDown();
    // Focused window may or may not receive ACTION_MOVE
    // But it should definitely receive ACTION_CANCEL due to the ANR
    InputEvent* event;
    std::optional<int32_t> moveOrCancelSequenceNum = mFocusedWindow->receiveEvent(&event);
    ASSERT_TRUE(moveOrCancelSequenceNum);
    mFocusedWindow->finishEvent(*moveOrCancelSequenceNum);
    ASSERT_NE(nullptr, event);
    ASSERT_EQ(event->getType(), AINPUT_EVENT_TYPE_MOTION);
    MotionEvent& motionEvent = static_cast<MotionEvent&>(*event);
    if (motionEvent.getAction() == AMOTION_EVENT_ACTION_MOVE) {
        mFocusedWindow->consumeMotionCancel();
    } else {
        ASSERT_EQ(AMOTION_EVENT_ACTION_CANCEL, motionEvent.getAction());
    }
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyWindowResponsiveWasCalled(mFocusedWindow->getToken());

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
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /*repeatCount*/, ADISPLAY_ID_DEFAULT,
                      InputEventInjectionSync::NONE, 10ms /*injectionTimeout*/,
                      false /* allowKeyRepeat */);
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
    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {UNFOCUSED_WINDOW_LOCATION});
    mDispatcher->notifyMotion(&motionArgs);

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
        mNoInputWindow = new FakeWindowHandle(mApplication, mDispatcher,
                                              "Window without input channel", ADISPLAY_ID_DEFAULT,
                                              std::make_optional<sp<IBinder>>(nullptr) /*token*/);

        mNoInputWindow->setInputFeatures(InputWindowInfo::Feature::NO_INPUT_CHANNEL);
        mNoInputWindow->setFrame(Rect(0, 0, 100, 100));
        // It's perfectly valid for this window to not have an associated input channel

        mBottomWindow = new FakeWindowHandle(mApplication, mDispatcher, "Bottom window",
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

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);

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
    mNoInputWindow = new FakeWindowHandle(mApplication, mDispatcher,
                                          "Window with input channel and NO_INPUT_CHANNEL",
                                          ADISPLAY_ID_DEFAULT);

    mNoInputWindow->setInputFeatures(InputWindowInfo::Feature::NO_INPUT_CHANNEL);
    mNoInputWindow->setFrame(Rect(0, 0, 100, 100));
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mNoInputWindow, mBottomWindow}}});

    PointF touchedPoint = {10, 10};

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);

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
        mWindow = new FakeWindowHandle(mApp, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mMirror = new FakeWindowHandle(mApp, mDispatcher, "TestWindowMirror", ADISPLAY_ID_DEFAULT,
                                       mWindow->getToken());
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
              injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */,
                        ADISPLAY_ID_DEFAULT, InputEventInjectionSync::NONE));

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
        mWindow = new FakeWindowHandle(mApp, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mWindow->setFocusable(true);
        mSecondWindow = new FakeWindowHandle(mApp, mDispatcher, "TestWindow2", ADISPLAY_ID_DEFAULT);
        mSecondWindow->setFocusable(true);

        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApp);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mSecondWindow}}});

        setFocusedWindow(mWindow);
        mWindow->consumeFocusEvent(true);
    }

    void notifyPointerCaptureChanged(const PointerCaptureRequest& request) {
        const NotifyPointerCaptureChangedArgs args = generatePointerCaptureChangedArgs(request);
        mDispatcher->notifyPointerCaptureChanged(&args);
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

    static const int32_t TOUCHED_APP_UID = 10001;
    static const int32_t APP_B_UID = 10002;
    static const int32_t APP_C_UID = 10003;

    sp<FakeWindowHandle> mTouchWindow;

    virtual void SetUp() override {
        InputDispatcherTest::SetUp();
        mTouchWindow = getWindow(TOUCHED_APP_UID, "Touched");
        mDispatcher->setBlockUntrustedTouchesMode(android::os::BlockUntrustedTouchesMode::BLOCK);
        mDispatcher->setMaximumObscuringOpacityForTouch(MAXIMUM_OBSCURING_OPACITY);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();
        mTouchWindow.clear();
    }

    sp<FakeWindowHandle> getOccludingWindow(int32_t uid, std::string name,
                                            os::TouchOcclusionMode mode, float alpha = 1.0f) {
        sp<FakeWindowHandle> window = getWindow(uid, name);
        window->setFlags(InputWindowInfo::Flag::NOT_TOUCHABLE);
        window->setTouchOcclusionMode(mode);
        window->setAlpha(alpha);
        return window;
    }

    sp<FakeWindowHandle> getWindow(int32_t uid, std::string name) {
        std::shared_ptr<FakeApplicationHandle> app = std::make_shared<FakeApplicationHandle>();
        sp<FakeWindowHandle> window =
                new FakeWindowHandle(app, mDispatcher, name, ADISPLAY_ID_DEFAULT);
        // Generate an arbitrary PID based on the UID
        window->setOwnerInfo(1777 + (uid % 10000), uid);
        return window;
    }

    void touch(const std::vector<PointF>& points = {PointF{100, 200}}) {
        NotifyMotionArgs args =
                generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                   ADISPLAY_ID_DEFAULT, points);
        mDispatcher->notifyMotion(&args);
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
    w->addFlags(InputWindowInfo::Flag::WATCH_OUTSIDE_TOUCH);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    w->consumeMotionOutside();
}

TEST_F(InputDispatcherUntrustedTouchesTest, OutsideEvent_HasZeroCoordinates) {
    const sp<FakeWindowHandle>& w =
            getOccludingWindow(APP_B_UID, "B", TouchOcclusionMode::BLOCK_UNTRUSTED, 0.0f);
    w->addFlags(InputWindowInfo::Flag::WATCH_OUTSIDE_TOUCH);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {w, mTouchWindow}}});

    touch();

    InputEvent* event = w->consume();
    ASSERT_EQ(AINPUT_EVENT_TYPE_MOTION, event->getType());
    MotionEvent& motionEvent = static_cast<MotionEvent&>(*event);
    EXPECT_EQ(0.0f, motionEvent.getRawPointerCoords(0)->getX());
    EXPECT_EQ(0.0f, motionEvent.getRawPointerCoords(0)->getY());
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

    void SetUp() override {
        InputDispatcherTest::SetUp();
        mApp = std::make_shared<FakeApplicationHandle>();
        mWindow = new FakeWindowHandle(mApp, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mWindow->setFrame(Rect(0, 0, 100, 100));
        mWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

        mSecondWindow = new FakeWindowHandle(mApp, mDispatcher, "TestWindow2", ADISPLAY_ID_DEFAULT);
        mSecondWindow->setFrame(Rect(100, 0, 200, 100));
        mSecondWindow->setFlags(InputWindowInfo::Flag::NOT_TOUCH_MODAL);

        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApp);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow, mSecondWindow}}});
    }

    // Start performing drag, we will create a drag window and transfer touch to it.
    void performDrag() {
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                   {50, 50}))
                << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";

        // Window should receive motion event.
        mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);

        // The drag window covers the entire display
        mDragWindow = new FakeWindowHandle(mApp, mDispatcher, "DragWindow", ADISPLAY_ID_DEFAULT);
        mDispatcher->setInputWindows(
                {{ADISPLAY_ID_DEFAULT, {mDragWindow, mWindow, mSecondWindow}}});

        // Transfer touch focus to the drag window
        mDispatcher->transferTouchFocus(mWindow->getToken(), mDragWindow->getToken(),
                                        true /* isDragDrop */);
        mWindow->consumeMotionCancel();
        mDragWindow->consumeMotionDown();
    }

    // Start performing drag, we will create a drag window and transfer touch to it.
    void performStylusDrag() {
        ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
                  injectMotionEvent(mDispatcher,
                                    MotionEventBuilder(AMOTION_EVENT_ACTION_DOWN,
                                                       AINPUT_SOURCE_STYLUS)
                                            .buttonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY)
                                            .pointer(PointerBuilder(0,
                                                                    AMOTION_EVENT_TOOL_TYPE_STYLUS)
                                                             .x(50)
                                                             .y(50))
                                            .build()));
        mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);

        // The drag window covers the entire display
        mDragWindow = new FakeWindowHandle(mApp, mDispatcher, "DragWindow", ADISPLAY_ID_DEFAULT);
        mDispatcher->setInputWindows(
                {{ADISPLAY_ID_DEFAULT, {mDragWindow, mWindow, mSecondWindow}}});

        // Transfer touch focus to the drag window
        mDispatcher->transferTouchFocus(mWindow->getToken(), mDragWindow->getToken(),
                                        true /* isDragDrop */);
        mWindow->consumeMotionCancel();
        mDragWindow->consumeMotionDown();
    }
};

TEST_F(InputDispatcherDragTests, DragEnterAndDragExit) {
    performDrag();

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

TEST_F(InputDispatcherDragTests, DragAndDrop) {
    performDrag();

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
    mFakePolicy->assertDropTargetEquals(mSecondWindow->getToken());
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, StylusDragAndDrop) {
    performStylusDrag();

    // Move on window and keep button pressed.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_STYLUS)
                                        .buttonState(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_STYLUS)
                                                         .x(50)
                                                         .y(50))
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
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_STYLUS)
                                                         .x(150)
                                                         .y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionMove(ADISPLAY_ID_DEFAULT);
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
    mFakePolicy->assertDropTargetEquals(mSecondWindow->getToken());

    // nothing to the window.
    ASSERT_EQ(InputEventInjectionResult::SUCCEEDED,
              injectMotionEvent(mDispatcher,
                                MotionEventBuilder(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_STYLUS)
                                        .buttonState(0)
                                        .pointer(PointerBuilder(0, AMOTION_EVENT_TOOL_TYPE_STYLUS)
                                                         .x(150)
                                                         .y(50))
                                        .build()))
            << "Inject motion event should return InputEventInjectionResult::SUCCEEDED";
    mDragWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT);
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

TEST_F(InputDispatcherDragTests, DragAndDrop_InvalidWindow) {
    performDrag();

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
    mFakePolicy->assertDropTargetEquals(nullptr);
    mWindow->assertNoEvents();
    mSecondWindow->assertNoEvents();
}

} // namespace android::inputdispatcher
