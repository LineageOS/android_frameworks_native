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
#include <input/Input.h>

#include <gtest/gtest.h>
#include <linux/input.h>
#include <cinttypes>
#include <thread>
#include <unordered_set>
#include <vector>

using android::base::StringPrintf;

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
    virtual ~FakeInputDispatcherPolicy() {
    }

public:
    FakeInputDispatcherPolicy() {
    }

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
    void assertNotifyAnrWasCalled(std::chrono::nanoseconds timeout,
                                  const sp<InputApplicationHandle>& expectedApplication,
                                  const sp<IBinder>& expectedToken) {
        std::pair<sp<InputApplicationHandle>, sp<IBinder>> anrData;
        ASSERT_NO_FATAL_FAILURE(anrData = getNotifyAnrData(timeout));
        ASSERT_EQ(expectedApplication, anrData.first);
        ASSERT_EQ(expectedToken, anrData.second);
    }

    std::pair<sp<InputApplicationHandle>, sp<IBinder>> getNotifyAnrData(
            std::chrono::nanoseconds timeout) {
        const std::chrono::time_point start = std::chrono::steady_clock::now();
        std::unique_lock lock(mLock);
        std::chrono::duration timeToWait = timeout + 100ms; // provide some slack
        android::base::ScopedLockAssertion assumeLocked(mLock);

        // If there is an ANR, Dispatcher won't be idle because there are still events
        // in the waitQueue that we need to check on. So we can't wait for dispatcher to be idle
        // before checking if ANR was called.
        // Since dispatcher is not guaranteed to call notifyAnr right away, we need to provide
        // it some time to act. 100ms seems reasonable.
        mNotifyAnr.wait_for(lock, timeToWait, [this]() REQUIRES(mLock) {
            return !mAnrApplications.empty() && !mAnrWindowTokens.empty();
        });
        const std::chrono::duration waited = std::chrono::steady_clock::now() - start;
        if (mAnrApplications.empty() || mAnrWindowTokens.empty()) {
            ADD_FAILURE() << "Did not receive ANR callback";
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
        std::pair<sp<InputApplicationHandle>, sp<IBinder>> result =
                std::make_pair(mAnrApplications.front(), mAnrWindowTokens.front());
        mAnrApplications.pop();
        mAnrWindowTokens.pop();
        return result;
    }

    void assertNotifyAnrWasNotCalled() {
        std::scoped_lock lock(mLock);
        ASSERT_TRUE(mAnrApplications.empty());
        ASSERT_TRUE(mAnrWindowTokens.empty());
    }

    void setKeyRepeatConfiguration(nsecs_t timeout, nsecs_t delay) {
        mConfig.keyRepeatTimeout = timeout;
        mConfig.keyRepeatDelay = delay;
    }

    void setAnrTimeout(std::chrono::nanoseconds timeout) { mAnrTimeout = timeout; }

private:
    std::mutex mLock;
    std::unique_ptr<InputEvent> mFilteredEvent GUARDED_BY(mLock);
    std::optional<nsecs_t> mConfigurationChangedTime GUARDED_BY(mLock);
    sp<IBinder> mOnPointerDownToken GUARDED_BY(mLock);
    std::optional<NotifySwitchArgs> mLastNotifySwitch GUARDED_BY(mLock);

    // ANR handling
    std::queue<sp<InputApplicationHandle>> mAnrApplications GUARDED_BY(mLock);
    std::queue<sp<IBinder>> mAnrWindowTokens GUARDED_BY(mLock);
    std::condition_variable mNotifyAnr;
    std::chrono::nanoseconds mAnrTimeout = 0ms;

    virtual void notifyConfigurationChanged(nsecs_t when) override {
        std::scoped_lock lock(mLock);
        mConfigurationChangedTime = when;
    }

    virtual nsecs_t notifyAnr(const sp<InputApplicationHandle>& application,
                              const sp<IBinder>& windowToken, const std::string&) override {
        std::scoped_lock lock(mLock);
        mAnrApplications.push(application);
        mAnrWindowTokens.push(windowToken);
        mNotifyAnr.notify_all();
        return mAnrTimeout.count();
    }

    virtual void notifyInputChannelBroken(const sp<IBinder>&) override {}

    virtual void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) override {}

    virtual void getDispatcherConfiguration(InputDispatcherConfiguration* outConfig) override {
        *outConfig = mConfig;
    }

    virtual bool filterInputEvent(const InputEvent* inputEvent, uint32_t policyFlags) override {
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

    virtual void interceptKeyBeforeQueueing(const KeyEvent*, uint32_t&) override {}

    virtual void interceptMotionBeforeQueueing(int32_t, nsecs_t, uint32_t&) override {}

    virtual nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent*,
                                                  uint32_t) override {
        return 0;
    }

    virtual bool dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent*, uint32_t,
                                      KeyEvent*) override {
        return false;
    }

    virtual void notifySwitch(nsecs_t when, uint32_t switchValues, uint32_t switchMask,
                              uint32_t policyFlags) override {
        std::scoped_lock lock(mLock);
        /** We simply reconstruct NotifySwitchArgs in policy because InputDispatcher is
         * essentially a passthrough for notifySwitch.
         */
        mLastNotifySwitch = NotifySwitchArgs(1 /*id*/, when, policyFlags, switchValues, switchMask);
    }

    virtual void pokeUserActivity(nsecs_t, int32_t) override {}

    virtual bool checkInjectEventsPermissionNonReentrant(int32_t, int32_t) override {
        return false;
    }

    virtual void onPointerDownOutsideFocus(const sp<IBinder>& newToken) override {
        std::scoped_lock lock(mLock);
        mOnPointerDownToken = newToken;
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

// --- HmacKeyManagerTest ---

class HmacKeyManagerTest : public testing::Test {
protected:
    HmacKeyManager mHmacKeyManager;
};

/**
 * Ensure that separate calls to sign the same data are generating the same key.
 * We avoid asserting against INVALID_HMAC. Since the key is random, there is a non-zero chance
 * that a specific key and data combination would produce INVALID_HMAC, which would cause flaky
 * tests.
 */
TEST_F(HmacKeyManagerTest, GeneratedHmac_IsConsistent) {
    KeyEvent event = getTestKeyEvent();
    VerifiedKeyEvent verifiedEvent = verifiedKeyEventFromKeyEvent(event);

    std::array<uint8_t, 32> hmac1 = mHmacKeyManager.sign(verifiedEvent);
    std::array<uint8_t, 32> hmac2 = mHmacKeyManager.sign(verifiedEvent);
    ASSERT_EQ(hmac1, hmac2);
}

/**
 * Ensure that changes in VerifiedKeyEvent produce a different hmac.
 */
TEST_F(HmacKeyManagerTest, GeneratedHmac_ChangesWhenFieldsChange) {
    KeyEvent event = getTestKeyEvent();
    VerifiedKeyEvent verifiedEvent = verifiedKeyEventFromKeyEvent(event);
    std::array<uint8_t, 32> initialHmac = mHmacKeyManager.sign(verifiedEvent);

    verifiedEvent.deviceId += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.source += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.eventTimeNanos += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.displayId += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.action += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.downTimeNanos += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.flags += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.keyCode += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.scanCode += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.metaState += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));

    verifiedEvent.repeatCount += 1;
    ASSERT_NE(initialHmac, mHmacKeyManager.sign(verifiedEvent));
}

// --- InputDispatcherTest ---

class InputDispatcherTest : public testing::Test {
protected:
    sp<FakeInputDispatcherPolicy> mFakePolicy;
    sp<InputDispatcher> mDispatcher;

    virtual void SetUp() override {
        mFakePolicy = new FakeInputDispatcherPolicy();
        mDispatcher = new InputDispatcher(mFakePolicy);
        mDispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
        //Start InputDispatcher thread
        ASSERT_EQ(OK, mDispatcher->start());
    }

    virtual void TearDown() override {
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
};


TEST_F(InputDispatcherTest, InjectInputEvent_ValidatesKeyEvents) {
    KeyEvent event;

    // Rejects undefined key actions.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
                     INVALID_HMAC,
                     /*action*/ -1, 0, AKEYCODE_A, KEY_A, AMETA_NONE, 0, ARBITRARY_TIME,
                     ARBITRARY_TIME);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject key events with undefined action.";

    // Rejects ACTION_MULTIPLE since it is not supported despite being defined in the API.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
                     INVALID_HMAC, AKEY_EVENT_ACTION_MULTIPLE, 0, AKEYCODE_A, KEY_A, AMETA_NONE, 0,
                     ARBITRARY_TIME, ARBITRARY_TIME);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
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

    // Rejects undefined motion actions.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     /*action*/ -1, 0, 0, edgeFlags, metaState, 0, classification, 1 /* xScale */,
                     1 /* yScale */, 0, 0, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with undefined action.";

    // Rejects pointer down with invalid index.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                             (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 1 /* xScale */, 1 /* yScale */,
                     0, 0, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with pointer down index too large.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 1 /* xScale */, 1 /* yScale */,
                     0, 0, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with pointer down index too small.";

    // Rejects pointer up with invalid index.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_UP |
                             (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 1 /* xScale */, 1 /* yScale */,
                     0, 0, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with pointer up index too large.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_POINTER_UP |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 1 /* xScale */, 1 /* yScale */,
                     0, 0, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with pointer up index too small.";

    // Rejects motion events with invalid number of pointers.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     1 /* xScale */, 1 /* yScale */, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 0, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with 0 pointers.";

    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     1 /* xScale */, 1 /* yScale */, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ MAX_POINTERS + 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with more than MAX_POINTERS pointers.";

    // Rejects motion events with invalid pointer ids.
    pointerProperties[0].id = -1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     1 /* xScale */, 1 /* yScale */, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with pointer ids less than 0.";

    pointerProperties[0].id = MAX_POINTER_ID + 1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     1 /* xScale */, 1 /* yScale */, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
            << "Should reject motion events with pointer ids greater than MAX_POINTER_ID.";

    // Rejects motion events with duplicate pointer ids.
    pointerProperties[0].id = 1;
    pointerProperties[1].id = 1;
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, DISPLAY_ID, INVALID_HMAC,
                     AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags, metaState, 0, classification,
                     1 /* xScale */, 1 /* yScale */, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 2, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              mDispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                            INPUT_EVENT_INJECTION_SYNC_NONE, 0ms, 0))
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
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT.count();
    }
    virtual ~FakeApplicationHandle() {}

    virtual bool updateInfo() override {
        return true;
    }

    void setDispatchingTimeout(std::chrono::nanoseconds timeout) {
        mInfo.dispatchingTimeout = timeout.count();
    }
};

class FakeInputReceiver {
public:
    explicit FakeInputReceiver(const sp<InputChannel>& clientChannel, const std::string name)
          : mName(name) {
        mConsumer = std::make_unique<InputConsumer>(clientChannel);
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

    void consumeEvent(int32_t expectedEventType, int32_t expectedAction, int32_t expectedDisplayId,
                      int32_t expectedFlags) {
        InputEvent* event = consume();

        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(expectedEventType, event->getType())
                << mName.c_str() << " expected " << inputEventTypeToString(expectedEventType)
                << " event, got " << inputEventTypeToString(event->getType()) << " event";

        EXPECT_EQ(expectedDisplayId, event->getDisplayId());

        switch (expectedEventType) {
            case AINPUT_EVENT_TYPE_KEY: {
                const KeyEvent& keyEvent = static_cast<const KeyEvent&>(*event);
                EXPECT_EQ(expectedAction, keyEvent.getAction());
                EXPECT_EQ(expectedFlags, keyEvent.getFlags());
                break;
            }
            case AINPUT_EVENT_TYPE_MOTION: {
                const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*event);
                EXPECT_EQ(expectedAction, motionEvent.getAction());
                EXPECT_EQ(expectedFlags, motionEvent.getFlags());
                break;
            }
            case AINPUT_EVENT_TYPE_FOCUS: {
                FAIL() << "Use 'consumeFocusEvent' for FOCUS events";
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

    FakeWindowHandle(const sp<InputApplicationHandle>& inputApplicationHandle,
                     const sp<InputDispatcher>& dispatcher, const std::string name,
                     int32_t displayId, sp<IBinder> token = nullptr)
          : mName(name) {
        if (token == nullptr) {
            sp<InputChannel> serverChannel, clientChannel;
            InputChannel::openInputChannelPair(name, serverChannel, clientChannel);
            mInputReceiver = std::make_unique<FakeInputReceiver>(clientChannel, name);
            dispatcher->registerInputChannel(serverChannel);
            token = serverChannel->getConnectionToken();
        }

        inputApplicationHandle->updateInfo();
        mInfo.applicationInfo = *inputApplicationHandle->getInfo();

        mInfo.token = token;
        mInfo.id = sId++;
        mInfo.name = name;
        mInfo.layoutParamsFlags = 0;
        mInfo.layoutParamsType = InputWindowInfo::TYPE_APPLICATION;
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT.count();
        mInfo.frameLeft = 0;
        mInfo.frameTop = 0;
        mInfo.frameRight = WIDTH;
        mInfo.frameBottom = HEIGHT;
        mInfo.globalScaleFactor = 1.0;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(Rect(0, 0, WIDTH, HEIGHT));
        mInfo.visible = true;
        mInfo.canReceiveKeys = true;
        mInfo.hasFocus = false;
        mInfo.hasWallpaper = false;
        mInfo.paused = false;
        mInfo.ownerPid = INJECTOR_PID;
        mInfo.ownerUid = INJECTOR_UID;
        mInfo.inputFeatures = 0;
        mInfo.displayId = displayId;
    }

    virtual bool updateInfo() { return true; }

    void setFocus(bool hasFocus) { mInfo.hasFocus = hasFocus; }

    void setDispatchingTimeout(std::chrono::nanoseconds timeout) {
        mInfo.dispatchingTimeout = timeout.count();
    }

    void setPaused(bool paused) { mInfo.paused = paused; }

    void setFrame(const Rect& frame) {
        mInfo.frameLeft = frame.left;
        mInfo.frameTop = frame.top;
        mInfo.frameRight = frame.right;
        mInfo.frameBottom = frame.bottom;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(frame);
    }

    void setLayoutParamFlags(int32_t flags) { mInfo.layoutParamsFlags = flags; }

    void setWindowScale(float xScale, float yScale) {
        mInfo.windowXScale = xScale;
        mInfo.windowYScale = yScale;
    }

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
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_DOWN, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionPointerDown(int32_t pointerIdx,
            int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT, int32_t expectedFlags = 0) {
        int32_t action = AMOTION_EVENT_ACTION_POINTER_DOWN
                | (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, action, expectedDisplayId, expectedFlags);
    }

    void consumeMotionPointerUp(int32_t pointerIdx, int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
            int32_t expectedFlags = 0) {
        int32_t action = AMOTION_EVENT_ACTION_POINTER_UP
                | (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, action, expectedDisplayId, expectedFlags);
    }

    void consumeMotionUp(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
            int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_UP, expectedDisplayId,
                     expectedFlags);
    }

    void consumeFocusEvent(bool hasFocus, bool inTouchMode = true) {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Cannot consume events from a window with no receiver";
        mInputReceiver->consumeFocusEvent(hasFocus, inTouchMode);
    }

    void consumeEvent(int32_t expectedEventType, int32_t expectedAction, int32_t expectedDisplayId,
                      int32_t expectedFlags) {
        ASSERT_NE(mInputReceiver, nullptr) << "Invalid consume event on window with no receiver";
        mInputReceiver->consumeEvent(expectedEventType, expectedAction, expectedDisplayId,
                                     expectedFlags);
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

    InputEvent* consume() {
        if (mInputReceiver == nullptr) {
            return nullptr;
        }
        return mInputReceiver->consume();
    }

    void assertNoEvents() {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Call 'assertNoEvents' on a window with an InputReceiver";
        mInputReceiver->assertNoEvents();
    }

    sp<IBinder> getToken() { return mInfo.token; }

    const std::string& getName() { return mName; }

private:
    const std::string mName;
    std::unique_ptr<FakeInputReceiver> mInputReceiver;
    static std::atomic<int32_t> sId; // each window gets a unique id, like in surfaceflinger
};

std::atomic<int32_t> FakeWindowHandle::sId{1};

static int32_t injectKey(const sp<InputDispatcher>& dispatcher, int32_t action, int32_t repeatCount,
                         int32_t displayId = ADISPLAY_ID_NONE,
                         int32_t syncMode = INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT,
                         std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT) {
    KeyEvent event;
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);

    // Define a valid key down event.
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_KEYBOARD, displayId,
                     INVALID_HMAC, action, /* flags */ 0, AKEYCODE_A, KEY_A, AMETA_NONE,
                     repeatCount, currentTime, currentTime);

    // Inject event until dispatch out.
    return dispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID, syncMode,
                                        injectionTimeout,
                                        POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);
}

static int32_t injectKeyDown(const sp<InputDispatcher>& dispatcher,
                             int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_DOWN, /* repeatCount */ 0, displayId);
}

static int32_t injectKeyUp(const sp<InputDispatcher>& dispatcher,
                           int32_t displayId = ADISPLAY_ID_NONE) {
    return injectKey(dispatcher, AKEY_EVENT_ACTION_UP, /* repeatCount */ 0, displayId);
}

static int32_t injectMotionEvent(
        const sp<InputDispatcher>& dispatcher, int32_t action, int32_t source, int32_t displayId,
        const PointF& position,
        const PointF& cursorPosition = {AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                        AMOTION_EVENT_INVALID_CURSOR_POSITION},
        std::chrono::milliseconds injectionTimeout = INJECT_EVENT_TIMEOUT,
        int32_t injectionMode = INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT,
        nsecs_t eventTime = systemTime(SYSTEM_TIME_MONOTONIC)) {
    MotionEvent event;
    PointerProperties pointerProperties[1];
    PointerCoords pointerCoords[1];

    pointerProperties[0].clear();
    pointerProperties[0].id = 0;
    pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, position.x);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, position.y);

    // Define a valid motion down event.
    event.initialize(InputEvent::nextId(), DEVICE_ID, source, displayId, INVALID_HMAC, action,
                     /* actionButton */ 0,
                     /* flags */ 0,
                     /* edgeFlags */ 0, AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                     /* xScale */ 1, /* yScale */ 1, /* xOffset */ 0, /* yOffset */ 0,
                     /* xPrecision */ 0, /* yPrecision */ 0, cursorPosition.x, cursorPosition.y,
                     eventTime, eventTime,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);

    // Inject event until dispatch out.
    return dispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID, injectionMode,
                                        injectionTimeout,
                                        POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);
}

static int32_t injectMotionDown(const sp<InputDispatcher>& dispatcher, int32_t source,
                                int32_t displayId, const PointF& location = {100, 200}) {
    return injectMotionEvent(dispatcher, AMOTION_EVENT_ACTION_DOWN, source, displayId, location);
}

static int32_t injectMotionUp(const sp<InputDispatcher>& dispatcher, int32_t source,
                              int32_t displayId, const PointF& location = {100, 200}) {
    return injectMotionEvent(dispatcher, AMOTION_EVENT_ACTION_UP, source, displayId, location);
}

static NotifyKeyArgs generateKeyArgs(int32_t action, int32_t displayId = ADISPLAY_ID_NONE) {
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid key event.
    NotifyKeyArgs args(/* id */ 0, currentTime, DEVICE_ID, AINPUT_SOURCE_KEYBOARD, displayId,
                       POLICY_FLAG_PASS_TO_USER, action, /* flags */ 0, AKEYCODE_A, KEY_A,
                       AMETA_NONE, currentTime);

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
    NotifyMotionArgs args(/* id */ 0, currentTime, DEVICE_ID, source, displayId,
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

TEST_F(InputDispatcherTest, SetInputWindow_SingleWindowTouch) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window = new FakeWindowHandle(application, mDispatcher, "Fake Window",
            ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";

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
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));
    window->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";

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
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFrame(Rect(0, 0, 100, 100));
    window->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {50, 50}))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    // Window should receive motion event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

// The foreground window should receive the first touch down event.
TEST_F(InputDispatcherTest, SetInputWindow_MultiWindowsTouch) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> windowTop = new FakeWindowHandle(application, mDispatcher, "Top",
            ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond = new FakeWindowHandle(application, mDispatcher, "Second",
            ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    // Top window should receive the touch down event. Second window should not receive anything.
    windowTop->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowSecond->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetInputWindow_FocusedWindow) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> windowTop = new FakeWindowHandle(application, mDispatcher, "Top",
            ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond = new FakeWindowHandle(application, mDispatcher, "Second",
            ADISPLAY_ID_DEFAULT);

    // Set focused application.
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    // Display should have only one focused window
    windowSecond->setFocus(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});

    windowSecond->consumeFocusEvent(true);
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    // Focused window should receive event.
    windowTop->assertNoEvents();
    windowSecond->consumeKeyDown(ADISPLAY_ID_NONE);
}

TEST_F(InputDispatcherTest, SetInputWindow_FocusPriority) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> windowTop = new FakeWindowHandle(application, mDispatcher, "Top",
            ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond = new FakeWindowHandle(application, mDispatcher, "Second",
            ADISPLAY_ID_DEFAULT);

    // Set focused application.
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    // Display has two focused windows. Add them to inputWindowsHandles in z-order (top most first)
    windowTop->setFocus(true);
    windowSecond->setFocus(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    windowTop->consumeFocusEvent(true);
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    // Top focused window should receive event.
    windowTop->consumeKeyDown(ADISPLAY_ID_NONE);
    windowSecond->assertNoEvents();
}

TEST_F(InputDispatcherTest, SetInputWindow_InputWindowInfo) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();

    sp<FakeWindowHandle> windowTop = new FakeWindowHandle(application, mDispatcher, "Top",
            ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> windowSecond = new FakeWindowHandle(application, mDispatcher, "Second",
            ADISPLAY_ID_DEFAULT);

    // Set focused application.
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    windowTop->setFocus(true);
    windowSecond->setFocus(true);
    // Release channel for window is no longer valid.
    windowTop->releaseChannel();
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowTop, windowSecond}}});
    windowSecond->consumeFocusEvent(true);

    // Test inject a key down, should dispatch to a valid window.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    // Top window is invalid, so it should not receive any input event.
    windowTop->assertNoEvents();
    windowSecond->consumeKeyDown(ADISPLAY_ID_NONE);
}

TEST_F(InputDispatcherTest, DispatchMouseEventsUnderCursor) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();

    sp<FakeWindowHandle> windowLeft =
            new FakeWindowHandle(application, mDispatcher, "Left", ADISPLAY_ID_DEFAULT);
    windowLeft->setFrame(Rect(0, 0, 600, 800));
    windowLeft->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL);
    sp<FakeWindowHandle> windowRight =
            new FakeWindowHandle(application, mDispatcher, "Right", ADISPLAY_ID_DEFAULT);
    windowRight->setFrame(Rect(600, 0, 1200, 800));
    windowRight->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowLeft, windowRight}}});

    // Inject an event with coordinate in the area of right window, with mouse cursor in the area of
    // left window. This event should be dispatched to the left window.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE,
                                ADISPLAY_ID_DEFAULT, {610, 400}, {599, 400}));
    windowLeft->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowRight->assertNoEvents();
}

TEST_F(InputDispatcherTest, NotifyDeviceReset_CancelsKeyStream) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFocus(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
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
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
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

TEST_F(InputDispatcherTest, TransferTouchFocus_OnePointer) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();

    // Create a couple of windows
    sp<FakeWindowHandle> firstWindow = new FakeWindowHandle(application, mDispatcher,
            "First Window", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> secondWindow = new FakeWindowHandle(application, mDispatcher,
            "Second Window", ADISPLAY_ID_DEFAULT);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    // Send down to the first window
    NotifyMotionArgs downMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&downMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Transfer touch focus to the second window
    mDispatcher->transferTouchFocus(firstWindow->getToken(), secondWindow->getToken());
    // The first window gets cancel and the second gets down
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionDown();

    // Send up event to the second window
    NotifyMotionArgs upMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_UP,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
    // The first  window gets no events and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
}

TEST_F(InputDispatcherTest, TransferTouchFocus_TwoPointerNoSplitTouch) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();

    PointF touchPoint = {10, 10};

    // Create a couple of windows
    sp<FakeWindowHandle> firstWindow = new FakeWindowHandle(application, mDispatcher,
            "First Window", ADISPLAY_ID_DEFAULT);
    sp<FakeWindowHandle> secondWindow = new FakeWindowHandle(application, mDispatcher,
            "Second Window", ADISPLAY_ID_DEFAULT);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    // Send down to the first window
    NotifyMotionArgs downMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {touchPoint});
    mDispatcher->notifyMotion(&downMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send pointer down to the first window
    NotifyMotionArgs pointerDownMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_DOWN
            | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {touchPoint, touchPoint});
    mDispatcher->notifyMotion(&pointerDownMotionArgs);
    // Only the first window should get the pointer down event
    firstWindow->consumeMotionPointerDown(1);
    secondWindow->assertNoEvents();

    // Transfer touch focus to the second window
    mDispatcher->transferTouchFocus(firstWindow->getToken(), secondWindow->getToken());
    // The first window gets cancel and the second gets down and pointer down
    firstWindow->consumeMotionCancel();
    secondWindow->consumeMotionDown();
    secondWindow->consumeMotionPointerDown(1);

    // Send pointer up to the second window
    NotifyMotionArgs pointerUpMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_UP
            | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {touchPoint, touchPoint});
    mDispatcher->notifyMotion(&pointerUpMotionArgs);
    // The first window gets nothing and the second gets pointer up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionPointerUp(1);

    // Send up event to the second window
    NotifyMotionArgs upMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_UP,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
    // The first window gets nothing and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
}

TEST_F(InputDispatcherTest, TransferTouchFocus_TwoPointersSplitTouch) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();

    // Create a non touch modal window that supports split touch
    sp<FakeWindowHandle> firstWindow = new FakeWindowHandle(application, mDispatcher,
            "First Window", ADISPLAY_ID_DEFAULT);
    firstWindow->setFrame(Rect(0, 0, 600, 400));
    firstWindow->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL
            | InputWindowInfo::FLAG_SPLIT_TOUCH);

    // Create a non touch modal window that supports split touch
    sp<FakeWindowHandle> secondWindow = new FakeWindowHandle(application, mDispatcher,
            "Second Window", ADISPLAY_ID_DEFAULT);
    secondWindow->setFrame(Rect(0, 400, 600, 800));
    secondWindow->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL
            | InputWindowInfo::FLAG_SPLIT_TOUCH);

    // Add the windows to the dispatcher
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {firstWindow, secondWindow}}});

    PointF pointInFirst = {300, 200};
    PointF pointInSecond = {300, 600};

    // Send down to the first window
    NotifyMotionArgs firstDownMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_DOWN,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {pointInFirst});
    mDispatcher->notifyMotion(&firstDownMotionArgs);
    // Only the first window should get the down event
    firstWindow->consumeMotionDown();
    secondWindow->assertNoEvents();

    // Send down to the second window
    NotifyMotionArgs secondDownMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_DOWN
            | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {pointInFirst, pointInSecond});
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
    NotifyMotionArgs pointerUpMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_POINTER_UP
            | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, {pointInFirst, pointInSecond});
    mDispatcher->notifyMotion(&pointerUpMotionArgs);
    // The first window gets nothing and the second gets pointer up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionPointerUp(1);

    // Send up event to the second window
    NotifyMotionArgs upMotionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_UP,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&upMotionArgs);
    // The first window gets nothing and the second gets up
    firstWindow->assertNoEvents();
    secondWindow->consumeMotionUp();
}

TEST_F(InputDispatcherTest, FocusedWindow_ReceivesFocusEventAndKeyEvent) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    window->setFocus(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    window->consumeFocusEvent(true);

    NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyKey(&keyArgs);

    // Window should receive key down event.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, UnfocusedWindow_DoesNotReceiveFocusEventOrKeyEvent) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
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
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
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

class FakeMonitorReceiver {
public:
    FakeMonitorReceiver(const sp<InputDispatcher>& dispatcher, const std::string name,
                        int32_t displayId, bool isGestureMonitor = false) {
        sp<InputChannel> serverChannel, clientChannel;
        InputChannel::openInputChannelPair(name, serverChannel, clientChannel);
        mInputReceiver = std::make_unique<FakeInputReceiver>(clientChannel, name);
        dispatcher->registerInputMonitor(serverChannel, displayId, isGestureMonitor);
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

    void assertNoEvents() { mInputReceiver->assertNoEvents(); }

private:
    std::unique_ptr<FakeInputReceiver> mInputReceiver;
};

// Tests for gesture monitors
TEST_F(InputDispatcherTest, GestureMonitor_ReceivesMotionEvents) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "GM_1", ADISPLAY_ID_DEFAULT,
                                                      true /*isGestureMonitor*/);

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, GestureMonitor_DoesNotReceiveKeyEvents) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocus(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(true);

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "GM_1", ADISPLAY_ID_DEFAULT,
                                                      true /*isGestureMonitor*/);

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    monitor.assertNoEvents();
}

TEST_F(InputDispatcherTest, GestureMonitor_CanPilferAfterWindowIsRemovedMidStream) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    FakeMonitorReceiver monitor = FakeMonitorReceiver(mDispatcher, "GM_1", ADISPLAY_ID_DEFAULT,
                                                      true /*isGestureMonitor*/);

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);

    window->releaseChannel();

    mDispatcher->pilferPointers(monitor.getToken());

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    monitor.consumeMotionUp(ADISPLAY_ID_DEFAULT);
}

TEST_F(InputDispatcherTest, UnresponsiveGestureMonitor_GetsAnr) {
    FakeMonitorReceiver monitor =
            FakeMonitorReceiver(mDispatcher, "Gesture monitor", ADISPLAY_ID_DEFAULT,
                                true /*isGestureMonitor*/);

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT));
    std::optional<uint32_t> consumeSeq = monitor.receiveEvent();
    ASSERT_TRUE(consumeSeq);

    mFakePolicy->assertNotifyAnrWasCalled(DISPATCHING_TIMEOUT, nullptr, monitor.getToken());
    monitor.finishEvent(*consumeSeq);
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

TEST_F(InputDispatcherTest, TestMoveEvent) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
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
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Test window", ADISPLAY_ID_DEFAULT);

    // Set focused application.
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocus(true);

    SCOPED_TRACE("Check default value of touch mode");
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(true /*hasFocus*/, true /*inTouchMode*/);

    SCOPED_TRACE("Remove the window to trigger focus loss");
    window->setFocus(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(false /*hasFocus*/, true /*inTouchMode*/);

    SCOPED_TRACE("Disable touch mode");
    mDispatcher->setInTouchMode(false);
    window->setFocus(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(true /*hasFocus*/, false /*inTouchMode*/);

    SCOPED_TRACE("Remove the window to trigger focus loss");
    window->setFocus(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(false /*hasFocus*/, false /*inTouchMode*/);

    SCOPED_TRACE("Enable touch mode again");
    mDispatcher->setInTouchMode(true);
    window->setFocus(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
    window->consumeFocusEvent(true /*hasFocus*/, true /*inTouchMode*/);

    window->assertNoEvents();
}

TEST_F(InputDispatcherTest, VerifyInputEvent_KeyEvent) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Test window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
    window->setFocus(true);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});
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
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
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

class InputDispatcherKeyRepeatTest : public InputDispatcherTest {
protected:
    static constexpr nsecs_t KEY_REPEAT_TIMEOUT = 40 * 1000000; // 40 ms
    static constexpr nsecs_t KEY_REPEAT_DELAY = 40 * 1000000;   // 40 ms

    sp<FakeApplicationHandle> mApp;
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
        mApp = new FakeApplicationHandle();
        mWindow = new FakeWindowHandle(mApp, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

        mWindow->setFocus(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});

        mWindow->consumeFocusEvent(true);
    }

    void sendAndConsumeKeyDown() {
        NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
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

    void sendAndConsumeKeyUp() {
        NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT);
        keyArgs.policyFlags |= POLICY_FLAG_TRUSTED; // Unless it won't generate repeat event
        mDispatcher->notifyKey(&keyArgs);

        // Window should receive key down event.
        mWindow->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT,
                              0 /*expectedFlags*/);
    }
};

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_ReceivesKeyRepeat) {
    sendAndConsumeKeyDown();
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        expectKeyRepeatOnce(repeatCount);
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_StopsKeyRepeatAfterUp) {
    sendAndConsumeKeyDown();
    expectKeyRepeatOnce(1 /*repeatCount*/);
    sendAndConsumeKeyUp();
    mWindow->assertNoEvents();
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_RepeatKeyEventsUseEventIdFromInputDispatcher) {
    sendAndConsumeKeyDown();
    for (int32_t repeatCount = 1; repeatCount <= 10; ++repeatCount) {
        InputEvent* repeatEvent = mWindow->consume();
        ASSERT_NE(nullptr, repeatEvent) << "Didn't receive event with repeat count " << repeatCount;
        EXPECT_EQ(IdGenerator::Source::INPUT_DISPATCHER,
                  IdGenerator::getSource(repeatEvent->getId()));
    }
}

TEST_F(InputDispatcherKeyRepeatTest, FocusedWindow_RepeatKeyEventsUseUniqueEventId) {
    sendAndConsumeKeyDown();

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

        application1 = new FakeApplicationHandle();
        windowInPrimary = new FakeWindowHandle(application1, mDispatcher, "D_1",
                ADISPLAY_ID_DEFAULT);

        // Set focus window for primary display, but focused display would be second one.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application1);
        windowInPrimary->setFocus(true);
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {windowInPrimary}}});
        windowInPrimary->consumeFocusEvent(true);

        application2 = new FakeApplicationHandle();
        windowInSecondary = new FakeWindowHandle(application2, mDispatcher, "D_2",
                SECOND_DISPLAY_ID);
        // Set focus to second display window.
        // Set focus display to second one.
        mDispatcher->setFocusedDisplay(SECOND_DISPLAY_ID);
        // Set focus window for second display.
        mDispatcher->setFocusedApplication(SECOND_DISPLAY_ID, application2);
        windowInSecondary->setFocus(true);
        mDispatcher->setInputWindows({{SECOND_DISPLAY_ID, {windowInSecondary}}});
        windowInSecondary->consumeFocusEvent(true);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();

        application1.clear();
        windowInPrimary.clear();
        application2.clear();
        windowInSecondary.clear();
    }

protected:
    sp<FakeApplicationHandle> application1;
    sp<FakeWindowHandle> windowInPrimary;
    sp<FakeApplicationHandle> application2;
    sp<FakeWindowHandle> windowInSecondary;
};

TEST_F(InputDispatcherFocusOnTwoDisplaysTest, SetInputWindow_MultiDisplayTouch) {
    // Test touch down on primary display.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowInSecondary->assertNoEvents();

    // Test touch down on second display.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    windowInSecondary->consumeMotionDown(SECOND_DISPLAY_ID);
}

TEST_F(InputDispatcherFocusOnTwoDisplaysTest, SetInputWindow_MultiDisplayFocus) {
    // Test inject a key down with display id specified.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    windowInSecondary->assertNoEvents();

    // Test inject a key down without display id specified.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    windowInSecondary->consumeKeyDown(ADISPLAY_ID_NONE);

    // Remove all windows in secondary display.
    mDispatcher->setInputWindows({{SECOND_DISPLAY_ID, {}}});

    // Expect old focus should receive a cancel event.
    windowInSecondary->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_NONE,
                                    AKEY_EVENT_FLAG_CANCELED);

    // Test inject a key down, should timeout because of no target window.
    ASSERT_EQ(INPUT_EVENT_INJECTION_TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_TIMED_OUT";
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
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitorInPrimary.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowInSecondary->assertNoEvents();
    monitorInSecondary.assertNoEvents();

    // Test touch down on second display.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary.assertNoEvents();
    windowInSecondary->consumeMotionDown(SECOND_DISPLAY_ID);
    monitorInSecondary.consumeMotionDown(SECOND_DISPLAY_ID);

    // Test inject a non-pointer motion event.
    // If specific a display, it will dispatch to the focused window of particular display,
    // or it will dispatch to the focused window of focused display.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
        AINPUT_SOURCE_TRACKBALL, ADISPLAY_ID_NONE))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary.assertNoEvents();
    windowInSecondary->consumeMotionDown(ADISPLAY_ID_NONE);
    monitorInSecondary.consumeMotionDown(ADISPLAY_ID_NONE);
}

// Test per-display input monitors for key event.
TEST_F(InputDispatcherFocusOnTwoDisplaysTest, MonitorKeyEvent_MultiDisplay) {
    //Input monitor per display.
    FakeMonitorReceiver monitorInPrimary =
            FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);
    FakeMonitorReceiver monitorInSecondary =
            FakeMonitorReceiver(mDispatcher, "M_2", SECOND_DISPLAY_ID);

    // Test inject a key down.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary.assertNoEvents();
    windowInSecondary->consumeKeyDown(ADISPLAY_ID_NONE);
    monitorInSecondary.consumeKeyDown(ADISPLAY_ID_NONE);
}

class InputFilterTest : public InputDispatcherTest {
protected:
    static constexpr int32_t SECOND_DISPLAY_ID = 1;

    void testNotifyMotion(int32_t displayId, bool expectToBeFiltered) {
        NotifyMotionArgs motionArgs;

        motionArgs = generateMotionArgs(
                AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN, displayId);
        mDispatcher->notifyMotion(&motionArgs);
        motionArgs = generateMotionArgs(
                AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN, displayId);
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

class InputDispatcherOnPointerDownOutsideFocus : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        sp<FakeApplicationHandle> application = new FakeApplicationHandle();
        mUnfocusedWindow = new FakeWindowHandle(application, mDispatcher, "Top",
                ADISPLAY_ID_DEFAULT);
        mUnfocusedWindow->setFrame(Rect(0, 0, 30, 30));
        // Adding FLAG_NOT_TOUCH_MODAL to ensure taps outside this window are not sent to this
        // window.
        mUnfocusedWindow->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL);

        mFocusedWindow =
                new FakeWindowHandle(application, mDispatcher, "Second", ADISPLAY_ID_DEFAULT);
        mFocusedWindow->setFrame(Rect(50, 50, 100, 100));
        mFocusedWindow->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL);

        // Set focused application.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
        mFocusedWindow->setFocus(true);

        // Expect one focus window exist in display.
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mUnfocusedWindow, mFocusedWindow}}});
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
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               {20, 20}))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    mUnfocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownEquals(mUnfocusedWindow->getToken());
}

// Have two windows, one with focus. Inject MotionEvent with source TRACKBALL and action
// DOWN on the window that doesn't have focus. Ensure no window received the
// onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_NonPointerSource) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TRACKBALL, ADISPLAY_ID_DEFAULT, {20, 20}))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    mFocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

// Have two windows, one with focus. Inject KeyEvent with action DOWN on the window that doesn't
// have focus. Ensure no window received the onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_NonMotionFailure) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    mFocusedWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

// Have two windows, one with focus. Inject MotionEvent with source TOUCHSCREEN and action
// DOWN on the window that already has focus. Ensure no window received the
// onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus,
        OnPointerDownOutsideFocus_OnAlreadyFocusedWindow) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_TOUCH_POINT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    mFocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

// These tests ensures we can send touch events to a single client when there are multiple input
// windows that point to the same client token.
class InputDispatcherMultiWindowSameTokenTests : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        sp<FakeApplicationHandle> application = new FakeApplicationHandle();
        mWindow1 = new FakeWindowHandle(application, mDispatcher, "Fake Window 1",
                                        ADISPLAY_ID_DEFAULT);
        // Adding FLAG_NOT_TOUCH_MODAL otherwise all taps will go to the top most window.
        // We also need FLAG_SPLIT_TOUCH or we won't be able to get touches for both windows.
        mWindow1->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL |
                                      InputWindowInfo::FLAG_SPLIT_TOUCH);
        mWindow1->setFrame(Rect(0, 0, 100, 100));

        mWindow2 = new FakeWindowHandle(application, mDispatcher, "Fake Window 2",
                                        ADISPLAY_ID_DEFAULT, mWindow1->getToken());
        mWindow2->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL |
                                      InputWindowInfo::FLAG_SPLIT_TOUCH);
        mWindow2->setFrame(Rect(100, 100, 200, 200));

        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow1, mWindow2}}});
    }

protected:
    sp<FakeWindowHandle> mWindow1;
    sp<FakeWindowHandle> mWindow2;

    // Helper function to convert the point from screen coordinates into the window's space
    static PointF getPointInWindow(const InputWindowInfo* windowInfo, const PointF& point) {
        float x = windowInfo->windowXScale * (point.x - windowInfo->frameLeft);
        float y = windowInfo->windowYScale * (point.y - windowInfo->frameTop);
        return {x, y};
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
};

TEST_F(InputDispatcherMultiWindowSameTokenTests, SingleTouchSameScale) {
    // Touch Window 1
    PointF touchedPoint = {10, 10};
    PointF expectedPoint = getPointInWindow(mWindow1->getInfo(), touchedPoint);

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_DOWN, {expectedPoint});

    // Release touch on Window 1
    motionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);
    // consume the UP event
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_UP, {expectedPoint});

    // Touch Window 2
    touchedPoint = {150, 150};
    expectedPoint = getPointInWindow(mWindow2->getInfo(), touchedPoint);

    motionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);

    // Consuming from window1 since it's the window that has the InputReceiver
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_DOWN, {expectedPoint});
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, SingleTouchDifferentScale) {
    mWindow2->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    PointF touchedPoint = {10, 10};
    PointF expectedPoint = getPointInWindow(mWindow1->getInfo(), touchedPoint);

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_DOWN, {expectedPoint});

    // Release touch on Window 1
    motionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);
    // consume the UP event
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_UP, {expectedPoint});

    // Touch Window 2
    touchedPoint = {150, 150};
    expectedPoint = getPointInWindow(mWindow2->getInfo(), touchedPoint);

    motionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, {touchedPoint});
    mDispatcher->notifyMotion(&motionArgs);

    // Consuming from window1 since it's the window that has the InputReceiver
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_DOWN, {expectedPoint});
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, MultipleTouchDifferentScale) {
    mWindow2->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    std::vector<PointF> touchedPoints = {PointF{10, 10}};
    std::vector<PointF> expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0])};

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_DOWN, expectedPoints);

    // Touch Window 2
    int32_t actionPointerDown =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchedPoints.emplace_back(PointF{150, 150});
    expectedPoints.emplace_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));

    motionArgs = generateMotionArgs(actionPointerDown, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);

    // Consuming from window1 since it's the window that has the InputReceiver
    consumeMotionEvent(mWindow1, actionPointerDown, expectedPoints);
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, MultipleTouchMoveDifferentScale) {
    mWindow2->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    std::vector<PointF> touchedPoints = {PointF{10, 10}};
    std::vector<PointF> expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0])};

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_DOWN, expectedPoints);

    // Touch Window 2
    int32_t actionPointerDown =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchedPoints.emplace_back(PointF{150, 150});
    expectedPoints.emplace_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));

    motionArgs = generateMotionArgs(actionPointerDown, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);

    // Consuming from window1 since it's the window that has the InputReceiver
    consumeMotionEvent(mWindow1, actionPointerDown, expectedPoints);

    // Move both windows
    touchedPoints = {{20, 20}, {175, 175}};
    expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0]),
                      getPointInWindow(mWindow2->getInfo(), touchedPoints[1])};

    motionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);

    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_MOVE, expectedPoints);
}

TEST_F(InputDispatcherMultiWindowSameTokenTests, MultipleWindowsFirstTouchWithScale) {
    mWindow1->setWindowScale(0.5f, 0.5f);

    // Touch Window 1
    std::vector<PointF> touchedPoints = {PointF{10, 10}};
    std::vector<PointF> expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0])};

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);
    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_DOWN, expectedPoints);

    // Touch Window 2
    int32_t actionPointerDown =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    touchedPoints.emplace_back(PointF{150, 150});
    expectedPoints.emplace_back(getPointInWindow(mWindow2->getInfo(), touchedPoints[1]));

    motionArgs = generateMotionArgs(actionPointerDown, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);

    // Consuming from window1 since it's the window that has the InputReceiver
    consumeMotionEvent(mWindow1, actionPointerDown, expectedPoints);

    // Move both windows
    touchedPoints = {{20, 20}, {175, 175}};
    expectedPoints = {getPointInWindow(mWindow1->getInfo(), touchedPoints[0]),
                      getPointInWindow(mWindow2->getInfo(), touchedPoints[1])};

    motionArgs = generateMotionArgs(AMOTION_EVENT_ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN,
                                    ADISPLAY_ID_DEFAULT, touchedPoints);
    mDispatcher->notifyMotion(&motionArgs);

    consumeMotionEvent(mWindow1, AMOTION_EVENT_ACTION_MOVE, expectedPoints);
}

class InputDispatcherSingleWindowAnr : public InputDispatcherTest {
    virtual void SetUp() override {
        InputDispatcherTest::SetUp();

        mApplication = new FakeApplicationHandle();
        mApplication->setDispatchingTimeout(20ms);
        mWindow =
                new FakeWindowHandle(mApplication, mDispatcher, "TestWindow", ADISPLAY_ID_DEFAULT);
        mWindow->setFrame(Rect(0, 0, 30, 30));
        mWindow->setDispatchingTimeout(10ms);
        mWindow->setFocus(true);
        // Adding FLAG_NOT_TOUCH_MODAL to ensure taps outside this window are not sent to this
        // window.
        mWindow->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL);

        // Set focused application.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApplication);

        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
        mWindow->consumeFocusEvent(true);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();
        mWindow.clear();
    }

protected:
    sp<FakeApplicationHandle> mApplication;
    sp<FakeWindowHandle> mWindow;
    static constexpr PointF WINDOW_LOCATION = {20, 20};

    void tapOnWindow() {
        ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
                  injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                   WINDOW_LOCATION));
        ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
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
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher));
    mWindow->consumeKeyDown(ADISPLAY_ID_NONE);
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// Send an event to the app and have the app not respond right away.
// When ANR is raised, policy will tell the dispatcher to cancel the events for that window.
// So InputDispatcher will enqueue ACTION_CANCEL event as well.
TEST_F(InputDispatcherSingleWindowAnr, OnPointerDown_BasicAnr) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));

    std::optional<uint32_t> sequenceNum = mWindow->receiveEvent(); // ACTION_DOWN
    ASSERT_TRUE(sequenceNum);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/, mWindow->getToken());

    // The remaining lines are not really needed for the test, but kept as a sanity check
    mWindow->finishEvent(*sequenceNum);
    mWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_CANCEL,
                          ADISPLAY_ID_DEFAULT, 0 /*flags*/);
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

// Send a key to the app and have the app not respond right away.
TEST_F(InputDispatcherSingleWindowAnr, OnKeyDown_BasicAnr) {
    // Inject a key, and don't respond - expect that ANR is called.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher));
    std::optional<uint32_t> sequenceNum = mWindow->receiveEvent();
    ASSERT_TRUE(sequenceNum);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/, mWindow->getToken());
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

// We have a focused application, but no focused window
TEST_F(InputDispatcherSingleWindowAnr, FocusedApplication_NoFocusedWindow) {
    mWindow->setFocus(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);

    // taps on the window work as normal
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));
    ASSERT_NO_FATAL_FAILURE(mWindow->consumeMotionDown());
    mDispatcher->waitForIdle();
    mFakePolicy->assertNotifyAnrWasNotCalled();

    // Once a focused event arrives, we get an ANR for this application
    // We specify the injection timeout to be smaller than the application timeout, to ensure that
    // injection times out (instead of failing).
    const int32_t result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
                      INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT, 10ms);
    ASSERT_EQ(INPUT_EVENT_INJECTION_TIMED_OUT, result);
    const std::chrono::duration timeout = mApplication->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(timeout, mApplication, nullptr /*windowToken*/);
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

// We have a focused application, but no focused window
// If the policy wants to keep waiting on the focused window to be added, make sure
// that this timeout extension is honored and ANR is raised again.
TEST_F(InputDispatcherSingleWindowAnr, NoFocusedWindow_ExtendsAnr) {
    mWindow->setFocus(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);
    const std::chrono::duration timeout = 5ms;
    mFakePolicy->setAnrTimeout(timeout);

    // Once a focused event arrives, we get an ANR for this application
    // We specify the injection timeout to be smaller than the application timeout, to ensure that
    // injection times out (instead of failing).
    const int32_t result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
                      INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT, 10ms);
    ASSERT_EQ(INPUT_EVENT_INJECTION_TIMED_OUT, result);
    const std::chrono::duration appTimeout =
            mApplication->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(appTimeout, mApplication, nullptr /*windowToken*/);

    // After the extended time has passed, ANR should be raised again
    mFakePolicy->assertNotifyAnrWasCalled(timeout, mApplication, nullptr /*windowToken*/);

    // If we stop extending the timeout, dispatcher should go to idle.
    // Another ANR may be raised during this time
    mFakePolicy->setAnrTimeout(0ms);
    ASSERT_TRUE(mDispatcher->waitForIdle());
}

// We have a focused application, but no focused window
TEST_F(InputDispatcherSingleWindowAnr, NoFocusedWindow_DropsFocusedEvents) {
    mWindow->setFocus(false);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mWindow}}});
    mWindow->consumeFocusEvent(false);

    // Once a focused event arrives, we get an ANR for this application
    const int32_t result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
                      INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT, 10ms);
    ASSERT_EQ(INPUT_EVENT_INJECTION_TIMED_OUT, result);

    const std::chrono::duration timeout = mApplication->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(timeout, mApplication, nullptr /*windowToken*/);

    // Future focused events get dropped right away
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, injectKeyDown(mDispatcher));
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
                      500ms, INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT, currentTime);

    // Now send ACTION_UP, with identical timestamp
    injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN,
                      ADISPLAY_ID_DEFAULT, WINDOW_LOCATION,
                      {AMOTION_EVENT_INVALID_CURSOR_POSITION,
                       AMOTION_EVENT_INVALID_CURSOR_POSITION},
                      500ms, INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT, currentTime);

    // We have now sent down and up. Let's consume first event and then ANR on the second.
    mWindow->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/, mWindow->getToken());
}

// If an app is not responding to a key event, gesture monitors should continue to receive
// new motion events
TEST_F(InputDispatcherSingleWindowAnr, GestureMonitors_ReceiveEventsDuringAppAnrOnKey) {
    FakeMonitorReceiver monitor =
            FakeMonitorReceiver(mDispatcher, "Gesture monitor", ADISPLAY_ID_DEFAULT,
                                true /*isGestureMonitor*/);

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT));
    mWindow->consumeKeyDown(ADISPLAY_ID_DEFAULT);
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyUp(mDispatcher, ADISPLAY_ID_DEFAULT));

    // Stuck on the ACTION_UP
    const std::chrono::duration timeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr, mWindow->getToken());

    // New tap will go to the gesture monitor, but not to the window
    tapOnWindow();
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeKeyUp(ADISPLAY_ID_DEFAULT); // still the previous motion
    mDispatcher->waitForIdle();
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
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr, mWindow->getToken());

    // New tap will go to the gesture monitor, but not to the window
    tapOnWindow();
    monitor.consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitor.consumeMotionUp(ADISPLAY_ID_DEFAULT);

    mWindow->consumeMotionUp(ADISPLAY_ID_DEFAULT); // still the previous motion
    mDispatcher->waitForIdle();
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
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/, mWindow->getToken());
    mWindow->consumeMotionUp(); // Now the connection should be healthy again
    mDispatcher->waitForIdle();
    mWindow->assertNoEvents();

    tapOnWindow();
    mWindow->consumeMotionDown();
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/, mWindow->getToken());
    mWindow->consumeMotionUp();

    mDispatcher->waitForIdle();
    mWindow->assertNoEvents();
}

// If the policy tells us to raise ANR again after some time, ensure that the timeout extension
// is honored
TEST_F(InputDispatcherSingleWindowAnr, Policy_CanExtendTimeout) {
    const std::chrono::duration timeout = 5ms;
    mFakePolicy->setAnrTimeout(timeout);

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               WINDOW_LOCATION));

    const std::chrono::duration windowTimeout = mWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(windowTimeout, nullptr /*application*/,
                                          mWindow->getToken());

    // Since the policy wanted to extend ANR, make sure it is called again after the extension
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/, mWindow->getToken());
    mFakePolicy->setAnrTimeout(0ms);
    std::this_thread::sleep_for(windowTimeout);
    // We are not checking if ANR has been called, because it may have been called again by the
    // time we set the timeout to 0

    // When the policy finally says stop, we should get ACTION_CANCEL
    mWindow->consumeMotionDown();
    mWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_CANCEL,
                          ADISPLAY_ID_DEFAULT, 0 /*flags*/);
    mWindow->assertNoEvents();
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

    int32_t result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */, ADISPLAY_ID_DEFAULT,
                      INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT, 10ms);
    ASSERT_EQ(INPUT_EVENT_INJECTION_TIMED_OUT, result);
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
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /* repeatCount */,
                        ADISPLAY_ID_DEFAULT, INPUT_EVENT_INJECTION_SYNC_NONE));
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

        mApplication = new FakeApplicationHandle();
        mApplication->setDispatchingTimeout(10ms);
        mUnfocusedWindow =
                new FakeWindowHandle(mApplication, mDispatcher, "Unfocused", ADISPLAY_ID_DEFAULT);
        mUnfocusedWindow->setFrame(Rect(0, 0, 30, 30));
        // Adding FLAG_NOT_TOUCH_MODAL to ensure taps outside this window are not sent to this
        // window.
        // Adding FLAG_WATCH_OUTSIDE_TOUCH to receive ACTION_OUTSIDE when another window is tapped
        mUnfocusedWindow->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL |
                                              InputWindowInfo::FLAG_WATCH_OUTSIDE_TOUCH |
                                              InputWindowInfo::FLAG_SPLIT_TOUCH);

        mFocusedWindow =
                new FakeWindowHandle(mApplication, mDispatcher, "Focused", ADISPLAY_ID_DEFAULT);
        mFocusedWindow->setDispatchingTimeout(10ms);
        mFocusedWindow->setFrame(Rect(50, 50, 100, 100));
        mFocusedWindow->setLayoutParamFlags(InputWindowInfo::FLAG_NOT_TOUCH_MODAL |
                                            InputWindowInfo::FLAG_SPLIT_TOUCH);

        // Set focused application.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, mApplication);
        mFocusedWindow->setFocus(true);

        // Expect one focus window exist in display.
        mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mUnfocusedWindow, mFocusedWindow}}});
        mFocusedWindow->consumeFocusEvent(true);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();

        mUnfocusedWindow.clear();
        mFocusedWindow.clear();
    }

protected:
    sp<FakeApplicationHandle> mApplication;
    sp<FakeWindowHandle> mUnfocusedWindow;
    sp<FakeWindowHandle> mFocusedWindow;
    static constexpr PointF UNFOCUSED_WINDOW_LOCATION = {20, 20};
    static constexpr PointF FOCUSED_WINDOW_LOCATION = {75, 75};
    static constexpr PointF LOCATION_OUTSIDE_ALL_WINDOWS = {40, 40};

    void tapOnFocusedWindow() { tap(FOCUSED_WINDOW_LOCATION); }

    void tapOnUnfocusedWindow() { tap(UNFOCUSED_WINDOW_LOCATION); }

private:
    void tap(const PointF& location) {
        ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
                  injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                   location));
        ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
                  injectMotionUp(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                                 location));
    }
};

// If we have 2 windows that are both unresponsive, the one with the shortest timeout
// should be ANR'd first.
TEST_F(InputDispatcherMultiWindowAnr, TwoWindows_BothUnresponsive) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_LOCATION))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    mFocusedWindow->consumeMotionDown();
    mUnfocusedWindow->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_OUTSIDE,
                                   ADISPLAY_ID_DEFAULT, 0 /*flags*/);
    // We consumed all events, so no ANR
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();

    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_LOCATION));
    std::optional<uint32_t> unfocusedSequenceNum = mUnfocusedWindow->receiveEvent();
    ASSERT_TRUE(unfocusedSequenceNum);
    std::optional<uint32_t> focusedSequenceNum = mFocusedWindow->receiveEvent();
    ASSERT_TRUE(focusedSequenceNum);

    const std::chrono::duration timeout =
            mFocusedWindow->getDispatchingTimeout(DISPATCHING_TIMEOUT);
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/,
                                          mFocusedWindow->getToken());

    mFocusedWindow->finishEvent(*focusedSequenceNum);
    mUnfocusedWindow->finishEvent(*unfocusedSequenceNum);
    ASSERT_TRUE(mDispatcher->waitForIdle());
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
    std::pair<sp<InputApplicationHandle>, sp<IBinder>> anrData1 =
            mFakePolicy->getNotifyAnrData(10ms);
    std::pair<sp<InputApplicationHandle>, sp<IBinder>> anrData2 =
            mFakePolicy->getNotifyAnrData(0ms);

    // We don't know which window will ANR first. But both of them should happen eventually.
    ASSERT_TRUE(mFocusedWindow->getToken() == anrData1.second ||
                mFocusedWindow->getToken() == anrData2.second);
    ASSERT_TRUE(mUnfocusedWindow->getToken() == anrData1.second ||
                mUnfocusedWindow->getToken() == anrData2.second);

    ASSERT_TRUE(mDispatcher->waitForIdle());
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
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/,
                                          mFocusedWindow->getToken());

    // Tap once again
    // We cannot use "tapOnFocusedWindow" because it asserts the injection result to be success
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               FOCUSED_WINDOW_LOCATION));
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
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
    // should not have another ANR after the window just became healthy again
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// If you tap outside of all windows, there will not be ANR
TEST_F(InputDispatcherMultiWindowAnr, TapOutsideAllWindows_DoesNotAnr) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
              injectMotionDown(mDispatcher, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                               LOCATION_OUTSIDE_ALL_WINDOWS));
    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertNotifyAnrWasNotCalled();
}

// Since the focused window is paused, tapping on it should not produce any events
TEST_F(InputDispatcherMultiWindowAnr, Window_CanBePaused) {
    mFocusedWindow->setPaused(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mUnfocusedWindow, mFocusedWindow}}});

    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED,
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

    int32_t result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /*repeatCount*/, ADISPLAY_ID_DEFAULT,
                      INPUT_EVENT_INJECTION_SYNC_NONE, 10ms /*injectionTimeout*/);
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, result);
    // Key will not be sent to the window, yet, because the window is still processing events
    // and the key remains pending, waiting for the touch events to be processed
    std::optional<uint32_t> keySequenceNum = mFocusedWindow->receiveEvent();
    ASSERT_FALSE(keySequenceNum);

    // Switch the focus to the "unfocused" window that we tapped. Expect the key to go there
    mFocusedWindow->setFocus(false);
    mUnfocusedWindow->setFocus(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mFocusedWindow, mUnfocusedWindow}}});

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
    mFakePolicy->assertNotifyAnrWasCalled(timeout, nullptr /*application*/,
                                          mFocusedWindow->getToken());

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
    mUnfocusedWindow->assertNoEvents();
    mFocusedWindow->assertNoEvents();
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
    sp<FakeApplicationHandle> focusedApplication = new FakeApplicationHandle();
    focusedApplication->setDispatchingTimeout(60ms);
    mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, focusedApplication);
    // The application that owns 'mFocusedWindow' and 'mUnfocusedWindow' is not focused.
    mFocusedWindow->setFocus(false);

    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mFocusedWindow, mUnfocusedWindow}}});
    mFocusedWindow->consumeFocusEvent(false);

    // Send a key. The ANR timer should start because there is no focused window.
    // 'focusedApplication' will get blamed if this timer completes.
    // Key will not be sent anywhere because we have no focused window. It will remain pending.
    int32_t result =
            injectKey(mDispatcher, AKEY_EVENT_ACTION_DOWN, 0 /*repeatCount*/, ADISPLAY_ID_DEFAULT,
                      INPUT_EVENT_INJECTION_SYNC_NONE, 10ms /*injectionTimeout*/);
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, result);

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
    mFocusedWindow->setFocus(true);
    mDispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {mFocusedWindow, mUnfocusedWindow}}});
    mFocusedWindow->consumeFocusEvent(true);
    // We do not call "setFocusedApplication" here, even though the newly focused window belongs
    // to another application. This could be a bug / behaviour in the policy.

    mUnfocusedWindow->consumeMotionDown();

    ASSERT_TRUE(mDispatcher->waitForIdle());
    // Should not ANR because we actually have a focused window. It was just added too slowly.
    ASSERT_NO_FATAL_FAILURE(mFakePolicy->assertNotifyAnrWasNotCalled());
}

} // namespace android::inputdispatcher
