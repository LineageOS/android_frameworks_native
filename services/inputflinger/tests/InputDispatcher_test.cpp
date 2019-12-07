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

#include <binder/Binder.h>
#include <input/Input.h>

#include <gtest/gtest.h>
#include <linux/input.h>

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

    void assertFilterInputEventWasNotCalled() { ASSERT_EQ(nullptr, mFilteredEvent); }

    void assertNotifyConfigurationChangedWasCalled(nsecs_t when) {
        ASSERT_TRUE(mConfigurationChangedTime)
                << "Timed out waiting for configuration changed call";
        ASSERT_EQ(*mConfigurationChangedTime, when);
        mConfigurationChangedTime = std::nullopt;
    }

    void assertNotifySwitchWasCalled(const NotifySwitchArgs& args) {
        ASSERT_TRUE(mLastNotifySwitch);
        // We do not check sequenceNum because it is not exposed to the policy
        EXPECT_EQ(args.eventTime, mLastNotifySwitch->eventTime);
        EXPECT_EQ(args.policyFlags, mLastNotifySwitch->policyFlags);
        EXPECT_EQ(args.switchValues, mLastNotifySwitch->switchValues);
        EXPECT_EQ(args.switchMask, mLastNotifySwitch->switchMask);
        mLastNotifySwitch = std::nullopt;
    }

    void assertOnPointerDownEquals(const sp<IBinder>& touchedToken) {
        ASSERT_EQ(touchedToken, mOnPointerDownToken);
        mOnPointerDownToken.clear();
    }

    void assertOnPointerDownWasNotCalled() {
        ASSERT_TRUE(mOnPointerDownToken == nullptr)
                << "Expected onPointerDownOutsideFocus to not have been called";
    }

private:
    std::unique_ptr<InputEvent> mFilteredEvent;
    std::optional<nsecs_t> mConfigurationChangedTime;
    sp<IBinder> mOnPointerDownToken;
    std::optional<NotifySwitchArgs> mLastNotifySwitch;

    virtual void notifyConfigurationChanged(nsecs_t when) override {
        mConfigurationChangedTime = when;
    }

    virtual nsecs_t notifyANR(const sp<InputApplicationHandle>&,
            const sp<IBinder>&,
            const std::string&) {
        return 0;
    }

    virtual void notifyInputChannelBroken(const sp<IBinder>&) {
    }

    virtual void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) {
    }

    virtual void getDispatcherConfiguration(InputDispatcherConfiguration* outConfig) {
        *outConfig = mConfig;
    }

    virtual bool filterInputEvent(const InputEvent* inputEvent, uint32_t policyFlags) override {
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

    virtual void interceptKeyBeforeQueueing(const KeyEvent*, uint32_t&) {
    }

    virtual void interceptMotionBeforeQueueing(int32_t, nsecs_t, uint32_t&) {
    }

    virtual nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&,
            const KeyEvent*, uint32_t) {
        return 0;
    }

    virtual bool dispatchUnhandledKey(const sp<IBinder>&,
            const KeyEvent*, uint32_t, KeyEvent*) {
        return false;
    }

    virtual void notifySwitch(nsecs_t when, uint32_t switchValues, uint32_t switchMask,
                              uint32_t policyFlags) override {
        /** We simply reconstruct NotifySwitchArgs in policy because InputDispatcher is
         * essentially a passthrough for notifySwitch.
         */
        mLastNotifySwitch =
                NotifySwitchArgs(1 /*sequenceNum*/, when, policyFlags, switchValues, switchMask);
    }

    virtual void pokeUserActivity(nsecs_t, int32_t) {
    }

    virtual bool checkInjectEventsPermissionNonReentrant(int32_t, int32_t) {
        return false;
    }

    virtual void onPointerDownOutsideFocus(const sp<IBinder>& newToken) {
        mOnPointerDownToken = newToken;
    }

    void assertFilterInputEventWasCalled(int type, nsecs_t eventTime, int32_t action,
                                         int32_t displayId) {
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
};


TEST_F(InputDispatcherTest, InjectInputEvent_ValidatesKeyEvents) {
    KeyEvent event;

    // Rejects undefined key actions.
    event.initialize(DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
            /*action*/ -1, 0,
            AKEYCODE_A, KEY_A, AMETA_NONE, 0, ARBITRARY_TIME, ARBITRARY_TIME);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject key events with undefined action.";

    // Rejects ACTION_MULTIPLE since it is not supported despite being defined in the API.
    event.initialize(DEVICE_ID, AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_NONE,
            AKEY_EVENT_ACTION_MULTIPLE, 0,
            AKEYCODE_A, KEY_A, AMETA_NONE, 0, ARBITRARY_TIME, ARBITRARY_TIME);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
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
    event.initialize(DEVICE_ID, source, DISPLAY_ID,
                     /*action*/ -1, 0, 0, edgeFlags, metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with undefined action.";

    // Rejects pointer down with invalid index.
    event.initialize(DEVICE_ID, source, DISPLAY_ID,
                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                             (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with pointer down index too large.";

    event.initialize(DEVICE_ID, source, DISPLAY_ID,
                     AMOTION_EVENT_ACTION_POINTER_DOWN |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with pointer down index too small.";

    // Rejects pointer up with invalid index.
    event.initialize(DEVICE_ID, source, DISPLAY_ID,
                     AMOTION_EVENT_ACTION_POINTER_UP |
                             (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with pointer up index too large.";

    event.initialize(DEVICE_ID, source, DISPLAY_ID,
                     AMOTION_EVENT_ACTION_POINTER_UP |
                             (~0U << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT),
                     0, 0, edgeFlags, metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with pointer up index too small.";

    // Rejects motion events with invalid number of pointers.
    event.initialize(DEVICE_ID, source, DISPLAY_ID, AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags,
                     metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 0, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with 0 pointers.";

    event.initialize(DEVICE_ID, source, DISPLAY_ID, AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags,
                     metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ MAX_POINTERS + 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with more than MAX_POINTERS pointers.";

    // Rejects motion events with invalid pointer ids.
    pointerProperties[0].id = -1;
    event.initialize(DEVICE_ID, source, DISPLAY_ID, AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags,
                     metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with pointer ids less than 0.";

    pointerProperties[0].id = MAX_POINTER_ID + 1;
    event.initialize(DEVICE_ID, source, DISPLAY_ID, AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags,
                     metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with pointer ids greater than MAX_POINTER_ID.";

    // Rejects motion events with duplicate pointer ids.
    pointerProperties[0].id = 1;
    pointerProperties[1].id = 1;
    event.initialize(DEVICE_ID, source, DISPLAY_ID, AMOTION_EVENT_ACTION_DOWN, 0, 0, edgeFlags,
                     metaState, 0, classification, 0, 0, 0, 0,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     ARBITRARY_TIME, ARBITRARY_TIME,
                     /*pointerCount*/ 2, pointerProperties, pointerCoords);
    ASSERT_EQ(INPUT_EVENT_INJECTION_FAILED, mDispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_NONE, 0, 0))
            << "Should reject motion events with duplicate pointer ids.";
}

/* Test InputDispatcher for notifyConfigurationChanged and notifySwitch events */

TEST_F(InputDispatcherTest, NotifyConfigurationChanged_CallsPolicy) {
    constexpr nsecs_t eventTime = 20;
    NotifyConfigurationChangedArgs args(10 /*sequenceNum*/, eventTime);
    mDispatcher->notifyConfigurationChanged(&args);
    ASSERT_TRUE(mDispatcher->waitForIdle());

    mFakePolicy->assertNotifyConfigurationChangedWasCalled(eventTime);
}

TEST_F(InputDispatcherTest, NotifySwitch_CallsPolicy) {
    NotifySwitchArgs args(10 /*sequenceNum*/, 20 /*eventTime*/, 0 /*policyFlags*/,
                          1 /*switchValues*/, 2 /*switchMask*/);
    mDispatcher->notifySwitch(&args);

    // InputDispatcher adds POLICY_FLAG_TRUSTED because the event went through InputListener
    args.policyFlags |= POLICY_FLAG_TRUSTED;
    mFakePolicy->assertNotifySwitchWasCalled(args);
}

// --- InputDispatcherTest SetInputWindowTest ---
static constexpr int32_t INJECT_EVENT_TIMEOUT = 500;
static constexpr int32_t DISPATCHING_TIMEOUT = 100;

class FakeApplicationHandle : public InputApplicationHandle {
public:
    FakeApplicationHandle() {}
    virtual ~FakeApplicationHandle() {}

    virtual bool updateInfo() {
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT;
        return true;
    }
};

class FakeInputReceiver {
public:
    InputEvent* consume() {
        uint32_t consumeSeq;
        InputEvent* event;

        std::chrono::time_point start = std::chrono::steady_clock::now();
        status_t status = WOULD_BLOCK;
        while (status == WOULD_BLOCK) {
            status = mConsumer->consume(&mEventFactory, false /*consumeBatches*/, -1, &consumeSeq,
                                        &event);
            std::chrono::duration elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > 100ms) {
                break;
            }
        }

        if (status == WOULD_BLOCK) {
            // Just means there's no event available.
            return nullptr;
        }

        if (status != OK) {
            ADD_FAILURE() << mName.c_str() << ": consumer consume should return OK.";
            return nullptr;
        }
        if (event == nullptr) {
            ADD_FAILURE() << "Consumed correctly, but received NULL event from consumer";
            return nullptr;
        }

        status = mConsumer->sendFinishedSignal(consumeSeq, handled());
        if (status != OK) {
            ADD_FAILURE() << mName.c_str() << ": consumer sendFinishedSignal should return OK.";
        }
        return event;
    }

    void consumeEvent(int32_t expectedEventType, int32_t expectedAction, int32_t expectedDisplayId,
                      int32_t expectedFlags) {
        InputEvent* event = consume();

        ASSERT_NE(nullptr, event) << mName.c_str()
                                  << ": consumer should have returned non-NULL event.";
        ASSERT_EQ(expectedEventType, event->getType())
                << mName.c_str() << "expected " << inputEventTypeToString(expectedEventType)
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
            default: {
                FAIL() << mName.c_str() << ": invalid event type: " << expectedEventType;
            }
        }
    }

    void consumeKeyDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_DOWN, expectedDisplayId,
                     expectedFlags);
    }

    void consumeMotionDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_DOWN, expectedDisplayId,
                     expectedFlags);
    }

    void assertNoEvents() {
        InputEvent* event = consume();
        ASSERT_EQ(nullptr, event)
                << mName.c_str()
                << ": should not have received any events, so consume() should return NULL";
    }

protected:
        explicit FakeInputReceiver(const sp<InputDispatcher>& dispatcher,
            const std::string name, int32_t displayId) :
                mDispatcher(dispatcher), mName(name), mDisplayId(displayId) {
            InputChannel::openInputChannelPair(name, mServerChannel, mClientChannel);
            mConsumer = new InputConsumer(mClientChannel);
        }

        virtual ~FakeInputReceiver() {
        }

        // return true if the event has been handled.
        virtual bool handled() {
            return false;
        }

        sp<InputDispatcher> mDispatcher;
        sp<InputChannel> mServerChannel, mClientChannel;
        InputConsumer *mConsumer;
        PreallocatedInputEventFactory mEventFactory;

        std::string mName;
        int32_t mDisplayId;
};

class FakeWindowHandle : public InputWindowHandle, public FakeInputReceiver {
public:
    static const int32_t WIDTH = 600;
    static const int32_t HEIGHT = 800;

    FakeWindowHandle(const sp<InputApplicationHandle>& inputApplicationHandle,
        const sp<InputDispatcher>& dispatcher, const std::string name, int32_t displayId) :
            FakeInputReceiver(dispatcher, name, displayId),
            mFocused(false), mFrame(Rect(0, 0, WIDTH, HEIGHT)), mLayoutParamFlags(0) {
            mDispatcher->registerInputChannel(mServerChannel);

            inputApplicationHandle->updateInfo();
            mInfo.applicationInfo = *inputApplicationHandle->getInfo();
    }

    virtual bool updateInfo() {
        mInfo.token = mServerChannel ? mServerChannel->getConnectionToken() : nullptr;
        mInfo.name = mName;
        mInfo.layoutParamsFlags = mLayoutParamFlags;
        mInfo.layoutParamsType = InputWindowInfo::TYPE_APPLICATION;
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT;
        mInfo.frameLeft = mFrame.left;
        mInfo.frameTop = mFrame.top;
        mInfo.frameRight = mFrame.right;
        mInfo.frameBottom = mFrame.bottom;
        mInfo.globalScaleFactor = 1.0;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(mFrame);
        mInfo.visible = true;
        mInfo.canReceiveKeys = true;
        mInfo.hasFocus = mFocused;
        mInfo.hasWallpaper = false;
        mInfo.paused = false;
        mInfo.layer = 0;
        mInfo.ownerPid = INJECTOR_PID;
        mInfo.ownerUid = INJECTOR_UID;
        mInfo.inputFeatures = 0;
        mInfo.displayId = mDisplayId;

        return true;
    }

    void setFocus() {
        mFocused = true;
    }

    void setFrame(const Rect& frame) {
        mFrame.set(frame);
    }

    void setLayoutParamFlags(int32_t flags) {
        mLayoutParamFlags = flags;
    }

    void releaseChannel() {
        mServerChannel.clear();
        InputWindowHandle::releaseChannel();
    }
protected:
    virtual bool handled() override { return true; }

    bool mFocused;
    Rect mFrame;
    int32_t mLayoutParamFlags;
};

static int32_t injectKeyDown(const sp<InputDispatcher>& dispatcher,
        int32_t displayId = ADISPLAY_ID_NONE) {
    KeyEvent event;
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);

    // Define a valid key down event.
    event.initialize(DEVICE_ID, AINPUT_SOURCE_KEYBOARD, displayId,
            AKEY_EVENT_ACTION_DOWN, /* flags */ 0,
            AKEYCODE_A, KEY_A, AMETA_NONE, /* repeatCount */ 0, currentTime, currentTime);

    // Inject event until dispatch out.
    return dispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT,
            INJECT_EVENT_TIMEOUT, POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);
}

static int32_t injectMotionEvent(const sp<InputDispatcher>& dispatcher, int32_t action,
                                 int32_t source, int32_t displayId, int32_t x, int32_t y,
                                 int32_t xCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                 int32_t yCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION) {
    MotionEvent event;
    PointerProperties pointerProperties[1];
    PointerCoords pointerCoords[1];

    pointerProperties[0].clear();
    pointerProperties[0].id = 0;
    pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, x);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, y);

    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid motion down event.
    event.initialize(DEVICE_ID, source, displayId, action, /* actionButton */ 0, /* flags */ 0,
                     /* edgeFlags */ 0, AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                     /* xOffset */ 0, /* yOffset */ 0, /* xPrecision */ 0,
                     /* yPrecision */ 0, xCursorPosition, yCursorPosition, currentTime, currentTime,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);

    // Inject event until dispatch out.
    return dispatcher->injectInputEvent(
            &event,
            INJECTOR_PID, INJECTOR_UID, INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT,
            INJECT_EVENT_TIMEOUT, POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);
}

static int32_t injectMotionDown(const sp<InputDispatcher>& dispatcher, int32_t source,
                                int32_t displayId, int32_t x = 100, int32_t y = 200) {
    return injectMotionEvent(dispatcher, AMOTION_EVENT_ACTION_DOWN, source, displayId, x, y);
}

static NotifyKeyArgs generateKeyArgs(int32_t action, int32_t displayId = ADISPLAY_ID_NONE) {
    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid key event.
    NotifyKeyArgs args(/* sequenceNum */ 0, currentTime, DEVICE_ID, AINPUT_SOURCE_KEYBOARD,
            displayId, POLICY_FLAG_PASS_TO_USER, action, /* flags */ 0,
            AKEYCODE_A, KEY_A, AMETA_NONE, currentTime);

    return args;
}

static NotifyMotionArgs generateMotionArgs(int32_t action, int32_t source, int32_t displayId) {
    PointerProperties pointerProperties[1];
    PointerCoords pointerCoords[1];

    pointerProperties[0].clear();
    pointerProperties[0].id = 0;
    pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 100);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 200);

    nsecs_t currentTime = systemTime(SYSTEM_TIME_MONOTONIC);
    // Define a valid motion event.
    NotifyMotionArgs args(/* sequenceNum */ 0, currentTime, DEVICE_ID, source, displayId,
                          POLICY_FLAG_PASS_TO_USER, action, /* actionButton */ 0, /* flags */ 0,
                          AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                          AMOTION_EVENT_EDGE_FLAG_NONE, 1, pointerProperties, pointerCoords,
                          /* xPrecision */ 0, /* yPrecision */ 0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, currentTime, /* videoFrames */ {});

    return args;
}

TEST_F(InputDispatcherTest, SetInputWindow_SingleWindowTouch) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window = new FakeWindowHandle(application, mDispatcher, "Fake Window",
            ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({window}, ADISPLAY_ID_DEFAULT);
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
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

    mDispatcher->setInputWindows({windowTop, windowSecond}, ADISPLAY_ID_DEFAULT);
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

    // Expect one focus window exist in display.
    windowSecond->setFocus();

    mDispatcher->setInputWindows({windowTop, windowSecond}, ADISPLAY_ID_DEFAULT);
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
    windowTop->setFocus();
    windowSecond->setFocus();

    mDispatcher->setInputWindows({windowTop, windowSecond}, ADISPLAY_ID_DEFAULT);
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

    windowTop->setFocus();
    windowSecond->setFocus();
    // Release channel for window is no longer valid.
    windowTop->releaseChannel();
    mDispatcher->setInputWindows({windowTop, windowSecond}, ADISPLAY_ID_DEFAULT);

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

    mDispatcher->setInputWindows({windowLeft, windowRight}, ADISPLAY_ID_DEFAULT);

    // Inject an event with coordinate in the area of right window, with mouse cursor in the area of
    // left window. This event should be dispatched to the left window.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED,
              injectMotionEvent(mDispatcher, AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_MOUSE,
                                ADISPLAY_ID_DEFAULT, 610, 400, 599, 400));
    windowLeft->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowRight->assertNoEvents();
}

TEST_F(InputDispatcherTest, NotifyDeviceReset_CancelsKeyStream) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);
    window->setFocus();

    mDispatcher->setInputWindows({window}, ADISPLAY_ID_DEFAULT);

    NotifyKeyArgs keyArgs = generateKeyArgs(AKEY_EVENT_ACTION_DOWN, ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyKey(&keyArgs);

    // Window should receive key down event.
    window->consumeKeyDown(ADISPLAY_ID_DEFAULT);

    // When device reset happens, that key stream should be terminated with FLAG_CANCELED
    // on the app side.
    NotifyDeviceResetArgs args(10 /*sequenceNum*/, 20 /*eventTime*/, DEVICE_ID);
    mDispatcher->notifyDeviceReset(&args);
    window->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_DEFAULT,
                         AKEY_EVENT_FLAG_CANCELED);
}

TEST_F(InputDispatcherTest, NotifyDeviceReset_CancelsMotionStream) {
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window =
            new FakeWindowHandle(application, mDispatcher, "Fake Window", ADISPLAY_ID_DEFAULT);

    mDispatcher->setInputWindows({window}, ADISPLAY_ID_DEFAULT);

    NotifyMotionArgs motionArgs =
            generateMotionArgs(AMOTION_EVENT_ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN,
                               ADISPLAY_ID_DEFAULT);
    mDispatcher->notifyMotion(&motionArgs);

    // Window should receive motion down event.
    window->consumeMotionDown(ADISPLAY_ID_DEFAULT);

    // When device reset happens, that motion stream should be terminated with ACTION_CANCEL
    // on the app side.
    NotifyDeviceResetArgs args(10 /*sequenceNum*/, 20 /*eventTime*/, DEVICE_ID);
    mDispatcher->notifyDeviceReset(&args);
    window->consumeEvent(AINPUT_EVENT_TYPE_MOTION, AMOTION_EVENT_ACTION_CANCEL, ADISPLAY_ID_DEFAULT,
                         0 /*expectedFlags*/);
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
        windowInPrimary->setFocus();
        mDispatcher->setInputWindows({windowInPrimary}, ADISPLAY_ID_DEFAULT);

        application2 = new FakeApplicationHandle();
        windowInSecondary = new FakeWindowHandle(application2, mDispatcher, "D_2",
                SECOND_DISPLAY_ID);
        // Set focus to second display window.
        // Set focus display to second one.
        mDispatcher->setFocusedDisplay(SECOND_DISPLAY_ID);
        // Set focus window for second display.
        mDispatcher->setFocusedApplication(SECOND_DISPLAY_ID, application2);
        windowInSecondary->setFocus();
        mDispatcher->setInputWindows({windowInSecondary}, SECOND_DISPLAY_ID);
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
    mDispatcher->setInputWindows({}, SECOND_DISPLAY_ID);

    // Expect old focus should receive a cancel event.
    windowInSecondary->consumeEvent(AINPUT_EVENT_TYPE_KEY, AKEY_EVENT_ACTION_UP, ADISPLAY_ID_NONE,
                                    AKEY_EVENT_FLAG_CANCELED);

    // Test inject a key down, should timeout because of no target window.
    ASSERT_EQ(INPUT_EVENT_INJECTION_TIMED_OUT, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_TIMED_OUT";
    windowInPrimary->assertNoEvents();
    windowInSecondary->assertNoEvents();
}

class FakeMonitorReceiver : public FakeInputReceiver, public RefBase {
public:
    FakeMonitorReceiver(const sp<InputDispatcher>& dispatcher, const std::string name,
            int32_t displayId, bool isGestureMonitor = false)
            : FakeInputReceiver(dispatcher, name, displayId) {
        mDispatcher->registerInputMonitor(mServerChannel, displayId, isGestureMonitor);
    }
};

// Test per-display input monitors for motion event.
TEST_F(InputDispatcherFocusOnTwoDisplaysTest, MonitorMotionEvent_MultiDisplay) {
    sp<FakeMonitorReceiver> monitorInPrimary =
            new FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);
    sp<FakeMonitorReceiver> monitorInSecondary =
            new FakeMonitorReceiver(mDispatcher, "M_2", SECOND_DISPLAY_ID);

    // Test touch down on primary display.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    monitorInPrimary->consumeMotionDown(ADISPLAY_ID_DEFAULT);
    windowInSecondary->assertNoEvents();
    monitorInSecondary->assertNoEvents();

    // Test touch down on second display.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, SECOND_DISPLAY_ID))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary->assertNoEvents();
    windowInSecondary->consumeMotionDown(SECOND_DISPLAY_ID);
    monitorInSecondary->consumeMotionDown(SECOND_DISPLAY_ID);

    // Test inject a non-pointer motion event.
    // If specific a display, it will dispatch to the focused window of particular display,
    // or it will dispatch to the focused window of focused display.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
        AINPUT_SOURCE_TRACKBALL, ADISPLAY_ID_NONE))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary->assertNoEvents();
    windowInSecondary->consumeMotionDown(ADISPLAY_ID_NONE);
    monitorInSecondary->consumeMotionDown(ADISPLAY_ID_NONE);
}

// Test per-display input monitors for key event.
TEST_F(InputDispatcherFocusOnTwoDisplaysTest, MonitorKeyEvent_MultiDisplay) {
    //Input monitor per display.
    sp<FakeMonitorReceiver> monitorInPrimary =
            new FakeMonitorReceiver(mDispatcher, "M_1", ADISPLAY_ID_DEFAULT);
    sp<FakeMonitorReceiver> monitorInSecondary =
            new FakeMonitorReceiver(mDispatcher, "M_2", SECOND_DISPLAY_ID);

    // Test inject a key down.
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";
    windowInPrimary->assertNoEvents();
    monitorInPrimary->assertNoEvents();
    windowInSecondary->consumeKeyDown(ADISPLAY_ID_NONE);
    monitorInSecondary->consumeKeyDown(ADISPLAY_ID_NONE);
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
        mFocusedWindowTouchPoint = 60;

        // Set focused application.
        mDispatcher->setFocusedApplication(ADISPLAY_ID_DEFAULT, application);
        mFocusedWindow->setFocus();

        // Expect one focus window exist in display.
        mDispatcher->setInputWindows({mUnfocusedWindow, mFocusedWindow}, ADISPLAY_ID_DEFAULT);
    }

    virtual void TearDown() override {
        InputDispatcherTest::TearDown();

        mUnfocusedWindow.clear();
        mFocusedWindow.clear();
    }

protected:
    sp<FakeWindowHandle> mUnfocusedWindow;
    sp<FakeWindowHandle> mFocusedWindow;
    int32_t mFocusedWindowTouchPoint;
};

// Have two windows, one with focus. Inject MotionEvent with source TOUCHSCREEN and action
// DOWN on the window that doesn't have focus. Ensure the window that didn't have focus received
// the onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_Success) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT, 20, 20))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownEquals(mUnfocusedWindow->getToken());
}

// Have two windows, one with focus. Inject MotionEvent with source TRACKBALL and action
// DOWN on the window that doesn't have focus. Ensure no window received the
// onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_NonPointerSource) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectMotionDown(mDispatcher,
            AINPUT_SOURCE_TRACKBALL, ADISPLAY_ID_DEFAULT, 20, 20))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

// Have two windows, one with focus. Inject KeyEvent with action DOWN on the window that doesn't
// have focus. Ensure no window received the onPointerDownOutsideFocus callback.
TEST_F(InputDispatcherOnPointerDownOutsideFocus, OnPointerDownOutsideFocus_NonMotionFailure) {
    ASSERT_EQ(INPUT_EVENT_INJECTION_SUCCEEDED, injectKeyDown(mDispatcher, ADISPLAY_ID_DEFAULT))
            << "Inject key event should return INPUT_EVENT_INJECTION_SUCCEEDED";

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
                               mFocusedWindowTouchPoint, mFocusedWindowTouchPoint))
            << "Inject motion event should return INPUT_EVENT_INJECTION_SUCCEEDED";

    ASSERT_TRUE(mDispatcher->waitForIdle());
    mFakePolicy->assertOnPointerDownWasNotCalled();
}

} // namespace android::inputdispatcher
