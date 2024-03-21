/*
 * Copyright 2024 The Android Open Source Project
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

#include "../dispatcher/InputDispatcher.h"
#include "TestEventMatchers.h"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <input/InputConsumer.h>

namespace android {

/**
 * If we expect to receive the event, the timeout can be made very long. When the test are running
 * correctly, we will actually never wait until the end of the timeout because the wait will end
 * when the event comes in. Still, this value shouldn't be infinite. During development, a local
 * change may cause the test to fail. This timeout should be short enough to not annoy so that the
 * developer can see the failure quickly (on human scale).
 */
static constexpr std::chrono::duration CONSUME_TIMEOUT_EVENT_EXPECTED = 1000ms;

/**
 * When no event is expected, we can have a very short timeout. A large value here would slow down
 * the tests. In the unlikely event of system being too slow, the event may still be present but the
 * timeout would complete before it is consumed. This would result in test flakiness. If this
 * occurs, the flakiness rate would be high. Since the flakes are treated with high priority, this
 * would get noticed and addressed quickly.
 */
static constexpr std::chrono::duration CONSUME_TIMEOUT_NO_EVENT_EXPECTED = 10ms;

/**
 * The default pid and uid for windows created on the primary display by the test.
 */
static constexpr gui::Pid WINDOW_PID{999};
static constexpr gui::Uid WINDOW_UID{1001};

/**
 * Default input dispatching timeout if there is no focused application or paused window
 * from which to determine an appropriate dispatching timeout.
 */
static const std::chrono::duration DISPATCHING_TIMEOUT = std::chrono::milliseconds(
        android::os::IInputConstants::UNMULTIPLIED_DEFAULT_DISPATCHING_TIMEOUT_MILLIS *
        android::base::HwTimeoutMultiplier());

// --- FakeInputReceiver ---

class FakeInputReceiver {
public:
    explicit FakeInputReceiver(std::unique_ptr<InputChannel> clientChannel, const std::string name);

    std::unique_ptr<InputEvent> consume(std::chrono::milliseconds timeout, bool handled = false);
    /**
     * Receive an event without acknowledging it.
     * Return the sequence number that could later be used to send finished signal.
     */
    std::pair<std::optional<uint32_t>, std::unique_ptr<InputEvent>> receiveEvent(
            std::chrono::milliseconds timeout);
    /**
     * To be used together with "receiveEvent" to complete the consumption of an event.
     */
    void finishEvent(uint32_t consumeSeq, bool handled = true);

    void sendTimeline(int32_t inputEventId, std::array<nsecs_t, GraphicsTimeline::SIZE> timeline);

    void consumeEvent(android::InputEventType expectedEventType, int32_t expectedAction,
                      std::optional<int32_t> expectedDisplayId,
                      std::optional<int32_t> expectedFlags);

    std::unique_ptr<MotionEvent> consumeMotion();
    void consumeMotionEvent(const ::testing::Matcher<MotionEvent>& matcher);

    void consumeFocusEvent(bool hasFocus, bool inTouchMode);
    void consumeCaptureEvent(bool hasCapture);
    void consumeDragEvent(bool isExiting, float x, float y);
    void consumeTouchModeEvent(bool inTouchMode);

    void assertNoEvents(std::chrono::milliseconds timeout);

    sp<IBinder> getToken();
    int getChannelFd();

private:
    InputConsumer mConsumer;
    DynamicInputEventFactory mEventFactory;
    std::string mName;
};

// --- FakeWindowHandle ---

class FakeWindowHandle : public gui::WindowInfoHandle {
public:
    static const int32_t WIDTH = 600;
    static const int32_t HEIGHT = 800;
    using InputConfig = gui::WindowInfo::InputConfig;

    // This is a callback that is fired when an event is received by the window.
    // It is static to avoid having to pass it individually into all of the FakeWindowHandles
    // created by tests.
    // TODO(b/210460522): Update the tests to use a factory pattern so that we can avoid
    //   the need to make this static.
    static std::function<void(const std::unique_ptr<InputEvent>&, const gui::WindowInfo&)>
            sOnEventReceivedCallback;

    FakeWindowHandle(const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle,
                     const std::unique_ptr<inputdispatcher::InputDispatcher>& dispatcher,
                     const std::string name, int32_t displayId, bool createInputChannel = true);

    sp<FakeWindowHandle> clone(int32_t displayId);

    inline void setTouchable(bool touchable) {
        mInfo.setInputConfig(InputConfig::NOT_TOUCHABLE, !touchable);
    }

    inline void setFocusable(bool focusable) {
        mInfo.setInputConfig(InputConfig::NOT_FOCUSABLE, !focusable);
    }

    inline void setVisible(bool visible) {
        mInfo.setInputConfig(InputConfig::NOT_VISIBLE, !visible);
    }

    inline void setDispatchingTimeout(std::chrono::nanoseconds timeout) {
        mInfo.dispatchingTimeout = timeout;
    }

    inline void setPaused(bool paused) {
        mInfo.setInputConfig(InputConfig::PAUSE_DISPATCHING, paused);
    }

    inline void setPreventSplitting(bool preventSplitting) {
        mInfo.setInputConfig(InputConfig::PREVENT_SPLITTING, preventSplitting);
    }

    inline void setSlippery(bool slippery) {
        mInfo.setInputConfig(InputConfig::SLIPPERY, slippery);
    }

    inline void setWatchOutsideTouch(bool watchOutside) {
        mInfo.setInputConfig(InputConfig::WATCH_OUTSIDE_TOUCH, watchOutside);
    }

    inline void setSpy(bool spy) { mInfo.setInputConfig(InputConfig::SPY, spy); }

    inline void setSecure(bool secure) {
        if (secure) {
            mInfo.layoutParamsFlags |= gui::WindowInfo::Flag::SECURE;
        } else {
            using namespace ftl::flag_operators;
            mInfo.layoutParamsFlags &= ~gui::WindowInfo::Flag::SECURE;
        }
        mInfo.setInputConfig(InputConfig::SENSITIVE_FOR_TRACING, secure);
    }

    inline void setInterceptsStylus(bool interceptsStylus) {
        mInfo.setInputConfig(InputConfig::INTERCEPTS_STYLUS, interceptsStylus);
    }

    inline void setDropInput(bool dropInput) {
        mInfo.setInputConfig(InputConfig::DROP_INPUT, dropInput);
    }

    inline void setDropInputIfObscured(bool dropInputIfObscured) {
        mInfo.setInputConfig(InputConfig::DROP_INPUT_IF_OBSCURED, dropInputIfObscured);
    }

    inline void setNoInputChannel(bool noInputChannel) {
        mInfo.setInputConfig(InputConfig::NO_INPUT_CHANNEL, noInputChannel);
    }

    inline void setDisableUserActivity(bool disableUserActivity) {
        mInfo.setInputConfig(InputConfig::DISABLE_USER_ACTIVITY, disableUserActivity);
    }

    inline void setGlobalStylusBlocksTouch(bool shouldGlobalStylusBlockTouch) {
        mInfo.setInputConfig(InputConfig::GLOBAL_STYLUS_BLOCKS_TOUCH, shouldGlobalStylusBlockTouch);
    }

    inline void setAlpha(float alpha) { mInfo.alpha = alpha; }

    inline void setTouchOcclusionMode(gui::TouchOcclusionMode mode) {
        mInfo.touchOcclusionMode = mode;
    }

    inline void setApplicationToken(sp<IBinder> token) { mInfo.applicationInfo.token = token; }

    inline void setFrame(const Rect& frame,
                         const ui::Transform& displayTransform = ui::Transform()) {
        mInfo.frame = frame;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(frame);

        const Rect logicalDisplayFrame = displayTransform.transform(frame);
        ui::Transform translate;
        translate.set(-logicalDisplayFrame.left, -logicalDisplayFrame.top);
        mInfo.transform = translate * displayTransform;
    }

    inline void setTouchableRegion(const Region& region) { mInfo.touchableRegion = region; }

    inline void setIsWallpaper(bool isWallpaper) {
        mInfo.setInputConfig(InputConfig::IS_WALLPAPER, isWallpaper);
    }

    inline void setDupTouchToWallpaper(bool hasWallpaper) {
        mInfo.setInputConfig(InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER, hasWallpaper);
    }

    inline void setTrustedOverlay(bool trustedOverlay) {
        mInfo.setInputConfig(InputConfig::TRUSTED_OVERLAY, trustedOverlay);
    }

    inline void setWindowTransform(float dsdx, float dtdx, float dtdy, float dsdy) {
        mInfo.transform.set(dsdx, dtdx, dtdy, dsdy);
    }

    inline void setWindowScale(float xScale, float yScale) {
        setWindowTransform(xScale, 0, 0, yScale);
    }

    inline void setWindowOffset(float offsetX, float offsetY) {
        mInfo.transform.set(offsetX, offsetY);
    }

    std::unique_ptr<KeyEvent> consumeKey(bool handled = true);

    inline std::unique_ptr<KeyEvent> consumeKeyEvent(const ::testing::Matcher<KeyEvent>& matcher) {
        std::unique_ptr<KeyEvent> keyEvent = consumeKey();
        EXPECT_NE(nullptr, keyEvent);
        if (!keyEvent) {
            return nullptr;
        }
        EXPECT_THAT(*keyEvent, matcher);
        return keyEvent;
    }

    inline void consumeKeyDown(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeKeyEvent(testing::AllOf(WithKeyAction(AKEY_EVENT_ACTION_DOWN),
                                       WithDisplayId(expectedDisplayId), WithFlags(expectedFlags)));
    }

    inline void consumeKeyUp(int32_t expectedDisplayId, int32_t expectedFlags = 0) {
        consumeKeyEvent(testing::AllOf(WithKeyAction(AKEY_EVENT_ACTION_UP),
                                       WithDisplayId(expectedDisplayId), WithFlags(expectedFlags)));
    }

    inline void consumeMotionCancel(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                    int32_t expectedFlags = 0) {
        consumeMotionEvent(testing::AllOf(WithMotionAction(AMOTION_EVENT_ACTION_CANCEL),
                                          WithDisplayId(expectedDisplayId),
                                          WithFlags(expectedFlags | AMOTION_EVENT_FLAG_CANCELED)));
    }

    inline void consumeMotionMove(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                  int32_t expectedFlags = 0) {
        consumeMotionEvent(testing::AllOf(WithMotionAction(AMOTION_EVENT_ACTION_MOVE),
                                          WithDisplayId(expectedDisplayId),
                                          WithFlags(expectedFlags)));
    }

    inline void consumeMotionDown(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                  int32_t expectedFlags = 0) {
        consumeAnyMotionDown(expectedDisplayId, expectedFlags);
    }

    inline void consumeAnyMotionDown(std::optional<int32_t> expectedDisplayId = std::nullopt,
                                     std::optional<int32_t> expectedFlags = std::nullopt) {
        consumeMotionEvent(
                testing::AllOf(WithMotionAction(AMOTION_EVENT_ACTION_DOWN),
                               testing::Conditional(expectedDisplayId.has_value(),
                                                    WithDisplayId(*expectedDisplayId), testing::_),
                               testing::Conditional(expectedFlags.has_value(),
                                                    WithFlags(*expectedFlags), testing::_)));
    }

    inline void consumeMotionPointerDown(int32_t pointerIdx,
                                         int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                         int32_t expectedFlags = 0) {
        const int32_t action = AMOTION_EVENT_ACTION_POINTER_DOWN |
                (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeMotionEvent(testing::AllOf(WithMotionAction(action),
                                          WithDisplayId(expectedDisplayId),
                                          WithFlags(expectedFlags)));
    }

    inline void consumeMotionPointerUp(int32_t pointerIdx,
                                       int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                       int32_t expectedFlags = 0) {
        const int32_t action = AMOTION_EVENT_ACTION_POINTER_UP |
                (pointerIdx << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        consumeMotionEvent(testing::AllOf(WithMotionAction(action),
                                          WithDisplayId(expectedDisplayId),
                                          WithFlags(expectedFlags)));
    }

    inline void consumeMotionUp(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                int32_t expectedFlags = 0) {
        consumeMotionEvent(testing::AllOf(WithMotionAction(AMOTION_EVENT_ACTION_UP),
                                          WithDisplayId(expectedDisplayId),
                                          WithFlags(expectedFlags)));
    }

    inline void consumeMotionOutside(int32_t expectedDisplayId = ADISPLAY_ID_DEFAULT,
                                     int32_t expectedFlags = 0) {
        consumeMotionEvent(testing::AllOf(WithMotionAction(AMOTION_EVENT_ACTION_OUTSIDE),
                                          WithDisplayId(expectedDisplayId),
                                          WithFlags(expectedFlags)));
    }

    inline void consumeMotionOutsideWithZeroedCoords() {
        consumeMotionEvent(testing::AllOf(WithMotionAction(AMOTION_EVENT_ACTION_OUTSIDE),
                                          WithRawCoords(0, 0)));
    }

    inline void consumeFocusEvent(bool hasFocus, bool inTouchMode = true) {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Cannot consume events from a window with no receiver";
        mInputReceiver->consumeFocusEvent(hasFocus, inTouchMode);
    }

    inline void consumeCaptureEvent(bool hasCapture) {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Cannot consume events from a window with no receiver";
        mInputReceiver->consumeCaptureEvent(hasCapture);
    }

    std::unique_ptr<MotionEvent> consumeMotionEvent(
            const ::testing::Matcher<MotionEvent>& matcher = testing::_);

    inline void consumeDragEvent(bool isExiting, float x, float y) {
        mInputReceiver->consumeDragEvent(isExiting, x, y);
    }

    inline void consumeTouchModeEvent(bool inTouchMode) {
        ASSERT_NE(mInputReceiver, nullptr)
                << "Cannot consume events from a window with no receiver";
        mInputReceiver->consumeTouchModeEvent(inTouchMode);
    }

    inline std::pair<std::optional<uint32_t>, std::unique_ptr<InputEvent>> receiveEvent() {
        return receive();
    }

    inline void finishEvent(uint32_t sequenceNum) {
        ASSERT_NE(mInputReceiver, nullptr) << "Invalid receive event on window with no receiver";
        mInputReceiver->finishEvent(sequenceNum);
    }

    inline void sendTimeline(int32_t inputEventId,
                             std::array<nsecs_t, GraphicsTimeline::SIZE> timeline) {
        ASSERT_NE(mInputReceiver, nullptr) << "Invalid receive event on window with no receiver";
        mInputReceiver->sendTimeline(inputEventId, timeline);
    }

    void assertNoEvents(std::optional<std::chrono::milliseconds> timeout = {});

    inline sp<IBinder> getToken() { return mInfo.token; }

    inline const std::string& getName() { return mName; }

    inline void setOwnerInfo(gui::Pid ownerPid, gui::Uid ownerUid) {
        mInfo.ownerPid = ownerPid;
        mInfo.ownerUid = ownerUid;
    }

    inline gui::Pid getPid() const { return mInfo.ownerPid; }

    inline void destroyReceiver() { mInputReceiver = nullptr; }

    inline int getChannelFd() { return mInputReceiver->getChannelFd(); }

    // FakeWindowHandle uses this consume method to ensure received events are added to the trace.
    std::unique_ptr<InputEvent> consume(std::chrono::milliseconds timeout, bool handled = true);

private:
    FakeWindowHandle(std::string name) : mName(name){};
    const std::string mName;
    std::shared_ptr<FakeInputReceiver> mInputReceiver;
    static std::atomic<int32_t> sId; // each window gets a unique id, like in surfaceflinger
    friend class sp<FakeWindowHandle>;

    // FakeWindowHandle uses this receive method to ensure received events are added to the trace.
    std::pair<std::optional<uint32_t /*seq*/>, std::unique_ptr<InputEvent>> receive();
};

} // namespace android
