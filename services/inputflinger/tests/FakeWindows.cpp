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

#include "FakeWindows.h"

#include <gtest/gtest.h>

namespace android {

// --- FakeInputReceiver ---

FakeInputReceiver::FakeInputReceiver(std::unique_ptr<InputChannel> clientChannel,
                                     const std::string name)
      : mConsumer(std::move(clientChannel)), mName(name) {}

std::unique_ptr<InputEvent> FakeInputReceiver::consume(std::chrono::milliseconds timeout,
                                                       bool handled) {
    auto [consumeSeq, event] = receiveEvent(timeout);
    if (!consumeSeq) {
        return nullptr;
    }
    finishEvent(*consumeSeq, handled);
    return std::move(event);
}

std::pair<std::optional<uint32_t>, std::unique_ptr<InputEvent>> FakeInputReceiver::receiveEvent(
        std::chrono::milliseconds timeout) {
    uint32_t consumeSeq;
    std::unique_ptr<InputEvent> event;

    std::chrono::time_point start = std::chrono::steady_clock::now();
    status_t status = WOULD_BLOCK;
    while (status == WOULD_BLOCK) {
        InputEvent* rawEventPtr = nullptr;
        status = mConsumer.consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq,
                                   &rawEventPtr);
        event = std::unique_ptr<InputEvent>(rawEventPtr);
        std::chrono::duration elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > timeout) {
            break;
        }
    }

    if (status == WOULD_BLOCK) {
        // Just means there's no event available.
        return std::make_pair(std::nullopt, nullptr);
    }

    if (status != OK) {
        ADD_FAILURE() << mName.c_str() << ": consumer consume should return OK.";
        return std::make_pair(std::nullopt, nullptr);
    }
    if (event == nullptr) {
        ADD_FAILURE() << "Consumed correctly, but received NULL event from consumer";
    }
    return std::make_pair(consumeSeq, std::move(event));
}

void FakeInputReceiver::finishEvent(uint32_t consumeSeq, bool handled) {
    const status_t status = mConsumer.sendFinishedSignal(consumeSeq, handled);
    ASSERT_EQ(OK, status) << mName.c_str() << ": consumer sendFinishedSignal should return OK.";
}

void FakeInputReceiver::sendTimeline(int32_t inputEventId,
                                     std::array<nsecs_t, GraphicsTimeline::SIZE> timeline) {
    const status_t status = mConsumer.sendTimeline(inputEventId, timeline);
    ASSERT_EQ(OK, status);
}

void FakeInputReceiver::consumeEvent(InputEventType expectedEventType, int32_t expectedAction,
                                     std::optional<ui::LogicalDisplayId> expectedDisplayId,
                                     std::optional<int32_t> expectedFlags) {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED);

    ASSERT_NE(nullptr, event) << mName.c_str() << ": consumer should have returned non-NULL event.";
    ASSERT_EQ(expectedEventType, event->getType())
            << mName.c_str() << " expected " << ftl::enum_string(expectedEventType)
            << " event, got " << *event;

    if (expectedDisplayId.has_value()) {
        EXPECT_EQ(expectedDisplayId, event->getDisplayId());
    }

    switch (expectedEventType) {
        case InputEventType::KEY: {
            const KeyEvent& keyEvent = static_cast<const KeyEvent&>(*event);
            ASSERT_THAT(keyEvent, WithKeyAction(expectedAction));
            if (expectedFlags.has_value()) {
                EXPECT_EQ(expectedFlags.value(), keyEvent.getFlags());
            }
            break;
        }
        case InputEventType::MOTION: {
            const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*event);
            ASSERT_THAT(motionEvent, WithMotionAction(expectedAction));
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

std::unique_ptr<MotionEvent> FakeInputReceiver::consumeMotion() {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED);

    if (event == nullptr) {
        ADD_FAILURE() << mName << ": expected a MotionEvent, but didn't get one.";
        return nullptr;
    }

    if (event->getType() != InputEventType::MOTION) {
        ADD_FAILURE() << mName << " expected a MotionEvent, got " << *event;
        return nullptr;
    }
    return std::unique_ptr<MotionEvent>(static_cast<MotionEvent*>(event.release()));
}

void FakeInputReceiver::consumeMotionEvent(const ::testing::Matcher<MotionEvent>& matcher) {
    std::unique_ptr<MotionEvent> motionEvent = consumeMotion();
    ASSERT_NE(nullptr, motionEvent) << "Did not get a motion event, but expected " << matcher;
    ASSERT_THAT(*motionEvent, matcher);
}

void FakeInputReceiver::consumeFocusEvent(bool hasFocus, bool inTouchMode) {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED);
    ASSERT_NE(nullptr, event) << mName.c_str() << ": consumer should have returned non-NULL event.";
    ASSERT_EQ(InputEventType::FOCUS, event->getType()) << "Instead of FocusEvent, got " << *event;

    ASSERT_EQ(ui::LogicalDisplayId::INVALID, event->getDisplayId())
            << mName.c_str() << ": event displayId should always be NONE.";

    FocusEvent& focusEvent = static_cast<FocusEvent&>(*event);
    EXPECT_EQ(hasFocus, focusEvent.getHasFocus());
}

void FakeInputReceiver::consumeCaptureEvent(bool hasCapture) {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED);
    ASSERT_NE(nullptr, event) << mName.c_str() << ": consumer should have returned non-NULL event.";
    ASSERT_EQ(InputEventType::CAPTURE, event->getType())
            << "Instead of CaptureEvent, got " << *event;

    ASSERT_EQ(ui::LogicalDisplayId::INVALID, event->getDisplayId())
            << mName.c_str() << ": event displayId should always be NONE.";

    const auto& captureEvent = static_cast<const CaptureEvent&>(*event);
    EXPECT_EQ(hasCapture, captureEvent.getPointerCaptureEnabled());
}

void FakeInputReceiver::consumeDragEvent(bool isExiting, float x, float y) {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED);
    ASSERT_NE(nullptr, event) << mName.c_str() << ": consumer should have returned non-NULL event.";
    ASSERT_EQ(InputEventType::DRAG, event->getType()) << "Instead of DragEvent, got " << *event;

    EXPECT_EQ(ui::LogicalDisplayId::INVALID, event->getDisplayId())
            << mName.c_str() << ": event displayId should always be NONE.";

    const auto& dragEvent = static_cast<const DragEvent&>(*event);
    EXPECT_EQ(isExiting, dragEvent.isExiting());
    EXPECT_EQ(x, dragEvent.getX());
    EXPECT_EQ(y, dragEvent.getY());
}

void FakeInputReceiver::consumeTouchModeEvent(bool inTouchMode) {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED);
    ASSERT_NE(nullptr, event) << mName.c_str() << ": consumer should have returned non-NULL event.";
    ASSERT_EQ(InputEventType::TOUCH_MODE, event->getType())
            << "Instead of TouchModeEvent, got " << *event;

    ASSERT_EQ(ui::LogicalDisplayId::INVALID, event->getDisplayId())
            << mName.c_str() << ": event displayId should always be NONE.";
    const auto& touchModeEvent = static_cast<const TouchModeEvent&>(*event);
    EXPECT_EQ(inTouchMode, touchModeEvent.isInTouchMode());
}

void FakeInputReceiver::assertNoEvents(std::chrono::milliseconds timeout) {
    std::unique_ptr<InputEvent> event = consume(timeout);
    if (event == nullptr) {
        return;
    }
    if (event->getType() == InputEventType::KEY) {
        KeyEvent& keyEvent = static_cast<KeyEvent&>(*event);
        ADD_FAILURE() << "Received key event " << keyEvent;
    } else if (event->getType() == InputEventType::MOTION) {
        MotionEvent& motionEvent = static_cast<MotionEvent&>(*event);
        ADD_FAILURE() << "Received motion event " << motionEvent;
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

sp<IBinder> FakeInputReceiver::getToken() {
    return mConsumer.getChannel()->getConnectionToken();
}

int FakeInputReceiver::getChannelFd() {
    return mConsumer.getChannel()->getFd();
}

// --- FakeWindowHandle ---

std::function<void(const std::unique_ptr<InputEvent>&, const gui::WindowInfo&)>
        FakeWindowHandle::sOnEventReceivedCallback{};

std::atomic<int32_t> FakeWindowHandle::sId{1};

FakeWindowHandle::FakeWindowHandle(
        const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle,
        const std::unique_ptr<inputdispatcher::InputDispatcher>& dispatcher, const std::string name,
        ui::LogicalDisplayId displayId, bool createInputChannel)
      : mName(name) {
    sp<IBinder> token;
    if (createInputChannel) {
        base::Result<std::unique_ptr<InputChannel>> channel = dispatcher->createInputChannel(name);
        token = (*channel)->getConnectionToken();
        mInputReceiver = std::make_unique<FakeInputReceiver>(std::move(*channel), name);
    }

    inputApplicationHandle->updateInfo();
    mInfo.applicationInfo = *inputApplicationHandle->getInfo();

    mInfo.token = token;
    mInfo.id = sId++;
    mInfo.name = name;
    mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT;
    mInfo.alpha = 1.0;
    mInfo.frame = Rect(0, 0, WIDTH, HEIGHT);
    mInfo.transform.set(0, 0);
    mInfo.globalScaleFactor = 1.0;
    mInfo.touchableRegion.clear();
    mInfo.addTouchableRegion(Rect(0, 0, WIDTH, HEIGHT));
    mInfo.ownerPid = WINDOW_PID;
    mInfo.ownerUid = WINDOW_UID;
    mInfo.displayId = displayId;
    mInfo.inputConfig = InputConfig::DEFAULT;
}

sp<FakeWindowHandle> FakeWindowHandle::clone(ui::LogicalDisplayId displayId) {
    sp<FakeWindowHandle> handle = sp<FakeWindowHandle>::make(mInfo.name + "(Mirror)");
    handle->mInfo = mInfo;
    handle->mInfo.displayId = displayId;
    handle->mInfo.id = sId++;
    handle->mInputReceiver = mInputReceiver;
    return handle;
}

std::unique_ptr<KeyEvent> FakeWindowHandle::consumeKey(bool handled) {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED, handled);
    if (event == nullptr) {
        ADD_FAILURE() << "No event";
        return nullptr;
    }
    if (event->getType() != InputEventType::KEY) {
        ADD_FAILURE() << "Instead of key event, got " << event;
        return nullptr;
    }
    return std::unique_ptr<KeyEvent>(static_cast<KeyEvent*>(event.release()));
}

std::unique_ptr<MotionEvent> FakeWindowHandle::consumeMotionEvent(
        const ::testing::Matcher<MotionEvent>& matcher) {
    std::unique_ptr<InputEvent> event = consume(CONSUME_TIMEOUT_EVENT_EXPECTED);
    if (event == nullptr) {
        std::ostringstream matcherDescription;
        matcher.DescribeTo(&matcherDescription);
        ADD_FAILURE() << "No event (expected " << matcherDescription.str() << ") on " << mName;
        return nullptr;
    }
    if (event->getType() != InputEventType::MOTION) {
        ADD_FAILURE() << "Instead of motion event, got " << *event << " on " << mName;
        return nullptr;
    }
    std::unique_ptr<MotionEvent> motionEvent =
            std::unique_ptr<MotionEvent>(static_cast<MotionEvent*>(event.release()));
    if (motionEvent == nullptr) {
        return nullptr;
    }
    EXPECT_THAT(*motionEvent, matcher) << " on " << mName;
    return motionEvent;
}

void FakeWindowHandle::assertNoEvents(std::optional<std::chrono::milliseconds> timeout) {
    if (mInputReceiver == nullptr && mInfo.inputConfig.test(InputConfig::NO_INPUT_CHANNEL)) {
        return; // Can't receive events if the window does not have input channel
    }
    ASSERT_NE(nullptr, mInputReceiver)
            << "Window without InputReceiver must specify feature NO_INPUT_CHANNEL";
    mInputReceiver->assertNoEvents(timeout.value_or(CONSUME_TIMEOUT_NO_EVENT_EXPECTED));
}

std::unique_ptr<InputEvent> FakeWindowHandle::consume(std::chrono::milliseconds timeout,
                                                      bool handled) {
    if (mInputReceiver == nullptr) {
        LOG(FATAL) << "Cannot consume event from a window with no input event receiver";
    }
    std::unique_ptr<InputEvent> event = mInputReceiver->consume(timeout, handled);
    if (event == nullptr) {
        ADD_FAILURE() << "Consume failed: no event";
    }

    if (sOnEventReceivedCallback != nullptr) {
        sOnEventReceivedCallback(event, mInfo);
    }
    return event;
}

std::pair<std::optional<uint32_t /*seq*/>, std::unique_ptr<InputEvent>>
FakeWindowHandle::receive() {
    if (mInputReceiver == nullptr) {
        ADD_FAILURE() << "Invalid receive event on window with no receiver";
        return std::make_pair(std::nullopt, nullptr);
    }
    auto out = mInputReceiver->receiveEvent(CONSUME_TIMEOUT_EVENT_EXPECTED);
    const auto& [_, event] = out;

    if (sOnEventReceivedCallback != nullptr) {
        sOnEventReceivedCallback(event, mInfo);
    }
    return out;
}

} // namespace android
