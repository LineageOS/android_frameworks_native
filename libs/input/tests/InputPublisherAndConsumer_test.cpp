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

#include <attestation/HmacKeyManager.h>
#include <gtest/gtest.h>
#include <input/InputConsumer.h>
#include <input/InputTransport.h>

using android::base::Result;

namespace android {

namespace {

static constexpr float EPSILON = MotionEvent::ROUNDING_PRECISION;
static constexpr int32_t POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_2_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

struct Pointer {
    int32_t id;
    float x;
    float y;
    bool isResampled = false;
};

// A collection of arguments to be sent as publishMotionEvent(). The saved members of this struct
// allow to check the expectations against the event acquired from the InputReceiver. To help
// simplify expectation checking it carries members not present in MotionEvent, like |rawXScale|.
struct PublishMotionArgs {
    const int32_t action;
    const nsecs_t downTime;
    const uint32_t seq;
    const int32_t eventId;
    const int32_t deviceId = 1;
    const uint32_t source = AINPUT_SOURCE_TOUCHSCREEN;
    const ui::LogicalDisplayId displayId = ui::LogicalDisplayId::DEFAULT;
    const int32_t actionButton = 0;
    const int32_t edgeFlags = AMOTION_EVENT_EDGE_FLAG_TOP;
    const int32_t metaState = AMETA_ALT_LEFT_ON | AMETA_ALT_ON;
    const int32_t buttonState = AMOTION_EVENT_BUTTON_PRIMARY;
    const MotionClassification classification = MotionClassification::AMBIGUOUS_GESTURE;
    const float xScale = 2;
    const float yScale = 3;
    const float xOffset = -10;
    const float yOffset = -20;
    const float rawXScale = 4;
    const float rawYScale = -5;
    const float rawXOffset = -11;
    const float rawYOffset = 42;
    const float xPrecision = 0.25;
    const float yPrecision = 0.5;
    const float xCursorPosition = 1.3;
    const float yCursorPosition = 50.6;
    std::array<uint8_t, 32> hmac;
    int32_t flags;
    ui::Transform transform;
    ui::Transform rawTransform;
    const nsecs_t eventTime;
    size_t pointerCount;
    std::vector<PointerProperties> pointerProperties;
    std::vector<PointerCoords> pointerCoords;

    PublishMotionArgs(int32_t action, nsecs_t downTime, const std::vector<Pointer>& pointers,
                      const uint32_t seq);
};

PublishMotionArgs::PublishMotionArgs(int32_t inAction, nsecs_t inDownTime,
                                     const std::vector<Pointer>& pointers, const uint32_t inSeq)
      : action(inAction),
        downTime(inDownTime),
        seq(inSeq),
        eventId(InputEvent::nextId()),
        eventTime(systemTime(SYSTEM_TIME_MONOTONIC)) {
    hmac = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    flags = AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED |
            AMOTION_EVENT_PRIVATE_FLAG_SUPPORTS_ORIENTATION |
            AMOTION_EVENT_PRIVATE_FLAG_SUPPORTS_DIRECTIONAL_ORIENTATION;
    if (action == AMOTION_EVENT_ACTION_CANCEL) {
        flags |= AMOTION_EVENT_FLAG_CANCELED;
    }
    pointerCount = pointers.size();
    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties.push_back({});
        pointerProperties[i].clear();
        pointerProperties[i].id = pointers[i].id;
        pointerProperties[i].toolType = ToolType::FINGER;

        pointerCoords.push_back({});
        pointerCoords[i].clear();
        pointerCoords[i].isResampled = pointers[i].isResampled;
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X, pointers[i].x);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y, pointers[i].y);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 0.5 * i);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_SIZE, 0.7 * i);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, 1.5 * i);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, 1.7 * i);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 2.5 * i);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, 2.7 * i);
        pointerCoords[i].setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, 3.5 * i);
    }
    transform.set({xScale, 0, xOffset, 0, yScale, yOffset, 0, 0, 1});
    rawTransform.set({rawXScale, 0, rawXOffset, 0, rawYScale, rawYOffset, 0, 0, 1});
}

// Checks expectations against |motionEvent| acquired from an InputConsumer. Floating point
// comparisons limit precision to EPSILON.
void verifyArgsEqualToEvent(const PublishMotionArgs& args, const MotionEvent& motionEvent) {
    EXPECT_EQ(args.eventId, motionEvent.getId());
    EXPECT_EQ(args.deviceId, motionEvent.getDeviceId());
    EXPECT_EQ(args.source, motionEvent.getSource());
    EXPECT_EQ(args.displayId, motionEvent.getDisplayId());
    EXPECT_EQ(args.hmac, motionEvent.getHmac());
    EXPECT_EQ(args.action, motionEvent.getAction());
    EXPECT_EQ(args.downTime, motionEvent.getDownTime());
    EXPECT_EQ(args.flags, motionEvent.getFlags());
    EXPECT_EQ(args.edgeFlags, motionEvent.getEdgeFlags());
    EXPECT_EQ(args.metaState, motionEvent.getMetaState());
    EXPECT_EQ(args.buttonState, motionEvent.getButtonState());
    EXPECT_EQ(args.classification, motionEvent.getClassification());
    EXPECT_EQ(args.transform, motionEvent.getTransform());
    EXPECT_NEAR((-args.rawXOffset / args.rawXScale) * args.xScale + args.xOffset,
                motionEvent.getRawXOffset(), EPSILON);
    EXPECT_NEAR((-args.rawYOffset / args.rawYScale) * args.yScale + args.yOffset,
                motionEvent.getRawYOffset(), EPSILON);
    EXPECT_EQ(args.xPrecision, motionEvent.getXPrecision());
    EXPECT_EQ(args.yPrecision, motionEvent.getYPrecision());
    EXPECT_NEAR(args.xCursorPosition, motionEvent.getRawXCursorPosition(), EPSILON);
    EXPECT_NEAR(args.yCursorPosition, motionEvent.getRawYCursorPosition(), EPSILON);
    EXPECT_NEAR(args.xCursorPosition * args.xScale + args.xOffset, motionEvent.getXCursorPosition(),
                EPSILON);
    EXPECT_NEAR(args.yCursorPosition * args.yScale + args.yOffset, motionEvent.getYCursorPosition(),
                EPSILON);
    EXPECT_EQ(args.rawTransform, motionEvent.getRawTransform());
    EXPECT_EQ(args.eventTime, motionEvent.getEventTime());
    EXPECT_EQ(args.pointerCount, motionEvent.getPointerCount());
    EXPECT_EQ(0U, motionEvent.getHistorySize());

    for (size_t i = 0; i < args.pointerCount; i++) {
        SCOPED_TRACE(i);
        EXPECT_EQ(args.pointerProperties[i].id, motionEvent.getPointerId(i));
        EXPECT_EQ(args.pointerProperties[i].toolType, motionEvent.getToolType(i));

        const auto& pc = args.pointerCoords[i];
        EXPECT_EQ(pc, motionEvent.getSamplePointerCoords()[i]);

        EXPECT_NEAR(pc.getX() * args.rawXScale + args.rawXOffset, motionEvent.getRawX(i), EPSILON);
        EXPECT_NEAR(pc.getY() * args.rawYScale + args.rawYOffset, motionEvent.getRawY(i), EPSILON);
        EXPECT_NEAR(pc.getX() * args.xScale + args.xOffset, motionEvent.getX(i), EPSILON);
        EXPECT_NEAR(pc.getY() * args.yScale + args.yOffset, motionEvent.getY(i), EPSILON);
        EXPECT_EQ(pc.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE), motionEvent.getPressure(i));
        EXPECT_EQ(pc.getAxisValue(AMOTION_EVENT_AXIS_SIZE), motionEvent.getSize(i));
        EXPECT_EQ(pc.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR), motionEvent.getTouchMajor(i));
        EXPECT_EQ(pc.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR), motionEvent.getTouchMinor(i));
        EXPECT_EQ(pc.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR), motionEvent.getToolMajor(i));
        EXPECT_EQ(pc.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR), motionEvent.getToolMinor(i));

        // Calculate the orientation after scaling, keeping in mind that an orientation of 0 is
        // "up", and the positive y direction is "down".
        const float unscaledOrientation = pc.getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION);
        const float x = sinf(unscaledOrientation) * args.xScale;
        const float y = -cosf(unscaledOrientation) * args.yScale;
        EXPECT_EQ(atan2f(x, -y), motionEvent.getOrientation(i));
    }
}

void publishMotionEvent(InputPublisher& publisher, const PublishMotionArgs& a) {
    status_t status =
            publisher.publishMotionEvent(a.seq, a.eventId, a.deviceId, a.source, a.displayId,
                                         a.hmac, a.action, a.actionButton, a.flags, a.edgeFlags,
                                         a.metaState, a.buttonState, a.classification, a.transform,
                                         a.xPrecision, a.yPrecision, a.xCursorPosition,
                                         a.yCursorPosition, a.rawTransform, a.downTime, a.eventTime,
                                         a.pointerCount, a.pointerProperties.data(),
                                         a.pointerCoords.data());
    ASSERT_EQ(OK, status) << "publisher publishMotionEvent should return OK";
}

void sendAndVerifyFinishedSignal(InputConsumer& consumer, InputPublisher& publisher, uint32_t seq,
                                 nsecs_t publishTime) {
    status_t status = consumer.sendFinishedSignal(seq, false);
    ASSERT_EQ(OK, status) << "consumer sendFinishedSignal should return OK";
    Result<InputPublisher::ConsumerResponse> result = publisher.receiveConsumerResponse();
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*result));
    const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*result);
    ASSERT_EQ(seq, finish.seq)
            << "receiveConsumerResponse should have returned the original sequence number";
    ASSERT_FALSE(finish.handled)
            << "receiveConsumerResponse should have set handled to consumer's reply";
    ASSERT_GE(finish.consumeTime, publishTime)
            << "finished signal's consume time should be greater than publish time";
}

void waitUntilInputAvailable(const InputConsumer& inputConsumer) {
    bool hasInput;
    do {
        // The probablyHasInput() can return false positive under rare circumstances uncontrollable
        // by the tests. Re-request the availability in this case. Returning |false| for a long
        // time is not intended, and would cause a test timeout.
        hasInput = inputConsumer.probablyHasInput();
    } while (!hasInput);
}

} // namespace

class InputPublisherAndConsumerTest : public testing::Test {
protected:
    std::unique_ptr<InputPublisher> mPublisher;
    std::unique_ptr<InputConsumer> mConsumer;
    PreallocatedInputEventFactory mEventFactory;

    void SetUp() override {
        std::unique_ptr<InputChannel> serverChannel, clientChannel;
        status_t result = InputChannel::openInputChannelPair("channel name",
                serverChannel, clientChannel);
        ASSERT_EQ(OK, result);

        mPublisher = std::make_unique<InputPublisher>(std::move(serverChannel));
        mConsumer = std::make_unique<InputConsumer>(std::move(clientChannel));
    }

    void publishAndConsumeKeyEvent();
    void publishAndConsumeMotionStream();
    void publishAndConsumeMotionDown(nsecs_t downTime);
    void publishAndConsumeBatchedMotionMove(nsecs_t downTime);
    void publishAndConsumeFocusEvent();
    void publishAndConsumeCaptureEvent();
    void publishAndConsumeDragEvent();
    void publishAndConsumeTouchModeEvent();
    void publishAndConsumeMotionEvent(int32_t action, nsecs_t downTime,
                                      const std::vector<Pointer>& pointers);

private:
    // The sequence number to use when publishing the next event
    uint32_t mSeq = 1;
};

TEST_F(InputPublisherAndConsumerTest, GetChannel_ReturnsTheChannel) {
    ASSERT_EQ(mPublisher->getChannel().getConnectionToken(),
              mConsumer->getChannel()->getConnectionToken());
}

void InputPublisherAndConsumerTest::publishAndConsumeKeyEvent() {
    status_t status;

    const uint32_t seq = mSeq++;
    int32_t eventId = InputEvent::nextId();
    constexpr int32_t deviceId = 1;
    constexpr uint32_t source = AINPUT_SOURCE_KEYBOARD;
    constexpr ui::LogicalDisplayId displayId = ui::LogicalDisplayId::DEFAULT;
    constexpr std::array<uint8_t, 32> hmac = {31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21,
                                              20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
                                              9,  8,  7,  6,  5,  4,  3,  2,  1,  0};
    constexpr int32_t action = AKEY_EVENT_ACTION_DOWN;
    constexpr int32_t flags = AKEY_EVENT_FLAG_FROM_SYSTEM;
    constexpr int32_t keyCode = AKEYCODE_ENTER;
    constexpr int32_t scanCode = 13;
    constexpr int32_t metaState = AMETA_ALT_LEFT_ON | AMETA_ALT_ON;
    constexpr int32_t repeatCount = 1;
    constexpr nsecs_t downTime = 3;
    constexpr nsecs_t eventTime = 4;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishKeyEvent(seq, eventId, deviceId, source, displayId, hmac, action,
                                         flags, keyCode, scanCode, metaState, repeatCount, downTime,
                                         eventTime);
    ASSERT_EQ(OK, status)
            << "publisher publishKeyEvent should return OK";

    waitUntilInputAvailable(*mConsumer);
    uint32_t consumeSeq;
    InputEvent* event;
    status = mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq, &event);
    ASSERT_EQ(OK, status)
            << "consumer consume should return OK";
    EXPECT_FALSE(mConsumer->probablyHasInput())
            << "no events should be waiting after being consumed";

    ASSERT_TRUE(event != nullptr)
            << "consumer should have returned non-NULL event";
    ASSERT_EQ(InputEventType::KEY, event->getType()) << "consumer should have returned a key event";

    KeyEvent* keyEvent = static_cast<KeyEvent*>(event);
    EXPECT_EQ(seq, consumeSeq);
    EXPECT_EQ(eventId, keyEvent->getId());
    EXPECT_EQ(deviceId, keyEvent->getDeviceId());
    EXPECT_EQ(source, keyEvent->getSource());
    EXPECT_EQ(displayId, keyEvent->getDisplayId());
    EXPECT_EQ(hmac, keyEvent->getHmac());
    EXPECT_EQ(action, keyEvent->getAction());
    EXPECT_EQ(flags, keyEvent->getFlags());
    EXPECT_EQ(keyCode, keyEvent->getKeyCode());
    EXPECT_EQ(scanCode, keyEvent->getScanCode());
    EXPECT_EQ(metaState, keyEvent->getMetaState());
    EXPECT_EQ(repeatCount, keyEvent->getRepeatCount());
    EXPECT_EQ(downTime, keyEvent->getDownTime());
    EXPECT_EQ(eventTime, keyEvent->getEventTime());

    status = mConsumer->sendFinishedSignal(seq, true);
    ASSERT_EQ(OK, status)
            << "consumer sendFinishedSignal should return OK";

    Result<InputPublisher::ConsumerResponse> result = mPublisher->receiveConsumerResponse();
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*result));
    const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*result);
    ASSERT_EQ(seq, finish.seq)
            << "receiveConsumerResponse should have returned the original sequence number";
    ASSERT_TRUE(finish.handled)
            << "receiveConsumerResponse should have set handled to consumer's reply";
    ASSERT_GE(finish.consumeTime, publishTime)
            << "finished signal's consume time should be greater than publish time";
}

void InputPublisherAndConsumerTest::publishAndConsumeMotionStream() {
    const nsecs_t downTime = systemTime(SYSTEM_TIME_MONOTONIC);

    publishAndConsumeMotionEvent(AMOTION_EVENT_ACTION_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30}});

    publishAndConsumeMotionEvent(POINTER_1_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30},
                                  Pointer{.id = 1, .x = 200, .y = 300}});

    publishAndConsumeMotionEvent(POINTER_2_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30},
                                  Pointer{.id = 1, .x = 200, .y = 300},
                                  Pointer{.id = 2, .x = 300, .y = 400}});

    // Provide a consistent input stream - cancel the gesture that was started above
    publishAndConsumeMotionEvent(AMOTION_EVENT_ACTION_CANCEL, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30},
                                  Pointer{.id = 1, .x = 200, .y = 300},
                                  Pointer{.id = 2, .x = 300, .y = 400}});
}

void InputPublisherAndConsumerTest::publishAndConsumeMotionDown(nsecs_t downTime) {
    publishAndConsumeMotionEvent(AMOTION_EVENT_ACTION_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30}});
}

void InputPublisherAndConsumerTest::publishAndConsumeBatchedMotionMove(nsecs_t downTime) {
    uint32_t seq = mSeq++;
    const std::vector<Pointer> pointers = {Pointer{.id = 0, .x = 20, .y = 30}};
    PublishMotionArgs args(AMOTION_EVENT_ACTION_MOVE, downTime, pointers, seq);
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);
    publishMotionEvent(*mPublisher, args);

    // Consume leaving a batch behind.
    uint32_t consumeSeq;
    InputEvent* event;
    status_t status = mConsumer->consume(&mEventFactory,
                                         /*consumeBatches=*/false, -1, &consumeSeq, &event);
    ASSERT_EQ(WOULD_BLOCK, status)
            << "consumer consume should return WOULD_BLOCK when a new batch is started";
    ASSERT_TRUE(mConsumer->hasPendingBatch()) << "consume should have created a batch";
    EXPECT_TRUE(mConsumer->probablyHasInput())
            << "should deterministically have input because there is a batch";
    sendAndVerifyFinishedSignal(*mConsumer, *mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerTest::publishAndConsumeMotionEvent(
        int32_t action, nsecs_t downTime, const std::vector<Pointer>& pointers) {
    uint32_t seq = mSeq++;
    PublishMotionArgs args(action, downTime, pointers, seq);
    nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);
    publishMotionEvent(*mPublisher, args);

    uint32_t consumeSeq;
    InputEvent* event;
    status_t status =
            mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq, &event);
    ASSERT_EQ(OK, status) << "consumer consume should return OK";
    ASSERT_TRUE(event != nullptr)
            << "consumer should have returned non-NULL event";
    ASSERT_EQ(InputEventType::MOTION, event->getType())
            << "consumer should have returned a motion event";
    EXPECT_EQ(seq, consumeSeq);

    verifyArgsEqualToEvent(args, static_cast<const MotionEvent&>(*event));
    sendAndVerifyFinishedSignal(*mConsumer, *mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerTest::publishAndConsumeFocusEvent() {
    status_t status;

    constexpr uint32_t seq = 15;
    int32_t eventId = InputEvent::nextId();
    constexpr bool hasFocus = true;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishFocusEvent(seq, eventId, hasFocus);
    ASSERT_EQ(OK, status) << "publisher publishFocusEvent should return OK";

    uint32_t consumeSeq;
    InputEvent* event;
    status = mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq, &event);
    ASSERT_EQ(OK, status) << "consumer consume should return OK";

    ASSERT_TRUE(event != nullptr) << "consumer should have returned non-NULL event";
    ASSERT_EQ(InputEventType::FOCUS, event->getType())
            << "consumer should have returned a focus event";

    FocusEvent* focusEvent = static_cast<FocusEvent*>(event);
    EXPECT_EQ(seq, consumeSeq);
    EXPECT_EQ(eventId, focusEvent->getId());
    EXPECT_EQ(hasFocus, focusEvent->getHasFocus());

    status = mConsumer->sendFinishedSignal(seq, true);
    ASSERT_EQ(OK, status) << "consumer sendFinishedSignal should return OK";

    Result<InputPublisher::ConsumerResponse> result = mPublisher->receiveConsumerResponse();
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*result));
    const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*result);

    ASSERT_EQ(seq, finish.seq)
            << "receiveConsumerResponse should have returned the original sequence number";
    ASSERT_TRUE(finish.handled)
            << "receiveConsumerResponse should have set handled to consumer's reply";
    ASSERT_GE(finish.consumeTime, publishTime)
            << "finished signal's consume time should be greater than publish time";
}

void InputPublisherAndConsumerTest::publishAndConsumeCaptureEvent() {
    status_t status;

    constexpr uint32_t seq = 42;
    int32_t eventId = InputEvent::nextId();
    constexpr bool captureEnabled = true;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishCaptureEvent(seq, eventId, captureEnabled);
    ASSERT_EQ(OK, status) << "publisher publishCaptureEvent should return OK";

    uint32_t consumeSeq;
    InputEvent* event;
    status = mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq, &event);
    ASSERT_EQ(OK, status) << "consumer consume should return OK";

    ASSERT_TRUE(event != nullptr) << "consumer should have returned non-NULL event";
    ASSERT_EQ(InputEventType::CAPTURE, event->getType())
            << "consumer should have returned a capture event";

    const CaptureEvent* captureEvent = static_cast<CaptureEvent*>(event);
    EXPECT_EQ(seq, consumeSeq);
    EXPECT_EQ(eventId, captureEvent->getId());
    EXPECT_EQ(captureEnabled, captureEvent->getPointerCaptureEnabled());

    status = mConsumer->sendFinishedSignal(seq, true);
    ASSERT_EQ(OK, status) << "consumer sendFinishedSignal should return OK";

    Result<InputPublisher::ConsumerResponse> result = mPublisher->receiveConsumerResponse();
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*result));
    const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*result);
    ASSERT_EQ(seq, finish.seq)
            << "receiveConsumerResponse should have returned the original sequence number";
    ASSERT_TRUE(finish.handled)
            << "receiveConsumerResponse should have set handled to consumer's reply";
    ASSERT_GE(finish.consumeTime, publishTime)
            << "finished signal's consume time should be greater than publish time";
}

void InputPublisherAndConsumerTest::publishAndConsumeDragEvent() {
    status_t status;

    constexpr uint32_t seq = 15;
    int32_t eventId = InputEvent::nextId();
    constexpr bool isExiting = false;
    constexpr float x = 10;
    constexpr float y = 15;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishDragEvent(seq, eventId, x, y, isExiting);
    ASSERT_EQ(OK, status) << "publisher publishDragEvent should return OK";

    uint32_t consumeSeq;
    InputEvent* event;
    status = mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq, &event);
    ASSERT_EQ(OK, status) << "consumer consume should return OK";

    ASSERT_TRUE(event != nullptr) << "consumer should have returned non-NULL event";
    ASSERT_EQ(InputEventType::DRAG, event->getType())
            << "consumer should have returned a drag event";

    const DragEvent& dragEvent = static_cast<const DragEvent&>(*event);
    EXPECT_EQ(seq, consumeSeq);
    EXPECT_EQ(eventId, dragEvent.getId());
    EXPECT_EQ(isExiting, dragEvent.isExiting());
    EXPECT_EQ(x, dragEvent.getX());
    EXPECT_EQ(y, dragEvent.getY());

    status = mConsumer->sendFinishedSignal(seq, true);
    ASSERT_EQ(OK, status) << "consumer sendFinishedSignal should return OK";

    Result<InputPublisher::ConsumerResponse> result = mPublisher->receiveConsumerResponse();
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*result));
    const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*result);
    ASSERT_EQ(seq, finish.seq)
            << "receiveConsumerResponse should have returned the original sequence number";
    ASSERT_TRUE(finish.handled)
            << "receiveConsumerResponse should have set handled to consumer's reply";
    ASSERT_GE(finish.consumeTime, publishTime)
            << "finished signal's consume time should be greater than publish time";
}

void InputPublisherAndConsumerTest::publishAndConsumeTouchModeEvent() {
    status_t status;

    constexpr uint32_t seq = 15;
    int32_t eventId = InputEvent::nextId();
    constexpr bool touchModeEnabled = true;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishTouchModeEvent(seq, eventId, touchModeEnabled);
    ASSERT_EQ(OK, status) << "publisher publishTouchModeEvent should return OK";

    uint32_t consumeSeq;
    InputEvent* event;
    status = mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq, &event);
    ASSERT_EQ(OK, status) << "consumer consume should return OK";

    ASSERT_TRUE(event != nullptr) << "consumer should have returned non-NULL event";
    ASSERT_EQ(InputEventType::TOUCH_MODE, event->getType())
            << "consumer should have returned a touch mode event";

    const TouchModeEvent& touchModeEvent = static_cast<const TouchModeEvent&>(*event);
    EXPECT_EQ(seq, consumeSeq);
    EXPECT_EQ(eventId, touchModeEvent.getId());
    EXPECT_EQ(touchModeEnabled, touchModeEvent.isInTouchMode());

    status = mConsumer->sendFinishedSignal(seq, true);
    ASSERT_EQ(OK, status) << "consumer sendFinishedSignal should return OK";

    Result<InputPublisher::ConsumerResponse> result = mPublisher->receiveConsumerResponse();
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*result));
    const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*result);
    ASSERT_EQ(seq, finish.seq)
            << "receiveConsumerResponse should have returned the original sequence number";
    ASSERT_TRUE(finish.handled)
            << "receiveConsumerResponse should have set handled to consumer's reply";
    ASSERT_GE(finish.consumeTime, publishTime)
            << "finished signal's consume time should be greater than publish time";
}

TEST_F(InputPublisherAndConsumerTest, SendTimeline) {
    const int32_t inputEventId = 20;
    std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;
    graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME] = 30;
    graphicsTimeline[GraphicsTimeline::PRESENT_TIME] = 40;
    status_t status = mConsumer->sendTimeline(inputEventId, graphicsTimeline);
    ASSERT_EQ(OK, status);

    Result<InputPublisher::ConsumerResponse> result = mPublisher->receiveConsumerResponse();
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Timeline>(*result));
    const InputPublisher::Timeline& timeline = std::get<InputPublisher::Timeline>(*result);
    ASSERT_EQ(inputEventId, timeline.inputEventId);
    ASSERT_EQ(graphicsTimeline, timeline.graphicsTimeline);
}

TEST_F(InputPublisherAndConsumerTest, PublishKeyEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeKeyEvent());
}

TEST_F(InputPublisherAndConsumerTest, PublishMotionEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeMotionStream());
}

TEST_F(InputPublisherAndConsumerTest, PublishMotionMoveEvent_EndToEnd) {
    // Publish a DOWN event before MOVE to pass the InputVerifier checks.
    const nsecs_t downTime = systemTime(SYSTEM_TIME_MONOTONIC);
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeMotionDown(downTime));

    // Publish the MOVE event and check expectations.
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeBatchedMotionMove(downTime));
}

TEST_F(InputPublisherAndConsumerTest, PublishFocusEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeFocusEvent());
}

TEST_F(InputPublisherAndConsumerTest, PublishCaptureEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeCaptureEvent());
}

TEST_F(InputPublisherAndConsumerTest, PublishDragEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeDragEvent());
}

TEST_F(InputPublisherAndConsumerTest, PublishTouchModeEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeTouchModeEvent());
}

TEST_F(InputPublisherAndConsumerTest, PublishMotionEvent_WhenSequenceNumberIsZero_ReturnsError) {
    status_t status;
    const size_t pointerCount = 1;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];
    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerCoords[i].clear();
    }

    ui::Transform identityTransform;
    status =
            mPublisher->publishMotionEvent(0, InputEvent::nextId(), 0, 0,
                                           ui::LogicalDisplayId::DEFAULT, INVALID_HMAC, 0, 0, 0, 0,
                                           0, 0, MotionClassification::NONE, identityTransform, 0,
                                           0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                           AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform,
                                           0, 0, pointerCount, pointerProperties, pointerCoords);
    ASSERT_EQ(BAD_VALUE, status) << "publisher publishMotionEvent should return BAD_VALUE";
}

TEST_F(InputPublisherAndConsumerTest, PublishMotionEvent_WhenPointerCountLessThan1_ReturnsError) {
    status_t status;
    const size_t pointerCount = 0;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];

    ui::Transform identityTransform;
    status =
            mPublisher->publishMotionEvent(1, InputEvent::nextId(), 0, 0,
                                           ui::LogicalDisplayId::DEFAULT, INVALID_HMAC, 0, 0, 0, 0,
                                           0, 0, MotionClassification::NONE, identityTransform, 0,
                                           0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                           AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform,
                                           0, 0, pointerCount, pointerProperties, pointerCoords);
    ASSERT_EQ(BAD_VALUE, status) << "publisher publishMotionEvent should return BAD_VALUE";
}

TEST_F(InputPublisherAndConsumerTest,
       PublishMotionEvent_WhenPointerCountGreaterThanMax_ReturnsError) {
    status_t status;
    const size_t pointerCount = MAX_POINTERS + 1;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];
    for (size_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].clear();
        pointerCoords[i].clear();
    }

    ui::Transform identityTransform;
    status =
            mPublisher->publishMotionEvent(1, InputEvent::nextId(), 0, 0,
                                           ui::LogicalDisplayId::DEFAULT, INVALID_HMAC, 0, 0, 0, 0,
                                           0, 0, MotionClassification::NONE, identityTransform, 0,
                                           0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                           AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform,
                                           0, 0, pointerCount, pointerProperties, pointerCoords);
    ASSERT_EQ(BAD_VALUE, status) << "publisher publishMotionEvent should return BAD_VALUE";
}

TEST_F(InputPublisherAndConsumerTest, PublishMultipleEvents_EndToEnd) {
    const nsecs_t downTime = systemTime(SYSTEM_TIME_MONOTONIC);

    publishAndConsumeMotionEvent(AMOTION_EVENT_ACTION_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30}});
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeKeyEvent());
    publishAndConsumeMotionEvent(POINTER_1_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30},
                                  Pointer{.id = 1, .x = 200, .y = 300}});
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeFocusEvent());
    publishAndConsumeMotionEvent(POINTER_2_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30},
                                  Pointer{.id = 1, .x = 200, .y = 300},
                                  Pointer{.id = 2, .x = 200, .y = 300}});
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeKeyEvent());
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeCaptureEvent());
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeDragEvent());
    // Provide a consistent input stream - cancel the gesture that was started above
    publishAndConsumeMotionEvent(AMOTION_EVENT_ACTION_CANCEL, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30},
                                  Pointer{.id = 1, .x = 200, .y = 300},
                                  Pointer{.id = 2, .x = 200, .y = 300}});
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeKeyEvent());
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeTouchModeEvent());
}

} // namespace android
