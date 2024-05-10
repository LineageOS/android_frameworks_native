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

#include <android-base/logging.h>
#include <attestation/HmacKeyManager.h>
#include <ftl/enum.h>
#include <gtest/gtest.h>
#include <input/BlockingQueue.h>
#include <input/InputConsumerNoResampling.h>
#include <input/InputTransport.h>

using android::base::Result;

namespace android {

namespace {

static constexpr float EPSILON = MotionEvent::ROUNDING_PRECISION;
static constexpr int32_t ACTION_MOVE = AMOTION_EVENT_ACTION_MOVE;
static constexpr int32_t POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t POINTER_2_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (2 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

static auto constexpr TIMEOUT = 5s;

struct Pointer {
    int32_t id;
    float x;
    float y;
    bool isResampled = false;
};

// A collection of arguments to be sent as publishMotionEvent(). The saved members of this struct
// allow to check the expectations against the event acquired from the InputConsumerCallbacks. To
// help simplify expectation checking it carries members not present in MotionEvent, like
// |rawXScale|.
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

    flags = AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED;
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

Result<InputPublisher::ConsumerResponse> receiveConsumerResponse(
        InputPublisher& publisher, std::chrono::milliseconds timeout) {
    const std::chrono::time_point start = std::chrono::steady_clock::now();

    while (true) {
        Result<InputPublisher::ConsumerResponse> result = publisher.receiveConsumerResponse();
        if (result.ok()) {
            return result;
        }
        const std::chrono::duration waited = std::chrono::steady_clock::now() - start;
        if (waited > timeout) {
            return result;
        }
    }
}

void verifyFinishedSignal(InputPublisher& publisher, uint32_t seq, nsecs_t publishTime) {
    Result<InputPublisher::ConsumerResponse> result = receiveConsumerResponse(publisher, TIMEOUT);
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse returned " << result.error().message();
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*result));
    const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*result);
    ASSERT_EQ(seq, finish.seq)
            << "receiveConsumerResponse should have returned the original sequence number";
    ASSERT_TRUE(finish.handled)
            << "receiveConsumerResponse should have set handled to consumer's reply";
    ASSERT_GE(finish.consumeTime, publishTime)
            << "finished signal's consume time should be greater than publish time";
}

} // namespace

class InputConsumerMessageHandler : public MessageHandler {
public:
    InputConsumerMessageHandler(std::function<void(const Message&)> function)
          : mFunction(function) {}

private:
    void handleMessage(const Message& message) override { mFunction(message); }

    std::function<void(const Message&)> mFunction;
};

class InputPublisherAndConsumerNoResamplingTest : public testing::Test,
                                                  public InputConsumerCallbacks {
protected:
    std::unique_ptr<InputChannel> mClientChannel;
    std::unique_ptr<InputPublisher> mPublisher;
    std::unique_ptr<InputConsumerNoResampling> mConsumer;

    std::thread mLooperThread;
    sp<Looper> mLooper = sp<Looper>::make(/*allowNonCallbacks=*/false);

    // LOOPER CONTROL
    // Set to false when you want the looper to exit
    std::atomic<bool> mExitLooper = false;
    std::mutex mLock;

    // Used by test to notify looper that the value of "mLooperMayProceed" has changed
    std::condition_variable mNotifyLooperMayProceed;
    bool mLooperMayProceed GUARDED_BY(mLock){true};
    // Used by looper to notify the test that it's about to block on "mLooperMayProceed" -> true
    std::condition_variable mNotifyLooperWaiting;
    bool mLooperIsBlocked GUARDED_BY(mLock){false};

    std::condition_variable mNotifyConsumerDestroyed;
    bool mConsumerDestroyed GUARDED_BY(mLock){false};

    void runLooper() {
        static constexpr int LOOP_INDEFINITELY = -1;
        Looper::setForThread(mLooper);
        // Loop forever -- this thread is dedicated to servicing the looper callbacks.
        while (!mExitLooper) {
            mLooper->pollOnce(/*timeoutMillis=*/LOOP_INDEFINITELY);
        }
    }

    void SetUp() override {
        std::unique_ptr<InputChannel> serverChannel;
        status_t result =
                InputChannel::openInputChannelPair("channel name", serverChannel, mClientChannel);
        ASSERT_EQ(OK, result);

        mPublisher = std::make_unique<InputPublisher>(std::move(serverChannel));
        mMessageHandler = sp<InputConsumerMessageHandler>::make(
                [this](const Message& message) { handleMessage(message); });
        mLooperThread = std::thread([this] { runLooper(); });
        sendMessage(LooperMessage::CREATE_CONSUMER);
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
    void TearDown() override {
        // Destroy the consumer, flushing any of the pending ack's.
        sendMessage(LooperMessage::DESTROY_CONSUMER);
        {
            std::unique_lock lock(mLock);
            base::ScopedLockAssertion assumeLocked(mLock);
            mNotifyConsumerDestroyed.wait(lock, [this] { return mConsumerDestroyed; });
        }
        // Stop the looper thread so that we can destroy the object.
        mExitLooper = true;
        mLooper->wake();
        mLooperThread.join();
    }

protected:
    // Interaction with the looper thread
    enum class LooperMessage : int {
        CALL_PROBABLY_HAS_INPUT,
        CREATE_CONSUMER,
        DESTROY_CONSUMER,
        CALL_REPORT_TIMELINE,
        BLOCK_LOOPER,
    };
    void sendMessage(LooperMessage message);
    struct ReportTimelineArgs {
        int32_t inputEventId;
        nsecs_t gpuCompletedTime;
        nsecs_t presentTime;
    };
    // The input to the function "InputConsumer::reportTimeline". Populated on the test thread and
    // accessed on the looper thread.
    BlockingQueue<ReportTimelineArgs> mReportTimelineArgs;
    // The output of calling "InputConsumer::probablyHasInput()". Populated on the looper thread and
    // accessed on the test thread.
    BlockingQueue<bool> mProbablyHasInputResponses;

private:
    sp<MessageHandler> mMessageHandler;
    void handleMessage(const Message& message);

    static auto constexpr NO_EVENT_TIMEOUT = 10ms;
    // The sequence number to use when publishing the next event
    uint32_t mSeq = 1;

    BlockingQueue<std::unique_ptr<KeyEvent>> mKeyEvents;
    BlockingQueue<std::unique_ptr<MotionEvent>> mMotionEvents;
    BlockingQueue<std::unique_ptr<FocusEvent>> mFocusEvents;
    BlockingQueue<std::unique_ptr<CaptureEvent>> mCaptureEvents;
    BlockingQueue<std::unique_ptr<DragEvent>> mDragEvents;
    BlockingQueue<std::unique_ptr<TouchModeEvent>> mTouchModeEvents;

    // InputConsumerCallbacks interface
    void onKeyEvent(std::unique_ptr<KeyEvent> event, uint32_t seq) override {
        mKeyEvents.push(std::move(event));
        mConsumer->finishInputEvent(seq, true);
    }
    void onMotionEvent(std::unique_ptr<MotionEvent> event, uint32_t seq) override {
        mMotionEvents.push(std::move(event));
        mConsumer->finishInputEvent(seq, true);
    }
    void onBatchedInputEventPending(int32_t pendingBatchSource) override {
        if (!mConsumer->probablyHasInput()) {
            ADD_FAILURE() << "should deterministically have input because there is a batch";
        }
        mConsumer->consumeBatchedInputEvents(std::nullopt);
    };
    void onFocusEvent(std::unique_ptr<FocusEvent> event, uint32_t seq) override {
        mFocusEvents.push(std::move(event));
        mConsumer->finishInputEvent(seq, true);
    };
    void onCaptureEvent(std::unique_ptr<CaptureEvent> event, uint32_t seq) override {
        mCaptureEvents.push(std::move(event));
        mConsumer->finishInputEvent(seq, true);
    };
    void onDragEvent(std::unique_ptr<DragEvent> event, uint32_t seq) override {
        mDragEvents.push(std::move(event));
        mConsumer->finishInputEvent(seq, true);
    }
    void onTouchModeEvent(std::unique_ptr<TouchModeEvent> event, uint32_t seq) override {
        mTouchModeEvents.push(std::move(event));
        mConsumer->finishInputEvent(seq, true);
    };
};

void InputPublisherAndConsumerNoResamplingTest::sendMessage(LooperMessage message) {
    Message msg{ftl::to_underlying(message)};
    mLooper->sendMessage(mMessageHandler, msg);
}

void InputPublisherAndConsumerNoResamplingTest::handleMessage(const Message& message) {
    switch (static_cast<LooperMessage>(message.what)) {
        case LooperMessage::CALL_PROBABLY_HAS_INPUT: {
            mProbablyHasInputResponses.push(mConsumer->probablyHasInput());
            break;
        }
        case LooperMessage::CREATE_CONSUMER: {
            mConsumer = std::make_unique<InputConsumerNoResampling>(std::move(mClientChannel),
                                                                    mLooper, *this);
            break;
        }
        case LooperMessage::DESTROY_CONSUMER: {
            mConsumer = nullptr;
            {
                std::unique_lock lock(mLock);
                mConsumerDestroyed = true;
            }
            mNotifyConsumerDestroyed.notify_all();
            break;
        }
        case LooperMessage::CALL_REPORT_TIMELINE: {
            std::optional<ReportTimelineArgs> args = mReportTimelineArgs.pop();
            if (!args.has_value()) {
                ADD_FAILURE() << "Couldn't get the 'reportTimeline' args in time";
                return;
            }
            mConsumer->reportTimeline(args->inputEventId, args->gpuCompletedTime,
                                      args->presentTime);
            break;
        }
        case LooperMessage::BLOCK_LOOPER: {
            {
                std::unique_lock lock(mLock);
                mLooperIsBlocked = true;
            }
            mNotifyLooperWaiting.notify_all();

            {
                std::unique_lock lock(mLock);
                base::ScopedLockAssertion assumeLocked(mLock);
                mNotifyLooperMayProceed.wait(lock, [this] { return mLooperMayProceed; });
            }

            {
                std::unique_lock lock(mLock);
                mLooperIsBlocked = false;
            }
            mNotifyLooperWaiting.notify_all();
            break;
        }
    }
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeKeyEvent() {
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
    ASSERT_EQ(OK, status) << "publisher publishKeyEvent should return OK";

    std::optional<std::unique_ptr<KeyEvent>> optKeyEvent = mKeyEvents.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(optKeyEvent.has_value()) << "consumer should have returned non-NULL event";
    std::unique_ptr<KeyEvent> keyEvent = std::move(*optKeyEvent);

    sendMessage(LooperMessage::CALL_PROBABLY_HAS_INPUT);
    std::optional<bool> probablyHasInput = mProbablyHasInputResponses.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(probablyHasInput.has_value());
    ASSERT_FALSE(probablyHasInput.value()) << "no events should be waiting after being consumed";

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

    verifyFinishedSignal(*mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeMotionStream() {
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

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeMotionDown(nsecs_t downTime) {
    publishAndConsumeMotionEvent(AMOTION_EVENT_ACTION_DOWN, downTime,
                                 {Pointer{.id = 0, .x = 20, .y = 30}});
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeBatchedMotionMove(
        nsecs_t downTime) {
    uint32_t seq = mSeq++;
    const std::vector<Pointer> pointers = {Pointer{.id = 0, .x = 20, .y = 30}};
    PublishMotionArgs args(AMOTION_EVENT_ACTION_MOVE, downTime, pointers, seq);
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    // Block the looper thread, preventing it from being able to service any of the fd callbacks.

    {
        std::scoped_lock lock(mLock);
        mLooperMayProceed = false;
    }
    sendMessage(LooperMessage::BLOCK_LOOPER);
    {
        std::unique_lock lock(mLock);
        mNotifyLooperWaiting.wait(lock, [this] { return mLooperIsBlocked; });
    }

    publishMotionEvent(*mPublisher, args);

    // Ensure no event arrives because the UI thread is blocked
    std::optional<std::unique_ptr<MotionEvent>> noEvent =
            mMotionEvents.popWithTimeout(NO_EVENT_TIMEOUT);
    ASSERT_FALSE(noEvent.has_value()) << "Got unexpected event: " << *noEvent;

    Result<InputPublisher::ConsumerResponse> result = mPublisher->receiveConsumerResponse();
    ASSERT_FALSE(result.ok());
    ASSERT_EQ(WOULD_BLOCK, result.error().code());

    // We shouldn't be calling mConsumer on the UI thread, but in this situation, the looper
    // thread is locked, so this should be safe to do.
    ASSERT_TRUE(mConsumer->probablyHasInput())
            << "should deterministically have input because there is a batch";

    // Now, unblock the looper thread, so that the event can arrive.
    {
        std::scoped_lock lock(mLock);
        mLooperMayProceed = true;
    }
    mNotifyLooperMayProceed.notify_all();

    std::optional<std::unique_ptr<MotionEvent>> optMotion = mMotionEvents.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(optMotion.has_value());
    std::unique_ptr<MotionEvent> motion = std::move(*optMotion);
    ASSERT_EQ(ACTION_MOVE, motion->getAction());

    verifyFinishedSignal(*mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeMotionEvent(
        int32_t action, nsecs_t downTime, const std::vector<Pointer>& pointers) {
    uint32_t seq = mSeq++;
    PublishMotionArgs args(action, downTime, pointers, seq);
    nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);
    publishMotionEvent(*mPublisher, args);

    std::optional<std::unique_ptr<MotionEvent>> optMotion = mMotionEvents.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(optMotion.has_value());
    std::unique_ptr<MotionEvent> event = std::move(*optMotion);

    verifyArgsEqualToEvent(args, *event);

    verifyFinishedSignal(*mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeFocusEvent() {
    status_t status;

    constexpr uint32_t seq = 15;
    int32_t eventId = InputEvent::nextId();
    constexpr bool hasFocus = true;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishFocusEvent(seq, eventId, hasFocus);
    ASSERT_EQ(OK, status) << "publisher publishFocusEvent should return OK";

    std::optional<std::unique_ptr<FocusEvent>> optFocusEvent = mFocusEvents.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(optFocusEvent.has_value()) << "consumer should have returned non-NULL event";
    std::unique_ptr<FocusEvent> focusEvent = std::move(*optFocusEvent);
    EXPECT_EQ(eventId, focusEvent->getId());
    EXPECT_EQ(hasFocus, focusEvent->getHasFocus());

    verifyFinishedSignal(*mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeCaptureEvent() {
    status_t status;

    constexpr uint32_t seq = 42;
    int32_t eventId = InputEvent::nextId();
    constexpr bool captureEnabled = true;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishCaptureEvent(seq, eventId, captureEnabled);
    ASSERT_EQ(OK, status) << "publisher publishCaptureEvent should return OK";

    std::optional<std::unique_ptr<CaptureEvent>> optEvent = mCaptureEvents.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(optEvent.has_value()) << "consumer should have returned non-NULL event";
    std::unique_ptr<CaptureEvent> event = std::move(*optEvent);

    const CaptureEvent& captureEvent = *event;
    EXPECT_EQ(eventId, captureEvent.getId());
    EXPECT_EQ(captureEnabled, captureEvent.getPointerCaptureEnabled());

    verifyFinishedSignal(*mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeDragEvent() {
    status_t status;

    constexpr uint32_t seq = 15;
    int32_t eventId = InputEvent::nextId();
    constexpr bool isExiting = false;
    constexpr float x = 10;
    constexpr float y = 15;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishDragEvent(seq, eventId, x, y, isExiting);
    ASSERT_EQ(OK, status) << "publisher publishDragEvent should return OK";

    std::optional<std::unique_ptr<DragEvent>> optEvent = mDragEvents.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(optEvent.has_value()) << "consumer should have returned non-NULL event";
    std::unique_ptr<DragEvent> event = std::move(*optEvent);

    const DragEvent& dragEvent = *event;
    EXPECT_EQ(eventId, dragEvent.getId());
    EXPECT_EQ(isExiting, dragEvent.isExiting());
    EXPECT_EQ(x, dragEvent.getX());
    EXPECT_EQ(y, dragEvent.getY());

    verifyFinishedSignal(*mPublisher, seq, publishTime);
}

void InputPublisherAndConsumerNoResamplingTest::publishAndConsumeTouchModeEvent() {
    status_t status;

    constexpr uint32_t seq = 15;
    int32_t eventId = InputEvent::nextId();
    constexpr bool touchModeEnabled = true;
    const nsecs_t publishTime = systemTime(SYSTEM_TIME_MONOTONIC);

    status = mPublisher->publishTouchModeEvent(seq, eventId, touchModeEnabled);
    ASSERT_EQ(OK, status) << "publisher publishTouchModeEvent should return OK";

    std::optional<std::unique_ptr<TouchModeEvent>> optEvent =
            mTouchModeEvents.popWithTimeout(TIMEOUT);
    ASSERT_TRUE(optEvent.has_value());
    std::unique_ptr<TouchModeEvent> event = std::move(*optEvent);

    const TouchModeEvent& touchModeEvent = *event;
    EXPECT_EQ(eventId, touchModeEvent.getId());
    EXPECT_EQ(touchModeEnabled, touchModeEvent.isInTouchMode());

    verifyFinishedSignal(*mPublisher, seq, publishTime);
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, SendTimeline) {
    const int32_t inputEventId = 20;
    const nsecs_t gpuCompletedTime = 30;
    const nsecs_t presentTime = 40;

    mReportTimelineArgs.emplace(inputEventId, gpuCompletedTime, presentTime);
    sendMessage(LooperMessage::CALL_REPORT_TIMELINE);

    Result<InputPublisher::ConsumerResponse> result = receiveConsumerResponse(*mPublisher, TIMEOUT);
    ASSERT_TRUE(result.ok()) << "receiveConsumerResponse should return OK";
    ASSERT_TRUE(std::holds_alternative<InputPublisher::Timeline>(*result));
    const InputPublisher::Timeline& timeline = std::get<InputPublisher::Timeline>(*result);
    ASSERT_EQ(inputEventId, timeline.inputEventId);
    ASSERT_EQ(gpuCompletedTime, timeline.graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME]);
    ASSERT_EQ(presentTime, timeline.graphicsTimeline[GraphicsTimeline::PRESENT_TIME]);
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishKeyEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeKeyEvent());
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishMotionEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeMotionStream());
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishMotionMoveEvent_EndToEnd) {
    // Publish a DOWN event before MOVE to pass the InputVerifier checks.
    const nsecs_t downTime = systemTime(SYSTEM_TIME_MONOTONIC);
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeMotionDown(downTime));

    // Publish the MOVE event and check expectations.
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeBatchedMotionMove(downTime));
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishFocusEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeFocusEvent());
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishCaptureEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeCaptureEvent());
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishDragEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeDragEvent());
}

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishTouchModeEvent_EndToEnd) {
    ASSERT_NO_FATAL_FAILURE(publishAndConsumeTouchModeEvent());
}

TEST_F(InputPublisherAndConsumerNoResamplingTest,
       PublishMotionEvent_WhenSequenceNumberIsZero_ReturnsError) {
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

TEST_F(InputPublisherAndConsumerNoResamplingTest,
       PublishMotionEvent_WhenPointerCountLessThan1_ReturnsError) {
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

TEST_F(InputPublisherAndConsumerNoResamplingTest,
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

TEST_F(InputPublisherAndConsumerNoResamplingTest, PublishMultipleEvents_EndToEnd) {
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
