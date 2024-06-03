/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <chrono>
#include <vector>

#include <attestation/HmacKeyManager.h>
#include <gtest/gtest.h>
#include <input/InputConsumer.h>
#include <input/InputTransport.h>

using namespace std::chrono_literals;

namespace android {

namespace {

struct Pointer {
    int32_t id;
    float x;
    float y;
    ToolType toolType = ToolType::FINGER;
    bool isResampled = false;
};

struct InputEventEntry {
    std::chrono::nanoseconds eventTime;
    std::vector<Pointer> pointers;
    int32_t action;
};

} // namespace

class TouchResamplingTest : public testing::Test {
protected:
    std::unique_ptr<InputPublisher> mPublisher;
    std::unique_ptr<InputConsumer> mConsumer;
    PreallocatedInputEventFactory mEventFactory;

    uint32_t mSeq = 1;

    void SetUp() override {
        std::unique_ptr<InputChannel> serverChannel, clientChannel;
        status_t result =
                InputChannel::openInputChannelPair("channel name", serverChannel, clientChannel);
        ASSERT_EQ(OK, result);

        mPublisher = std::make_unique<InputPublisher>(std::move(serverChannel));
        mConsumer = std::make_unique<InputConsumer>(std::move(clientChannel),
                                                    /*enableTouchResampling=*/true);
    }

    status_t publishSimpleMotionEventWithCoords(int32_t action, nsecs_t eventTime,
                                                const std::vector<PointerProperties>& properties,
                                                const std::vector<PointerCoords>& coords);
    void publishSimpleMotionEvent(int32_t action, nsecs_t eventTime,
                                  const std::vector<Pointer>& pointers);
    void publishInputEventEntries(const std::vector<InputEventEntry>& entries);
    void consumeInputEventEntries(const std::vector<InputEventEntry>& entries,
                                  std::chrono::nanoseconds frameTime);
    void receiveResponseUntilSequence(uint32_t seq);
};

status_t TouchResamplingTest::publishSimpleMotionEventWithCoords(
        int32_t action, nsecs_t eventTime, const std::vector<PointerProperties>& properties,
        const std::vector<PointerCoords>& coords) {
    const ui::Transform identityTransform;
    const nsecs_t downTime = 0;

    if (action == AMOTION_EVENT_ACTION_DOWN && eventTime != 0) {
        ADD_FAILURE() << "Downtime should be equal to 0 (hardcoded for convenience)";
    }
    return mPublisher->publishMotionEvent(mSeq++, InputEvent::nextId(), /*deviceId=*/1,
                                          AINPUT_SOURCE_TOUCHSCREEN, ui::LogicalDisplayId::DEFAULT,
                                          INVALID_HMAC, action, /*actionButton=*/0, /*flags=*/0,
                                          /*edgeFlags=*/0, AMETA_NONE, /*buttonState=*/0,
                                          MotionClassification::NONE, identityTransform,
                                          /*xPrecision=*/0, /*yPrecision=*/0,
                                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                          AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform,
                                          downTime, eventTime, properties.size(), properties.data(),
                                          coords.data());
}

void TouchResamplingTest::publishSimpleMotionEvent(int32_t action, nsecs_t eventTime,
                                                   const std::vector<Pointer>& pointers) {
    std::vector<PointerProperties> properties;
    std::vector<PointerCoords> coords;

    for (const Pointer& pointer : pointers) {
        properties.push_back({});
        properties.back().clear();
        properties.back().id = pointer.id;
        properties.back().toolType = pointer.toolType;

        coords.push_back({});
        coords.back().clear();
        coords.back().setAxisValue(AMOTION_EVENT_AXIS_X, pointer.x);
        coords.back().setAxisValue(AMOTION_EVENT_AXIS_Y, pointer.y);
    }

    status_t result = publishSimpleMotionEventWithCoords(action, eventTime, properties, coords);
    ASSERT_EQ(OK, result);
}

/**
 * Each entry is published separately, one entry at a time. As a result, action is used here
 * on a per-entry basis.
 */
void TouchResamplingTest::publishInputEventEntries(const std::vector<InputEventEntry>& entries) {
    for (const InputEventEntry& entry : entries) {
        publishSimpleMotionEvent(entry.action, entry.eventTime.count(), entry.pointers);
    }
}

/**
 * Inside the publisher, read responses repeatedly until the desired sequence number is returned.
 *
 * Sometimes, when you call 'sendFinishedSignal', you would be finishing a batch which is comprised
 * of several input events. As a result, consumer will generate multiple 'finish' signals on your
 * behalf.
 *
 * In this function, we call 'receiveConsumerResponse' in a loop until the desired sequence number
 * is returned.
 */
void TouchResamplingTest::receiveResponseUntilSequence(uint32_t seq) {
    size_t consumedEvents = 0;
    while (consumedEvents < 100) {
        android::base::Result<InputPublisher::ConsumerResponse> response =
                mPublisher->receiveConsumerResponse();
        ASSERT_TRUE(response.ok());
        ASSERT_TRUE(std::holds_alternative<InputPublisher::Finished>(*response));
        const InputPublisher::Finished& finish = std::get<InputPublisher::Finished>(*response);
        ASSERT_TRUE(finish.handled)
                << "publisher receiveFinishedSignal should have set handled to consumer's reply";
        if (finish.seq == seq) {
            return;
        }
        consumedEvents++;
    }
    FAIL() << "Got " << consumedEvents << "events, but still no event with seq=" << seq;
}

/**
 * All entries are compared against a single MotionEvent, but the same data structure
 * InputEventEntry is used here for simpler code. As a result, the entire array of InputEventEntry
 * must contain identical values for the action field.
 */
void TouchResamplingTest::consumeInputEventEntries(const std::vector<InputEventEntry>& entries,
                                                   std::chrono::nanoseconds frameTime) {
    ASSERT_GE(entries.size(), 1U) << "Must have at least 1 InputEventEntry to compare against";

    uint32_t consumeSeq;
    InputEvent* event;

    status_t status = mConsumer->consume(&mEventFactory, /*consumeBatches=*/true, frameTime.count(),
                                         &consumeSeq, &event);
    ASSERT_EQ(OK, status);
    MotionEvent* motionEvent = static_cast<MotionEvent*>(event);

    ASSERT_EQ(entries.size() - 1, motionEvent->getHistorySize());
    for (size_t i = 0; i < entries.size(); i++) { // most recent sample is last
        SCOPED_TRACE(i);
        const InputEventEntry& entry = entries[i];
        ASSERT_EQ(entry.action, motionEvent->getAction());
        ASSERT_EQ(entry.eventTime.count(), motionEvent->getHistoricalEventTime(i));
        ASSERT_EQ(entry.pointers.size(), motionEvent->getPointerCount());

        for (size_t p = 0; p < motionEvent->getPointerCount(); p++) {
            SCOPED_TRACE(p);
            // The pointers can be in any order, both in MotionEvent as well as InputEventEntry
            ssize_t motionEventPointerIndex = motionEvent->findPointerIndex(entry.pointers[p].id);
            ASSERT_GE(motionEventPointerIndex, 0) << "Pointer must be present in MotionEvent";
            ASSERT_EQ(entry.pointers[p].x,
                      motionEvent->getHistoricalAxisValue(AMOTION_EVENT_AXIS_X,
                                                          motionEventPointerIndex, i));
            ASSERT_EQ(entry.pointers[p].x,
                      motionEvent->getHistoricalRawAxisValue(AMOTION_EVENT_AXIS_X,
                                                             motionEventPointerIndex, i));
            ASSERT_EQ(entry.pointers[p].y,
                      motionEvent->getHistoricalAxisValue(AMOTION_EVENT_AXIS_Y,
                                                          motionEventPointerIndex, i));
            ASSERT_EQ(entry.pointers[p].y,
                      motionEvent->getHistoricalRawAxisValue(AMOTION_EVENT_AXIS_Y,
                                                             motionEventPointerIndex, i));
            ASSERT_EQ(entry.pointers[p].isResampled,
                      motionEvent->isResampled(motionEventPointerIndex, i));
        }
    }

    status = mConsumer->sendFinishedSignal(consumeSeq, true);
    ASSERT_EQ(OK, status);

    receiveResponseUntilSequence(consumeSeq);
}

/**
 * Timeline
 * ---------+------------------+------------------+--------+-----------------+----------------------
 *          0 ms               10 ms              20 ms    25 ms            35 ms
 *          ACTION_DOWN       ACTION_MOVE      ACTION_MOVE  ^                ^
 *                                                          |                |
 *                                                         resampled value   |
 *                                                                          frameTime
 * Typically, the prediction is made for time frameTime - RESAMPLE_LATENCY, or 30 ms in this case
 * However, that would be 10 ms later than the last real sample (which came in at 20 ms).
 * Therefore, the resampling should happen at 20 ms + RESAMPLE_MAX_PREDICTION = 28 ms.
 * In this situation, though, resample time is further limited by taking half of the difference
 * between the last two real events, which would put this time at:
 * 20 ms + (20 ms - 10 ms) / 2 = 25 ms.
 */
TEST_F(TouchResamplingTest, EventIsResampled) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 35ms;
    expectedEntries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {25ms, {{0, 35, 30, .isResampled = true}}, AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

/**
 * Same as above test, but use pointer id=1 instead of 0 to make sure that system does not
 * have these hardcoded.
 */
TEST_F(TouchResamplingTest, EventIsResampledWithDifferentId) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{1, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{1, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{1, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{1, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 35ms;
    expectedEntries = {
            //      id  x   y
            {10ms, {{1, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{1, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {25ms, {{1, 35, 30, .isResampled = true}}, AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

/**
 * Stylus pointer coordinates are resampled.
 */
TEST_F(TouchResamplingTest, StylusEventIsResampled) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 10, 20, .toolType = ToolType::STYLUS}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 10, 20, .toolType = ToolType::STYLUS}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{0, 20, 30, .toolType = ToolType::STYLUS}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30, .toolType = ToolType::STYLUS}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 35ms;
    expectedEntries = {
            //      id  x   y
            {10ms, {{0, 20, 30, .toolType = ToolType::STYLUS}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30, .toolType = ToolType::STYLUS}}, AMOTION_EVENT_ACTION_MOVE},
            {25ms,
             {{0, 35, 30, .toolType = ToolType::STYLUS, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

/**
 * Mouse pointer coordinates are resampled.
 */
TEST_F(TouchResamplingTest, MouseEventIsResampled) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 10, 20, .toolType = ToolType::MOUSE}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 10, 20, .toolType = ToolType::MOUSE}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{0, 20, 30, .toolType = ToolType::MOUSE}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30, .toolType = ToolType::MOUSE}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 35ms;
    expectedEntries = {
            //      id  x   y
            {10ms, {{0, 20, 30, .toolType = ToolType::MOUSE}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30, .toolType = ToolType::MOUSE}}, AMOTION_EVENT_ACTION_MOVE},
            {25ms,
             {{0, 35, 30, .toolType = ToolType::MOUSE, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

/**
 * Motion events with palm tool type are not resampled.
 */
TEST_F(TouchResamplingTest, PalmEventIsNotResampled) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 10, 20, .toolType = ToolType::PALM}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 10, 20, .toolType = ToolType::PALM}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{0, 20, 30, .toolType = ToolType::PALM}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30, .toolType = ToolType::PALM}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 35ms;
    expectedEntries = {
            //      id  x   y
            {10ms, {{0, 20, 30, .toolType = ToolType::PALM}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30, .toolType = ToolType::PALM}}, AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

/**
 * Event should not be resampled when sample time is equal to event time.
 */
TEST_F(TouchResamplingTest, SampleTimeEqualsEventTime) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 20ms + 5ms /*RESAMPLE_LATENCY*/;
    expectedEntries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
            // no resampled event because the time of resample falls exactly on the existing event
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

/**
 * Once we send a resampled value to the app, we should continue to "lie" if the pointer
 * does not move. So, if the pointer keeps the same coordinates, resampled value should continue
 * to be used.
 */
TEST_F(TouchResamplingTest, ResampledValueIsUsedForIdenticalCoordinates) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 35ms;
    expectedEntries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {25ms, {{0, 35, 30, .isResampled = true}}, AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Coordinate value 30 has been resampled to 35. When a new event comes in with value 30 again,
    // the system should still report 35.
    entries = {
            //      id  x   y
            {40ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 45ms + 5ms /*RESAMPLE_LATENCY*/;
    expectedEntries = {
            //      id  x   y
            {40ms,
             {{0, 35, 30, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE}, // original event, rewritten
            {45ms,
             {{0, 35, 30, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE}, // resampled event, rewritten
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

TEST_F(TouchResamplingTest, OldEventReceivedAfterResampleOccurs) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 10, 20}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Two ACTION_MOVE events 10 ms apart that move in X direction and stay still in Y
    entries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 35ms;
    expectedEntries = {
            //      id  x   y
            {10ms, {{0, 20, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {20ms, {{0, 30, 30}}, AMOTION_EVENT_ACTION_MOVE},
            {25ms, {{0, 35, 30, .isResampled = true}}, AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);
    // Above, the resampled event is at 25ms rather than at 30 ms = 35ms - RESAMPLE_LATENCY
    // because we are further bound by how far we can extrapolate by the "last time delta".
    // That's 50% of (20 ms - 10ms) => 5ms. So we can't predict more than 5 ms into the future
    // from the event at 20ms, which is why the resampled event is at t = 25 ms.

    // We resampled the event to 25 ms. Now, an older 'real' event comes in.
    entries = {
            //      id  x   y
            {24ms, {{0, 40, 30}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 50ms;
    expectedEntries = {
            //      id  x   y
            {24ms,
             {{0, 35, 30, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE}, // original event, rewritten
            {26ms,
             {{0, 45, 30, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE}, // resampled event, rewritten
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

TEST_F(TouchResamplingTest, TwoPointersAreResampledIndependently) {
    std::chrono::nanoseconds frameTime;
    std::vector<InputEventEntry> entries, expectedEntries;

    // full action for when a pointer with id=1 appears (some other pointer must already be present)
    constexpr int32_t actionPointer1Down =
            AMOTION_EVENT_ACTION_POINTER_DOWN + (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

    // full action for when a pointer with id=0 disappears (some other pointer must still remain)
    constexpr int32_t actionPointer0Up =
            AMOTION_EVENT_ACTION_POINTER_UP + (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

    // Initial ACTION_DOWN should be separate, because the first consume event will only return
    // InputEvent with a single action.
    entries = {
            //      id  x   y
            {0ms, {{0, 100, 100}}, AMOTION_EVENT_ACTION_DOWN},
    };
    publishInputEventEntries(entries);
    frameTime = 5ms;
    expectedEntries = {
            //      id  x   y
            {0ms, {{0, 100, 100}}, AMOTION_EVENT_ACTION_DOWN},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    entries = {
            //       id  x   y
            {10ms, {{0, 100, 100}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 10ms + 5ms /*RESAMPLE_LATENCY*/;
    expectedEntries = {
            //       id  x   y
            {10ms, {{0, 100, 100}}, AMOTION_EVENT_ACTION_MOVE},
            // no resampled value because frameTime - RESAMPLE_LATENCY == eventTime
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Second pointer id=1 appears
    entries = {
            //      id  x    y
            {15ms, {{0, 100, 100}, {1, 500, 500}}, actionPointer1Down},
    };
    publishInputEventEntries(entries);
    frameTime = 20ms + 5ms /*RESAMPLE_LATENCY*/;
    expectedEntries = {
            //      id  x    y
            {15ms, {{0, 100, 100}, {1, 500, 500}}, actionPointer1Down},
            // no resampled value because frameTime - RESAMPLE_LATENCY == eventTime
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Both pointers move
    entries = {
            //      id  x    y
            {30ms, {{0, 100, 100}, {1, 500, 500}}, AMOTION_EVENT_ACTION_MOVE},
            {40ms, {{0, 120, 120}, {1, 600, 600}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 45ms + 5ms /*RESAMPLE_LATENCY*/;
    expectedEntries = {
            //      id  x    y
            {30ms, {{0, 100, 100}, {1, 500, 500}}, AMOTION_EVENT_ACTION_MOVE},
            {40ms, {{0, 120, 120}, {1, 600, 600}}, AMOTION_EVENT_ACTION_MOVE},
            {45ms,
             {{0, 130, 130, .isResampled = true}, {1, 650, 650, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Both pointers move again
    entries = {
            //      id  x    y
            {60ms, {{0, 120, 120}, {1, 600, 600}}, AMOTION_EVENT_ACTION_MOVE},
            {70ms, {{0, 130, 130}, {1, 700, 700}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 75ms + 5ms /*RESAMPLE_LATENCY*/;
    /**
     * The sample at t = 60, pointer id 0 is not equal to 120, because this value of 120 was
     * received twice, and resampled to 130. So if we already reported it as "130", we continue
     * to report it as such. Similar with pointer id 1.
     */
    expectedEntries = {
            {60ms,
             {{0, 130, 130, .isResampled = true}, // not 120! because it matches previous real event
              {1, 650, 650, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE},
            {70ms, {{0, 130, 130}, {1, 700, 700}}, AMOTION_EVENT_ACTION_MOVE},
            {75ms,
             {{0, 135, 135, .isResampled = true}, {1, 750, 750, .isResampled = true}},
             AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // First pointer id=0 leaves the screen
    entries = {
            //      id  x    y
            {80ms, {{0, 120, 120}, {1, 600, 600}}, actionPointer0Up},
    };
    publishInputEventEntries(entries);
    frameTime = 90ms;
    expectedEntries = {
            //      id  x    y
            {80ms, {{0, 120, 120}, {1, 600, 600}}, actionPointer0Up},
            // no resampled event for ACTION_POINTER_UP
    };
    consumeInputEventEntries(expectedEntries, frameTime);

    // Remaining pointer id=1 is still present, but doesn't move
    entries = {
            //      id  x    y
            {90ms, {{1, 600, 600}}, AMOTION_EVENT_ACTION_MOVE},
    };
    publishInputEventEntries(entries);
    frameTime = 100ms;
    expectedEntries = {
            //      id  x    y
            {90ms, {{1, 600, 600}}, AMOTION_EVENT_ACTION_MOVE},
            /**
             * The latest event with ACTION_MOVE was at t = 70, coord = 700.
             * Use that value for resampling here: (600 - 700) / (90 - 70) * 5 + 600
             */
            {95ms, {{1, 575, 575, .isResampled = true}}, AMOTION_EVENT_ACTION_MOVE},
    };
    consumeInputEventEntries(expectedEntries, frameTime);
}

} // namespace android
