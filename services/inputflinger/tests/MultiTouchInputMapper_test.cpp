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

#include "MultiTouchInputMapper.h"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <list>
#include <optional>

#include "InputMapperTest.h"
#include "InterfaceMocks.h"
#include "TestEventMatchers.h"

#define TAG "MultiTouchpadInputMapperUnit_test"

namespace android {

using testing::_;
using testing::IsEmpty;
using testing::Return;
using testing::SetArgPointee;
using testing::VariantWith;

static constexpr int32_t DISPLAY_ID = 0;
static constexpr int32_t DISPLAY_WIDTH = 480;
static constexpr int32_t DISPLAY_HEIGHT = 800;
static constexpr std::optional<uint8_t> NO_PORT = std::nullopt; // no physical port is specified
static constexpr int32_t SLOT_COUNT = 5;

static constexpr int32_t ACTION_POINTER_0_UP =
        AMOTION_EVENT_ACTION_POINTER_UP | (0 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
static constexpr int32_t ACTION_POINTER_1_DOWN =
        AMOTION_EVENT_ACTION_POINTER_DOWN | (1 << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);

/**
 * Unit tests for MultiTouchInputMapper.
 */
class MultiTouchInputMapperUnitTest : public InputMapperUnitTest {
protected:
    void SetUp() override {
        InputMapperUnitTest::SetUp();

        // Present scan codes
        expectScanCodes(/*present=*/true,
                        {BTN_TOUCH, BTN_TOOL_FINGER, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP,
                         BTN_TOOL_QUADTAP, BTN_TOOL_QUINTTAP});

        // Missing scan codes that the mapper checks for.
        expectScanCodes(/*present=*/false,
                        {BTN_TOOL_PEN, BTN_TOOL_RUBBER, BTN_TOOL_BRUSH, BTN_TOOL_PENCIL,
                         BTN_TOOL_AIRBRUSH});

        // Current scan code state - all keys are UP by default
        setScanCodeState(KeyState::UP, {BTN_LEFT,           BTN_RIGHT,        BTN_MIDDLE,
                                        BTN_BACK,           BTN_SIDE,         BTN_FORWARD,
                                        BTN_EXTRA,          BTN_TASK,         BTN_TOUCH,
                                        BTN_STYLUS,         BTN_STYLUS2,      BTN_0,
                                        BTN_TOOL_FINGER,    BTN_TOOL_PEN,     BTN_TOOL_RUBBER,
                                        BTN_TOOL_BRUSH,     BTN_TOOL_PENCIL,  BTN_TOOL_AIRBRUSH,
                                        BTN_TOOL_MOUSE,     BTN_TOOL_LENS,    BTN_TOOL_DOUBLETAP,
                                        BTN_TOOL_TRIPLETAP, BTN_TOOL_QUADTAP, BTN_TOOL_QUINTTAP});

        setKeyCodeState(KeyState::UP,
                        {AKEYCODE_STYLUS_BUTTON_PRIMARY, AKEYCODE_STYLUS_BUTTON_SECONDARY});

        // Input properties - only INPUT_PROP_DIRECT for touchscreen
        EXPECT_CALL(mMockEventHub, hasInputProperty(EVENTHUB_ID, _)).WillRepeatedly(Return(false));
        EXPECT_CALL(mMockEventHub, hasInputProperty(EVENTHUB_ID, INPUT_PROP_DIRECT))
                .WillRepeatedly(Return(true));

        // Axes that the device has
        setupAxis(ABS_MT_SLOT, /*valid=*/true, /*min=*/0, /*max=*/SLOT_COUNT - 1, /*resolution=*/0);
        setupAxis(ABS_MT_TRACKING_ID, /*valid=*/true, /*min*/ 0, /*max=*/255, /*resolution=*/0);
        setupAxis(ABS_MT_POSITION_X, /*valid=*/true, /*min=*/0, /*max=*/2000, /*resolution=*/24);
        setupAxis(ABS_MT_POSITION_Y, /*valid=*/true, /*min=*/0, /*max=*/1000, /*resolution=*/24);

        // Axes that the device does not have
        setupAxis(ABS_MT_PRESSURE, /*valid=*/false, /*min*/ 0, /*max=*/255, /*resolution=*/0);
        setupAxis(ABS_MT_ORIENTATION, /*valid=*/false, /*min=*/0, /*max=*/0, /*resolution=*/0);
        setupAxis(ABS_MT_DISTANCE, /*valid=*/false, /*min=*/0, /*max=*/0, /*resolution=*/0);
        setupAxis(ABS_MT_TOUCH_MAJOR, /*valid=*/false, /*min=*/0, /*max=*/0, /*resolution=*/0);
        setupAxis(ABS_MT_TOUCH_MINOR, /*valid=*/false, /*min=*/0, /*max=*/0, /*resolution=*/0);
        setupAxis(ABS_MT_WIDTH_MAJOR, /*valid=*/false, /*min=*/0, /*max=*/0, /*resolution=*/0);
        setupAxis(ABS_MT_WIDTH_MINOR, /*valid=*/false, /*min=*/0, /*max=*/0, /*resolution=*/0);
        setupAxis(ABS_MT_TOOL_TYPE, /*valid=*/false, /*min=*/0, /*max=*/0, /*resolution=*/0);

        // reset current slot at the beginning
        EXPECT_CALL(mMockEventHub, getAbsoluteAxisValue(EVENTHUB_ID, ABS_MT_SLOT, _))
                .WillRepeatedly([](int32_t, int32_t, int32_t* outValue) {
                    *outValue = 0;
                    return OK;
                });

        // mark all slots not in use
        mockSlotValues({});

        mFakePolicy->setDefaultPointerDisplayId(DISPLAY_ID);
        mFakePolicy->addDisplayViewport(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, ui::ROTATION_0,
                                        /*isActive=*/true, "local:0", NO_PORT,
                                        ViewportType::INTERNAL);
        createDevice();
        mMapper = createInputMapper<MultiTouchInputMapper>(*mDeviceContext,
                                                           mFakePolicy->getReaderConfiguration());
    }

    // Mocks position and tracking Ids for the provided slots. Remaining slots will be marked
    // unused.
    void mockSlotValues(
            const std::unordered_map<int32_t /*slotIndex*/,
                                     std::pair<Point /*position*/, int32_t /*trackingId*/>>&
                    slotValues) {
        EXPECT_CALL(mMockEventHub, getMtSlotValues(EVENTHUB_ID, _, SLOT_COUNT))
                .WillRepeatedly([=](int32_t, int32_t axis,
                                    size_t slotCount) -> base::Result<std::vector<int32_t>> {
                    // tracking Id for the unused slots must set to be < 0
                    std::vector<int32_t> outMtSlotValues(slotCount + 1, -1);
                    outMtSlotValues[0] = axis;
                    switch (axis) {
                        case ABS_MT_POSITION_X:
                            for (const auto& [slotIndex, valuePair] : slotValues) {
                                outMtSlotValues[slotIndex] = valuePair.first.x;
                            }
                            return outMtSlotValues;
                        case ABS_MT_POSITION_Y:
                            for (const auto& [slotIndex, valuePair] : slotValues) {
                                outMtSlotValues[slotIndex] = valuePair.first.y;
                            }
                            return outMtSlotValues;
                        case ABS_MT_TRACKING_ID:
                            for (const auto& [slotIndex, valuePair] : slotValues) {
                                outMtSlotValues[slotIndex] = valuePair.second;
                            }
                            return outMtSlotValues;
                        default:
                            return base::ResultError("Axis not supported", NAME_NOT_FOUND);
                    }
                });
    }

    std::list<NotifyArgs> processPosition(int32_t x, int32_t y) {
        std::list<NotifyArgs> args;
        args += process(EV_ABS, ABS_MT_POSITION_X, x);
        args += process(EV_ABS, ABS_MT_POSITION_Y, y);
        return args;
    }

    std::list<NotifyArgs> processId(int32_t id) { return process(EV_ABS, ABS_MT_TRACKING_ID, id); }

    std::list<NotifyArgs> processKey(int32_t code, int32_t value) {
        return process(EV_KEY, code, value);
    }

    std::list<NotifyArgs> processSlot(int32_t slot) { return process(EV_ABS, ABS_MT_SLOT, slot); }

    std::list<NotifyArgs> processSync() { return process(EV_SYN, SYN_REPORT, 0); }
};

// This test simulates a multi-finger gesture with unexpected reset in between. This might happen
// due to buffer overflow and device with report a SYN_DROPPED. In this case we expect mapper to be
// reset, MT slot state to be re-populated and the gesture should be cancelled and restarted.
TEST_F(MultiTouchInputMapperUnitTest, MultiFingerGestureWithUnexpectedReset) {
    std::list<NotifyArgs> args;

    // Two fingers down at once.
    constexpr int32_t FIRST_TRACKING_ID = 1, SECOND_TRACKING_ID = 2;
    int32_t x1 = 100, y1 = 125, x2 = 200, y2 = 225;
    processKey(BTN_TOUCH, 1);
    args += processPosition(x1, y1);
    args += processId(FIRST_TRACKING_ID);
    args += processSlot(1);
    args += processPosition(x2, y2);
    args += processId(SECOND_TRACKING_ID);
    ASSERT_THAT(args, IsEmpty());

    args = processSync();
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    WithMotionAction(AMOTION_EVENT_ACTION_DOWN)),
                            VariantWith<NotifyMotionArgs>(
                                    WithMotionAction(ACTION_POINTER_1_DOWN))));

    // Move.
    x1 += 10;
    y1 += 15;
    x2 += 5;
    y2 -= 10;
    args = processSlot(0);
    args += processPosition(x1, y1);
    args += processSlot(1);
    args += processPosition(x2, y2);
    ASSERT_THAT(args, IsEmpty());

    args = processSync();
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        WithMotionAction(AMOTION_EVENT_ACTION_MOVE))));
    const auto pointerCoordsBeforeReset = std::get<NotifyMotionArgs>(args.back()).pointerCoords;

    // On buffer overflow mapper will be reset and MT slots data will be repopulated
    EXPECT_CALL(mMockEventHub, getAbsoluteAxisValue(EVENTHUB_ID, ABS_MT_SLOT, _))
            .WillRepeatedly([=](int32_t, int32_t, int32_t* outValue) {
                *outValue = 1;
                return OK;
            });

    mockSlotValues(
            {{1, {Point{x1, y1}, FIRST_TRACKING_ID}}, {2, {Point{x2, y2}, SECOND_TRACKING_ID}}});

    setScanCodeState(KeyState::DOWN, {BTN_TOUCH});

    args = mMapper->reset(systemTime(SYSTEM_TIME_MONOTONIC));
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        WithMotionAction(AMOTION_EVENT_ACTION_CANCEL))));

    // SYN_REPORT should restart the gesture again
    args = processSync();
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                                    WithMotionAction(AMOTION_EVENT_ACTION_DOWN)),
                            VariantWith<NotifyMotionArgs>(
                                    WithMotionAction(ACTION_POINTER_1_DOWN))));
    ASSERT_EQ(std::get<NotifyMotionArgs>(args.back()).pointerCoords, pointerCoordsBeforeReset);

    // Move.
    x1 += 10;
    y1 += 15;
    x2 += 5;
    y2 -= 10;
    args = processSlot(0);
    args += processPosition(x1, y1);
    args += processSlot(1);
    args += processPosition(x2, y2);
    ASSERT_THAT(args, IsEmpty());

    args = processSync();
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(
                        WithMotionAction(AMOTION_EVENT_ACTION_MOVE))));

    // First finger up.
    args = processSlot(0);
    args += processId(-1);
    ASSERT_THAT(args, IsEmpty());

    args = processSync();
    ASSERT_THAT(args,
                ElementsAre(VariantWith<NotifyMotionArgs>(WithMotionAction(ACTION_POINTER_0_UP))));

    // Second finger up.
    processKey(BTN_TOUCH, 0);
    args = processSlot(1);
    args += processId(-1);
    ASSERT_THAT(args, IsEmpty());

    args = processSync();
    ASSERT_THAT(args,
                ElementsAre(
                        VariantWith<NotifyMotionArgs>(WithMotionAction(AMOTION_EVENT_ACTION_UP))));
}

} // namespace android
