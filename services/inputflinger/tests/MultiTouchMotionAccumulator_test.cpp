/*
 * Copyright 2023 The Android Open Source Project
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

#include "MultiTouchMotionAccumulator.h"
#include "InputMapperTest.h"

namespace android {

class MultiTouchMotionAccumulatorTest : public InputMapperUnitTest {
protected:
    static constexpr size_t SLOT_COUNT = 8;

    void SetUp() override {
        InputMapperUnitTest::SetUp();
        createDevice();
    }

    MultiTouchMotionAccumulator mMotionAccumulator;

    void processMotionEvent(int32_t type, int32_t code, int32_t value) {
        RawEvent event;
        event.when = ARBITRARY_TIME;
        event.readTime = READ_TIME;
        event.deviceId = EVENTHUB_ID;
        event.type = type;
        event.code = code;
        event.value = value;
        mMotionAccumulator.process(&event);
    }
};

TEST_F(MultiTouchMotionAccumulatorTest, ActiveSlotCountUsingSlotsProtocol) {
    mMotionAccumulator.configure(*mDeviceContext, SLOT_COUNT, /*usingSlotsProtocol=*/true);
    // We expect active slot count to match the touches being tracked
    // first touch
    processMotionEvent(EV_ABS, ABS_MT_SLOT, 0);
    processMotionEvent(EV_ABS, ABS_MT_TRACKING_ID, 123);
    processMotionEvent(EV_SYN, SYN_REPORT, 0);
    ASSERT_EQ(1u, mMotionAccumulator.getActiveSlotsCount());

    // second touch
    processMotionEvent(EV_ABS, ABS_MT_SLOT, 1);
    processMotionEvent(EV_ABS, ABS_MT_TRACKING_ID, 456);
    processMotionEvent(EV_SYN, SYN_REPORT, 0);
    ASSERT_EQ(2u, mMotionAccumulator.getActiveSlotsCount());

    // second lifted
    processMotionEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    processMotionEvent(EV_SYN, SYN_REPORT, 0);
    ASSERT_EQ(1u, mMotionAccumulator.getActiveSlotsCount());

    // first lifted
    processMotionEvent(EV_ABS, ABS_MT_SLOT, 0);
    processMotionEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    processMotionEvent(EV_SYN, SYN_REPORT, 0);
    ASSERT_EQ(0u, mMotionAccumulator.getActiveSlotsCount());
}

TEST_F(MultiTouchMotionAccumulatorTest, ActiveSlotCountNotUsingSlotsProtocol) {
    mMotionAccumulator.configure(*mDeviceContext, SLOT_COUNT, /*usingSlotsProtocol=*/false);

    // first touch
    processMotionEvent(EV_ABS, ABS_MT_POSITION_X, 0);
    processMotionEvent(EV_ABS, ABS_MT_POSITION_Y, 0);
    processMotionEvent(EV_SYN, SYN_MT_REPORT, 0);
    ASSERT_EQ(1u, mMotionAccumulator.getActiveSlotsCount());

    // second touch
    processMotionEvent(EV_ABS, ABS_MT_POSITION_X, 50);
    processMotionEvent(EV_ABS, ABS_MT_POSITION_Y, 50);
    processMotionEvent(EV_SYN, SYN_MT_REPORT, 0);
    ASSERT_EQ(2u, mMotionAccumulator.getActiveSlotsCount());

    // reset
    mMotionAccumulator.finishSync();
    ASSERT_EQ(0u, mMotionAccumulator.getActiveSlotsCount());
}

} // namespace android
