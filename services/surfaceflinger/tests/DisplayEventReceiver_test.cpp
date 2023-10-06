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

#include <gtest/gtest.h>
#include <gui/DisplayEventReceiver.h>

namespace android {

class DisplayEventReceiverTest : public ::testing::Test {
public:
    void SetUp() override { EXPECT_EQ(NO_ERROR, mDisplayEventReceiver.initCheck()); }

    DisplayEventReceiver mDisplayEventReceiver;
};

TEST_F(DisplayEventReceiverTest, getLatestVsyncEventData) {
    const nsecs_t now = systemTime();
    ParcelableVsyncEventData parcelableVsyncEventData;
    EXPECT_EQ(NO_ERROR, mDisplayEventReceiver.getLatestVsyncEventData(&parcelableVsyncEventData));

    const VsyncEventData& vsyncEventData = parcelableVsyncEventData.vsync;
    EXPECT_NE(std::numeric_limits<size_t>::max(), vsyncEventData.preferredFrameTimelineIndex);
    EXPECT_GT(static_cast<int64_t>(vsyncEventData.frameTimelinesLength), 0)
            << "Frame timelines length should be greater than 0";
    EXPECT_LE(static_cast<int64_t>(vsyncEventData.frameTimelinesLength),
              VsyncEventData::kFrameTimelinesCapacity)
            << "Frame timelines length should not exceed max capacity";
    EXPECT_GT(vsyncEventData.frameTimelines[0].deadlineTimestamp, now)
            << "Deadline timestamp should be greater than frame time";
    for (size_t i = 0; i < vsyncEventData.frameTimelinesLength; i++) {
        EXPECT_NE(gui::FrameTimelineInfo::INVALID_VSYNC_ID,
                  vsyncEventData.frameTimelines[i].vsyncId);
        EXPECT_GT(vsyncEventData.frameTimelines[i].expectedPresentationTime,
                  vsyncEventData.frameTimelines[i].deadlineTimestamp)
                << "Expected vsync timestamp should be greater than deadline";
        if (i > 0) {
            EXPECT_GT(vsyncEventData.frameTimelines[i].deadlineTimestamp,
                      vsyncEventData.frameTimelines[i - 1].deadlineTimestamp)
                    << "Deadline timestamp out of order for frame timeline " << i;
            EXPECT_GT(vsyncEventData.frameTimelines[i].expectedPresentationTime,
                      vsyncEventData.frameTimelines[i - 1].expectedPresentationTime)
                    << "Expected vsync timestamp out of order for frame timeline " << i;
        }
    }
}

} // namespace android
