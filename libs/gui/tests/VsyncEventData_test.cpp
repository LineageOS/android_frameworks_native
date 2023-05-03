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

#include <binder/Parcel.h>

#include <gui/VsyncEventData.h>

namespace android {

using gui::ParcelableVsyncEventData;
using gui::VsyncEventData;
using FrameTimeline = gui::VsyncEventData::FrameTimeline;

namespace test {

TEST(ParcelableVsyncEventData, Parcelling) {
    ParcelableVsyncEventData data;
    data.vsync.frameInterval = 789;
    data.vsync.preferredFrameTimelineIndex = 1;
    FrameTimeline timeline0 = FrameTimeline{1, 2, 3};
    FrameTimeline timeline1 = FrameTimeline{4, 5, 6};
    data.vsync.frameTimelines[0] = timeline0;
    data.vsync.frameTimelines[1] = timeline1;
    data.vsync.frameTimelinesLength = 2;

    Parcel p;
    data.writeToParcel(&p);
    p.setDataPosition(0);

    ParcelableVsyncEventData data2;
    data2.readFromParcel(&p);
    ASSERT_EQ(data.vsync.frameInterval, data2.vsync.frameInterval);
    ASSERT_EQ(data.vsync.preferredFrameTimelineIndex, data2.vsync.preferredFrameTimelineIndex);
    ASSERT_EQ(data.vsync.frameTimelinesLength, data2.vsync.frameTimelinesLength);
    for (int i = 0; i < VsyncEventData::kFrameTimelinesCapacity; i++) {
        ASSERT_EQ(data.vsync.frameTimelines[i].vsyncId, data2.vsync.frameTimelines[i].vsyncId);
        ASSERT_EQ(data.vsync.frameTimelines[i].deadlineTimestamp,
                  data2.vsync.frameTimelines[i].deadlineTimestamp);
        ASSERT_EQ(data.vsync.frameTimelines[i].expectedPresentationTime,
                  data2.vsync.frameTimelines[i].expectedPresentationTime);
    }
}

} // namespace test
} // namespace android
