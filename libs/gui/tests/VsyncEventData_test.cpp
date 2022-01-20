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

using gui::VsyncEventData;
using FrameTimeline = gui::VsyncEventData::FrameTimeline;

namespace test {

TEST(VsyncEventData, Parcelling) {
    VsyncEventData data;
    data.id = 123;
    data.deadlineTimestamp = 456;
    data.frameInterval = 789;
    data.preferredFrameTimelineIndex = 1;
    FrameTimeline timeline0 = FrameTimeline(1, 2, 3);
    FrameTimeline timeline1 = FrameTimeline(4, 5, 6);
    data.frameTimelines[0] = timeline0;
    data.frameTimelines[1] = timeline1;

    Parcel p;
    data.writeToParcel(&p);
    p.setDataPosition(0);

    VsyncEventData data2;
    data2.readFromParcel(&p);
    ASSERT_EQ(data.id, data2.id);
    ASSERT_EQ(data.deadlineTimestamp, data2.deadlineTimestamp);
    ASSERT_EQ(data.frameInterval, data2.frameInterval);
    ASSERT_EQ(data.preferredFrameTimelineIndex, data2.preferredFrameTimelineIndex);
    for (int i = 0; i < data.frameTimelines.size(); i++) {
        ASSERT_EQ(data.frameTimelines[i].id, data2.frameTimelines[i].id);
        ASSERT_EQ(data.frameTimelines[i].deadlineTimestamp,
                  data2.frameTimelines[i].deadlineTimestamp);
        ASSERT_EQ(data.frameTimelines[i].expectedPresentTime,
                  data2.frameTimelines[i].expectedPresentTime);
    }
}

TEST(FrameTimeline, Parcelling) {
    FrameTimeline timeline = FrameTimeline(1, 2, 3);

    Parcel p;
    timeline.writeToParcel(&p);
    p.setDataPosition(0);

    FrameTimeline timeline2;
    timeline2.readFromParcel(&p);
    ASSERT_EQ(timeline.id, timeline2.id);
    ASSERT_EQ(timeline.deadlineTimestamp, timeline2.deadlineTimestamp);
    ASSERT_EQ(timeline.expectedPresentTime, timeline2.expectedPresentTime);
}

} // namespace test
} // namespace android
