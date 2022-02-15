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

#pragma once

#include <gui/FrameTimelineInfo.h>

#include <array>

namespace android::gui {
struct VsyncEventData : public Parcelable {
    // Max amount of frame timelines is arbitrarily set to be reasonable.
    static constexpr int64_t kFrameTimelinesLength = 7;

    // The Vsync Id corresponsing to this vsync event. This will be used to
    // populate ISurfaceComposer::setFrameTimelineVsync and
    // SurfaceComposerClient::setFrameTimelineVsync
    // TODO(b/198191703): Remove when JNI DisplayEventReceiver uses frameTimelines array.
    int64_t id = FrameTimelineInfo::INVALID_VSYNC_ID;

    // The deadline in CLOCK_MONOTONIC that the app needs to complete its
    // frame by (both on the CPU and the GPU)
    // TODO(b/198191703): Remove when JNI DisplayEventReceiver uses frameTimelines array.
    int64_t deadlineTimestamp = std::numeric_limits<int64_t>::max();

    // The current frame interval in ns when this frame was scheduled.
    int64_t frameInterval = 0;

    struct FrameTimeline : public Parcelable {
        FrameTimeline() = default;
        FrameTimeline(int64_t id, int64_t deadlineTimestamp, int64_t expectedPresentTime)
              : id(id),
                deadlineTimestamp(deadlineTimestamp),
                expectedPresentTime(expectedPresentTime) {}

        // The Vsync Id corresponsing to this vsync event. This will be used to
        // populate ISurfaceComposer::setFrameTimelineVsync and
        // SurfaceComposerClient::setFrameTimelineVsync
        int64_t id = FrameTimelineInfo::INVALID_VSYNC_ID;

        // The deadline in CLOCK_MONOTONIC that the app needs to complete its
        // frame by (both on the CPU and the GPU)
        int64_t deadlineTimestamp = std::numeric_limits<int64_t>::max();

        // The anticipated Vsync present time.
        int64_t expectedPresentTime = 0;

        status_t readFromParcel(const Parcel*) override;
        status_t writeToParcel(Parcel*) const override;
    };

    // Sorted possible frame timelines.
    std::array<FrameTimeline, kFrameTimelinesLength> frameTimelines;

    // Index into the frameTimelines that represents the platform's preferred frame timeline.
    size_t preferredFrameTimelineIndex = std::numeric_limits<size_t>::max();

    status_t readFromParcel(const Parcel*) override;
    status_t writeToParcel(Parcel*) const override;
};
} // namespace android::gui
