/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_GUI_FRAMETIMESTAMPS_H
#define ANDROID_GUI_FRAMETIMESTAMPS_H

#include <ui/Fence.h>
#include <utils/Flattenable.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include <array>

namespace android {


struct FrameEvents;
class String8;


enum class SupportableFrameTimestamps {
    REQUESTED_PRESENT,
    ACQUIRE,
    REFRESH_START,
    GL_COMPOSITION_DONE_TIME,
    DISPLAY_PRESENT_TIME,
    DISPLAY_RETIRE_TIME,
    RELEASE_TIME,
};


// The timestamps the consumer sends to the producer over binder.
struct FrameTimestamps : public LightFlattenablePod<FrameTimestamps> {
    FrameTimestamps() = default;
    explicit FrameTimestamps(const FrameEvents& fences);

    uint64_t frameNumber{0};
    nsecs_t postedTime{0};
    nsecs_t requestedPresentTime{0};
    nsecs_t acquireTime{0};
    nsecs_t refreshStartTime{0};
    nsecs_t glCompositionDoneTime{0};
    nsecs_t displayPresentTime{0};
    nsecs_t displayRetireTime{0};
    nsecs_t releaseTime{0};
};


// A collection of timestamps corresponding to a single frame.
struct FrameEvents {
    void checkFencesForCompletion();
    void dump(String8& outString) const;

    bool valid{false};
    uint64_t frameNumber{0};

    // Whether or not certain points in the frame's life cycle have been
    // encountered help us determine if timestamps aren't available because
    // a) we'll just never get them or b) they're not ready yet.
    bool addPostCompositeCalled{false};
    bool addRetireCalled{false};

    nsecs_t postedTime{0};
    nsecs_t requestedPresentTime{0};
    nsecs_t latchTime{0};
    nsecs_t firstRefreshStartTime{0};
    nsecs_t lastRefreshStartTime{0};

    nsecs_t acquireTime{0};
    nsecs_t gpuCompositionDoneTime{0};
    nsecs_t displayPresentTime{0};
    nsecs_t displayRetireTime{0};
    nsecs_t releaseTime{0};

    sp<Fence> acquireFence{Fence::NO_FENCE};
    sp<Fence> gpuCompositionDoneFence{Fence::NO_FENCE};
    sp<Fence> displayPresentFence{Fence::NO_FENCE};
    sp<Fence> displayRetireFence{Fence::NO_FENCE};
    sp<Fence> releaseFence{Fence::NO_FENCE};
};


struct NewFrameEventsEntry {
    uint64_t frameNumber{0};
    nsecs_t postedTime{0};
    nsecs_t requestedPresentTime{0};
    sp<Fence> acquireFence{Fence::NO_FENCE};
};


class FrameEventHistory {
public:
    FrameEvents* getFrame(uint64_t frameNumber);
    FrameEvents* getFrame(uint64_t frameNumber, size_t* iHint);
    void checkFencesForCompletion();
    void dump(String8& outString) const;

    void addQueue(const NewFrameEventsEntry& newFrameEntry);
    void addLatch(uint64_t frameNumber, nsecs_t latchTime);
    void addPreComposition(uint64_t frameNumber, nsecs_t refreshStartTime);
    void addPostComposition(uint64_t frameNumber,
            sp<Fence> gpuCompositionDone, sp<Fence> displayPresent);
    void addRetire(uint64_t frameNumber, sp<Fence> displayRetire);
    void addRelease(uint64_t frameNumber, sp<Fence> release);

private:
    static constexpr size_t MAX_FRAME_HISTORY = 8;
    std::array<FrameEvents, MAX_FRAME_HISTORY> mFrames;
    size_t mQueueOffset{0};
    size_t mCompositionOffset{0};
    size_t mRetireOffset{0};
    size_t mReleaseOffset{0};
};

} // namespace android
#endif
