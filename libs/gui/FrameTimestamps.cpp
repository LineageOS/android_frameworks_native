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

#include <gui/FrameTimestamps.h>

#include <inttypes.h>
#include <utils/String8.h>

#include <algorithm>
#include <limits>

namespace android {

static inline bool isValidTimestamp(nsecs_t time) {
    return time > 0 && time < INT64_MAX;
}

// ============================================================================
// FrameTimestamps
// ============================================================================

FrameTimestamps::FrameTimestamps(const FrameEvents& events) :
    frameNumber(events.frameNumber),
    postedTime(events.postedTime),
    requestedPresentTime(events.requestedPresentTime),
    acquireTime(events.acquireTime),
    refreshStartTime(events.firstRefreshStartTime),
    glCompositionDoneTime(events.gpuCompositionDoneTime),
    displayPresentTime(events.displayPresentTime),
    displayRetireTime(events.displayRetireTime),
    releaseTime(events.releaseTime) {}


// ============================================================================
// FrameEvents
// ============================================================================

static void checkFenceForCompletion(sp<Fence>* fence, nsecs_t* dstTime) {
    if ((*fence)->isValid()) {
        nsecs_t time = (*fence)->getSignalTime();
        if (isValidTimestamp(time)) {
            *dstTime = time;
            *fence = Fence::NO_FENCE;
        }
    }
}

void FrameEvents::checkFencesForCompletion() {
    checkFenceForCompletion(&acquireFence, &acquireTime);
    checkFenceForCompletion(&gpuCompositionDoneFence, &gpuCompositionDoneTime);
    checkFenceForCompletion(&displayPresentFence, &displayPresentTime);
    checkFenceForCompletion(&displayRetireFence, &displayRetireTime);
    checkFenceForCompletion(&releaseFence, &releaseTime);
}

void FrameEvents::dump(String8& outString) const
{
    if (!valid) {
        return;
    }

    outString.appendFormat("-- Frame %" PRIu64 "\n", frameNumber);
    outString.appendFormat("--- Posted      \t%" PRId64 "\n", postedTime);
    outString.appendFormat("--- Req. Present\t%" PRId64 "\n", requestedPresentTime);

    outString.appendFormat("--- Latched     \t");
    if (isValidTimestamp(latchTime)) {
        outString.appendFormat("%" PRId64 "\n", latchTime);
    } else {
        outString.appendFormat("Pending\n");
    }

    outString.appendFormat("--- Refresh (First)\t");
    if (isValidTimestamp(firstRefreshStartTime)) {
        outString.appendFormat("%" PRId64 "\n", firstRefreshStartTime);
    } else {
        outString.appendFormat("Pending\n");
    }

    outString.appendFormat("--- Refresh (Last)\t");
    if (isValidTimestamp(lastRefreshStartTime)) {
        outString.appendFormat("%" PRId64 "\n", lastRefreshStartTime);
    } else {
        outString.appendFormat("Pending\n");
    }

    outString.appendFormat("--- Acquire     \t");
    if (isValidTimestamp(acquireTime)) {
        outString.appendFormat("%" PRId64 "\n", acquireTime);
    } else {
        outString.appendFormat("Pending\n");
    }

    outString.appendFormat("--- GPU Composite Done\t");
    if (isValidTimestamp(gpuCompositionDoneTime)) {
        outString.appendFormat("%" PRId64 "\n", gpuCompositionDoneTime);
    } else if (!addPostCompositeCalled || gpuCompositionDoneFence->isValid()) {
        outString.appendFormat("Pending\n");
    } else {
        outString.appendFormat("N/A\n");
    }

    outString.appendFormat("--- Display Present\t");
    if (isValidTimestamp(displayPresentTime)) {
        outString.appendFormat("%" PRId64 "\n", displayPresentTime);
    } else if (!addPostCompositeCalled || displayPresentFence->isValid()) {
        outString.appendFormat("Pending\n");
    } else {
        outString.appendFormat("N/A\n");
    }

    outString.appendFormat("--- Display Retire\t");
    if (isValidTimestamp(displayRetireTime)) {
        outString.appendFormat("%" PRId64 "\n", displayRetireTime);
    } else if (!addRetireCalled || displayRetireFence->isValid()) {
        outString.appendFormat("Pending\n");
    } else {
        outString.appendFormat("N/A\n");
    }

    outString.appendFormat("--- Release     \t");
    if (isValidTimestamp(releaseTime)) {
        outString.appendFormat("%" PRId64 "\n", releaseTime);
    } else {
        outString.appendFormat("Pending\n");
    }
}


// ============================================================================
// FrameEventHistory
// ============================================================================

namespace {

struct FrameNumberEqual {
    FrameNumberEqual(uint64_t frameNumber) : mFrameNumber(frameNumber) {}
    bool operator()(const FrameEvents& frame) {
        return frame.valid && mFrameNumber == frame.frameNumber;
    }
    const uint64_t mFrameNumber;
};

}  // namespace


FrameEvents* FrameEventHistory::getFrame(uint64_t frameNumber) {
    auto frame = std::find_if(
            mFrames.begin(), mFrames.end(), FrameNumberEqual(frameNumber));
    return frame == mFrames.end() ? nullptr : &(*frame);
}

FrameEvents* FrameEventHistory::getFrame(uint64_t frameNumber, size_t* iHint) {
    *iHint = std::min(*iHint, mFrames.size());
    auto hint = mFrames.begin() + *iHint;
    auto frame = std::find_if(
            hint, mFrames.end(), FrameNumberEqual(frameNumber));
    if (frame == mFrames.end()) {
        frame = std::find_if(
                mFrames.begin(), hint, FrameNumberEqual(frameNumber));
        if (frame == hint) {
            return nullptr;
        }
    }
    *iHint = static_cast<size_t>(std::distance(mFrames.begin(), frame));
    return &(*frame);
}

void FrameEventHistory::checkFencesForCompletion() {
    for (auto& frame : mFrames) {
        frame.checkFencesForCompletion();
    }
}

// Uses !|valid| as the MSB.
static bool FrameNumberLessThan(
        const FrameEvents& lhs, const FrameEvents& rhs) {
    if (lhs.valid == rhs.valid) {
        return lhs.frameNumber < rhs.frameNumber;
    }
    return lhs.valid;
}

void FrameEventHistory::dump(String8& outString) const {
    auto earliestFrame = std::min_element(
            mFrames.begin(), mFrames.end(), &FrameNumberLessThan);
    if (!earliestFrame->valid) {
        outString.appendFormat("-- N/A\n");
        return;
    }
    for (auto frame = earliestFrame; frame != mFrames.end(); ++frame) {
        frame->dump(outString);
    }
    for (auto frame = mFrames.begin(); frame != earliestFrame; ++frame) {
        frame->dump(outString);
    }
}

void FrameEventHistory::addQueue(const NewFrameEventsEntry& newFrameEntry) {
    // Overwrite all fields of the frame with default values unless set here.
    FrameEvents newTimestamps;
    newTimestamps.frameNumber = newFrameEntry.frameNumber;
    newTimestamps.postedTime = newFrameEntry.postedTime;
    newTimestamps.requestedPresentTime = newFrameEntry.requestedPresentTime;
    newTimestamps.acquireFence = newFrameEntry.acquireFence;
    newTimestamps.valid = true;
    mFrames[mQueueOffset] = newTimestamps;

    mQueueOffset = mQueueOffset + 1;
    if (mQueueOffset >= mFrames.size()) {
        mQueueOffset = 0;
    }
}

void FrameEventHistory::addLatch(uint64_t frameNumber, nsecs_t latchTime) {
    FrameEvents* frame = getFrame(frameNumber, &mCompositionOffset);
    if (frame == nullptr) {
        ALOGE("FrameEventHistory::addLatch: Did not find frame.");
        return;
    }
    frame->latchTime = latchTime;
    return;
}

void FrameEventHistory::addPreComposition(
        uint64_t frameNumber, nsecs_t refreshStartTime) {
    FrameEvents* frame = getFrame(frameNumber, &mCompositionOffset);
    if (frame == nullptr) {
        ALOGE("FrameEventHistory::addPreComposition: Did not find frame.");
        return;
    }
    frame->lastRefreshStartTime = refreshStartTime;
    if (!isValidTimestamp(frame->firstRefreshStartTime)) {
        frame->firstRefreshStartTime = refreshStartTime;
    }
}

void FrameEventHistory::addPostComposition(uint64_t frameNumber,
        sp<Fence> gpuCompositionDone, sp<Fence> displayPresent) {
    FrameEvents* frame = getFrame(frameNumber, &mCompositionOffset);
    if (frame == nullptr) {
        ALOGE("FrameEventHistory::addPostComposition: Did not find frame.");
        return;
    }

    // Only get GPU and present info for the first composite.
    if (!frame->addPostCompositeCalled) {
        frame->addPostCompositeCalled = true;
        frame->gpuCompositionDoneFence = gpuCompositionDone;
        if (!frame->displayPresentFence->isValid()) {
            frame->displayPresentFence = displayPresent;
        }
    }
}

void FrameEventHistory::addRetire(
        uint64_t frameNumber, sp<Fence> displayRetire) {
    FrameEvents* frame = getFrame(frameNumber, &mRetireOffset);
    if (frame == nullptr) {
        ALOGE("FrameEventHistory::addRetire: Did not find frame.");
        return;
    }
    frame->addRetireCalled = true;
    frame->displayRetireFence = displayRetire;
}

void FrameEventHistory::addRelease(
        uint64_t frameNumber, sp<Fence> release) {
    FrameEvents* frame = getFrame(frameNumber, &mReleaseOffset);
    if (frame == nullptr) {
        ALOGE("FrameEventHistory::addRelease: Did not find frame.");
        return;
    }
    frame->releaseFence = release;
}

} // namespace android
