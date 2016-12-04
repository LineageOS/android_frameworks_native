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
#include <numeric>

namespace android {

static inline bool isValidTimestamp(nsecs_t time) {
    return time > 0 && time < INT64_MAX;
}

// ============================================================================
// FrameEvents
// ============================================================================

bool FrameEvents::hasPostedInfo() const {
    return isValidTimestamp(postedTime);
}

bool FrameEvents::hasRequestedPresentInfo() const {
    return isValidTimestamp(requestedPresentTime);
}

bool FrameEvents::hasLatchInfo() const {
    return isValidTimestamp(latchTime);
}

bool FrameEvents::hasFirstRefreshStartInfo() const {
    return isValidTimestamp(firstRefreshStartTime);
}

bool FrameEvents::hasLastRefreshStartInfo() const {
    // The last refresh start time may continue to update until a new frame
    // is latched. We know we have the final value once the release or retire
    // info is set. See ConsumerFrameEventHistory::addRetire/Release.
    return addRetireCalled || addReleaseCalled;
}

bool FrameEvents::hasAcquireInfo() const {
    return isValidTimestamp(acquireTime) || acquireFence->isValid();
}

bool FrameEvents::hasGpuCompositionDoneInfo() const {
    // We may not get a gpuCompositionDone in addPostComposite if
    // client/gles compositing isn't needed.
    return addPostCompositeCalled;
}

bool FrameEvents::hasDisplayPresentInfo() const {
    // We may not get a displayPresent in addPostComposite for HWC1.
    return addPostCompositeCalled;
}

bool FrameEvents::hasDisplayRetireInfo() const {
    // We may not get a displayRetire in addRetire for HWC2.
    return addRetireCalled;
}

bool FrameEvents::hasReleaseInfo() const {
    return addReleaseCalled;
}

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

FrameEventHistory::~FrameEventHistory() = default;

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


// ============================================================================
// ProducerFrameEventHistory
// ============================================================================

ProducerFrameEventHistory::~ProducerFrameEventHistory() = default;

void ProducerFrameEventHistory::updateAcquireFence(
        uint64_t frameNumber, sp<Fence> acquire) {
    FrameEvents* frame = getFrame(frameNumber, &mAcquireOffset);
    if (frame == nullptr) {
        ALOGE("ProducerFrameEventHistory::updateAcquireFence: "
              "Did not find frame.");
        return;
    }

    if (acquire->isValid()) {
        frame->acquireFence = acquire;
    } else {
        // If there isn't an acquire fence, assume that buffer was
        // ready for the consumer when posted.
        frame->acquireTime = frame->postedTime;
    }
}

static void applyFenceDelta(sp<Fence>* dst, const sp<Fence>& src) {
    if (src->isValid()) {
        if ((*dst)->isValid()) {
            ALOGE("applyFenceDelta: Unexpected fence.");
        }
        *dst = src;
    }
}

void ProducerFrameEventHistory::applyDelta(
        const FrameEventHistoryDelta& delta) {
    for (auto& d : delta.mDeltas) {
        // Avoid out-of-bounds access.
        if (d.mIndex >= mFrames.size()) {
            ALOGE("ProducerFrameEventHistory::applyDelta: Bad index.");
            return;
        }

        FrameEvents& frame = mFrames[d.mIndex];

        frame.addPostCompositeCalled = d.mAddPostCompositeCalled != 0;
        frame.addRetireCalled = d.mAddRetireCalled != 0;
        frame.addReleaseCalled = d.mAddReleaseCalled != 0;

        frame.postedTime = d.mPostedTime;
        frame.requestedPresentTime = d.mRequestedPresentTime;
        frame.latchTime = d.mLatchTime;
        frame.firstRefreshStartTime = d.mFirstRefreshStartTime;
        frame.lastRefreshStartTime = d.mLastRefreshStartTime;

        if (frame.frameNumber == d.mFrameNumber) {
            // Existing frame. Merge.
            // Consumer never sends timestamps of fences, only the fences
            // themselves, so we never need to update the fence timestamps here.
            applyFenceDelta(
                    &frame.gpuCompositionDoneFence, d.mGpuCompositionDoneFence);
            applyFenceDelta(&frame.displayPresentFence, d.mDisplayPresentFence);
            applyFenceDelta(&frame.displayRetireFence, d.mDisplayRetireFence);
            applyFenceDelta(&frame.releaseFence, d.mReleaseFence);
        } else {
            // New frame. Overwrite.
            frame.frameNumber = d.mFrameNumber;

            frame.gpuCompositionDoneFence = d.mGpuCompositionDoneFence;
            frame.displayPresentFence = d.mDisplayPresentFence;
            frame.displayRetireFence = d.mDisplayRetireFence;
            frame.releaseFence = d.mReleaseFence;

            // Set aquire fence and time at this point.
            frame.acquireTime = 0;
            frame.acquireFence = Fence::NO_FENCE;

            // Reset fence-related timestamps
            frame.gpuCompositionDoneTime = 0;
            frame.displayPresentTime = 0;
            frame.displayRetireTime = 0;
            frame.releaseTime = 0;

            // The consumer only sends valid frames.
            frame.valid = true;
        }
    }
}


// ============================================================================
// ConsumerFrameEventHistory
// ============================================================================

ConsumerFrameEventHistory::~ConsumerFrameEventHistory() = default;

void ConsumerFrameEventHistory::addQueue(const NewFrameEventsEntry& newEntry) {
    // Overwrite all fields of the frame with default values unless set here.
    FrameEvents newTimestamps;
    newTimestamps.frameNumber = newEntry.frameNumber;
    newTimestamps.postedTime = newEntry.postedTime;
    newTimestamps.requestedPresentTime = newEntry.requestedPresentTime;
    newTimestamps.acquireFence = newEntry.acquireFence;
    newTimestamps.valid = true;
    mFrames[mQueueOffset] = newTimestamps;

    // Note: We avoid sending the acquire fence back to the caller since
    // they have the original one already, so there is no need to set the
    // acquire dirty bit.
    mFramesDirty[mQueueOffset].setDirty<FrameEvent::POSTED>();

    mQueueOffset = (mQueueOffset + 1) % mFrames.size();
}

void ConsumerFrameEventHistory::addLatch(
        uint64_t frameNumber, nsecs_t latchTime) {
    FrameEvents* frame = getFrame(frameNumber, &mCompositionOffset);
    if (frame == nullptr) {
        ALOGE("ConsumerFrameEventHistory::addLatch: Did not find frame.");
        return;
    }
    frame->latchTime = latchTime;
    mFramesDirty[mCompositionOffset].setDirty<FrameEvent::LATCH>();
}

void ConsumerFrameEventHistory::addPreComposition(
        uint64_t frameNumber, nsecs_t refreshStartTime) {
    FrameEvents* frame = getFrame(frameNumber, &mCompositionOffset);
    if (frame == nullptr) {
        ALOGE("ConsumerFrameEventHistory::addPreComposition: "
              "Did not find frame.");
        return;
    }
    frame->lastRefreshStartTime = refreshStartTime;
    mFramesDirty[mCompositionOffset].setDirty<FrameEvent::LAST_REFRESH_START>();
    if (!isValidTimestamp(frame->firstRefreshStartTime)) {
        frame->firstRefreshStartTime = refreshStartTime;
        mFramesDirty[mCompositionOffset].setDirty<FrameEvent::FIRST_REFRESH_START>();
    }
}

void ConsumerFrameEventHistory::addPostComposition(uint64_t frameNumber,
        sp<Fence> gpuCompositionDone, sp<Fence> displayPresent) {
    FrameEvents* frame = getFrame(frameNumber, &mCompositionOffset);
    if (frame == nullptr) {
        ALOGE("ConsumerFrameEventHistory::addPostComposition: "
              "Did not find frame.");
        return;
    }
    // Only get GPU and present info for the first composite.
    if (!frame->addPostCompositeCalled) {
        frame->addPostCompositeCalled = true;
        frame->gpuCompositionDoneFence = gpuCompositionDone;
        mFramesDirty[mCompositionOffset].setDirty<FrameEvent::GL_COMPOSITION_DONE>();
        if (!frame->displayPresentFence->isValid()) {
            frame->displayPresentFence = displayPresent;
            mFramesDirty[mCompositionOffset].setDirty<FrameEvent::DISPLAY_PRESENT>();
        }
    }
}

void ConsumerFrameEventHistory::addRetire(
        uint64_t frameNumber, sp<Fence> displayRetire) {
    FrameEvents* frame = getFrame(frameNumber, &mRetireOffset);
    if (frame == nullptr) {
        ALOGE("ConsumerFrameEventHistory::addRetire: Did not find frame.");
        return;
    }
    frame->addRetireCalled = true;
    frame->displayRetireFence = displayRetire;
    mFramesDirty[mRetireOffset].setDirty<FrameEvent::DISPLAY_RETIRE>();
}

void ConsumerFrameEventHistory::addRelease(
        uint64_t frameNumber, sp<Fence> release) {
    FrameEvents* frame = getFrame(frameNumber, &mReleaseOffset);
    if (frame == nullptr) {
        ALOGE("ConsumerFrameEventHistory::addRelease: Did not find frame.");
        return;
    }
    frame->addReleaseCalled = true;
    frame->releaseFence = release;
    mFramesDirty[mReleaseOffset].setDirty<FrameEvent::RELEASE>();
}

void ConsumerFrameEventHistory::getAndResetDelta(
        FrameEventHistoryDelta* delta) {
    delta->mDeltas.reserve(mFramesDirty.size());
    for (size_t i = 0; i < mFramesDirty.size(); i++) {
        if (mFramesDirty[i].anyDirty()) {
            delta->mDeltas.push_back(
                    FrameEventsDelta(i, mFrames[i], mFramesDirty[i]));
            mFramesDirty[i].reset();
        }
    }
}


// ============================================================================
// FrameEventsDelta
// ============================================================================

FrameEventsDelta::FrameEventsDelta(
        size_t index,
        const FrameEvents& frameTimestamps,
        const FrameEventDirtyFields& dirtyFields)
    : mIndex(index),
      mFrameNumber(frameTimestamps.frameNumber),
      mAddPostCompositeCalled(frameTimestamps.addPostCompositeCalled),
      mAddRetireCalled(frameTimestamps.addRetireCalled),
      mAddReleaseCalled(frameTimestamps.addReleaseCalled),
      mPostedTime(frameTimestamps.postedTime),
      mRequestedPresentTime(frameTimestamps.requestedPresentTime),
      mLatchTime(frameTimestamps.latchTime),
      mFirstRefreshStartTime(frameTimestamps.firstRefreshStartTime),
      mLastRefreshStartTime(frameTimestamps.lastRefreshStartTime) {
    mGpuCompositionDoneFence =
            dirtyFields.isDirty<FrameEvent::GL_COMPOSITION_DONE>() ?
                    frameTimestamps.gpuCompositionDoneFence : Fence::NO_FENCE;
    mDisplayPresentFence = dirtyFields.isDirty<FrameEvent::DISPLAY_PRESENT>() ?
            frameTimestamps.displayPresentFence : Fence::NO_FENCE;
    mDisplayRetireFence = dirtyFields.isDirty<FrameEvent::DISPLAY_RETIRE>() ?
            frameTimestamps.displayRetireFence : Fence::NO_FENCE;
    mReleaseFence = dirtyFields.isDirty<FrameEvent::RELEASE>() ?
            frameTimestamps.releaseFence : Fence::NO_FENCE;
}

size_t FrameEventsDelta::minFlattenedSize() {
    constexpr size_t min =
            sizeof(FrameEventsDelta::mFrameNumber) +
            sizeof(uint8_t) + // mIndex
            sizeof(uint8_t) + // mAddPostCompositeCalled
            sizeof(uint8_t) + // mAddRetireCalled
            sizeof(uint8_t) + // mAddReleaseCalled
            sizeof(FrameEventsDelta::mPostedTime) +
            sizeof(FrameEventsDelta::mRequestedPresentTime) +
            sizeof(FrameEventsDelta::mLatchTime) +
            sizeof(FrameEventsDelta::mFirstRefreshStartTime) +
            sizeof(FrameEventsDelta::mLastRefreshStartTime);
    return min;
}

// Flattenable implementation
size_t FrameEventsDelta::getFlattenedSize() const {
    auto fences = allFences(this);
    return minFlattenedSize() +
            std::accumulate(fences.begin(), fences.end(), size_t(0),
                    [](size_t a, const sp<Fence>* fence) {
                            return a + (*fence)->getFlattenedSize();
                    });
}

size_t FrameEventsDelta::getFdCount() const {
    auto fences = allFences(this);
    return std::accumulate(fences.begin(), fences.end(), size_t(0),
            [](size_t a, const sp<Fence>* fence) {
                return a + (*fence)->getFdCount();
            });
}

status_t FrameEventsDelta::flatten(void*& buffer, size_t& size, int*& fds,
            size_t& count) const {
    if (size < getFlattenedSize() || count < getFdCount()) {
        return NO_MEMORY;
    }

    if (mIndex >= FrameEventHistory::MAX_FRAME_HISTORY ||
            mIndex > std::numeric_limits<uint8_t>::max()) {
        return BAD_VALUE;
    }

    FlattenableUtils::write(buffer, size, mFrameNumber);

    // These are static_cast to uint8_t for alignment.
    FlattenableUtils::write(buffer, size, static_cast<uint8_t>(mIndex));
    FlattenableUtils::write(
            buffer, size, static_cast<uint8_t>(mAddPostCompositeCalled));
    FlattenableUtils::write(
            buffer, size, static_cast<uint8_t>(mAddRetireCalled));
    FlattenableUtils::write(
            buffer, size, static_cast<uint8_t>(mAddReleaseCalled));

    FlattenableUtils::write(buffer, size, mPostedTime);
    FlattenableUtils::write(buffer, size, mRequestedPresentTime);
    FlattenableUtils::write(buffer, size, mLatchTime);
    FlattenableUtils::write(buffer, size, mFirstRefreshStartTime);
    FlattenableUtils::write(buffer, size, mLastRefreshStartTime);

    // Fences
    for (auto fence : allFences(this)) {
        status_t status = (*fence)->flatten(buffer, size, fds, count);
        if (status != NO_ERROR) {
            return status;
        }
    }
    return NO_ERROR;
}

status_t FrameEventsDelta::unflatten(void const*& buffer, size_t& size,
            int const*& fds, size_t& count) {
    if (size < minFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::read(buffer, size, mFrameNumber);

    // These were written as uint8_t for alignment.
    uint8_t temp = 0;
    FlattenableUtils::read(buffer, size, temp);
    mIndex = temp;
    if (mIndex >= FrameEventHistory::MAX_FRAME_HISTORY) {
        return BAD_VALUE;
    }
    FlattenableUtils::read(buffer, size, temp);
    mAddPostCompositeCalled = static_cast<bool>(temp);
    FlattenableUtils::read(buffer, size, temp);
    mAddRetireCalled = static_cast<bool>(temp);
    FlattenableUtils::read(buffer, size, temp);
    mAddReleaseCalled = static_cast<bool>(temp);

    FlattenableUtils::read(buffer, size, mPostedTime);
    FlattenableUtils::read(buffer, size, mRequestedPresentTime);
    FlattenableUtils::read(buffer, size, mLatchTime);
    FlattenableUtils::read(buffer, size, mFirstRefreshStartTime);
    FlattenableUtils::read(buffer, size, mLastRefreshStartTime);

    // Fences
    for (auto fence : allFences(this)) {
        *fence = new Fence;
        status_t status = (*fence)->unflatten(buffer, size, fds, count);
        if (status != NO_ERROR) {
            return status;
        }
    }
    return NO_ERROR;
}


// ============================================================================
// FrameEventHistoryDelta
// ============================================================================

size_t FrameEventHistoryDelta::minFlattenedSize() {
    return sizeof(uint32_t);
}

size_t FrameEventHistoryDelta::getFlattenedSize() const {
    return minFlattenedSize() +
            std::accumulate(mDeltas.begin(), mDeltas.end(), size_t(0),
                    [](size_t a, const FrameEventsDelta& delta) {
                            return a + delta.getFlattenedSize();
                    });
}

size_t FrameEventHistoryDelta::getFdCount() const {
    return std::accumulate(mDeltas.begin(), mDeltas.end(), size_t(0),
            [](size_t a, const FrameEventsDelta& delta) {
                    return a + delta.getFdCount();
            });
}

status_t FrameEventHistoryDelta::flatten(
            void*& buffer, size_t& size, int*& fds, size_t& count) const {
    if (mDeltas.size() > FrameEventHistory::MAX_FRAME_HISTORY) {
        return BAD_VALUE;
    }
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::write(
            buffer, size, static_cast<uint32_t>(mDeltas.size()));
    for (auto& d : mDeltas) {
        status_t status = d.flatten(buffer, size, fds, count);
        if (status != NO_ERROR) {
            return status;
        }
    }
    return NO_ERROR;
}

status_t FrameEventHistoryDelta::unflatten(
            void const*& buffer, size_t& size, int const*& fds, size_t& count) {
    if (size < minFlattenedSize()) {
        return NO_MEMORY;
    }

    uint32_t deltaCount = 0;
    FlattenableUtils::read(buffer, size, deltaCount);
    if (deltaCount > FrameEventHistory::MAX_FRAME_HISTORY) {
        return BAD_VALUE;
    }
    mDeltas.resize(deltaCount);
    for (auto& d : mDeltas) {
        status_t status = d.unflatten(buffer, size, fds, count);
        if (status != NO_ERROR) {
            return status;
        }
    }
    return NO_ERROR;
}


} // namespace android
