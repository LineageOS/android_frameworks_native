/*
 * Copyright (C) 2019 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "BLASTBufferQueue"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include <gui/BLASTBufferQueue.h>
#include <gui/BufferItemConsumer.h>
#include <gui/GLConsumer.h>
#include <gui/Surface.h>

#include <utils/Trace.h>

#include <chrono>

using namespace std::chrono_literals;

namespace {
inline const char* toString(bool b) {
    return b ? "true" : "false";
}
} // namespace

namespace android {

// Macros to include adapter info in log messages
#define BQA_LOGV(x, ...) \
    ALOGV("[%s](f:%u,a:%u) " x, mName.c_str(), mNumFrameAvailable, mNumAcquired, ##__VA_ARGS__)
// enable logs for a single layer
//#define BQA_LOGV(x, ...) \
//    ALOGV_IF((strstr(mName.c_str(), "SurfaceView") != nullptr), "[%s](f:%u,a:%u) " x, \
//              mName.c_str(), mNumFrameAvailable, mNumAcquired, ##__VA_ARGS__)
#define BQA_LOGE(x, ...) \
    ALOGE("[%s](f:%u,a:%u) " x, mName.c_str(), mNumFrameAvailable, mNumAcquired, ##__VA_ARGS__)

void BLASTBufferItemConsumer::onDisconnect() {
    Mutex::Autolock lock(mFrameEventHistoryMutex);
    mPreviouslyConnected = mCurrentlyConnected;
    mCurrentlyConnected = false;
    if (mPreviouslyConnected) {
        mDisconnectEvents.push(mCurrentFrameNumber);
    }
    mFrameEventHistory.onDisconnect();
}

void BLASTBufferItemConsumer::addAndGetFrameTimestamps(const NewFrameEventsEntry* newTimestamps,
                                                       FrameEventHistoryDelta* outDelta) {
    Mutex::Autolock lock(mFrameEventHistoryMutex);
    if (newTimestamps) {
        // BufferQueueProducer only adds a new timestamp on
        // queueBuffer
        mCurrentFrameNumber = newTimestamps->frameNumber;
        mFrameEventHistory.addQueue(*newTimestamps);
    }
    if (outDelta) {
        // frame event histories will be processed
        // only after the producer connects and requests
        // deltas for the first time.  Forward this intent
        // to SF-side to turn event processing back on
        mPreviouslyConnected = mCurrentlyConnected;
        mCurrentlyConnected = true;
        mFrameEventHistory.getAndResetDelta(outDelta);
    }
}

void BLASTBufferItemConsumer::updateFrameTimestamps(uint64_t frameNumber, nsecs_t refreshStartTime,
                                                    const sp<Fence>& glDoneFence,
                                                    const sp<Fence>& presentFence,
                                                    const sp<Fence>& prevReleaseFence,
                                                    CompositorTiming compositorTiming,
                                                    nsecs_t latchTime, nsecs_t dequeueReadyTime) {
    Mutex::Autolock lock(mFrameEventHistoryMutex);

    // if the producer is not connected, don't bother updating,
    // the next producer that connects won't access this frame event
    if (!mCurrentlyConnected) return;
    std::shared_ptr<FenceTime> glDoneFenceTime = std::make_shared<FenceTime>(glDoneFence);
    std::shared_ptr<FenceTime> presentFenceTime = std::make_shared<FenceTime>(presentFence);
    std::shared_ptr<FenceTime> releaseFenceTime = std::make_shared<FenceTime>(prevReleaseFence);

    mFrameEventHistory.addLatch(frameNumber, latchTime);
    mFrameEventHistory.addRelease(frameNumber, dequeueReadyTime, std::move(releaseFenceTime));
    mFrameEventHistory.addPreComposition(frameNumber, refreshStartTime);
    mFrameEventHistory.addPostComposition(frameNumber, glDoneFenceTime, presentFenceTime,
                                          compositorTiming);
}

void BLASTBufferItemConsumer::getConnectionEvents(uint64_t frameNumber, bool* needsDisconnect) {
    bool disconnect = false;
    Mutex::Autolock lock(mFrameEventHistoryMutex);
    while (!mDisconnectEvents.empty() && mDisconnectEvents.front() <= frameNumber) {
        disconnect = true;
        mDisconnectEvents.pop();
    }
    if (needsDisconnect != nullptr) *needsDisconnect = disconnect;
}

BLASTBufferQueue::BLASTBufferQueue(const std::string& name, const sp<SurfaceControl>& surface,
                                   int width, int height, bool enableTripleBuffering)
      : mName(name),
        mSurfaceControl(surface),
        mSize(width, height),
        mRequestedSize(mSize),
        mNextTransaction(nullptr) {
    BufferQueue::createBufferQueue(&mProducer, &mConsumer);
    // since the adapter is in the client process, set dequeue timeout
    // explicitly so that dequeueBuffer will block
    mProducer->setDequeueTimeout(std::numeric_limits<int64_t>::max());

    if (enableTripleBuffering) {
        mProducer->setMaxDequeuedBufferCount(2);
    }
    mBufferItemConsumer =
        new BLASTBufferItemConsumer(mConsumer, GraphicBuffer::USAGE_HW_COMPOSER, 1, false);
    static int32_t id = 0;
    auto consumerName = mName + "(BLAST Consumer)" + std::to_string(id);
    id++;
    mBufferItemConsumer->setName(String8(consumerName.c_str()));
    mBufferItemConsumer->setFrameAvailableListener(this);
    mBufferItemConsumer->setBufferFreedListener(this);
    mBufferItemConsumer->setDefaultBufferSize(mSize.width, mSize.height);
    mBufferItemConsumer->setDefaultBufferFormat(PIXEL_FORMAT_RGBA_8888);

    mTransformHint = mSurfaceControl->getTransformHint();
    mBufferItemConsumer->setTransformHint(mTransformHint);

    mNumAcquired = 0;
    mNumFrameAvailable = 0;
    mPendingReleaseItem.item = BufferItem();
    mPendingReleaseItem.releaseFence = nullptr;
}

void BLASTBufferQueue::update(const sp<SurfaceControl>& surface, uint32_t width, uint32_t height) {
    std::unique_lock _lock{mMutex};
    mSurfaceControl = surface;

    ui::Size newSize(width, height);
    if (mRequestedSize != newSize) {
        mRequestedSize.set(newSize);
        mBufferItemConsumer->setDefaultBufferSize(mRequestedSize.width, mRequestedSize.height);
        if (mLastBufferScalingMode != NATIVE_WINDOW_SCALING_MODE_FREEZE) {
            // If the buffer supports scaling, update the frame immediately since the client may
            // want to scale the existing buffer to the new size.
            mSize = mRequestedSize;
            SurfaceComposerClient::Transaction t;
            t.setFrame(mSurfaceControl,
                       {0, 0, static_cast<int32_t>(mSize.width),
                        static_cast<int32_t>(mSize.height)});
            t.apply();
        }
    }
}

static void transactionCallbackThunk(void* context, nsecs_t latchTime,
                                     const sp<Fence>& presentFence,
                                     const std::vector<SurfaceControlStats>& stats) {
    if (context == nullptr) {
        return;
    }
    sp<BLASTBufferQueue> bq = static_cast<BLASTBufferQueue*>(context);
    bq->transactionCallback(latchTime, presentFence, stats);
}

void BLASTBufferQueue::transactionCallback(nsecs_t /*latchTime*/, const sp<Fence>& /*presentFence*/,
                                           const std::vector<SurfaceControlStats>& stats) {
    std::unique_lock _lock{mMutex};
    ATRACE_CALL();
    BQA_LOGV("transactionCallback");
    mInitialCallbackReceived = true;

    if (!stats.empty()) {
        mTransformHint = stats[0].transformHint;
        mBufferItemConsumer->setTransformHint(mTransformHint);
        mBufferItemConsumer->updateFrameTimestamps(stats[0].frameEventStats.frameNumber,
                                                   stats[0].frameEventStats.refreshStartTime,
                                                   stats[0].frameEventStats.gpuCompositionDoneFence,
                                                   stats[0].presentFence,
                                                   stats[0].previousReleaseFence,
                                                   stats[0].frameEventStats.compositorTiming,
                                                   stats[0].latchTime,
                                                   stats[0].frameEventStats.dequeueReadyTime);
    }
    if (mPendingReleaseItem.item.mGraphicBuffer != nullptr) {
        if (!stats.empty()) {
            mPendingReleaseItem.releaseFence = stats[0].previousReleaseFence;
        } else {
            BQA_LOGE("Warning: no SurfaceControlStats returned in BLASTBufferQueue callback");
            mPendingReleaseItem.releaseFence = nullptr;
        }
        mBufferItemConsumer->releaseBuffer(mPendingReleaseItem.item,
                                           mPendingReleaseItem.releaseFence
                                                   ? mPendingReleaseItem.releaseFence
                                                   : Fence::NO_FENCE);
        mNumAcquired--;
        mPendingReleaseItem.item = BufferItem();
        mPendingReleaseItem.releaseFence = nullptr;
    }

    if (mSubmitted.empty()) {
        BQA_LOGE("ERROR: callback with no corresponding submitted buffer item");
    }
    mPendingReleaseItem.item = std::move(mSubmitted.front());
    mSubmitted.pop();

    processNextBufferLocked(false);

    mCallbackCV.notify_all();
    decStrong((void*)transactionCallbackThunk);
}

void BLASTBufferQueue::processNextBufferLocked(bool useNextTransaction) {
    ATRACE_CALL();
    BQA_LOGV("processNextBufferLocked useNextTransaction=%s", toString(useNextTransaction));

    // Wait to acquire a buffer if there are no frames available or we have acquired the max
    // number of buffers.
    if (mNumFrameAvailable == 0 || maxBuffersAcquired()) {
        BQA_LOGV("processNextBufferLocked waiting for frame available or callback");
        mCallbackCV.notify_all();
        return;
    }

    if (mSurfaceControl == nullptr) {
        BQA_LOGE("ERROR : surface control is null");
        return;
    }

    SurfaceComposerClient::Transaction localTransaction;
    bool applyTransaction = true;
    SurfaceComposerClient::Transaction* t = &localTransaction;
    if (mNextTransaction != nullptr && useNextTransaction) {
        t = mNextTransaction;
        mNextTransaction = nullptr;
        applyTransaction = false;
    }

    BufferItem bufferItem;

    status_t status =
            mBufferItemConsumer->acquireBuffer(&bufferItem, 0 /* expectedPresent */, false);
    if (status != OK) {
        BQA_LOGE("Failed to acquire a buffer, err=%s", statusToString(status).c_str());
        return;
    }
    auto buffer = bufferItem.mGraphicBuffer;
    mNumFrameAvailable--;

    if (buffer == nullptr) {
        mBufferItemConsumer->releaseBuffer(bufferItem, Fence::NO_FENCE);
        BQA_LOGE("Buffer was empty");
        return;
    }

    if (rejectBuffer(bufferItem)) {
        BQA_LOGE("rejecting buffer:active_size=%dx%d, requested_size=%dx%d"
                 "buffer{size=%dx%d transform=%d}",
                 mSize.width, mSize.height, mRequestedSize.width, mRequestedSize.height,
                 buffer->getWidth(), buffer->getHeight(), bufferItem.mTransform);
        mBufferItemConsumer->releaseBuffer(bufferItem, Fence::NO_FENCE);
        processNextBufferLocked(useNextTransaction);
        return;
    }

    mNumAcquired++;
    mSubmitted.push(bufferItem);

    bool needsDisconnect = false;
    mBufferItemConsumer->getConnectionEvents(bufferItem.mFrameNumber, &needsDisconnect);

    // if producer disconnected before, notify SurfaceFlinger
    if (needsDisconnect) {
        t->notifyProducerDisconnect(mSurfaceControl);
    }

    // Ensure BLASTBufferQueue stays alive until we receive the transaction complete callback.
    incStrong((void*)transactionCallbackThunk);

    mLastBufferScalingMode = bufferItem.mScalingMode;

    t->setBuffer(mSurfaceControl, buffer);
    t->setDataspace(mSurfaceControl, static_cast<ui::Dataspace>(bufferItem.mDataSpace));
    t->setHdrMetadata(mSurfaceControl, bufferItem.mHdrMetadata);
    t->setSurfaceDamageRegion(mSurfaceControl, bufferItem.mSurfaceDamage);
    t->setAcquireFence(mSurfaceControl,
                       bufferItem.mFence ? new Fence(bufferItem.mFence->dup()) : Fence::NO_FENCE);
    t->addTransactionCompletedCallback(transactionCallbackThunk, static_cast<void*>(this));

    t->setFrame(mSurfaceControl,
                {0, 0, static_cast<int32_t>(mSize.width), static_cast<int32_t>(mSize.height)});
    t->setCrop(mSurfaceControl, computeCrop(bufferItem));
    t->setTransform(mSurfaceControl, bufferItem.mTransform);
    t->setTransformToDisplayInverse(mSurfaceControl, bufferItem.mTransformToDisplayInverse);
    t->setDesiredPresentTime(bufferItem.mTimestamp);
    t->setFrameNumber(mSurfaceControl, bufferItem.mFrameNumber);

    if (!mNextFrameTimelineVsyncIdQueue.empty()) {
        t->setFrameTimelineVsync(mSurfaceControl, mNextFrameTimelineVsyncIdQueue.front());
        mNextFrameTimelineVsyncIdQueue.pop();
    }

    if (mAutoRefresh != bufferItem.mAutoRefresh) {
        t->setAutoRefresh(mSurfaceControl, bufferItem.mAutoRefresh);
        mAutoRefresh = bufferItem.mAutoRefresh;
    }

    if (applyTransaction) {
        t->apply();
    }

    BQA_LOGV("processNextBufferLocked size=%dx%d mFrameNumber=%" PRIu64
             " applyTransaction=%s mTimestamp=%" PRId64,
             mSize.width, mSize.height, bufferItem.mFrameNumber, toString(applyTransaction),
             bufferItem.mTimestamp);
}

Rect BLASTBufferQueue::computeCrop(const BufferItem& item) {
    if (item.mScalingMode == NATIVE_WINDOW_SCALING_MODE_SCALE_CROP) {
        return GLConsumer::scaleDownCrop(item.mCrop, mSize.width, mSize.height);
    }
    return item.mCrop;
}

void BLASTBufferQueue::onFrameAvailable(const BufferItem& item) {
    ATRACE_CALL();
    std::unique_lock _lock{mMutex};

    const bool nextTransactionSet = mNextTransaction != nullptr;
    BQA_LOGV("onFrameAvailable framenumber=%" PRIu64 " nextTransactionSet=%s mFlushShadowQueue=%s",
             item.mFrameNumber, toString(nextTransactionSet), toString(mFlushShadowQueue));

    if (nextTransactionSet || mFlushShadowQueue) {
        while (mNumFrameAvailable > 0 || maxBuffersAcquired()) {
            BQA_LOGV("waiting in onFrameAvailable...");
            mCallbackCV.wait(_lock);
        }
    }
    mFlushShadowQueue = false;
    // add to shadow queue
    mNumFrameAvailable++;
    processNextBufferLocked(true);
}

void BLASTBufferQueue::onFrameReplaced(const BufferItem& item) {
    BQA_LOGV("onFrameReplaced framenumber=%" PRIu64, item.mFrameNumber);
    // Do nothing since we are not storing unacquired buffer items locally.
}

void BLASTBufferQueue::setNextTransaction(SurfaceComposerClient::Transaction* t) {
    std::lock_guard _lock{mMutex};
    mNextTransaction = t;
}

bool BLASTBufferQueue::rejectBuffer(const BufferItem& item) {
    if (item.mScalingMode != NATIVE_WINDOW_SCALING_MODE_FREEZE) {
        // Only reject buffers if scaling mode is freeze.
        return false;
    }

    uint32_t bufWidth = item.mGraphicBuffer->getWidth();
    uint32_t bufHeight = item.mGraphicBuffer->getHeight();

    // Take the buffer's orientation into account
    if (item.mTransform & ui::Transform::ROT_90) {
        std::swap(bufWidth, bufHeight);
    }
    ui::Size bufferSize(bufWidth, bufHeight);
    if (mRequestedSize != mSize && mRequestedSize == bufferSize) {
        mSize = mRequestedSize;
        return false;
    }

    // reject buffers if the buffer size doesn't match.
    return mSize != bufferSize;
}

// Check if we have acquired the maximum number of buffers.
// As a special case, we wait for the first callback before acquiring the second buffer so we
// can ensure the first buffer is presented if multiple buffers are queued in succession.
bool BLASTBufferQueue::maxBuffersAcquired() const {
    return mNumAcquired == MAX_ACQUIRED_BUFFERS + 1 ||
            (!mInitialCallbackReceived && mNumAcquired == 1);
}

class BBQSurface : public Surface {
private:
    sp<BLASTBufferQueue> mBbq;
public:
    BBQSurface(const sp<IGraphicBufferProducer>& igbp, bool controlledByApp,
               const sp<IBinder>& scHandle, const sp<BLASTBufferQueue>& bbq)
          : Surface(igbp, controlledByApp, scHandle), mBbq(bbq) {}

    void allocateBuffers() override {
        uint32_t reqWidth = mReqWidth ? mReqWidth : mUserWidth;
        uint32_t reqHeight = mReqHeight ? mReqHeight : mUserHeight;
        auto gbp = getIGraphicBufferProducer();
        std::thread ([reqWidth, reqHeight, gbp=getIGraphicBufferProducer(),
                      reqFormat=mReqFormat, reqUsage=mReqUsage] () {
            gbp->allocateBuffers(reqWidth, reqHeight,
                                 reqFormat, reqUsage);

        }).detach();
    }

    status_t setFrameRate(float frameRate, int8_t compatibility, bool shouldBeSeamless) override {
        if (!ValidateFrameRate(frameRate, compatibility, "BBQSurface::setFrameRate")) {
            return BAD_VALUE;
        }
        return mBbq->setFrameRate(frameRate, compatibility, shouldBeSeamless);
    }

    status_t setFrameTimelineVsync(int64_t frameTimelineVsyncId) override {
        return mBbq->setFrameTimelineVsync(frameTimelineVsyncId);
    }
};

// TODO: Can we coalesce this with frame updates? Need to confirm
// no timing issues.
status_t BLASTBufferQueue::setFrameRate(float frameRate, int8_t compatibility,
                                        bool shouldBeSeamless) {
    std::unique_lock _lock{mMutex};
    SurfaceComposerClient::Transaction t;

    return t.setFrameRate(mSurfaceControl, frameRate, compatibility, shouldBeSeamless).apply();
}

status_t BLASTBufferQueue::setFrameTimelineVsync(int64_t frameTimelineVsyncId) {
    std::unique_lock _lock{mMutex};
    mNextFrameTimelineVsyncIdQueue.push(frameTimelineVsyncId);
    return OK;
}

sp<Surface> BLASTBufferQueue::getSurface(bool includeSurfaceControlHandle) {
    std::unique_lock _lock{mMutex};
    sp<IBinder> scHandle = nullptr;
    if (includeSurfaceControlHandle && mSurfaceControl) {
        scHandle = mSurfaceControl->getHandle();
    }
    return new BBQSurface(mProducer, true, scHandle, this);
}

} // namespace android
