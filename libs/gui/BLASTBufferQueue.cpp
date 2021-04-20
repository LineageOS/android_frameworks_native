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
#include <gui/BufferQueueConsumer.h>
#include <gui/BufferQueueCore.h>
#include <gui/BufferQueueProducer.h>
#include <gui/GLConsumer.h>
#include <gui/IProducerListener.h>
#include <gui/Surface.h>
#include <utils/Singleton.h>

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
    Mutex::Autolock lock(mMutex);
    mPreviouslyConnected = mCurrentlyConnected;
    mCurrentlyConnected = false;
    if (mPreviouslyConnected) {
        mDisconnectEvents.push(mCurrentFrameNumber);
    }
    mFrameEventHistory.onDisconnect();
}

void BLASTBufferItemConsumer::addAndGetFrameTimestamps(const NewFrameEventsEntry* newTimestamps,
                                                       FrameEventHistoryDelta* outDelta) {
    Mutex::Autolock lock(mMutex);
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
    Mutex::Autolock lock(mMutex);

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
    Mutex::Autolock lock(mMutex);
    while (!mDisconnectEvents.empty() && mDisconnectEvents.front() <= frameNumber) {
        disconnect = true;
        mDisconnectEvents.pop();
    }
    if (needsDisconnect != nullptr) *needsDisconnect = disconnect;
}

void BLASTBufferItemConsumer::setBlastBufferQueue(BLASTBufferQueue* blastbufferqueue) {
    Mutex::Autolock lock(mMutex);
    mBLASTBufferQueue = blastbufferqueue;
}

void BLASTBufferItemConsumer::onSidebandStreamChanged() {
    Mutex::Autolock lock(mMutex);
    if (mBLASTBufferQueue != nullptr) {
        sp<NativeHandle> stream = getSidebandStream();
        mBLASTBufferQueue->setSidebandStream(stream);
    }
}

BLASTBufferQueue::BLASTBufferQueue(const std::string& name, const sp<SurfaceControl>& surface,
                                   int width, int height, int32_t format)
      : mName(name),
        mSurfaceControl(surface),
        mSize(width, height),
        mRequestedSize(mSize),
        mFormat(format),
        mNextTransaction(nullptr) {
    createBufferQueue(&mProducer, &mConsumer);
    // since the adapter is in the client process, set dequeue timeout
    // explicitly so that dequeueBuffer will block
    mProducer->setDequeueTimeout(std::numeric_limits<int64_t>::max());

    // safe default, most producers are expected to override this
    mProducer->setMaxDequeuedBufferCount(2);
    mBufferItemConsumer = new BLASTBufferItemConsumer(mConsumer,
                                                      GraphicBuffer::USAGE_HW_COMPOSER |
                                                              GraphicBuffer::USAGE_HW_TEXTURE,
                                                      1, false);
    static int32_t id = 0;
    auto consumerName = mName + "(BLAST Consumer)" + std::to_string(id);
    id++;
    mBufferItemConsumer->setName(String8(consumerName.c_str()));
    mBufferItemConsumer->setFrameAvailableListener(this);
    mBufferItemConsumer->setBufferFreedListener(this);
    mBufferItemConsumer->setDefaultBufferSize(mSize.width, mSize.height);
    mBufferItemConsumer->setDefaultBufferFormat(convertBufferFormat(format));
    mBufferItemConsumer->setBlastBufferQueue(this);

    mTransformHint = mSurfaceControl->getTransformHint();
    mBufferItemConsumer->setTransformHint(mTransformHint);
    SurfaceComposerClient::Transaction()
          .setFlags(surface, layer_state_t::eEnableBackpressure,
                    layer_state_t::eEnableBackpressure)
          .apply();

    mNumAcquired = 0;
    mNumFrameAvailable = 0;
}

BLASTBufferQueue::~BLASTBufferQueue() {
    mBufferItemConsumer->setBlastBufferQueue(nullptr);
    if (mPendingTransactions.empty()) {
        return;
    }
    BQA_LOGE("Applying pending transactions on dtor %d",
             static_cast<uint32_t>(mPendingTransactions.size()));
    SurfaceComposerClient::Transaction t;
    for (auto& [targetFrameNumber, transaction] : mPendingTransactions) {
        t.merge(std::move(transaction));
    }
    t.apply();
}

void BLASTBufferQueue::update(const sp<SurfaceControl>& surface, uint32_t width, uint32_t height,
                              int32_t format) {
    std::unique_lock _lock{mMutex};
    if (mFormat != format) {
        mFormat = format;
        mBufferItemConsumer->setDefaultBufferFormat(convertBufferFormat(format));
    }

    SurfaceComposerClient::Transaction t;
    bool applyTransaction = false;
    if (!SurfaceControl::isSameSurface(mSurfaceControl, surface)) {
        mSurfaceControl = surface;
        t.setFlags(mSurfaceControl, layer_state_t::eEnableBackpressure,
                   layer_state_t::eEnableBackpressure);
        applyTransaction = true;
    }

    ui::Size newSize(width, height);
    if (mRequestedSize != newSize) {
        mRequestedSize.set(newSize);
        mBufferItemConsumer->setDefaultBufferSize(mRequestedSize.width, mRequestedSize.height);
        if (mLastBufferInfo.scalingMode != NATIVE_WINDOW_SCALING_MODE_FREEZE) {
            // If the buffer supports scaling, update the frame immediately since the client may
            // want to scale the existing buffer to the new size.
            mSize = mRequestedSize;
            // We only need to update the scale if we've received at least one buffer. The reason
            // for this is the scale is calculated based on the requested size and buffer size.
            // If there's no buffer, the scale will always be 1.
            if (mLastBufferInfo.hasBuffer) {
                setMatrix(&t, mLastBufferInfo);
            }
            applyTransaction = true;
        }
    }
    if (applyTransaction) {
        t.apply();
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
    std::function<void(int64_t)> transactionCompleteCallback = nullptr;
    uint64_t currFrameNumber = 0;

    {
        std::unique_lock _lock{mMutex};
        ATRACE_CALL();
        BQA_LOGV("transactionCallback");

        if (!stats.empty()) {
            mTransformHint = stats[0].transformHint;
            mBufferItemConsumer->setTransformHint(mTransformHint);
            mBufferItemConsumer
                    ->updateFrameTimestamps(stats[0].frameEventStats.frameNumber,
                                            stats[0].frameEventStats.refreshStartTime,
                                            stats[0].frameEventStats.gpuCompositionDoneFence,
                                            stats[0].presentFence, stats[0].previousReleaseFence,
                                            stats[0].frameEventStats.compositorTiming,
                                            stats[0].latchTime,
                                            stats[0].frameEventStats.dequeueReadyTime);
            currFrameNumber = stats[0].frameEventStats.frameNumber;

            if (mTransactionCompleteCallback &&
                currFrameNumber >= mTransactionCompleteFrameNumber) {
                if (currFrameNumber > mTransactionCompleteFrameNumber) {
                    BQA_LOGE("transactionCallback received for a newer framenumber=%" PRIu64
                             " than expected=%" PRIu64,
                             currFrameNumber, mTransactionCompleteFrameNumber);
                }
                transactionCompleteCallback = std::move(mTransactionCompleteCallback);
                mTransactionCompleteFrameNumber = 0;
            }
        }

        decStrong((void*)transactionCallbackThunk);
    }

    if (transactionCompleteCallback) {
        transactionCompleteCallback(currFrameNumber);
    }
}

// Unlike transactionCallbackThunk the release buffer callback does not extend the life of the
// BBQ. This is because if the BBQ is destroyed, then the buffers will be released by the client.
// So we pass in a weak pointer to the BBQ and if it still alive, then we release the buffer.
// Otherwise, this is a no-op.
static void releaseBufferCallbackThunk(wp<BLASTBufferQueue> context, uint64_t graphicBufferId,
                                       const sp<Fence>& releaseFence) {
    sp<BLASTBufferQueue> blastBufferQueue = context.promote();
    ALOGV("releaseBufferCallbackThunk graphicBufferId=%" PRIu64 " blastBufferQueue=%s",
          graphicBufferId, blastBufferQueue ? "alive" : "dead");
    if (blastBufferQueue) {
        blastBufferQueue->releaseBufferCallback(graphicBufferId, releaseFence);
    }
}

void BLASTBufferQueue::releaseBufferCallback(uint64_t graphicBufferId,
                                             const sp<Fence>& releaseFence) {
    ATRACE_CALL();
    std::unique_lock _lock{mMutex};
    BQA_LOGV("releaseBufferCallback graphicBufferId=%" PRIu64, graphicBufferId);

    auto it = mSubmitted.find(graphicBufferId);
    if (it == mSubmitted.end()) {
        BQA_LOGE("ERROR: releaseBufferCallback without corresponding submitted buffer %" PRIu64,
                 graphicBufferId);
        return;
    }

    mBufferItemConsumer->releaseBuffer(it->second, releaseFence);
    mSubmitted.erase(it);
    mNumAcquired--;
    processNextBufferLocked(false /* useNextTransaction */);
    mCallbackCV.notify_all();
}

void BLASTBufferQueue::processNextBufferLocked(bool useNextTransaction) {
    ATRACE_CALL();
    // If the next transaction is set, we want to guarantee the our acquire will not fail, so don't
    // include the extra buffer when checking if we can acquire the next buffer.
    const bool includeExtraAcquire = !useNextTransaction;
    if (mNumFrameAvailable == 0 || maxBuffersAcquired(includeExtraAcquire)) {
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
    if (status == BufferQueue::NO_BUFFER_AVAILABLE) {
        BQA_LOGV("Failed to acquire a buffer, err=NO_BUFFER_AVAILABLE");
        return;
    } else if (status != OK) {
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
    mSubmitted[buffer->getId()] = bufferItem;

    bool needsDisconnect = false;
    mBufferItemConsumer->getConnectionEvents(bufferItem.mFrameNumber, &needsDisconnect);

    // if producer disconnected before, notify SurfaceFlinger
    if (needsDisconnect) {
        t->notifyProducerDisconnect(mSurfaceControl);
    }

    // Ensure BLASTBufferQueue stays alive until we receive the transaction complete callback.
    incStrong((void*)transactionCallbackThunk);

    mLastAcquiredFrameNumber = bufferItem.mFrameNumber;
    mLastBufferInfo.update(true /* hasBuffer */, bufferItem.mGraphicBuffer->getWidth(),
                           bufferItem.mGraphicBuffer->getHeight(), bufferItem.mTransform,
                           bufferItem.mScalingMode);

    auto releaseBufferCallback =
            std::bind(releaseBufferCallbackThunk, wp<BLASTBufferQueue>(this) /* callbackContext */,
                      std::placeholders::_1, std::placeholders::_2);
    t->setBuffer(mSurfaceControl, buffer, releaseBufferCallback);
    t->setDataspace(mSurfaceControl, static_cast<ui::Dataspace>(bufferItem.mDataSpace));
    t->setHdrMetadata(mSurfaceControl, bufferItem.mHdrMetadata);
    t->setSurfaceDamageRegion(mSurfaceControl, bufferItem.mSurfaceDamage);
    t->setAcquireFence(mSurfaceControl,
                       bufferItem.mFence ? new Fence(bufferItem.mFence->dup()) : Fence::NO_FENCE);
    t->addTransactionCompletedCallback(transactionCallbackThunk, static_cast<void*>(this));

    setMatrix(t, mLastBufferInfo);
    t->setCrop(mSurfaceControl, computeCrop(bufferItem));
    t->setTransform(mSurfaceControl, bufferItem.mTransform);
    t->setTransformToDisplayInverse(mSurfaceControl, bufferItem.mTransformToDisplayInverse);
    if (!bufferItem.mIsAutoTimestamp) {
        t->setDesiredPresentTime(bufferItem.mTimestamp);
    }
    t->setFrameNumber(mSurfaceControl, bufferItem.mFrameNumber);

    if (!mNextFrameTimelineInfoQueue.empty()) {
        t->setFrameTimelineInfo(mNextFrameTimelineInfoQueue.front());
        mNextFrameTimelineInfoQueue.pop();
    }

    if (mAutoRefresh != bufferItem.mAutoRefresh) {
        t->setAutoRefresh(mSurfaceControl, bufferItem.mAutoRefresh);
        mAutoRefresh = bufferItem.mAutoRefresh;
    }
    {
        std::unique_lock _lock{mTimestampMutex};
        auto dequeueTime = mDequeueTimestamps.find(buffer->getId());
        if (dequeueTime != mDequeueTimestamps.end()) {
            Parcel p;
            p.writeInt64(dequeueTime->second);
            t->setMetadata(mSurfaceControl, METADATA_DEQUEUE_TIME, p);
            mDequeueTimestamps.erase(dequeueTime);
        }
    }

    auto mergeTransaction =
            [&t, currentFrameNumber = bufferItem.mFrameNumber](
                    std::tuple<uint64_t, SurfaceComposerClient::Transaction> pendingTransaction) {
                auto& [targetFrameNumber, transaction] = pendingTransaction;
                if (currentFrameNumber < targetFrameNumber) {
                    return false;
                }
                t->merge(std::move(transaction));
                return true;
            };

    mPendingTransactions.erase(std::remove_if(mPendingTransactions.begin(),
                                              mPendingTransactions.end(), mergeTransaction),
                               mPendingTransactions.end());

    if (applyTransaction) {
        t->setApplyToken(mApplyToken).apply();
    }

    BQA_LOGV("processNextBufferLocked size=%dx%d mFrameNumber=%" PRIu64
             " applyTransaction=%s mTimestamp=%" PRId64 "%s mPendingTransactions.size=%d"
             " graphicBufferId=%" PRIu64,
             mSize.width, mSize.height, bufferItem.mFrameNumber, toString(applyTransaction),
             bufferItem.mTimestamp, bufferItem.mIsAutoTimestamp ? "(auto)" : "",
             static_cast<uint32_t>(mPendingTransactions.size()),
             bufferItem.mGraphicBuffer->getId());
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
    if (nextTransactionSet) {
        while (mNumFrameAvailable > 0 || maxBuffersAcquired(false /* includeExtraAcquire */)) {
            BQA_LOGV("waiting in onFrameAvailable...");
            mCallbackCV.wait(_lock);
        }
    }
    // add to shadow queue
    mNumFrameAvailable++;

    BQA_LOGV("onFrameAvailable framenumber=%" PRIu64 " nextTransactionSet=%s", item.mFrameNumber,
             toString(nextTransactionSet));
    processNextBufferLocked(nextTransactionSet /* useNextTransaction */);
}

void BLASTBufferQueue::onFrameReplaced(const BufferItem& item) {
    BQA_LOGV("onFrameReplaced framenumber=%" PRIu64, item.mFrameNumber);
    // Do nothing since we are not storing unacquired buffer items locally.
}

void BLASTBufferQueue::onFrameDequeued(const uint64_t bufferId) {
    std::unique_lock _lock{mTimestampMutex};
    mDequeueTimestamps[bufferId] = systemTime();
};

void BLASTBufferQueue::onFrameCancelled(const uint64_t bufferId) {
    std::unique_lock _lock{mTimestampMutex};
    mDequeueTimestamps.erase(bufferId);
};

void BLASTBufferQueue::setNextTransaction(SurfaceComposerClient::Transaction* t) {
    std::lock_guard _lock{mMutex};
    mNextTransaction = t;
}

bool BLASTBufferQueue::rejectBuffer(const BufferItem& item) {
    if (item.mScalingMode != NATIVE_WINDOW_SCALING_MODE_FREEZE) {
        mSize = mRequestedSize;
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

void BLASTBufferQueue::setMatrix(SurfaceComposerClient::Transaction* t,
                                 const BufferInfo& bufferInfo) {
    uint32_t bufWidth = bufferInfo.width;
    uint32_t bufHeight = bufferInfo.height;

    float dsdx = mSize.width / static_cast<float>(bufWidth);
    float dsdy = mSize.height / static_cast<float>(bufHeight);

    t->setMatrix(mSurfaceControl, dsdx, 0, 0, dsdy);
}

void BLASTBufferQueue::setTransactionCompleteCallback(
        uint64_t frameNumber, std::function<void(int64_t)>&& transactionCompleteCallback) {
    std::lock_guard _lock{mMutex};
    if (transactionCompleteCallback == nullptr) {
        mTransactionCompleteCallback = nullptr;
    } else {
        mTransactionCompleteCallback = std::move(transactionCompleteCallback);
        mTransactionCompleteFrameNumber = frameNumber;
    }
}

// Check if we have acquired the maximum number of buffers.
// Consumer can acquire an additional buffer if that buffer is not droppable. Set
// includeExtraAcquire is true to include this buffer to the count. Since this depends on the state
// of the buffer, the next acquire may return with NO_BUFFER_AVAILABLE.
bool BLASTBufferQueue::maxBuffersAcquired(bool includeExtraAcquire) const {
    int maxAcquiredBuffers = MAX_ACQUIRED_BUFFERS + (includeExtraAcquire ? 2 : 1);
    return mNumAcquired == maxAcquiredBuffers;
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

    status_t setFrameRate(float frameRate, int8_t compatibility,
                          int8_t changeFrameRateStrategy) override {
        if (!ValidateFrameRate(frameRate, compatibility, changeFrameRateStrategy,
                               "BBQSurface::setFrameRate")) {
            return BAD_VALUE;
        }
        return mBbq->setFrameRate(frameRate, compatibility, changeFrameRateStrategy);
    }

    status_t setFrameTimelineInfo(const FrameTimelineInfo& frameTimelineInfo) override {
        return mBbq->setFrameTimelineInfo(frameTimelineInfo);
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

status_t BLASTBufferQueue::setFrameTimelineInfo(const FrameTimelineInfo& frameTimelineInfo) {
    std::unique_lock _lock{mMutex};
    mNextFrameTimelineInfoQueue.push(frameTimelineInfo);
    return OK;
}

void BLASTBufferQueue::setSidebandStream(const sp<NativeHandle>& stream) {
    std::unique_lock _lock{mMutex};
    SurfaceComposerClient::Transaction t;

    t.setSidebandStream(mSurfaceControl, stream).apply();
}

sp<Surface> BLASTBufferQueue::getSurface(bool includeSurfaceControlHandle) {
    std::unique_lock _lock{mMutex};
    sp<IBinder> scHandle = nullptr;
    if (includeSurfaceControlHandle && mSurfaceControl) {
        scHandle = mSurfaceControl->getHandle();
    }
    return new BBQSurface(mProducer, true, scHandle, this);
}

void BLASTBufferQueue::mergeWithNextTransaction(SurfaceComposerClient::Transaction* t,
                                                uint64_t frameNumber) {
    std::lock_guard _lock{mMutex};
    if (mLastAcquiredFrameNumber >= frameNumber) {
        // Apply the transaction since we have already acquired the desired frame.
        t->apply();
    } else {
        mPendingTransactions.emplace_back(frameNumber, *t);
        // Clear the transaction so it can't be applied elsewhere.
        t->clear();
    }
}

// Maintains a single worker thread per process that services a list of runnables.
class AsyncWorker : public Singleton<AsyncWorker> {
private:
    std::thread mThread;
    bool mDone = false;
    std::deque<std::function<void()>> mRunnables;
    std::mutex mMutex;
    std::condition_variable mCv;
    void run() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mDone) {
            mCv.wait(lock);
            while (!mRunnables.empty()) {
                std::function<void()> runnable = mRunnables.front();
                mRunnables.pop_front();
                runnable();
            }
        }
    }

public:
    AsyncWorker() : Singleton<AsyncWorker>() { mThread = std::thread(&AsyncWorker::run, this); }

    ~AsyncWorker() {
        mDone = true;
        mCv.notify_all();
        if (mThread.joinable()) {
            mThread.join();
        }
    }

    void post(std::function<void()> runnable) {
        std::unique_lock<std::mutex> lock(mMutex);
        mRunnables.emplace_back(std::move(runnable));
        mCv.notify_one();
    }
};
ANDROID_SINGLETON_STATIC_INSTANCE(AsyncWorker);

// Asynchronously calls ProducerListener functions so we can emulate one way binder calls.
class AsyncProducerListener : public BnProducerListener {
private:
    const sp<IProducerListener> mListener;

public:
    AsyncProducerListener(const sp<IProducerListener>& listener) : mListener(listener) {}

    void onBufferReleased() override {
        AsyncWorker::getInstance().post([listener = mListener]() { listener->onBufferReleased(); });
    }

    void onBuffersDiscarded(const std::vector<int32_t>& slots) override {
        AsyncWorker::getInstance().post(
                [listener = mListener, slots = slots]() { listener->onBuffersDiscarded(slots); });
    }
};

// Extends the BufferQueueProducer to create a wrapper around the listener so the listener calls
// can be non-blocking when the producer is in the client process.
class BBQBufferQueueProducer : public BufferQueueProducer {
public:
    BBQBufferQueueProducer(const sp<BufferQueueCore>& core)
          : BufferQueueProducer(core, false /* consumerIsSurfaceFlinger*/) {}

    status_t connect(const sp<IProducerListener>& listener, int api, bool producerControlledByApp,
                     QueueBufferOutput* output) override {
        if (!listener) {
            return BufferQueueProducer::connect(listener, api, producerControlledByApp, output);
        }

        return BufferQueueProducer::connect(new AsyncProducerListener(listener), api,
                                            producerControlledByApp, output);
    }

    int query(int what, int* value) override {
        if (what == NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER) {
            *value = 1;
            return NO_ERROR;
        }
        return BufferQueueProducer::query(what, value);
    }
};

// Similar to BufferQueue::createBufferQueue but creates an adapter specific bufferqueue producer.
// This BQP allows invoking client specified ProducerListeners and invoke them asynchronously,
// emulating one way binder call behavior. Without this, if the listener calls back into the queue,
// we can deadlock.
void BLASTBufferQueue::createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                                         sp<IGraphicBufferConsumer>* outConsumer) {
    LOG_ALWAYS_FATAL_IF(outProducer == nullptr, "BLASTBufferQueue: outProducer must not be NULL");
    LOG_ALWAYS_FATAL_IF(outConsumer == nullptr, "BLASTBufferQueue: outConsumer must not be NULL");

    sp<BufferQueueCore> core(new BufferQueueCore());
    LOG_ALWAYS_FATAL_IF(core == nullptr, "BLASTBufferQueue: failed to create BufferQueueCore");

    sp<IGraphicBufferProducer> producer(new BBQBufferQueueProducer(core));
    LOG_ALWAYS_FATAL_IF(producer == nullptr,
                        "BLASTBufferQueue: failed to create BBQBufferQueueProducer");

    sp<BufferQueueConsumer> consumer(new BufferQueueConsumer(core));
    consumer->setAllowExtraAcquire(true);
    LOG_ALWAYS_FATAL_IF(consumer == nullptr,
                        "BLASTBufferQueue: failed to create BufferQueueConsumer");

    *outProducer = producer;
    *outConsumer = consumer;
}

PixelFormat BLASTBufferQueue::convertBufferFormat(PixelFormat& format) {
    PixelFormat convertedFormat = format;
    switch (format) {
        case PIXEL_FORMAT_TRANSPARENT:
        case PIXEL_FORMAT_TRANSLUCENT:
            convertedFormat = PIXEL_FORMAT_RGBA_8888;
            break;
        case PIXEL_FORMAT_OPAQUE:
            convertedFormat = PIXEL_FORMAT_RGBX_8888;
            break;
    }
    return convertedFormat;
}

} // namespace android
