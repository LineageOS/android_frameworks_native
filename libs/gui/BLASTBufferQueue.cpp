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

#include <gui/BLASTBufferQueue.h>
#include <gui/BufferItemConsumer.h>
#include <gui/GLConsumer.h>

#include <utils/Trace.h>

#include <chrono>

using namespace std::chrono_literals;

namespace android {

BLASTBufferQueue::BLASTBufferQueue(const sp<SurfaceControl>& surface, int width, int height)
      : mSurfaceControl(surface),
        mWidth(width),
        mHeight(height),
        mNextTransaction(nullptr) {
    BufferQueue::createBufferQueue(&mProducer, &mConsumer);
    mConsumer->setMaxAcquiredBufferCount(MAX_ACQUIRED_BUFFERS);
    mBufferItemConsumer =
            new BufferItemConsumer(mConsumer, AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER, 1, true);
    static int32_t id = 0;
    auto name = std::string("BLAST Consumer") + std::to_string(id);
    id++;
    mBufferItemConsumer->setName(String8(name.c_str()));
    mBufferItemConsumer->setFrameAvailableListener(this);
    mBufferItemConsumer->setBufferFreedListener(this);
    mBufferItemConsumer->setDefaultBufferSize(mWidth, mHeight);
    mBufferItemConsumer->setDefaultBufferFormat(PIXEL_FORMAT_RGBA_8888);
    mTransformHint = mSurfaceControl->getTransformHint();

    mNumAcquired = 0;
    mNumFrameAvailable = 0;
    mPendingReleaseItem.item = BufferItem();
    mPendingReleaseItem.releaseFence = nullptr;
}

void BLASTBufferQueue::update(const sp<SurfaceControl>& surface, int width, int height) {
    std::unique_lock _lock{mMutex};
    mSurfaceControl = surface;
    mWidth = width;
    mHeight = height;
    mBufferItemConsumer->setDefaultBufferSize(mWidth, mHeight);
}

static void transactionCallbackThunk(void* context, nsecs_t latchTime,
                                     const sp<Fence>& presentFence,
                                     const std::vector<SurfaceControlStats>& stats) {
    if (context == nullptr) {
        return;
    }
    BLASTBufferQueue* bq = static_cast<BLASTBufferQueue*>(context);
    bq->transactionCallback(latchTime, presentFence, stats);
}

void BLASTBufferQueue::transactionCallback(nsecs_t /*latchTime*/, const sp<Fence>& /*presentFence*/,
                                           const std::vector<SurfaceControlStats>& stats) {
    std::unique_lock _lock{mMutex};
    ATRACE_CALL();

    if (mPendingReleaseItem.item.mGraphicBuffer != nullptr) {
        if (stats.size() > 0) {
            mPendingReleaseItem.releaseFence = stats[0].previousReleaseFence;
            mTransformHint = stats[0].transformHint;
            mBufferItemConsumer->setTransformHint(mTransformHint);
        } else {
            ALOGE("Warning: no SurfaceControlStats returned in BLASTBufferQueue callback");
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
        ALOGE("ERROR: callback with no corresponding submitted buffer item");
    }
    mPendingReleaseItem.item = std::move(mSubmitted.front());
    mSubmitted.pop();
    processNextBufferLocked();
    mCallbackCV.notify_all();
    decStrong((void*)transactionCallbackThunk);
}

void BLASTBufferQueue::processNextBufferLocked() {
    ATRACE_CALL();
    if (mNumFrameAvailable == 0 || mNumAcquired == MAX_ACQUIRED_BUFFERS) {
        return;
    }

    if (mSurfaceControl == nullptr) {
        ALOGE("ERROR : surface control is null");
        return;
    }

    SurfaceComposerClient::Transaction localTransaction;
    bool applyTransaction = true;
    SurfaceComposerClient::Transaction* t = &localTransaction;
    if (mNextTransaction != nullptr) {
        t = mNextTransaction;
        mNextTransaction = nullptr;
        applyTransaction = false;
    }

    BufferItem bufferItem;

    status_t status = mBufferItemConsumer->acquireBuffer(&bufferItem, -1, false);
    if (status != OK) {
        return;
    }
    auto buffer = bufferItem.mGraphicBuffer;
    mNumFrameAvailable--;

    if (buffer == nullptr) {
        mBufferItemConsumer->releaseBuffer(bufferItem, Fence::NO_FENCE);
        return;
    }

    mNumAcquired++;
    mSubmitted.push(bufferItem);

    // Ensure BLASTBufferQueue stays alive until we receive the transaction complete callback.
    incStrong((void*)transactionCallbackThunk);

    t->setBuffer(mSurfaceControl, buffer);
    t->setAcquireFence(mSurfaceControl,
                       bufferItem.mFence ? new Fence(bufferItem.mFence->dup()) : Fence::NO_FENCE);
    t->addTransactionCompletedCallback(transactionCallbackThunk, static_cast<void*>(this));

    t->setFrame(mSurfaceControl, {0, 0, mWidth, mHeight});
    t->setCrop(mSurfaceControl, computeCrop(bufferItem));
    t->setTransform(mSurfaceControl, bufferItem.mTransform);
    t->setTransformToDisplayInverse(mSurfaceControl, bufferItem.mTransformToDisplayInverse);
    t->setDesiredPresentTime(bufferItem.mTimestamp);

    if (applyTransaction) {
        t->apply();
    }
}

Rect BLASTBufferQueue::computeCrop(const BufferItem& item) {
    if (item.mScalingMode == NATIVE_WINDOW_SCALING_MODE_SCALE_CROP) {
        return GLConsumer::scaleDownCrop(item.mCrop, mWidth, mHeight);
    }
    return item.mCrop;
}

void BLASTBufferQueue::onFrameAvailable(const BufferItem& /*item*/) {
    ATRACE_CALL();
    std::lock_guard _lock{mMutex};

    // add to shadow queue
    mNumFrameAvailable++;
    processNextBufferLocked();
}

void BLASTBufferQueue::setNextTransaction(SurfaceComposerClient::Transaction* t) {
    std::lock_guard _lock{mMutex};
    mNextTransaction = t;
}

} // namespace android
