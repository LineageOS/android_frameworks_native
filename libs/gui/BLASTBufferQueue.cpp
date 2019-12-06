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

#include <gui/BLASTBufferQueue.h>
#include <gui/BufferItemConsumer.h>
#include <gui/GLConsumer.h>

#include <chrono>

using namespace std::chrono_literals;

namespace android {

BLASTBufferQueue::BLASTBufferQueue(const sp<SurfaceControl>& surface, int width, int height)
      : mSurfaceControl(surface),
        mPendingCallbacks(0),
        mWidth(width),
        mHeight(height),
        mNextTransaction(nullptr) {
    BufferQueue::createBufferQueue(&mProducer, &mConsumer);
    mConsumer->setMaxBufferCount(MAX_BUFFERS);
    mProducer->setMaxDequeuedBufferCount(MAX_BUFFERS - 1);
    mBufferItemConsumer =
            new BufferItemConsumer(mConsumer, AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER, 1, true);
    mBufferItemConsumer->setName(String8("BLAST Consumer"));
    mBufferItemConsumer->setFrameAvailableListener(this);
    mBufferItemConsumer->setBufferFreedListener(this);
    mBufferItemConsumer->setDefaultBufferSize(mWidth, mHeight);
    mBufferItemConsumer->setDefaultBufferFormat(PIXEL_FORMAT_RGBA_8888);
    mBufferItemConsumer->setTransformHint(mSurfaceControl->getTransformHint());

    mAcquired = false;
}

void BLASTBufferQueue::update(const sp<SurfaceControl>& surface, int width, int height) {
    std::unique_lock _lock{mMutex};
    mSurfaceControl = surface;
    mWidth = width;
    mHeight = height;
    mBufferItemConsumer->setDefaultBufferSize(mWidth, mHeight);
    mBufferItemConsumer->setTransformHint(mSurfaceControl->getTransformHint());
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

    if (stats.size() > 0 && !mShadowQueue.empty()) {
        mBufferItemConsumer->releaseBuffer(mNextCallbackBufferItem,
                                           stats[0].previousReleaseFence
                                                   ? stats[0].previousReleaseFence
                                                   : Fence::NO_FENCE);
        mAcquired = false;
        mNextCallbackBufferItem = BufferItem();
        mBufferItemConsumer->setTransformHint(stats[0].transformHint);
    }
    mPendingCallbacks--;
    processNextBufferLocked();
    mCallbackCV.notify_all();
    decStrong((void*)transactionCallbackThunk);
}

void BLASTBufferQueue::processNextBufferLocked() {
    if (mShadowQueue.empty()) {
        return;
    }

    if (mAcquired) {
        return;
    }

    BufferItem item = std::move(mShadowQueue.front());
    mShadowQueue.pop();

    SurfaceComposerClient::Transaction localTransaction;
    bool applyTransaction = true;
    SurfaceComposerClient::Transaction* t = &localTransaction;
    if (mNextTransaction != nullptr) {
        t = mNextTransaction;
        mNextTransaction = nullptr;
        applyTransaction = false;
    }

    mNextCallbackBufferItem = mLastSubmittedBufferItem;
    mLastSubmittedBufferItem = BufferItem();

    status_t status = mBufferItemConsumer->acquireBuffer(&mLastSubmittedBufferItem, -1, false);
    mAcquired = true;
    if (status != OK) {
        ALOGE("Failed to acquire?");
    }

    auto buffer = mLastSubmittedBufferItem.mGraphicBuffer;

    if (buffer == nullptr) {
        ALOGE("Null buffer");
        return;
    }

    // Ensure BLASTBufferQueue stays alive until we receive the transaction complete callback.
    incStrong((void*)transactionCallbackThunk);

    t->setBuffer(mSurfaceControl, buffer);
    t->setAcquireFence(mSurfaceControl,
                       item.mFence ? new Fence(item.mFence->dup()) : Fence::NO_FENCE);
    t->addTransactionCompletedCallback(transactionCallbackThunk, static_cast<void*>(this));

    t->setFrame(mSurfaceControl, {0, 0, (int32_t)buffer->getWidth(), (int32_t)buffer->getHeight()});
    t->setCrop(mSurfaceControl, computeCrop(mLastSubmittedBufferItem));
    t->setTransform(mSurfaceControl, mLastSubmittedBufferItem.mTransform);

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

void BLASTBufferQueue::onFrameAvailable(const BufferItem& item) {
    std::lock_guard _lock{mMutex};

    // add to shadow queue
    mShadowQueue.push(item);
    processNextBufferLocked();
    mPendingCallbacks++;
}

void BLASTBufferQueue::setNextTransaction(SurfaceComposerClient::Transaction* t) {
    std::lock_guard _lock{mMutex};
    mNextTransaction = t;
}

} // namespace android
