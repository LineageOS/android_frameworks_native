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

#ifndef ANDROID_GUI_BLAST_BUFFER_QUEUE_H
#define ANDROID_GUI_BLAST_BUFFER_QUEUE_H

#include <gui/IGraphicBufferProducer.h>
#include <gui/BufferItemConsumer.h>
#include <gui/BufferItem.h>
#include <gui/SurfaceComposerClient.h>

#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>

#include <system/window.h>
#include <thread>

namespace android {

class BufferItemConsumer;

class BLASTBufferQueue
    : public ConsumerBase::FrameAvailableListener, public BufferItemConsumer::BufferFreedListener
{
public:
    BLASTBufferQueue(const sp<SurfaceControl>& surface, int width, int height);
    sp<IGraphicBufferProducer> getIGraphicBufferProducer() const {
        return mProducer;
    }

    void onBufferFreed(const wp<GraphicBuffer>&/* graphicBuffer*/) override { /* TODO */ }
    void onFrameReplaced(const BufferItem& item) override {onFrameAvailable(item);}
    void onFrameAvailable(const BufferItem& item) override;

    void transactionCallback(nsecs_t latchTime, const sp<Fence>& presentFence,
            const std::vector<SurfaceControlStats>& stats);
    void setNextTransaction(SurfaceComposerClient::Transaction *t);

    void update(const sp<SurfaceControl>& surface, int width, int height);

    virtual ~BLASTBufferQueue() = default;

private:
    friend class BLASTBufferQueueHelper;

    // can't be copied
    BLASTBufferQueue& operator = (const BLASTBufferQueue& rhs);
    BLASTBufferQueue(const BLASTBufferQueue& rhs);

    void processNextBufferLocked() REQUIRES(mMutex);
    Rect computeCrop(const BufferItem& item);

    sp<SurfaceControl> mSurfaceControl;

    std::mutex mMutex;
    std::condition_variable mCallbackCV;

    static const int MAX_ACQUIRED_BUFFERS = 2;

    int32_t mNumFrameAvailable GUARDED_BY(mMutex);
    int32_t mNumAcquired GUARDED_BY(mMutex);

    struct PendingReleaseItem {
        BufferItem item;
        sp<Fence> releaseFence;
    };

    std::queue<const BufferItem> mSubmitted GUARDED_BY(mMutex);
    PendingReleaseItem mPendingReleaseItem GUARDED_BY(mMutex);

    int mWidth GUARDED_BY(mMutex);
    int mHeight GUARDED_BY(mMutex);

    uint32_t mTransformHint GUARDED_BY(mMutex);

    sp<IGraphicBufferConsumer> mConsumer;
    sp<IGraphicBufferProducer> mProducer;
    sp<BufferItemConsumer> mBufferItemConsumer;

    SurfaceComposerClient::Transaction* mNextTransaction GUARDED_BY(mMutex);
};

} // namespace android

#endif  // ANDROID_GUI_SURFACE_H
