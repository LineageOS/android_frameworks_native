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

    sp<SurfaceControl> mSurfaceControl;
    
    mutable std::mutex mMutex;

    static const int MAX_BUFFERS = 2;
    struct BufferInfo {
        sp<GraphicBuffer> buffer;
        int fence;
    };
    
    int mDequeuedBuffers = 0;

    int mWidth;
    int mHeight;

    BufferItem mLastSubmittedBufferItem;
    BufferItem mNextCallbackBufferItem;
    sp<Fence> mLastFence;

    std::condition_variable mDequeueWaitCV;

    sp<IGraphicBufferConsumer> mConsumer;
    sp<IGraphicBufferProducer> mProducer;
    sp<BufferItemConsumer> mBufferItemConsumer;

    SurfaceComposerClient::Transaction* mNextTransaction = nullptr;
};

} // namespace android

#endif  // ANDROID_GUI_SURFACE_H
