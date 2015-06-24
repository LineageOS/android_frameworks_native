/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "BufferQueue"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include <gui/BufferQueue.h>
#include <gui/BufferQueueCore.h>

namespace android {

BufferQueue::ProxyConsumerListener::ProxyConsumerListener(
        const wp<ConsumerListener>& consumerListener):
        mConsumerListener(consumerListener) {}

BufferQueue::ProxyConsumerListener::~ProxyConsumerListener() {}

void BufferQueue::ProxyConsumerListener::onFrameAvailable(
        const android::BufferItem& item) {
    sp<ConsumerListener> listener(mConsumerListener.promote());
    if (listener != NULL) {
        listener->onFrameAvailable(item);
    }
}

void BufferQueue::ProxyConsumerListener::onBuffersReleased() {
    sp<ConsumerListener> listener(mConsumerListener.promote());
    if (listener != NULL) {
        listener->onBuffersReleased();
    }
}

void BufferQueue::createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
        sp<IGraphicBufferConsumer>* outConsumer,
        const sp<IGraphicBufferAlloc>& allocator) {
    LOG_ALWAYS_FATAL_IF(outProducer == NULL,
            "BufferQueue: outProducer must not be NULL");
    LOG_ALWAYS_FATAL_IF(outConsumer == NULL,
            "BufferQueue: outConsumer must not be NULL");

    sp<BufferQueueCore> core(new BufferQueueCore(allocator));
    LOG_ALWAYS_FATAL_IF(core == NULL,
            "BufferQueue: failed to create BufferQueueCore");

    sp<IGraphicBufferProducer> producer(new BufferQueueProducer(core));
    LOG_ALWAYS_FATAL_IF(producer == NULL,
            "BufferQueue: failed to create BufferQueueProducer");

    sp<IGraphicBufferConsumer> consumer(new BufferQueueConsumer(core));
    LOG_ALWAYS_FATAL_IF(consumer == NULL,
            "BufferQueue: failed to create BufferQueueConsumer");

    *outProducer = producer;
    *outConsumer = consumer;
}

BufferQueue::BufferQueue(const sp<IGraphicBufferAlloc>& allocator) :
    mProducer(),
    mConsumer()
{
    sp<BufferQueueCore> core(new BufferQueueCore(allocator));
    mProducer = new BufferQueueProducer(core);
    mConsumer = new BufferQueueConsumer(core);
}

BufferQueue::~BufferQueue() {}

void BufferQueue::binderDied(const wp<IBinder>& who) {
    mProducer->binderDied(who);
}

int BufferQueue::query(int what, int* outValue) {
    return mProducer->query(what, outValue);
}

status_t BufferQueue::setBufferCount(int bufferCount) {
    return mProducer->setBufferCount(bufferCount);
}

status_t BufferQueue::requestBuffer(int slot, sp<GraphicBuffer>* buf) {
    return mProducer->requestBuffer(slot, buf);
}

status_t BufferQueue::dequeueBuffer(int *outBuf, sp<Fence>* outFence, bool async,
        uint32_t w, uint32_t h, uint32_t format, uint32_t usage) {
    return mProducer->dequeueBuffer(outBuf, outFence, async, w, h, format, usage);
}

status_t BufferQueue::detachProducerBuffer(int slot) {
    return mProducer->detachBuffer(slot);
}

status_t BufferQueue::detachNextBuffer(sp<GraphicBuffer>* outBuffer,
        sp<Fence>* outFence) {
    return mProducer->detachNextBuffer(outBuffer, outFence);
}

status_t BufferQueue::attachProducerBuffer(int* slot,
        const sp<GraphicBuffer>& buffer) {
    return mProducer->attachBuffer(slot, buffer);
}

status_t BufferQueue::queueBuffer(int buf,
        const QueueBufferInput& input, QueueBufferOutput* output) {
    return mProducer->queueBuffer(buf, input, output);
}

void BufferQueue::cancelBuffer(int buf, const sp<Fence>& fence) {
    mProducer->cancelBuffer(buf, fence);
}

status_t BufferQueue::connect(const sp<IProducerListener>& listener,
        int api, bool producerControlledByApp, QueueBufferOutput* output) {
    return mProducer->connect(listener, api, producerControlledByApp, output);
}

status_t BufferQueue::disconnect(int api) {
    return mProducer->disconnect(api);
}

status_t BufferQueue::setSidebandStream(const sp<NativeHandle>& stream) {
    return mProducer->setSidebandStream(stream);
}

status_t BufferQueue::acquireBuffer(BufferItem* buffer, nsecs_t presentWhen) {
    return mConsumer->acquireBuffer(buffer, presentWhen);
}

status_t BufferQueue::detachConsumerBuffer(int slot) {
    return mConsumer->detachBuffer(slot);
}

status_t BufferQueue::attachConsumerBuffer(int* slot,
        const sp<GraphicBuffer>& buffer) {
    return mConsumer->attachBuffer(slot, buffer);
}

status_t BufferQueue::releaseBuffer(
        int buf, uint64_t frameNumber, EGLDisplay display,
        EGLSyncKHR eglFence, const sp<Fence>& fence) {
    return mConsumer->releaseBuffer(buf, frameNumber, fence, display, eglFence);
}

status_t BufferQueue::consumerConnect(const sp<IConsumerListener>& consumerListener,
        bool controlledByApp) {
    return mConsumer->connect(consumerListener, controlledByApp);
}

status_t BufferQueue::consumerDisconnect() {
    return mConsumer->disconnect();
}

status_t BufferQueue::getReleasedBuffers(uint64_t* slotMask) {
    return mConsumer->getReleasedBuffers(slotMask);
}

status_t BufferQueue::setDefaultBufferSize(uint32_t w, uint32_t h) {
    return mConsumer->setDefaultBufferSize(w, h);
}

status_t BufferQueue::setDefaultMaxBufferCount(int bufferCount) {
    return mConsumer->setDefaultMaxBufferCount(bufferCount);
}

status_t BufferQueue::disableAsyncBuffer() {
    return mConsumer->disableAsyncBuffer();
}

status_t BufferQueue::setMaxAcquiredBufferCount(int maxAcquiredBuffers) {
    return mConsumer->setMaxAcquiredBufferCount(maxAcquiredBuffers);
}

void BufferQueue::setConsumerName(const String8& name) {
    mConsumer->setConsumerName(name);
}

status_t BufferQueue::setDefaultBufferFormat(uint32_t defaultFormat) {
    return mConsumer->setDefaultBufferFormat(defaultFormat);
}

status_t BufferQueue::setConsumerUsageBits(uint32_t usage) {
    return mConsumer->setConsumerUsageBits(usage);
}

status_t BufferQueue::setTransformHint(uint32_t hint) {
    return mConsumer->setTransformHint(hint);
}

sp<NativeHandle> BufferQueue::getSidebandStream() const {
    return mConsumer->getSidebandStream();
}

void BufferQueue::dump(String8& result, const char* prefix) const {
    mConsumer->dump(result, prefix);
}

void BufferQueue::ProxyConsumerListener::onSidebandStreamChanged() {
    sp<ConsumerListener> listener(mConsumerListener.promote());
    if (listener != NULL) {
        listener->onSidebandStreamChanged();
    }
}

}; // namespace android
