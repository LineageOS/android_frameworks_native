/*
 * Copyright 2022 The Android Open Source Project
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
#include <android-base/stringprintf.h>
#include <gui/BufferQueueConsumer.h>
#include <gui/BufferQueueCore.h>
#include <gui/BufferQueueProducer.h>
#include <gui/bufferqueue/2.0/types.h>
#include <system/window.h>

#include <libgui_fuzzer_utils.h>

using namespace android;
using namespace hardware::graphics::bufferqueue;
using namespace V1_0::utils;
using namespace V2_0::utils;

constexpr int32_t kMaxBytes = 256;

constexpr int32_t kError[] = {
        OK,        NO_MEMORY,   NO_INIT,       BAD_VALUE,      DEAD_OBJECT, INVALID_OPERATION,
        TIMED_OUT, WOULD_BLOCK, UNKNOWN_ERROR, ALREADY_EXISTS,
};

constexpr int32_t kAPIConnection[] = {
        BufferQueueCore::CURRENTLY_CONNECTED_API,
        BufferQueueCore::NO_CONNECTED_API,
        NATIVE_WINDOW_API_EGL,
        NATIVE_WINDOW_API_CPU,
        NATIVE_WINDOW_API_MEDIA,
        NATIVE_WINDOW_API_CAMERA,
};

class BufferQueueFuzzer {
public:
    BufferQueueFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

private:
    void invokeTypes();
    void invokeH2BGraphicBufferV1();
    void invokeH2BGraphicBufferV2();
    void invokeBufferQueueConsumer();
    void invokeBufferQueueProducer();
    void invokeBlastBufferQueue();
    void invokeQuery(sp<BufferQueueProducer>);
    void invokeQuery(sp<V1_0::utils::H2BGraphicBufferProducer>);
    void invokeQuery(sp<V2_0::utils::H2BGraphicBufferProducer>);
    void invokeAcquireBuffer(sp<BufferQueueConsumer>);
    void invokeOccupancyTracker(sp<BufferQueueConsumer>);
    sp<SurfaceControl> makeSurfaceControl();
    sp<BLASTBufferQueue> makeBLASTBufferQueue(sp<SurfaceControl>);

    FuzzedDataProvider mFdp;
};

class ManageResourceHandle {
public:
    ManageResourceHandle(FuzzedDataProvider* fdp) {
        mNativeHandle = native_handle_create(0 /*numFds*/, 1 /*numInts*/);
        mShouldOwn = fdp->ConsumeBool();
        mStream = NativeHandle::create(mNativeHandle, mShouldOwn);
    }
    ~ManageResourceHandle() {
        if (!mShouldOwn) {
            native_handle_close(mNativeHandle);
            native_handle_delete(mNativeHandle);
        }
    }
    sp<NativeHandle> getStream() { return mStream; }

private:
    bool mShouldOwn;
    sp<NativeHandle> mStream;
    native_handle_t* mNativeHandle;
};

sp<SurfaceControl> BufferQueueFuzzer::makeSurfaceControl() {
    sp<IBinder> handle;
    const sp<FakeBnSurfaceComposerClient> testClient(new FakeBnSurfaceComposerClient());
    sp<SurfaceComposerClient> client = new SurfaceComposerClient(testClient);
    sp<BnGraphicBufferProducer> producer;
    uint32_t layerId = mFdp.ConsumeIntegral<uint32_t>();
    std::string layerName = base::StringPrintf("#%d", layerId);
    return sp<SurfaceControl>::make(client, handle, layerId, layerName,
                                    mFdp.ConsumeIntegral<int32_t>(),
                                    mFdp.ConsumeIntegral<uint32_t>(),
                                    mFdp.ConsumeIntegral<int32_t>(),
                                    mFdp.ConsumeIntegral<uint32_t>(),
                                    mFdp.ConsumeIntegral<uint32_t>());
}

sp<BLASTBufferQueue> BufferQueueFuzzer::makeBLASTBufferQueue(sp<SurfaceControl> surface) {
    return sp<BLASTBufferQueue>::make(mFdp.ConsumeRandomLengthString(kMaxBytes), surface,
                                      mFdp.ConsumeIntegral<uint32_t>(),
                                      mFdp.ConsumeIntegral<uint32_t>(),
                                      mFdp.ConsumeIntegral<int32_t>());
}

void BufferQueueFuzzer::invokeBlastBufferQueue() {
    sp<SurfaceControl> surface = makeSurfaceControl();
    sp<BLASTBufferQueue> queue = makeBLASTBufferQueue(surface);

    BufferItem item;
    queue->onFrameAvailable(item);
    queue->onFrameReplaced(item);
    uint64_t bufferId = mFdp.ConsumeIntegral<uint64_t>();
    queue->onFrameDequeued(bufferId);
    queue->onFrameCancelled(bufferId);

    SurfaceComposerClient::Transaction next;
    uint64_t frameNumber = mFdp.ConsumeIntegral<uint64_t>();
    queue->mergeWithNextTransaction(&next, frameNumber);
    queue->applyPendingTransactions(frameNumber);

    queue->update(surface, mFdp.ConsumeIntegral<uint32_t>(), mFdp.ConsumeIntegral<uint32_t>(),
                  mFdp.ConsumeIntegral<int32_t>());
    queue->setFrameRate(mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeIntegral<int8_t>(),
                        mFdp.ConsumeBool() /*shouldBeSeamless*/);
    FrameTimelineInfo info;
    queue->setFrameTimelineInfo(mFdp.ConsumeIntegral<uint64_t>(), info);

    ManageResourceHandle handle(&mFdp);
    queue->setSidebandStream(handle.getStream());

    queue->getLastTransformHint();
    queue->getLastAcquiredFrameNum();

    CompositorTiming compTiming;
    sp<Fence> previousFence = new Fence(memfd_create("pfd", MFD_ALLOW_SEALING));
    sp<Fence> gpuFence = new Fence(memfd_create("gfd", MFD_ALLOW_SEALING));
    FrameEventHistoryStats frameStats(frameNumber, gpuFence, compTiming,
                                      mFdp.ConsumeIntegral<int64_t>(),
                                      mFdp.ConsumeIntegral<int64_t>());
    std::vector<SurfaceControlStats> stats;
    sp<Fence> presentFence = new Fence(memfd_create("fd", MFD_ALLOW_SEALING));
    SurfaceControlStats controlStats(surface, mFdp.ConsumeIntegral<int64_t>(),
                                     mFdp.ConsumeIntegral<int64_t>(), presentFence, previousFence,
                                     mFdp.ConsumeIntegral<uint32_t>(), frameStats,
                                     mFdp.ConsumeIntegral<uint32_t>());
    stats.push_back(controlStats);
}

void BufferQueueFuzzer::invokeQuery(sp<BufferQueueProducer> producer) {
    int32_t value;
    producer->query(mFdp.ConsumeIntegral<int32_t>(), &value);
}

void BufferQueueFuzzer::invokeQuery(sp<V1_0::utils::H2BGraphicBufferProducer> producer) {
    int32_t value;
    producer->query(mFdp.ConsumeIntegral<int32_t>(), &value);
}

void BufferQueueFuzzer::invokeQuery(sp<V2_0::utils::H2BGraphicBufferProducer> producer) {
    int32_t value;
    producer->query(mFdp.ConsumeIntegral<int32_t>(), &value);
}

void BufferQueueFuzzer::invokeBufferQueueProducer() {
    sp<BufferQueueCore> core(new BufferQueueCore());
    sp<BufferQueueProducer> producer(new BufferQueueProducer(core));
    const sp<android::IProducerListener> listener;
    android::IGraphicBufferProducer::QueueBufferOutput output;
    uint32_t api = mFdp.ConsumeIntegral<uint32_t>();
    producer->connect(listener, api, mFdp.ConsumeBool() /*producerControlledByApp*/, &output);

    sp<GraphicBuffer> buffer;
    int32_t slot = mFdp.ConsumeIntegral<int32_t>();
    uint32_t maxBuffers = mFdp.ConsumeIntegral<uint32_t>();
    producer->requestBuffer(slot, &buffer);
    producer->setMaxDequeuedBufferCount(maxBuffers);
    producer->setAsyncMode(mFdp.ConsumeBool() /*async*/);

    android::IGraphicBufferProducer::QueueBufferInput input;
    producer->attachBuffer(&slot, buffer);
    producer->queueBuffer(slot, input, &output);

    int32_t format = mFdp.ConsumeIntegral<int32_t>();
    uint32_t width = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t height = mFdp.ConsumeIntegral<uint32_t>();
    uint64_t usage = mFdp.ConsumeIntegral<uint64_t>();
    uint64_t outBufferAge;
    FrameEventHistoryDelta outTimestamps;
    sp<android::Fence> fence;
    producer->dequeueBuffer(&slot, &fence, width, height, format, usage, &outBufferAge,
                            &outTimestamps);
    producer->detachBuffer(slot);
    producer->detachNextBuffer(&buffer, &fence);
    producer->cancelBuffer(slot, fence);

    invokeQuery(producer);

    ManageResourceHandle handle(&mFdp);
    producer->setSidebandStream(handle.getStream());

    producer->allocateBuffers(width, height, format, usage);
    producer->allowAllocation(mFdp.ConsumeBool() /*allow*/);
    producer->setSharedBufferMode(mFdp.ConsumeBool() /*sharedBufferMode*/);
    producer->setAutoRefresh(mFdp.ConsumeBool() /*autoRefresh*/);
    producer->setLegacyBufferDrop(mFdp.ConsumeBool() /*drop*/);
    producer->setAutoPrerotation(mFdp.ConsumeBool() /*autoPrerotation*/);

    producer->setGenerationNumber(mFdp.ConsumeIntegral<uint32_t>());
    producer->setDequeueTimeout(mFdp.ConsumeIntegral<uint32_t>());
    producer->disconnect(api);
}

void BufferQueueFuzzer::invokeAcquireBuffer(sp<BufferQueueConsumer> consumer) {
    BufferItem item;
    consumer->acquireBuffer(&item, mFdp.ConsumeIntegral<uint32_t>(),
                            mFdp.ConsumeIntegral<uint64_t>());
}

void BufferQueueFuzzer::invokeOccupancyTracker(sp<BufferQueueConsumer> consumer) {
    String8 outResult;
    String8 prefix((mFdp.ConsumeRandomLengthString(kMaxBytes)).c_str());
    consumer->dumpState(prefix, &outResult);

    std::vector<OccupancyTracker::Segment> outHistory;
    consumer->getOccupancyHistory(mFdp.ConsumeBool() /*forceFlush*/, &outHistory);
}

void BufferQueueFuzzer::invokeBufferQueueConsumer() {
    sp<BufferQueueCore> core(new BufferQueueCore());
    sp<BufferQueueConsumer> consumer(new BufferQueueConsumer(core));
    sp<android::IConsumerListener> listener;
    consumer->consumerConnect(listener, mFdp.ConsumeBool() /*controlledByApp*/);
    invokeAcquireBuffer(consumer);

    int32_t slot = mFdp.ConsumeIntegral<int32_t>();
    sp<GraphicBuffer> buffer =
            new GraphicBuffer(mFdp.ConsumeIntegral<uint32_t>(), mFdp.ConsumeIntegral<uint32_t>(),
                              mFdp.ConsumeIntegral<int32_t>(), mFdp.ConsumeIntegral<uint32_t>(),
                              mFdp.ConsumeIntegral<uint64_t>());
    consumer->attachBuffer(&slot, buffer);
    consumer->detachBuffer(slot);

    consumer->setDefaultBufferSize(mFdp.ConsumeIntegral<uint32_t>(),
                                   mFdp.ConsumeIntegral<uint32_t>());
    consumer->setMaxBufferCount(mFdp.ConsumeIntegral<int32_t>());
    consumer->setMaxAcquiredBufferCount(mFdp.ConsumeIntegral<int32_t>());

    String8 name((mFdp.ConsumeRandomLengthString(kMaxBytes)).c_str());
    consumer->setConsumerName(name);
    consumer->setDefaultBufferFormat(mFdp.ConsumeIntegral<int32_t>());
    android_dataspace dataspace =
            static_cast<android_dataspace>(mFdp.PickValueInArray(kDataspaces));
    consumer->setDefaultBufferDataSpace(dataspace);

    consumer->setTransformHint(mFdp.ConsumeIntegral<uint32_t>());
    consumer->setConsumerUsageBits(mFdp.ConsumeIntegral<uint64_t>());
    consumer->setConsumerIsProtected(mFdp.ConsumeBool() /*isProtected*/);
    invokeOccupancyTracker(consumer);

    sp<Fence> releaseFence = new Fence(memfd_create("fd", MFD_ALLOW_SEALING));
    consumer->releaseBuffer(mFdp.ConsumeIntegral<int32_t>(), mFdp.ConsumeIntegral<uint64_t>(),
                            EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, releaseFence);
    consumer->consumerDisconnect();
}

void BufferQueueFuzzer::invokeTypes() {
    HStatus hStatus;
    int32_t status = mFdp.PickValueInArray(kError);
    bool bufferNeedsReallocation = mFdp.ConsumeBool();
    bool releaseAllBuffers = mFdp.ConsumeBool();
    b2h(status, &hStatus, &bufferNeedsReallocation, &releaseAllBuffers);
    h2b(hStatus, &status);

    HConnectionType type;
    int32_t apiConnection = mFdp.PickValueInArray(kAPIConnection);
    b2h(apiConnection, &type);
    h2b(type, &apiConnection);
}

void BufferQueueFuzzer::invokeH2BGraphicBufferV1() {
    sp<V1_0::utils::H2BGraphicBufferProducer> producer(
            new V1_0::utils::H2BGraphicBufferProducer(new FakeGraphicBufferProducerV1()));
    const sp<android::IProducerListener> listener;
    android::IGraphicBufferProducer::QueueBufferOutput output;
    uint32_t api = mFdp.ConsumeIntegral<uint32_t>();
    producer->connect(listener, api, mFdp.ConsumeBool() /*producerControlledByApp*/, &output);

    sp<GraphicBuffer> buffer;
    int32_t slot = mFdp.ConsumeIntegral<int32_t>();
    producer->requestBuffer(slot, &buffer);
    producer->setMaxDequeuedBufferCount(mFdp.ConsumeIntegral<int32_t>());
    producer->setAsyncMode(mFdp.ConsumeBool());

    android::IGraphicBufferProducer::QueueBufferInput input;
    input.fence = new Fence(memfd_create("ffd", MFD_ALLOW_SEALING));
    producer->attachBuffer(&slot, buffer);
    producer->queueBuffer(slot, input, &output);

    int32_t format = mFdp.ConsumeIntegral<int32_t>();
    uint32_t width = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t height = mFdp.ConsumeIntegral<uint32_t>();
    uint64_t usage = mFdp.ConsumeIntegral<uint64_t>();
    uint64_t outBufferAge;
    FrameEventHistoryDelta outTimestamps;
    sp<android::Fence> fence;
    producer->dequeueBuffer(&slot, &fence, width, height, format, usage, &outBufferAge,
                            &outTimestamps);
    producer->detachBuffer(slot);
    producer->cancelBuffer(slot, fence);

    invokeQuery(producer);

    ManageResourceHandle handle(&mFdp);
    producer->setSidebandStream(handle.getStream());

    producer->allocateBuffers(width, height, format, usage);
    producer->allowAllocation(mFdp.ConsumeBool() /*allow*/);
    producer->setSharedBufferMode(mFdp.ConsumeBool() /*sharedBufferMode*/);
    producer->setAutoRefresh(mFdp.ConsumeBool() /*autoRefresh*/);

    producer->setGenerationNumber(mFdp.ConsumeIntegral<uint32_t>());
    producer->setDequeueTimeout(mFdp.ConsumeIntegral<uint32_t>());
    producer->disconnect(api);
}

void BufferQueueFuzzer::invokeH2BGraphicBufferV2() {
    sp<V2_0::utils::H2BGraphicBufferProducer> producer(
            new V2_0::utils::H2BGraphicBufferProducer(new FakeGraphicBufferProducerV2()));
    const sp<android::IProducerListener> listener;
    android::IGraphicBufferProducer::QueueBufferOutput output;
    uint32_t api = mFdp.ConsumeIntegral<uint32_t>();
    producer->connect(listener, api, mFdp.ConsumeBool() /*producerControlledByApp*/, &output);

    sp<GraphicBuffer> buffer;
    int32_t slot = mFdp.ConsumeIntegral<int32_t>();
    producer->requestBuffer(slot, &buffer);
    producer->setMaxDequeuedBufferCount(mFdp.ConsumeIntegral<uint32_t>());
    producer->setAsyncMode(mFdp.ConsumeBool());

    android::IGraphicBufferProducer::QueueBufferInput input;
    input.fence = new Fence(memfd_create("ffd", MFD_ALLOW_SEALING));
    producer->attachBuffer(&slot, buffer);
    producer->queueBuffer(slot, input, &output);

    int32_t format = mFdp.ConsumeIntegral<int32_t>();
    uint32_t width = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t height = mFdp.ConsumeIntegral<uint32_t>();
    uint64_t usage = mFdp.ConsumeIntegral<uint64_t>();
    uint64_t outBufferAge;
    FrameEventHistoryDelta outTimestamps;
    sp<android::Fence> fence;
    producer->dequeueBuffer(&slot, &fence, width, height, format, usage, &outBufferAge,
                            &outTimestamps);
    producer->detachBuffer(slot);
    producer->cancelBuffer(slot, fence);

    invokeQuery(producer);

    ManageResourceHandle handle(&mFdp);
    producer->setSidebandStream(handle.getStream());

    producer->allocateBuffers(width, height, format, usage);
    producer->allowAllocation(mFdp.ConsumeBool() /*allow*/);
    producer->setSharedBufferMode(mFdp.ConsumeBool() /*sharedBufferMode*/);
    producer->setAutoRefresh(mFdp.ConsumeBool() /*autoRefresh*/);

    producer->setGenerationNumber(mFdp.ConsumeIntegral<uint32_t>());
    producer->setDequeueTimeout(mFdp.ConsumeIntegral<uint32_t>());
    producer->disconnect(api);
}

void BufferQueueFuzzer::process() {
    invokeBlastBufferQueue();
    invokeH2BGraphicBufferV1();
    invokeH2BGraphicBufferV2();
    invokeTypes();
    invokeBufferQueueConsumer();
    invokeBufferQueueProducer();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    BufferQueueFuzzer bufferQueueFuzzer(data, size);
    bufferQueueFuzzer.process();
    return 0;
}
