/*
 * Copyright 2013 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

// #define LOG_NDEBUG 0

#include <cinttypes>

#include <ftl/enum.h>
#include <ftl/flags.h>
#include <gui/BufferItem.h>
#include <gui/BufferQueue.h>
#include <gui/IProducerListener.h>
#include <system/window.h>

#include "HWComposer.h"
#include "SurfaceFlinger.h"
#include "VirtualDisplaySurface.h"

#define VDS_LOGE(msg, ...) ALOGE("[%s] " msg, \
        mDisplayName.c_str(), ##__VA_ARGS__)
#define VDS_LOGW_IF(cond, msg, ...) ALOGW_IF(cond, "[%s] " msg, \
        mDisplayName.c_str(), ##__VA_ARGS__)
#define VDS_LOGV(msg, ...) ALOGV("[%s] " msg, \
        mDisplayName.c_str(), ##__VA_ARGS__)

#define UNSUPPORTED()                                               \
    VDS_LOGE("%s: Invalid operation on virtual display", __func__); \
    return INVALID_OPERATION

namespace android {

VirtualDisplaySurface::VirtualDisplaySurface(HWComposer& hwc, VirtualDisplayId displayId,
                                             const sp<IGraphicBufferProducer>& sink,
                                             const sp<IGraphicBufferProducer>& bqProducer,
                                             const sp<IGraphicBufferConsumer>& bqConsumer,
                                             const std::string& name, bool secure)
      : ConsumerBase(bqConsumer),
        mHwc(hwc),
        mDisplayId(displayId),
        mDisplayName(name),
        mSource{},
        mDefaultOutputFormat(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED),
        mOutputFormat(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED),
        mOutputUsage(GRALLOC_USAGE_HW_COMPOSER),
        mProducerSlotSource(0),
        mProducerBuffers(),
        mProducerSlotNeedReallocation(0),
        mQueueBufferOutput(),
        mSinkBufferWidth(0),
        mSinkBufferHeight(0),
        mFbFence(Fence::NO_FENCE),
        mOutputFence(Fence::NO_FENCE),
        mFbProducerSlot(BufferQueue::INVALID_BUFFER_SLOT),
        mOutputProducerSlot(BufferQueue::INVALID_BUFFER_SLOT),
        mForceHwcCopy(SurfaceFlinger::useHwcForRgbToYuv),
        mSecure(secure),
        mSinkUsage(0) {
    mSource[SOURCE_SINK] = sink;
    mSource[SOURCE_SCRATCH] = bqProducer;

    resetPerFrameState();

    int sinkWidth, sinkHeight;
    sink->query(NATIVE_WINDOW_WIDTH, &sinkWidth);
    sink->query(NATIVE_WINDOW_HEIGHT, &sinkHeight);
    mSinkBufferWidth = sinkWidth;
    mSinkBufferHeight = sinkHeight;

    // Pick the buffer format to request from the sink when not rendering to it
    // with GPU. If the consumer needs CPU access, use the default format
    // set by the consumer. Otherwise allow gralloc to decide the format based
    // on usage bits.
    int sinkUsage;
    sink->query(NATIVE_WINDOW_CONSUMER_USAGE_BITS, &sinkUsage);
    mSinkUsage |= (GRALLOC_USAGE_HW_COMPOSER | sinkUsage);
    setOutputUsage(mSinkUsage);
    if (sinkUsage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK)) {
        int sinkFormat;
        sink->query(NATIVE_WINDOW_FORMAT, &sinkFormat);
        mDefaultOutputFormat = sinkFormat;
    } else {
        mDefaultOutputFormat = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    }
    mOutputFormat = mDefaultOutputFormat;

    ConsumerBase::mName = String8::format("VDS: %s", mDisplayName.c_str());
    mConsumer->setConsumerName(ConsumerBase::mName);
    mConsumer->setConsumerUsageBits(GRALLOC_USAGE_HW_COMPOSER);
    mConsumer->setDefaultBufferSize(sinkWidth, sinkHeight);
    sink->setAsyncMode(true);
    IGraphicBufferProducer::QueueBufferOutput output;
    mSource[SOURCE_SCRATCH]->connect(nullptr, NATIVE_WINDOW_API_EGL, false, &output);
}

VirtualDisplaySurface::~VirtualDisplaySurface() {
    mSource[SOURCE_SCRATCH]->disconnect(NATIVE_WINDOW_API_EGL);
}

status_t VirtualDisplaySurface::beginFrame(bool mustRecompose) {
    if (GpuVirtualDisplayId::tryCast(mDisplayId)) {
        return NO_ERROR;
    }

    mMustRecompose = mustRecompose;
    //For WFD use cases we must always set the recompose flag in order
    //to support pause/resume functionality
    if (mOutputUsage & GRALLOC_USAGE_HW_VIDEO_ENCODER) {
        mMustRecompose = true;
    }
    VDS_LOGW_IF(mDebugState != DebugState::Idle, "Unexpected %s in %s state", __func__,
                ftl::enum_string(mDebugState).c_str());
    mDebugState = DebugState::Begun;

    return refreshOutputBuffer();
}

status_t VirtualDisplaySurface::prepareFrame(CompositionType compositionType) {
    if (GpuVirtualDisplayId::tryCast(mDisplayId)) {
        return NO_ERROR;
    }

    VDS_LOGW_IF(mDebugState != DebugState::Begun, "Unexpected %s in %s state", __func__,
                ftl::enum_string(mDebugState).c_str());
    mDebugState = DebugState::Prepared;

    mCompositionType = compositionType;
    if (mForceHwcCopy && mCompositionType == CompositionType::Gpu) {
        // Some hardware can do RGB->YUV conversion more efficiently in hardware
        // controlled by HWC than in hardware controlled by the video encoder.
        // Forcing GPU-composed frames to go through an extra copy by the HWC
        // allows the format conversion to happen there, rather than passing RGB
        // directly to the consumer.
        //
        // On the other hand, when the consumer prefers RGB or can consume RGB
        // inexpensively, this forces an unnecessary copy.
        mCompositionType = CompositionType::Mixed;
    }

    if (mCompositionType != mDebugLastCompositionType) {
        VDS_LOGV("%s: composition type changed to %s", __func__,
                 toString(mCompositionType).c_str());
        mDebugLastCompositionType = mCompositionType;
    }

    if (mCompositionType != CompositionType::Gpu &&
        (mOutputFormat != mDefaultOutputFormat || !(mOutputUsage & GRALLOC_USAGE_HW_COMPOSER))) {
        // We must have just switched from GPU-only to MIXED or HWC
        // composition. Stop using the format and usage requested by the GPU
        // driver; they may be suboptimal when HWC is writing to the output
        // buffer. For example, if the output is going to a video encoder, and
        // HWC can write directly to YUV, some hardware can skip a
        // memory-to-memory RGB-to-YUV conversion step.
        //
        // If we just switched *to* GPU-only mode, we'll change the
        // format/usage and get a new buffer when the GPU driver calls
        // dequeueBuffer().
        mOutputFormat = mDefaultOutputFormat;
        setOutputUsage(GRALLOC_USAGE_HW_COMPOSER);
        refreshOutputBuffer();
    }

    return NO_ERROR;
}

status_t VirtualDisplaySurface::advanceFrame() {
    if (GpuVirtualDisplayId::tryCast(mDisplayId)) {
        return NO_ERROR;
    }

    if (mCompositionType == CompositionType::Hwc) {
        VDS_LOGW_IF(mDebugState != DebugState::Prepared, "Unexpected %s in %s state on HWC frame",
                    __func__, ftl::enum_string(mDebugState).c_str());
    } else {
        VDS_LOGW_IF(mDebugState != DebugState::GpuDone,
                    "Unexpected %s in %s state on GPU/MIXED frame", __func__,
                    ftl::enum_string(mDebugState).c_str());
    }
    mDebugState = DebugState::Hwc;

    if (mOutputProducerSlot < 0 ||
        (mCompositionType != CompositionType::Hwc && mFbProducerSlot < 0)) {
        // Last chance bailout if something bad happened earlier. For example,
        // in a graphics API configuration, if the sink disappears then dequeueBuffer
        // will fail, the GPU driver won't queue a buffer, but SurfaceFlinger
        // will soldier on. So we end up here without a buffer. There should
        // be lots of scary messages in the log just before this.
        VDS_LOGE("%s: no buffer, bailing out", __func__);
        return NO_MEMORY;
    }

    sp<GraphicBuffer> fbBuffer = mFbProducerSlot >= 0 ?
            mProducerBuffers[mFbProducerSlot] : sp<GraphicBuffer>(nullptr);
    sp<GraphicBuffer> outBuffer = mProducerBuffers[mOutputProducerSlot];
    VDS_LOGV("%s: fb=%d(%p) out=%d(%p)", __func__, mFbProducerSlot, fbBuffer.get(),
             mOutputProducerSlot, outBuffer.get());

    const auto halDisplayId = HalVirtualDisplayId::tryCast(mDisplayId);
    LOG_FATAL_IF(!halDisplayId);
    // At this point we know the output buffer acquire fence,
    // so update HWC state with it.
    mHwc.setOutputBuffer(*halDisplayId, mOutputFence, outBuffer);

    status_t result = NO_ERROR;
    if (fbBuffer != nullptr) {
        uint32_t hwcSlot = 0;
        sp<GraphicBuffer> hwcBuffer;
        mHwcBufferCache.getHwcBuffer(mFbProducerSlot, fbBuffer, &hwcSlot, &hwcBuffer);

        // TODO: Correctly propagate the dataspace from GL composition
        result = mHwc.setClientTarget(*halDisplayId, hwcSlot, mFbFence, hwcBuffer,
                                      ui::Dataspace::UNKNOWN);
    }

    return result;
}

void VirtualDisplaySurface::onFrameCommitted() {
    const auto halDisplayId = HalVirtualDisplayId::tryCast(mDisplayId);
    if (!halDisplayId) {
        return;
    }

    VDS_LOGW_IF(mDebugState != DebugState::Hwc, "Unexpected %s in %s state", __func__,
                ftl::enum_string(mDebugState).c_str());
    mDebugState = DebugState::Idle;

    sp<Fence> retireFence = mHwc.getPresentFence(*halDisplayId);
    if (mCompositionType == CompositionType::Mixed && mFbProducerSlot >= 0) {
        // release the scratch buffer back to the pool
        Mutex::Autolock lock(mMutex);
        int sslot = mapProducer2SourceSlot(SOURCE_SCRATCH, mFbProducerSlot);
        VDS_LOGV("%s: release scratch sslot=%d", __func__, sslot);
        addReleaseFenceLocked(sslot, mProducerBuffers[mFbProducerSlot],
                retireFence);
        releaseBufferLocked(sslot, mProducerBuffers[mFbProducerSlot]);
    }

    if (mOutputProducerSlot >= 0) {
        int sslot = mapProducer2SourceSlot(SOURCE_SINK, mOutputProducerSlot);
        QueueBufferOutput qbo;
        VDS_LOGV("%s: queue sink sslot=%d", __func__, sslot);
        if (retireFence->isValid() && mMustRecompose) {
            status_t result = mSource[SOURCE_SINK]->queueBuffer(sslot,
                    QueueBufferInput(
                        systemTime(), false /* isAutoTimestamp */,
                        HAL_DATASPACE_UNKNOWN,
                        Rect(mSinkBufferWidth, mSinkBufferHeight),
                        NATIVE_WINDOW_SCALING_MODE_FREEZE, 0 /* transform */,
                        retireFence),
                    &qbo);
            if (result == NO_ERROR) {
                updateQueueBufferOutput(std::move(qbo));
            }
        } else {
            // If the surface hadn't actually been updated, then we only went
            // through the motions of updating the display to keep our state
            // machine happy. We cancel the buffer to avoid triggering another
            // re-composition and causing an infinite loop.
            mSource[SOURCE_SINK]->cancelBuffer(sslot, retireFence);
        }
    }

    resetPerFrameState();
}

void VirtualDisplaySurface::dumpAsString(String8& /* result */) const {
}

void VirtualDisplaySurface::resizeBuffers(const ui::Size& newSize) {
    mQueueBufferOutput.width = newSize.width;
    mQueueBufferOutput.height = newSize.height;
    mSinkBufferWidth = newSize.width;
    mSinkBufferHeight = newSize.height;
}

const sp<Fence>& VirtualDisplaySurface::getClientTargetAcquireFence() const {
    return mFbFence;
}

status_t VirtualDisplaySurface::requestBuffer(int pslot,
        sp<GraphicBuffer>* outBuf) {
    if (GpuVirtualDisplayId::tryCast(mDisplayId)) {
        return mSource[SOURCE_SINK]->requestBuffer(pslot, outBuf);
    }

    VDS_LOGW_IF(mDebugState != DebugState::Gpu, "Unexpected %s pslot=%d in %s state", __func__,
                pslot, ftl::enum_string(mDebugState).c_str());

    *outBuf = mProducerBuffers[pslot];
    return NO_ERROR;
}

status_t VirtualDisplaySurface::setMaxDequeuedBufferCount(
        int maxDequeuedBuffers) {
    return mSource[SOURCE_SINK]->setMaxDequeuedBufferCount(maxDequeuedBuffers);
}

status_t VirtualDisplaySurface::setAsyncMode(bool async) {
    return mSource[SOURCE_SINK]->setAsyncMode(async);
}

status_t VirtualDisplaySurface::dequeueBuffer(Source source,
        PixelFormat format, uint64_t usage, int* sslot, sp<Fence>* fence) {
    LOG_ALWAYS_FATAL_IF(GpuVirtualDisplayId::tryCast(mDisplayId).has_value());

    // Exclude video encoder usage flag from scratch buffer usage flags.
    if (source == SOURCE_SCRATCH) {
        usage |= GRALLOC_USAGE_HW_FB;
        usage &= ~(GRALLOC_USAGE_HW_VIDEO_ENCODER);
        VDS_LOGV("dequeueBuffer(%s): updated scratch buffer usage flags=%#" PRIx64,
                dbgSourceStr(source), usage);
    }

    status_t result =
            mSource[source]->dequeueBuffer(sslot, fence, mSinkBufferWidth, mSinkBufferHeight,
                                           format, usage, nullptr, nullptr);
    if (result < 0)
        return result;
    int pslot = mapSource2ProducerSlot(source, *sslot);
    VDS_LOGV("%s(%s): sslot=%d pslot=%d result=%d", __func__, ftl::enum_string(source).c_str(),
             *sslot, pslot, result);
    uint64_t sourceBit = static_cast<uint64_t>(source) << pslot;

    // reset producer slot reallocation flag
    mProducerSlotNeedReallocation &= ~(1ULL << pslot);

    if ((mProducerSlotSource & (1ULL << pslot)) != sourceBit) {
        // This slot was previously dequeued from the other source; must
        // re-request the buffer.
        mProducerSlotNeedReallocation |= 1ULL << pslot;

        mProducerSlotSource &= ~(1ULL << pslot);
        mProducerSlotSource |= sourceBit;
    }

    if (result & RELEASE_ALL_BUFFERS) {
        for (uint32_t i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
            if ((mProducerSlotSource & (1ULL << i)) == sourceBit)
                mProducerBuffers[i].clear();
        }
    }
    if (result & BUFFER_NEEDS_REALLOCATION) {
        auto status  = mSource[source]->requestBuffer(*sslot, &mProducerBuffers[pslot]);
        if (status < 0) {
            mProducerBuffers[pslot].clear();
            mSource[source]->cancelBuffer(*sslot, *fence);
            return status;
        }
        VDS_LOGV("%s(%s): buffers[%d]=%p fmt=%d usage=%#" PRIx64, __func__,
                 ftl::enum_string(source).c_str(), pslot, mProducerBuffers[pslot].get(),
                 mProducerBuffers[pslot]->getPixelFormat(), mProducerBuffers[pslot]->getUsage());

        // propagate reallocation to VDS consumer
        mProducerSlotNeedReallocation |= 1ULL << pslot;
    }

    return result;
}

status_t VirtualDisplaySurface::dequeueBuffer(int* pslot, sp<Fence>* fence, uint32_t w, uint32_t h,
                                              PixelFormat format, uint64_t usage,
                                              uint64_t* outBufferAge,
                                              FrameEventHistoryDelta* outTimestamps) {
    if (GpuVirtualDisplayId::tryCast(mDisplayId)) {
        return mSource[SOURCE_SINK]->dequeueBuffer(pslot, fence, w, h, format, usage, outBufferAge,
                                                   outTimestamps);
    }

    VDS_LOGW_IF(mDebugState != DebugState::Prepared, "Unexpected %s in %s state", __func__,
                ftl::enum_string(mDebugState).c_str());
    mDebugState = DebugState::Gpu;

    VDS_LOGV("%s %dx%d fmt=%d usage=%#" PRIx64, __func__, w, h, format, usage);

    status_t result = NO_ERROR;
    Source source = fbSourceForCompositionType(mCompositionType);

    if (source == SOURCE_SINK) {

        if (mOutputProducerSlot < 0) {
            // Last chance bailout if something bad happened earlier. For example,
            // in a graphics API configuration, if the sink disappears then dequeueBuffer
            // will fail, the GPU driver won't queue a buffer, but SurfaceFlinger
            // will soldier on. So we end up here without a buffer. There should
            // be lots of scary messages in the log just before this.
            VDS_LOGE("%s: no buffer, bailing out", __func__);
            return NO_MEMORY;
        }

        // We already dequeued the output buffer. If the GPU driver wants
        // something incompatible, we have to cancel and get a new one. This
        // will mean that HWC will see a different output buffer between
        // prepare and set, but since we're in GPU-only mode already it
        // shouldn't matter.

        usage |= GRALLOC_USAGE_HW_COMPOSER;
        const sp<GraphicBuffer>& buf = mProducerBuffers[mOutputProducerSlot];
        if ((usage & ~buf->getUsage()) != 0 ||
                (format != 0 && format != buf->getPixelFormat()) ||
                (w != 0 && w != mSinkBufferWidth) ||
                (h != 0 && h != mSinkBufferHeight)) {
            VDS_LOGV("%s: dequeueing new output buffer: "
                     "want %dx%d fmt=%d use=%#" PRIx64 ", "
                     "have %dx%d fmt=%d use=%#" PRIx64,
                     __func__, w, h, format, usage, mSinkBufferWidth, mSinkBufferHeight,
                     buf->getPixelFormat(), buf->getUsage());
            mOutputFormat = format;
            setOutputUsage(usage);
            result = refreshOutputBuffer();
            if (result < 0)
                return result;
        }
    }

    if (source == SOURCE_SINK) {
        *pslot = mOutputProducerSlot;
        *fence = mOutputFence;
    } else {
        int sslot;
        result = dequeueBuffer(source, format, usage, &sslot, fence);
        if (result >= 0) {
            *pslot = mapSource2ProducerSlot(source, sslot);
        }
    }
    if (outBufferAge) {
        *outBufferAge = 0;
    }

    if ((mProducerSlotNeedReallocation & (1ULL << *pslot)) != 0) {
        result |= BUFFER_NEEDS_REALLOCATION;
    }

    return result;
}

status_t VirtualDisplaySurface::detachBuffer(int) {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::detachNextBuffer(sp<GraphicBuffer>*, sp<Fence>*) {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::attachBuffer(int*, const sp<GraphicBuffer>&) {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::queueBuffer(int pslot,
        const QueueBufferInput& input, QueueBufferOutput* output) {
    if (GpuVirtualDisplayId::tryCast(mDisplayId)) {
        return mSource[SOURCE_SINK]->queueBuffer(pslot, input, output);
    }

    VDS_LOGW_IF(mDebugState != DebugState::Gpu, "Unexpected %s(pslot=%d) in %s state", __func__,
                pslot, ftl::enum_string(mDebugState).c_str());
    mDebugState = DebugState::GpuDone;

    VDS_LOGV("%s pslot=%d", __func__, pslot);

    status_t result;
    if (mCompositionType == CompositionType::Mixed) {
        // Queue the buffer back into the scratch pool
        QueueBufferOutput scratchQBO;
        int sslot = mapProducer2SourceSlot(SOURCE_SCRATCH, pslot);
        result = mSource[SOURCE_SCRATCH]->queueBuffer(sslot, input, &scratchQBO);
        if (result != NO_ERROR)
            return result;

        // Now acquire the buffer from the scratch pool -- should be the same
        // slot and fence as we just queued.
        Mutex::Autolock lock(mMutex);
        BufferItem item;
        result = acquireBufferLocked(&item, 0);
        if (result != NO_ERROR)
            return result;
        VDS_LOGW_IF(item.mSlot != sslot,
                    "%s: acquired sslot %d from SCRATCH after queueing sslot %d", __func__,
                    item.mSlot, sslot);
        mFbProducerSlot = mapSource2ProducerSlot(SOURCE_SCRATCH, item.mSlot);
        mFbFence = mSlots[item.mSlot].mFence;

    } else {
        LOG_FATAL_IF(mCompositionType != CompositionType::Gpu,
                     "Unexpected %s in state %s for composition type %s", __func__,
                     ftl::enum_string(mDebugState).c_str(), toString(mCompositionType).c_str());

        // Extract the GPU release fence for HWC to acquire
        int64_t timestamp;
        bool isAutoTimestamp;
        android_dataspace dataSpace;
        Rect crop;
        int scalingMode;
        uint32_t transform;
        input.deflate(&timestamp, &isAutoTimestamp, &dataSpace, &crop,
                &scalingMode, &transform, &mFbFence);

        mFbProducerSlot = pslot;
        mOutputFence = mFbFence;
    }

    // This moves the frame timestamps and keeps a copy of all other fields.
    *output = std::move(mQueueBufferOutput);
    return NO_ERROR;
}

status_t VirtualDisplaySurface::cancelBuffer(int pslot,
        const sp<Fence>& fence) {
    if (GpuVirtualDisplayId::tryCast(mDisplayId)) {
        return mSource[SOURCE_SINK]->cancelBuffer(mapProducer2SourceSlot(SOURCE_SINK, pslot), fence);
    }

    VDS_LOGW_IF(mDebugState != DebugState::Gpu, "Unexpected %s(pslot=%d) in %s state", __func__,
                pslot, ftl::enum_string(mDebugState).c_str());
    VDS_LOGV("%s pslot=%d", __func__, pslot);
    Source source = fbSourceForCompositionType(mCompositionType);
    return mSource[source]->cancelBuffer(
            mapProducer2SourceSlot(source, pslot), fence);
}

int VirtualDisplaySurface::query(int what, int* value) {
    switch (what) {
        case NATIVE_WINDOW_WIDTH:
            *value = mSinkBufferWidth;
            break;
        case NATIVE_WINDOW_HEIGHT:
            *value = mSinkBufferHeight;
            break;
        default:
            return mSource[SOURCE_SINK]->query(what, value);
    }
    return NO_ERROR;
}

status_t VirtualDisplaySurface::connect(const sp<IProducerListener>& listener,
        int api, bool producerControlledByApp,
        QueueBufferOutput* output) {
    QueueBufferOutput qbo;
    status_t result = mSource[SOURCE_SINK]->connect(listener, api,
            producerControlledByApp, &qbo);
    if (result == NO_ERROR) {
        updateQueueBufferOutput(std::move(qbo));
        // This moves the frame timestamps and keeps a copy of all other fields.
        *output = std::move(mQueueBufferOutput);
    }
    return result;
}

status_t VirtualDisplaySurface::disconnect(int api, DisconnectMode mode) {
    return mSource[SOURCE_SINK]->disconnect(api, mode);
}

status_t VirtualDisplaySurface::setSidebandStream(const sp<NativeHandle>&) {
    UNSUPPORTED();
}

void VirtualDisplaySurface::allocateBuffers(uint32_t /* width */,
        uint32_t /* height */, PixelFormat /* format */, uint64_t /* usage */) {
    // TODO: Should we actually allocate buffers for a virtual display?
}

status_t VirtualDisplaySurface::allowAllocation(bool /* allow */) {
    return INVALID_OPERATION;
}

status_t VirtualDisplaySurface::setGenerationNumber(uint32_t) {
    UNSUPPORTED();
}

String8 VirtualDisplaySurface::getConsumerName() const {
    return String8("VirtualDisplaySurface");
}

status_t VirtualDisplaySurface::setSharedBufferMode(bool) {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::setAutoRefresh(bool) {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::setDequeueTimeout(nsecs_t) {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::getLastQueuedBuffer(sp<GraphicBuffer>*, sp<Fence>*, float[16]) {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::getUniqueId(uint64_t*) const {
    UNSUPPORTED();
}

status_t VirtualDisplaySurface::getConsumerUsage(uint64_t* outUsage) const {
    return mSource[SOURCE_SINK]->getConsumerUsage(outUsage);
}

void VirtualDisplaySurface::updateQueueBufferOutput(
        QueueBufferOutput&& qbo) {
    mQueueBufferOutput = std::move(qbo);
    mQueueBufferOutput.transformHint = 0;
}

void VirtualDisplaySurface::resetPerFrameState() {
    mCompositionType = CompositionType::Unknown;
    mFbFence = Fence::NO_FENCE;
    mOutputFence = Fence::NO_FENCE;
    mOutputProducerSlot = -1;
    mFbProducerSlot = -1;
}

status_t VirtualDisplaySurface::refreshOutputBuffer() {
    LOG_ALWAYS_FATAL_IF(GpuVirtualDisplayId::tryCast(mDisplayId).has_value());

    if (mOutputProducerSlot >= 0) {
        mSource[SOURCE_SINK]->cancelBuffer(
                mapProducer2SourceSlot(SOURCE_SINK, mOutputProducerSlot),
                mOutputFence);
    }

    int sslot;
    status_t result = dequeueBuffer(SOURCE_SINK, mOutputFormat, mOutputUsage,
            &sslot, &mOutputFence);
    if (result < 0)
        return result;
    mOutputProducerSlot = mapSource2ProducerSlot(SOURCE_SINK, sslot);

    // On GPU-only frames, we don't have the right output buffer acquire fence
    // until after GPU calls queueBuffer(). So here we just set the buffer
    // (for use in HWC prepare) but not the fence; we'll call this again with
    // the proper fence once we have it.
    const auto halDisplayId = HalVirtualDisplayId::tryCast(mDisplayId);
    LOG_FATAL_IF(!halDisplayId);
    result = mHwc.setOutputBuffer(*halDisplayId, Fence::NO_FENCE,
                                  mProducerBuffers[mOutputProducerSlot]);

    return result;
}

// This slot mapping function is its own inverse, so two copies are unnecessary.
// Both are kept to make the intent clear where the function is called, and for
// the (unlikely) chance that we switch to a different mapping function.
int VirtualDisplaySurface::mapSource2ProducerSlot(Source source, int sslot) {
    if (source == SOURCE_SCRATCH) {
        return BufferQueue::NUM_BUFFER_SLOTS - sslot - 1;
    } else {
        return sslot;
    }
}
int VirtualDisplaySurface::mapProducer2SourceSlot(Source source, int pslot) {
    return mapSource2ProducerSlot(source, pslot);
}

auto VirtualDisplaySurface::fbSourceForCompositionType(CompositionType type) -> Source {
    return type == CompositionType::Mixed ? SOURCE_SCRATCH : SOURCE_SINK;
}

std::string VirtualDisplaySurface::toString(CompositionType type) {
    using namespace std::literals;
    return type == CompositionType::Unknown ? "Unknown"s : ftl::Flags(type).string();
}

/* Helper to update the output usage when the display is secure */

void VirtualDisplaySurface::setOutputUsage(uint64_t /*flag*/) {

    mOutputUsage = mSinkUsage;
    if (mSecure && (mOutputUsage & GRALLOC_USAGE_HW_VIDEO_ENCODER)) {
        /*TODO: Currently, the framework can only say whether the display
         * and its subsequent session are secure or not. However, there is
         * no mechanism to distinguish the different levels of security.
         * The current solution assumes WV L3 protection.
         */
        mOutputUsage |= GRALLOC_USAGE_PROTECTED;
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
