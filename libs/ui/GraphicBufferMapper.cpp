/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define LOG_TAG "GraphicBufferMapper"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include <ui/GraphicBufferMapper.h>

#include <grallocusage/GrallocUsageConversion.h>

// We would eliminate the non-conforming zero-length array, but we can't since
// this is effectively included from the Linux kernel
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#include <sync/sync.h>
#pragma clang diagnostic pop

#include <utils/Log.h>
#include <utils/Trace.h>

#include <ui/Gralloc2.h>
#include <ui/GraphicBuffer.h>

#include <system/graphics.h>

namespace android {
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE( GraphicBufferMapper )

GraphicBufferMapper::GraphicBufferMapper()
  : mMapper(std::make_unique<const Gralloc2::Mapper>())
{
    if (!mMapper->valid()) {
        mLoader = std::make_unique<Gralloc1::Loader>();
        mDevice = mLoader->getDevice();
    }
}

status_t GraphicBufferMapper::importBuffer(buffer_handle_t rawHandle,
        buffer_handle_t* outHandle)
{
    ATRACE_CALL();

    Gralloc2::Error error;
    if (mMapper->valid()) {
        error = mMapper->importBuffer(hardware::hidl_handle(rawHandle),
                outHandle);
    } else {
        error = Gralloc2::Error::UNSUPPORTED;
    }

    ALOGW_IF(error != Gralloc2::Error::NONE, "importBuffer(%p) failed: %d",
            rawHandle, error);

    return static_cast<status_t>(error);
}

status_t GraphicBufferMapper::importBuffer(const GraphicBuffer* buffer)
{
    ATRACE_CALL();

    ANativeWindowBuffer* nativeBuffer = buffer->getNativeBuffer();
    buffer_handle_t rawHandle = nativeBuffer->handle;

    gralloc1_error_t error;
    if (mMapper->valid()) {
        buffer_handle_t importedHandle;
        error = static_cast<gralloc1_error_t>(mMapper->importBuffer(
                    hardware::hidl_handle(rawHandle), &importedHandle));
        if (error == GRALLOC1_ERROR_NONE) {
            nativeBuffer->handle = importedHandle;
        }
    } else {
        native_handle_t* clonedHandle = native_handle_clone(rawHandle);
        if (clonedHandle) {
            nativeBuffer->handle = clonedHandle;
            error = mDevice->retain(buffer);
            if (error != GRALLOC1_ERROR_NONE) {
                nativeBuffer->handle = rawHandle;
                native_handle_close(clonedHandle);
                native_handle_delete(clonedHandle);
            }
        } else {
            error = GRALLOC1_ERROR_NO_RESOURCES;
        }
    }

    // the raw handle is owned by GraphicBuffer and is now replaced
    if (error == GRALLOC1_ERROR_NONE) {
        native_handle_close(rawHandle);
        native_handle_delete(const_cast<native_handle_t*>(rawHandle));
    }

    ALOGW_IF(error != GRALLOC1_ERROR_NONE, "importBuffer(%p) failed: %d",
            rawHandle, error);

    return error;
}

status_t GraphicBufferMapper::freeBuffer(buffer_handle_t handle)
{
    ATRACE_CALL();

    gralloc1_error_t error;
    if (mMapper->valid()) {
        mMapper->freeBuffer(handle);
        error = GRALLOC1_ERROR_NONE;
    } else {
        error = mDevice->release(handle);
        if (!mDevice->hasCapability(GRALLOC1_CAPABILITY_RELEASE_IMPLY_DELETE)) {
            native_handle_close(handle);
            native_handle_delete(const_cast<native_handle_t*>(handle));
        }
    }

    ALOGW_IF(error != GRALLOC1_ERROR_NONE, "freeBuffer(%p): failed %d",
            handle, error);

    return error;
}

static inline gralloc1_rect_t asGralloc1Rect(const Rect& rect) {
    gralloc1_rect_t outRect{};
    outRect.left = rect.left;
    outRect.top = rect.top;
    outRect.width = rect.width();
    outRect.height = rect.height();
    return outRect;
}

static inline Gralloc2::IMapper::Rect asGralloc2Rect(const Rect& rect) {
    Gralloc2::IMapper::Rect outRect{};
    outRect.left = rect.left;
    outRect.top = rect.top;
    outRect.width = rect.width();
    outRect.height = rect.height();
    return outRect;
}

status_t GraphicBufferMapper::lock(buffer_handle_t handle, uint32_t usage,
        const Rect& bounds, void** vaddr)
{
    return lockAsync(handle, usage, bounds, vaddr, -1);
}

status_t GraphicBufferMapper::lockYCbCr(buffer_handle_t handle, uint32_t usage,
        const Rect& bounds, android_ycbcr *ycbcr)
{
    return lockAsyncYCbCr(handle, usage, bounds, ycbcr, -1);
}

status_t GraphicBufferMapper::unlock(buffer_handle_t handle)
{
    int32_t fenceFd = -1;
    status_t error = unlockAsync(handle, &fenceFd);
    if (error == NO_ERROR) {
        sync_wait(fenceFd, -1);
        close(fenceFd);
    }
    return error;
}

status_t GraphicBufferMapper::lockAsync(buffer_handle_t handle,
        uint32_t usage, const Rect& bounds, void** vaddr, int fenceFd)
{
    return lockAsync(handle, usage, usage, bounds, vaddr, fenceFd);
}

status_t GraphicBufferMapper::lockAsync(buffer_handle_t handle,
        uint64_t producerUsage, uint64_t consumerUsage, const Rect& bounds,
        void** vaddr, int fenceFd)
{
    ATRACE_CALL();

    gralloc1_error_t error;
    if (mMapper->valid()) {
        const uint64_t usage =
            static_cast<uint64_t>(android_convertGralloc1To0Usage(
                        producerUsage, consumerUsage));
        error = static_cast<gralloc1_error_t>(mMapper->lock(handle,
                usage, asGralloc2Rect(bounds), fenceFd, vaddr));
    } else {
        gralloc1_rect_t accessRegion = asGralloc1Rect(bounds);
        sp<Fence> fence = new Fence(fenceFd);
        error = mDevice->lock(handle,
                static_cast<gralloc1_producer_usage_t>(producerUsage),
                static_cast<gralloc1_consumer_usage_t>(consumerUsage),
                &accessRegion, vaddr, fence);
    }

    ALOGW_IF(error != GRALLOC1_ERROR_NONE, "lock(%p, ...) failed: %d", handle,
            error);

    return error;
}

static inline bool isValidYCbCrPlane(const android_flex_plane_t& plane) {
    if (plane.bits_per_component != 8) {
        ALOGV("Invalid number of bits per component: %d",
                plane.bits_per_component);
        return false;
    }
    if (plane.bits_used != 8) {
        ALOGV("Invalid number of bits used: %d", plane.bits_used);
        return false;
    }

    bool hasValidIncrement = plane.h_increment == 1 ||
            (plane.component != FLEX_COMPONENT_Y && plane.h_increment == 2);
    hasValidIncrement = hasValidIncrement && plane.v_increment > 0;
    if (!hasValidIncrement) {
        ALOGV("Invalid increment: h %d v %d", plane.h_increment,
                plane.v_increment);
        return false;
    }

    return true;
}

status_t GraphicBufferMapper::lockAsyncYCbCr(buffer_handle_t handle,
        uint32_t usage, const Rect& bounds, android_ycbcr *ycbcr, int fenceFd)
{
    ATRACE_CALL();

    gralloc1_rect_t accessRegion = asGralloc1Rect(bounds);

    std::vector<android_flex_plane_t> planes;
    android_flex_layout_t flexLayout{};
    gralloc1_error_t error;

    if (mMapper->valid()) {
        Gralloc2::YCbCrLayout layout;
        error = static_cast<gralloc1_error_t>(mMapper->lock(handle, usage,
                asGralloc2Rect(bounds), fenceFd, &layout));
        if (error == GRALLOC1_ERROR_NONE) {
            ycbcr->y = layout.y;
            ycbcr->cb = layout.cb;
            ycbcr->cr = layout.cr;
            ycbcr->ystride = static_cast<size_t>(layout.yStride);
            ycbcr->cstride = static_cast<size_t>(layout.cStride);
            ycbcr->chroma_step = static_cast<size_t>(layout.chromaStep);
        }

        return error;
    } else {
        sp<Fence> fence = new Fence(fenceFd);

        if (mDevice->hasCapability(GRALLOC1_CAPABILITY_ON_ADAPTER)) {
            error = mDevice->lockYCbCr(handle,
                    static_cast<gralloc1_producer_usage_t>(usage),
                    static_cast<gralloc1_consumer_usage_t>(usage),
                    &accessRegion, ycbcr, fence);
            ALOGW_IF(error != GRALLOC1_ERROR_NONE,
                    "lockYCbCr(%p, ...) failed: %d", handle, error);
            return error;
        }

        uint32_t numPlanes = 0;
        error = mDevice->getNumFlexPlanes(handle, &numPlanes);

        if (error != GRALLOC1_ERROR_NONE) {
            ALOGV("Failed to retrieve number of flex planes: %d", error);
            return error;
        }
        if (numPlanes < 3) {
            ALOGV("Not enough planes for YCbCr (%u found)", numPlanes);
            return GRALLOC1_ERROR_UNSUPPORTED;
        }

        planes.resize(numPlanes);
        flexLayout.num_planes = numPlanes;
        flexLayout.planes = planes.data();

        error = mDevice->lockFlex(handle,
                static_cast<gralloc1_producer_usage_t>(usage),
                static_cast<gralloc1_consumer_usage_t>(usage),
                &accessRegion, &flexLayout, fence);
    }

    if (error != GRALLOC1_ERROR_NONE) {
        ALOGW("lockFlex(%p, ...) failed: %d", handle, error);
        return error;
    }
    if (flexLayout.format != FLEX_FORMAT_YCbCr) {
        ALOGV("Unable to convert flex-format buffer to YCbCr");
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }

    // Find planes
    auto yPlane = planes.cend();
    auto cbPlane = planes.cend();
    auto crPlane = planes.cend();
    for (auto planeIter = planes.cbegin(); planeIter != planes.cend();
            ++planeIter) {
        if (planeIter->component == FLEX_COMPONENT_Y) {
            yPlane = planeIter;
        } else if (planeIter->component == FLEX_COMPONENT_Cb) {
            cbPlane = planeIter;
        } else if (planeIter->component == FLEX_COMPONENT_Cr) {
            crPlane = planeIter;
        }
    }
    if (yPlane == planes.cend()) {
        ALOGV("Unable to find Y plane");
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }
    if (cbPlane == planes.cend()) {
        ALOGV("Unable to find Cb plane");
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }
    if (crPlane == planes.cend()) {
        ALOGV("Unable to find Cr plane");
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }

    // Validate planes
    if (!isValidYCbCrPlane(*yPlane)) {
        ALOGV("Y plane is invalid");
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }
    if (!isValidYCbCrPlane(*cbPlane)) {
        ALOGV("Cb plane is invalid");
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }
    if (!isValidYCbCrPlane(*crPlane)) {
        ALOGV("Cr plane is invalid");
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }
    if (cbPlane->v_increment != crPlane->v_increment) {
        ALOGV("Cb and Cr planes have different step (%d vs. %d)",
                cbPlane->v_increment, crPlane->v_increment);
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }
    if (cbPlane->h_increment != crPlane->h_increment) {
        ALOGV("Cb and Cr planes have different stride (%d vs. %d)",
                cbPlane->h_increment, crPlane->h_increment);
        unlock(handle);
        return GRALLOC1_ERROR_UNSUPPORTED;
    }

    // Pack plane data into android_ycbcr struct
    ycbcr->y = yPlane->top_left;
    ycbcr->cb = cbPlane->top_left;
    ycbcr->cr = crPlane->top_left;
    ycbcr->ystride = static_cast<size_t>(yPlane->v_increment);
    ycbcr->cstride = static_cast<size_t>(cbPlane->v_increment);
    ycbcr->chroma_step = static_cast<size_t>(cbPlane->h_increment);

    return error;
}

status_t GraphicBufferMapper::unlockAsync(buffer_handle_t handle, int *fenceFd)
{
    ATRACE_CALL();

    gralloc1_error_t error;
    if (mMapper->valid()) {
        *fenceFd = mMapper->unlock(handle);
        error = GRALLOC1_ERROR_NONE;
    } else {
        sp<Fence> fence = Fence::NO_FENCE;
        error = mDevice->unlock(handle, &fence);
        if (error != GRALLOC1_ERROR_NONE) {
            ALOGE("unlock(%p) failed: %d", handle, error);
            return error;
        }

        *fenceFd = fence->dup();
    }
    return error;
}

#if defined(EXYNOS4_ENHANCEMENTS)
status_t GraphicBufferMapper::getphys(buffer_handle_t handle, void** paddr)
{
    status_t err;

    err = mDevice->getphys(handle, paddr);

    ALOGW_IF(err, "getphys(%p) fail %d(%s)", handle, err, strerror(-err));
    return err;
}
#endif

// ---------------------------------------------------------------------------
}; // namespace android
