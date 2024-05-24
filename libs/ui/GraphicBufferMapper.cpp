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

#include <ui/Gralloc.h>
#include <ui/Gralloc2.h>
#include <ui/Gralloc3.h>
#include <ui/Gralloc4.h>
#include <ui/Gralloc5.h>
#include <ui/GraphicBuffer.h>

#include <system/graphics.h>

using unique_fd = ::android::base::unique_fd;

namespace android {
// ---------------------------------------------------------------------------

using LockResult = GraphicBufferMapper::LockResult;

ANDROID_SINGLETON_STATIC_INSTANCE( GraphicBufferMapper )

void GraphicBufferMapper::preloadHal() {
    Gralloc2Mapper::preload();
    Gralloc3Mapper::preload();
    Gralloc4Mapper::preload();
    Gralloc5Mapper::preload();
}

GraphicBufferMapper::GraphicBufferMapper() {
    mMapper = std::make_unique<const Gralloc5Mapper>();
    if (mMapper->isLoaded()) {
        mMapperVersion = Version::GRALLOC_5;
        return;
    }
    mMapper = std::make_unique<const Gralloc4Mapper>();
    if (mMapper->isLoaded()) {
        mMapperVersion = Version::GRALLOC_4;
        return;
    }
    mMapper = std::make_unique<const Gralloc3Mapper>();
    if (mMapper->isLoaded()) {
        mMapperVersion = Version::GRALLOC_3;
        return;
    }
    mMapper = std::make_unique<const Gralloc2Mapper>();
    if (mMapper->isLoaded()) {
        mMapperVersion = Version::GRALLOC_2;
        return;
    }

    LOG_ALWAYS_FATAL("gralloc-mapper is missing");
}

void GraphicBufferMapper::dumpBuffer(buffer_handle_t bufferHandle, std::string& result,
                                     bool less) const {
    result.append(mMapper->dumpBuffer(bufferHandle, less));
}

void GraphicBufferMapper::dumpBufferToSystemLog(buffer_handle_t bufferHandle, bool less) {
    std::string s;
    GraphicBufferMapper::getInstance().dumpBuffer(bufferHandle, s, less);
    ALOGD("%s", s.c_str());
}

status_t GraphicBufferMapper::importBuffer(const native_handle_t* rawHandle, uint32_t width,
                                           uint32_t height, uint32_t layerCount, PixelFormat format,
                                           uint64_t usage, uint32_t stride,
                                           buffer_handle_t* outHandle) {
    ATRACE_CALL();

    buffer_handle_t bufferHandle;
    status_t error = mMapper->importBuffer(rawHandle, &bufferHandle);
    if (error != NO_ERROR) {
        ALOGW("importBuffer(%p) failed: %d", rawHandle, error);
        return error;
    }

    error = mMapper->validateBufferSize(bufferHandle, width, height, format, layerCount, usage,
                                        stride);
    if (error != NO_ERROR) {
        ALOGE("validateBufferSize(%p) failed: %d", rawHandle, error);
        freeBuffer(bufferHandle);
        return static_cast<status_t>(error);
    }

    *outHandle = bufferHandle;

    return NO_ERROR;
}

status_t GraphicBufferMapper::importBufferNoValidate(const native_handle_t* rawHandle,
                                                     buffer_handle_t* outHandle) {
    return mMapper->importBuffer(rawHandle, outHandle);
}

void GraphicBufferMapper::getTransportSize(buffer_handle_t handle,
            uint32_t* outTransportNumFds, uint32_t* outTransportNumInts)
{
    mMapper->getTransportSize(handle, outTransportNumFds, outTransportNumInts);
}

status_t GraphicBufferMapper::freeBuffer(buffer_handle_t handle)
{
    ATRACE_CALL();

    mMapper->freeBuffer(handle);

    return NO_ERROR;
}

ui::Result<LockResult> GraphicBufferMapper::lock(buffer_handle_t handle, int64_t usage,
                                                 const Rect& bounds, unique_fd&& acquireFence) {
    ATRACE_CALL();

    LockResult result;
    status_t status = mMapper->lock(handle, usage, bounds, acquireFence.release(), &result.address,
                                    &result.bytesPerPixel, &result.bytesPerStride);
    if (status != OK) {
        return base::unexpected(ui::Error::statusToCode(status));
    } else {
        return result;
    }
}

ui::Result<android_ycbcr> GraphicBufferMapper::lockYCbCr(buffer_handle_t handle, int64_t usage,
                                                         const Rect& bounds,
                                                         base::unique_fd&& acquireFence) {
    ATRACE_CALL();

    android_ycbcr result = {};
    status_t status = mMapper->lock(handle, usage, bounds, acquireFence.release(), &result);
    if (status != OK) {
        return base::unexpected(ui::Error::statusToCode(status));
    } else {
        return result;
    }
}

status_t GraphicBufferMapper::unlock(buffer_handle_t handle, base::unique_fd* outFence) {
    ATRACE_CALL();
    int fence = mMapper->unlock(handle);
    if (outFence) {
        *outFence = unique_fd{fence};
    } else {
        sync_wait(fence, -1);
        close(fence);
    }
    return OK;
}

status_t GraphicBufferMapper::lock(buffer_handle_t handle, uint32_t usage, const Rect& bounds,
                                   void** vaddr) {
    auto result = lock(handle, static_cast<int64_t>(usage), bounds);
    if (!result.has_value()) return result.asStatus();
    auto val = result.value();
    *vaddr = val.address;
    return OK;
}

status_t GraphicBufferMapper::lockYCbCr(buffer_handle_t handle, uint32_t usage, const Rect& bounds,
                                        android_ycbcr* ycbcr) {
    auto result = lockYCbCr(handle, static_cast<int64_t>(usage), bounds);
    if (!result.has_value()) return result.asStatus();
    *ycbcr = result.value();
    return OK;
}

status_t GraphicBufferMapper::lockAsync(buffer_handle_t handle, uint32_t usage, const Rect& bounds,
                                        void** vaddr, int fenceFd) {
    auto result = lock(handle, static_cast<int64_t>(usage), bounds, unique_fd{fenceFd});
    if (!result.has_value()) return result.asStatus();
    auto val = result.value();
    *vaddr = val.address;
    return OK;
}

status_t GraphicBufferMapper::lockAsync(buffer_handle_t handle, uint64_t producerUsage,
                                        uint64_t consumerUsage, const Rect& bounds, void** vaddr,
                                        int fenceFd) {
    return lockAsync(handle, android_convertGralloc1To0Usage(producerUsage, consumerUsage), bounds,
                     vaddr, fenceFd);
}

status_t GraphicBufferMapper::lockAsyncYCbCr(buffer_handle_t handle, uint32_t usage,
                                             const Rect& bounds, android_ycbcr* ycbcr,
                                             int fenceFd) {
    auto result = lockYCbCr(handle, static_cast<int64_t>(usage), bounds, unique_fd{fenceFd});
    if (!result.has_value()) return result.asStatus();
    *ycbcr = result.value();
    return OK;
}

status_t GraphicBufferMapper::isSupported(uint32_t width, uint32_t height,
                                          android::PixelFormat format, uint32_t layerCount,
                                          uint64_t usage, bool* outSupported) {
    return mMapper->isSupported(width, height, format, layerCount, usage, outSupported);
}

status_t GraphicBufferMapper::getBufferId(buffer_handle_t bufferHandle, uint64_t* outBufferId) {
    return mMapper->getBufferId(bufferHandle, outBufferId);
}

status_t GraphicBufferMapper::getName(buffer_handle_t bufferHandle, std::string* outName) {
    return mMapper->getName(bufferHandle, outName);
}

status_t GraphicBufferMapper::getWidth(buffer_handle_t bufferHandle, uint64_t* outWidth) {
    return mMapper->getWidth(bufferHandle, outWidth);
}

status_t GraphicBufferMapper::getHeight(buffer_handle_t bufferHandle, uint64_t* outHeight) {
    return mMapper->getHeight(bufferHandle, outHeight);
}

status_t GraphicBufferMapper::getLayerCount(buffer_handle_t bufferHandle, uint64_t* outLayerCount) {
    return mMapper->getLayerCount(bufferHandle, outLayerCount);
}

status_t GraphicBufferMapper::getPixelFormatRequested(buffer_handle_t bufferHandle,
                                                      ui::PixelFormat* outPixelFormatRequested) {
    return mMapper->getPixelFormatRequested(bufferHandle, outPixelFormatRequested);
}

status_t GraphicBufferMapper::getPixelFormatFourCC(buffer_handle_t bufferHandle,
                                                   uint32_t* outPixelFormatFourCC) {
    return mMapper->getPixelFormatFourCC(bufferHandle, outPixelFormatFourCC);
}

status_t GraphicBufferMapper::getPixelFormatModifier(buffer_handle_t bufferHandle,
                                                     uint64_t* outPixelFormatModifier) {
    return mMapper->getPixelFormatModifier(bufferHandle, outPixelFormatModifier);
}

status_t GraphicBufferMapper::getUsage(buffer_handle_t bufferHandle, uint64_t* outUsage) {
    return mMapper->getUsage(bufferHandle, outUsage);
}

status_t GraphicBufferMapper::getAllocationSize(buffer_handle_t bufferHandle,
                                                uint64_t* outAllocationSize) {
    return mMapper->getAllocationSize(bufferHandle, outAllocationSize);
}

status_t GraphicBufferMapper::getProtectedContent(buffer_handle_t bufferHandle,
                                                  uint64_t* outProtectedContent) {
    return mMapper->getProtectedContent(bufferHandle, outProtectedContent);
}

status_t GraphicBufferMapper::getCompression(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType* outCompression) {
    return mMapper->getCompression(bufferHandle, outCompression);
}

status_t GraphicBufferMapper::getCompression(buffer_handle_t bufferHandle,
                                             ui::Compression* outCompression) {
    return mMapper->getCompression(bufferHandle, outCompression);
}

status_t GraphicBufferMapper::getInterlaced(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType* outInterlaced) {
    return mMapper->getInterlaced(bufferHandle, outInterlaced);
}

status_t GraphicBufferMapper::getInterlaced(buffer_handle_t bufferHandle,
                                            ui::Interlaced* outInterlaced) {
    return mMapper->getInterlaced(bufferHandle, outInterlaced);
}

status_t GraphicBufferMapper::getChromaSiting(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType* outChromaSiting) {
    return mMapper->getChromaSiting(bufferHandle, outChromaSiting);
}

status_t GraphicBufferMapper::getChromaSiting(buffer_handle_t bufferHandle,
                                              ui::ChromaSiting* outChromaSiting) {
    return mMapper->getChromaSiting(bufferHandle, outChromaSiting);
}

status_t GraphicBufferMapper::getPlaneLayouts(buffer_handle_t bufferHandle,
                                              std::vector<ui::PlaneLayout>* outPlaneLayouts) {
    return mMapper->getPlaneLayouts(bufferHandle, outPlaneLayouts);
}

ui::Result<std::vector<ui::PlaneLayout>> GraphicBufferMapper::getPlaneLayouts(
        buffer_handle_t bufferHandle) {
    std::vector<ui::PlaneLayout> temp;
    status_t status = mMapper->getPlaneLayouts(bufferHandle, &temp);
    if (status == OK) {
        return std::move(temp);
    } else {
        return base::unexpected(ui::Error::statusToCode(status));
    }
}

status_t GraphicBufferMapper::getDataspace(buffer_handle_t bufferHandle,
                                           ui::Dataspace* outDataspace) {
    return mMapper->getDataspace(bufferHandle, outDataspace);
}

status_t GraphicBufferMapper::setDataspace(buffer_handle_t bufferHandle, ui::Dataspace dataspace) {
    return mMapper->setDataspace(bufferHandle, dataspace);
}

status_t GraphicBufferMapper::getBlendMode(buffer_handle_t bufferHandle,
                                           ui::BlendMode* outBlendMode) {
    return mMapper->getBlendMode(bufferHandle, outBlendMode);
}

status_t GraphicBufferMapper::getSmpte2086(buffer_handle_t bufferHandle,
                                           std::optional<ui::Smpte2086>* outSmpte2086) {
    return mMapper->getSmpte2086(bufferHandle, outSmpte2086);
}

status_t GraphicBufferMapper::setSmpte2086(buffer_handle_t bufferHandle,
                                           std::optional<ui::Smpte2086> smpte2086) {
    return mMapper->setSmpte2086(bufferHandle, smpte2086);
}

status_t GraphicBufferMapper::getCta861_3(buffer_handle_t bufferHandle,
                                          std::optional<ui::Cta861_3>* outCta861_3) {
    return mMapper->getCta861_3(bufferHandle, outCta861_3);
}

status_t GraphicBufferMapper::setCta861_3(buffer_handle_t bufferHandle,
                                          std::optional<ui::Cta861_3> cta861_3) {
    return mMapper->setCta861_3(bufferHandle, cta861_3);
}

status_t GraphicBufferMapper::getSmpte2094_40(
        buffer_handle_t bufferHandle, std::optional<std::vector<uint8_t>>* outSmpte2094_40) {
    return mMapper->getSmpte2094_40(bufferHandle, outSmpte2094_40);
}

status_t GraphicBufferMapper::setSmpte2094_40(buffer_handle_t bufferHandle,
                                              std::optional<std::vector<uint8_t>> smpte2094_40) {
    return mMapper->setSmpte2094_40(bufferHandle, smpte2094_40);
}

status_t GraphicBufferMapper::getSmpte2094_10(
        buffer_handle_t bufferHandle, std::optional<std::vector<uint8_t>>* outSmpte2094_10) {
    return mMapper->getSmpte2094_10(bufferHandle, outSmpte2094_10);
}

status_t GraphicBufferMapper::setSmpte2094_10(buffer_handle_t bufferHandle,
                                              std::optional<std::vector<uint8_t>> smpte2094_10) {
    return mMapper->setSmpte2094_10(bufferHandle, smpte2094_10);
}

// ---------------------------------------------------------------------------
}; // namespace android
