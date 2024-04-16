/*
 * Copyright (C) 2022 The Android Open Source Project
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

#pragma once

#include <aidl/android/hardware/graphics/allocator/IAllocator.h>
#include <android/hardware/graphics/mapper/IMapper.h>
#include <ui/Gralloc.h>

namespace android {

class Gralloc5Mapper : public GrallocMapper {
public:
public:
    static void preload();

    Gralloc5Mapper();

    [[nodiscard]] bool isLoaded() const override;

    [[nodiscard]] std::string dumpBuffer(buffer_handle_t bufferHandle, bool less) const override;

    [[nodiscard]] std::string dumpBuffers(bool less = true) const;

    [[nodiscard]] status_t importBuffer(const native_handle_t *rawHandle,
                                        buffer_handle_t *outBufferHandle) const override;

    void freeBuffer(buffer_handle_t bufferHandle) const override;

    [[nodiscard]] status_t validateBufferSize(buffer_handle_t bufferHandle, uint32_t width,
                                              uint32_t height, PixelFormat format,
                                              uint32_t layerCount, uint64_t usage,
                                              uint32_t stride) const override;

    void getTransportSize(buffer_handle_t bufferHandle, uint32_t *outNumFds,
                          uint32_t *outNumInts) const override;

    [[nodiscard]] status_t lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect &bounds,
                                int acquireFence, void **outData, int32_t *outBytesPerPixel,
                                int32_t *outBytesPerStride) const override;

    [[nodiscard]] status_t lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect &bounds,
                                int acquireFence, android_ycbcr *ycbcr) const override;

    [[nodiscard]] int unlock(buffer_handle_t bufferHandle) const override;

    [[nodiscard]] status_t isSupported(uint32_t width, uint32_t height, PixelFormat format,
                                       uint32_t layerCount, uint64_t usage,
                                       bool *outSupported) const override;

    [[nodiscard]] status_t getBufferId(buffer_handle_t bufferHandle,
                                       uint64_t *outBufferId) const override;

    [[nodiscard]] status_t getName(buffer_handle_t bufferHandle,
                                   std::string *outName) const override;

    [[nodiscard]] status_t getWidth(buffer_handle_t bufferHandle,
                                    uint64_t *outWidth) const override;

    [[nodiscard]] status_t getHeight(buffer_handle_t bufferHandle,
                                     uint64_t *outHeight) const override;

    [[nodiscard]] status_t getLayerCount(buffer_handle_t bufferHandle,
                                         uint64_t *outLayerCount) const override;

    [[nodiscard]] status_t getPixelFormatRequested(
            buffer_handle_t bufferHandle, ui::PixelFormat *outPixelFormatRequested) const override;

    [[nodiscard]] status_t getPixelFormatFourCC(buffer_handle_t bufferHandle,
                                                uint32_t *outPixelFormatFourCC) const override;

    [[nodiscard]] status_t getPixelFormatModifier(buffer_handle_t bufferHandle,
                                                  uint64_t *outPixelFormatModifier) const override;

    [[nodiscard]] status_t getUsage(buffer_handle_t bufferHandle,
                                    uint64_t *outUsage) const override;

    [[nodiscard]] status_t getAllocationSize(buffer_handle_t bufferHandle,
                                             uint64_t *outAllocationSize) const override;

    [[nodiscard]] status_t getProtectedContent(buffer_handle_t bufferHandle,
                                               uint64_t *outProtectedContent) const override;

    [[nodiscard]] status_t getCompression(buffer_handle_t bufferHandle,
                                          aidl::android::hardware::graphics::common::ExtendableType
                                                  *outCompression) const override;

    [[nodiscard]] status_t getCompression(buffer_handle_t bufferHandle,
                                          ui::Compression *outCompression) const override;

    [[nodiscard]] status_t getInterlaced(buffer_handle_t bufferHandle,
                                         aidl::android::hardware::graphics::common::ExtendableType
                                                 *outInterlaced) const override;

    [[nodiscard]] status_t getInterlaced(buffer_handle_t bufferHandle,
                                         ui::Interlaced *outInterlaced) const override;

    [[nodiscard]] status_t getChromaSiting(buffer_handle_t bufferHandle,
                                           aidl::android::hardware::graphics::common::ExtendableType
                                                   *outChromaSiting) const override;

    [[nodiscard]] status_t getChromaSiting(buffer_handle_t bufferHandle,
                                           ui::ChromaSiting *outChromaSiting) const override;

    [[nodiscard]] status_t getPlaneLayouts(
            buffer_handle_t bufferHandle,
            std::vector<ui::PlaneLayout> *outPlaneLayouts) const override;

    [[nodiscard]] status_t getDataspace(buffer_handle_t bufferHandle,
                                        ui::Dataspace *outDataspace) const override;

    [[nodiscard]] status_t setDataspace(buffer_handle_t bufferHandle,
                                        ui::Dataspace dataspace) const override;

    [[nodiscard]] status_t getBlendMode(buffer_handle_t bufferHandle,
                                        ui::BlendMode *outBlendMode) const override;

    [[nodiscard]] status_t getSmpte2086(buffer_handle_t bufferHandle,
                                        std::optional<ui::Smpte2086> *outSmpte2086) const override;

    [[nodiscard]] status_t setSmpte2086(buffer_handle_t bufferHandle,
                                        std::optional<ui::Smpte2086> smpte2086) const override;

    [[nodiscard]] status_t getCta861_3(buffer_handle_t bufferHandle,
                                       std::optional<ui::Cta861_3> *outCta861_3) const override;

    [[nodiscard]] status_t setCta861_3(buffer_handle_t bufferHandle,
                                       std::optional<ui::Cta861_3> cta861_3) const override;

    [[nodiscard]] status_t getSmpte2094_40(
            buffer_handle_t bufferHandle,
            std::optional<std::vector<uint8_t>> *outSmpte2094_40) const override;

    [[nodiscard]] status_t setSmpte2094_40(
            buffer_handle_t bufferHandle,
            std::optional<std::vector<uint8_t>> smpte2094_40) const override;

    [[nodiscard]] status_t getSmpte2094_10(
            buffer_handle_t bufferHandle,
            std::optional<std::vector<uint8_t>> *outSmpte2094_10) const override;

    [[nodiscard]] status_t setSmpte2094_10(
            buffer_handle_t bufferHandle,
            std::optional<std::vector<uint8_t>> smpte2094_10) const override;

private:
    void unlockBlocking(buffer_handle_t bufferHandle) const;

    AIMapper *mMapper = nullptr;
};

class Gralloc5Allocator : public GrallocAllocator {
public:
    Gralloc5Allocator(const Gralloc5Mapper &mapper);

    [[nodiscard]] bool isLoaded() const override;

    [[nodiscard]] std::string dumpDebugInfo(bool less) const override;

    [[nodiscard]] status_t allocate(std::string requestorName, uint32_t width, uint32_t height,
                                    PixelFormat format, uint32_t layerCount, uint64_t usage,
                                    uint32_t* outStride, buffer_handle_t* outBufferHandles,
                                    bool importBuffers) const override;

    [[nodiscard]] GraphicBufferAllocator::AllocationResult allocate(
            const GraphicBufferAllocator::AllocationRequest&) const override;

    bool supportsAdditionalOptions() const override { return true; }

private:
    const Gralloc5Mapper &mMapper;
    std::shared_ptr<aidl::android::hardware::graphics::allocator::IAllocator> mAllocator;
};

} // namespace android
