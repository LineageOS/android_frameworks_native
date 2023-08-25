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

#define LOG_TAG "Gralloc5"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <ui/Gralloc5.h>

#include <aidlcommonsupport/NativeHandle.h>
#include <android/binder_manager.h>
#include <android/hardware/graphics/mapper/utils/IMapperMetadataTypes.h>
#include <binder/IPCThreadState.h>
#include <dlfcn.h>
#include <ui/FatVector.h>
#include <vndksupport/linker.h>

using namespace aidl::android::hardware::graphics::allocator;
using namespace aidl::android::hardware::graphics::common;
using namespace ::android::hardware::graphics::mapper;

namespace android {

static const auto kIAllocatorServiceName = IAllocator::descriptor + std::string("/default");
static const auto kIAllocatorMinimumVersion = 2;

// TODO(b/72323293, b/72703005): Remove these invalid bits from callers
static constexpr uint64_t kRemovedUsageBits = static_cast<uint64_t>((1 << 10) | (1 << 13));

typedef AIMapper_Error (*AIMapper_loadIMapperFn)(AIMapper *_Nullable *_Nonnull outImplementation);

struct Gralloc5 {
    std::shared_ptr<IAllocator> allocator;
    AIMapper *mapper = nullptr;
};

static std::shared_ptr<IAllocator> waitForAllocator() {
    if (__builtin_available(android 31, *)) {
        if (!AServiceManager_isDeclared(kIAllocatorServiceName.c_str())) {
            return nullptr;
        }
        auto allocator = IAllocator::fromBinder(
                ndk::SpAIBinder(AServiceManager_waitForService(kIAllocatorServiceName.c_str())));
        if (!allocator) {
            ALOGE("AIDL IAllocator declared but failed to get service");
            return nullptr;
        }

        int32_t version = 0;
        if (!allocator->getInterfaceVersion(&version).isOk()) {
            ALOGE("Failed to query interface version");
            return nullptr;
        }
        if (version < kIAllocatorMinimumVersion) {
            return nullptr;
        }
        return allocator;
    } else {
        // TODO: LOG_ALWAYS_FATAL("libui is not backwards compatible");
        return nullptr;
    }
}

static void *loadIMapperLibrary() {
    static void *imapperLibrary = []() -> void * {
        auto allocator = waitForAllocator();
        std::string mapperSuffix;
        auto status = allocator->getIMapperLibrarySuffix(&mapperSuffix);
        if (!status.isOk()) {
            ALOGE("Failed to get IMapper library suffix");
            return nullptr;
        }

        std::string lib_name = "mapper." + mapperSuffix + ".so";
        void *so = android_load_sphal_library(lib_name.c_str(), RTLD_LOCAL | RTLD_NOW);
        if (!so) {
            ALOGE("Failed to load %s", lib_name.c_str());
        }
        return so;
    }();
    return imapperLibrary;
}

static const Gralloc5 &getInstance() {
    static Gralloc5 instance = []() {
        auto allocator = waitForAllocator();
        if (!allocator) {
            return Gralloc5{};
        }
        void *so = loadIMapperLibrary();
        if (!so) {
            return Gralloc5{};
        }
        auto loadIMapper = (AIMapper_loadIMapperFn)dlsym(so, "AIMapper_loadIMapper");
        AIMapper *mapper = nullptr;
        AIMapper_Error error = loadIMapper(&mapper);
        if (error != AIMAPPER_ERROR_NONE) {
            ALOGE("AIMapper_loadIMapper failed %d", error);
            return Gralloc5{};
        }
        return Gralloc5{std::move(allocator), mapper};
    }();
    return instance;
}

template <StandardMetadataType T>
static auto getStandardMetadata(AIMapper *mapper, buffer_handle_t bufferHandle)
        -> decltype(StandardMetadata<T>::value::decode(nullptr, 0)) {
    using Value = typename StandardMetadata<T>::value;
    // TODO: Tune for common-case better
    FatVector<uint8_t, 128> buffer;
    int32_t sizeRequired = mapper->v5.getStandardMetadata(bufferHandle, static_cast<int64_t>(T),
                                                          buffer.data(), buffer.size());
    if (sizeRequired < 0) {
        ALOGW_IF(-AIMAPPER_ERROR_UNSUPPORTED != sizeRequired,
                 "Unexpected error %d from valid getStandardMetadata call", -sizeRequired);
        return std::nullopt;
    }
    if ((size_t)sizeRequired > buffer.size()) {
        buffer.resize(sizeRequired);
        sizeRequired = mapper->v5.getStandardMetadata(bufferHandle, static_cast<int64_t>(T),
                                                      buffer.data(), buffer.size());
    }
    if (sizeRequired < 0 || (size_t)sizeRequired > buffer.size()) {
        ALOGW("getStandardMetadata failed, received %d with buffer size %zd", sizeRequired,
              buffer.size());
        // Generate a fail type
        return std::nullopt;
    }
    return Value::decode(buffer.data(), sizeRequired);
}

template <StandardMetadataType T>
static AIMapper_Error setStandardMetadata(AIMapper *mapper, buffer_handle_t bufferHandle,
                                          const typename StandardMetadata<T>::value_type &value) {
    using Value = typename StandardMetadata<T>::value;
    int32_t sizeRequired = Value::encode(value, nullptr, 0);
    if (sizeRequired < 0) {
        ALOGW("Failed to calculate required size");
        return static_cast<AIMapper_Error>(-sizeRequired);
    }
    FatVector<uint8_t, 128> buffer;
    buffer.resize(sizeRequired);
    sizeRequired = Value::encode(value, buffer.data(), buffer.size());
    if (sizeRequired < 0 || (size_t)sizeRequired > buffer.size()) {
        ALOGW("Failed to encode with calculated size %d; buffer size %zd", sizeRequired,
              buffer.size());
        return static_cast<AIMapper_Error>(-sizeRequired);
    }
    return mapper->v5.setStandardMetadata(bufferHandle, static_cast<int64_t>(T), buffer.data(),
                                          sizeRequired);
}

Gralloc5Allocator::Gralloc5Allocator(const Gralloc5Mapper &mapper) : mMapper(mapper) {
    mAllocator = getInstance().allocator;
}

bool Gralloc5Allocator::isLoaded() const {
    return mAllocator != nullptr;
}

static uint64_t getValidUsageBits() {
    static const uint64_t validUsageBits = []() -> uint64_t {
        uint64_t bits = 0;
        for (const auto bit : ndk::enum_range<BufferUsage>{}) {
            bits |= static_cast<int64_t>(bit);
        }
        return bits;
    }();
    return validUsageBits | kRemovedUsageBits;
}

static std::optional<BufferDescriptorInfo> makeDescriptor(std::string requestorName, uint32_t width,
                                                          uint32_t height, PixelFormat format,
                                                          uint32_t layerCount, uint64_t usage) {
    uint64_t validUsageBits = getValidUsageBits();
    if (usage & ~validUsageBits) {
        ALOGE("buffer descriptor contains invalid usage bits 0x%" PRIx64, usage & ~validUsageBits);
        return std::nullopt;
    }

    BufferDescriptorInfo descriptorInfo{
            .width = static_cast<int32_t>(width),
            .height = static_cast<int32_t>(height),
            .layerCount = static_cast<int32_t>(layerCount),
            .format = static_cast<::aidl::android::hardware::graphics::common::PixelFormat>(format),
            .usage = static_cast<BufferUsage>(usage),
    };
    auto nameLength = std::min(requestorName.length(), descriptorInfo.name.size() - 1);
    memcpy(descriptorInfo.name.data(), requestorName.data(), nameLength);
    requestorName.data()[nameLength] = 0;
    return descriptorInfo;
}

std::string Gralloc5Allocator::dumpDebugInfo(bool less) const {
    return mMapper.dumpBuffers(less);
}

status_t Gralloc5Allocator::allocate(std::string requestorName, uint32_t width, uint32_t height,
                                     android::PixelFormat format, uint32_t layerCount,
                                     uint64_t usage, uint32_t bufferCount, uint32_t *outStride,
                                     buffer_handle_t *outBufferHandles, bool importBuffers) const {
    auto descriptorInfo = makeDescriptor(requestorName, width, height, format, layerCount, usage);
    if (!descriptorInfo) {
        return BAD_VALUE;
    }

    AllocationResult result;
    auto status = mAllocator->allocate2(*descriptorInfo, bufferCount, &result);
    if (!status.isOk()) {
        auto error = status.getExceptionCode();
        if (error == EX_SERVICE_SPECIFIC) {
            error = status.getServiceSpecificError();
        }
        if (error == OK) {
            error = UNKNOWN_ERROR;
        }
        return error;
    }

    if (importBuffers) {
        for (uint32_t i = 0; i < bufferCount; i++) {
            auto handle = makeFromAidl(result.buffers[i]);
            auto error = mMapper.importBuffer(handle, &outBufferHandles[i]);
            native_handle_delete(handle);
            if (error != NO_ERROR) {
                for (uint32_t j = 0; j < i; j++) {
                    mMapper.freeBuffer(outBufferHandles[j]);
                    outBufferHandles[j] = nullptr;
                }
                return error;
            }
        }
    } else {
        for (uint32_t i = 0; i < bufferCount; i++) {
            outBufferHandles[i] = dupFromAidl(result.buffers[i]);
            if (!outBufferHandles[i]) {
                for (uint32_t j = 0; j < i; j++) {
                    auto buffer = const_cast<native_handle_t *>(outBufferHandles[j]);
                    native_handle_close(buffer);
                    native_handle_delete(buffer);
                    outBufferHandles[j] = nullptr;
                }
                return NO_MEMORY;
            }
        }
    }

    *outStride = result.stride;

    // Release all the resources held by AllocationResult (specifically any remaining FDs)
    result = {};
    // make sure the kernel driver sees BC_FREE_BUFFER and closes the fds now
    // TODO: Re-enable this at some point if it's necessary. We can't do it now because libui
    // is marked apex_available (b/214400477) and libbinder isn't (which of course is correct)
    // IPCThreadState::self()->flushCommands();

    return OK;
}

void Gralloc5Mapper::preload() {
    // TODO(b/261858155): Implement. We can't bounce off of IAllocator for this because zygote can't
    // use binder. So when an alternate strategy of retrieving the library prefix is available,
    // use that here.
}

Gralloc5Mapper::Gralloc5Mapper() {
    mMapper = getInstance().mapper;
}

bool Gralloc5Mapper::isLoaded() const {
    return mMapper != nullptr && mMapper->version >= AIMAPPER_VERSION_5;
}

std::string Gralloc5Mapper::dumpBuffer(buffer_handle_t bufferHandle, bool less) const {
    // TODO(b/261858392): Implement
    (void)bufferHandle;
    (void)less;
    return {};
}

std::string Gralloc5Mapper::dumpBuffers(bool less) const {
    // TODO(b/261858392): Implement
    (void)less;
    return {};
}

status_t Gralloc5Mapper::importBuffer(const native_handle_t *rawHandle,
                                      buffer_handle_t *outBufferHandle) const {
    return mMapper->v5.importBuffer(rawHandle, outBufferHandle);
}

void Gralloc5Mapper::freeBuffer(buffer_handle_t bufferHandle) const {
    mMapper->v5.freeBuffer(bufferHandle);
}

status_t Gralloc5Mapper::validateBufferSize(buffer_handle_t bufferHandle, uint32_t width,
                                            uint32_t height, PixelFormat format,
                                            uint32_t layerCount, uint64_t usage,
                                            uint32_t stride) const {
    {
        auto value = getStandardMetadata<StandardMetadataType::WIDTH>(mMapper, bufferHandle);
        if (width != value) {
            ALOGW("Width didn't match, expected %d got %" PRId64, width, value.value_or(-1));
            return BAD_VALUE;
        }
    }
    {
        auto value = getStandardMetadata<StandardMetadataType::HEIGHT>(mMapper, bufferHandle);
        if (height != value) {
            ALOGW("Height didn't match, expected %d got %" PRId64, height, value.value_or(-1));
            return BAD_VALUE;
        }
    }
    {
        auto value =
                getStandardMetadata<StandardMetadataType::PIXEL_FORMAT_REQUESTED>(mMapper,
                                                                                  bufferHandle);
        if (static_cast<::aidl::android::hardware::graphics::common::PixelFormat>(format) !=
            value) {
            ALOGW("Format didn't match, expected %d got %s", format,
                  value.has_value() ? toString(*value).c_str() : "<null>");
            return BAD_VALUE;
        }
    }
    {
        auto value = getStandardMetadata<StandardMetadataType::LAYER_COUNT>(mMapper, bufferHandle);
        if (layerCount != value) {
            ALOGW("Layer count didn't match, expected %d got %" PRId64, layerCount,
                  value.value_or(-1));
            return BAD_VALUE;
        }
    }
    // TODO: This can false-positive fail if the allocator adjusted the USAGE bits internally
    //       Investigate further & re-enable or remove, but for now ignoring usage should be OK
    (void)usage;
    // {
    //     auto value = getStandardMetadata<StandardMetadataType::USAGE>(mMapper, bufferHandle);
    //     if (static_cast<BufferUsage>(usage) != value) {
    //         ALOGW("Usage didn't match, expected %" PRIu64 " got %" PRId64, usage,
    //               static_cast<int64_t>(value.value_or(BufferUsage::CPU_READ_NEVER)));
    //         return BAD_VALUE;
    //     }
    // }
    {
        auto value = getStandardMetadata<StandardMetadataType::STRIDE>(mMapper, bufferHandle);
        if (stride != value) {
            ALOGW("Stride didn't match, expected %" PRIu32 " got %" PRId32, stride,
                  value.value_or(-1));
            return BAD_VALUE;
        }
    }
    return OK;
}

void Gralloc5Mapper::getTransportSize(buffer_handle_t bufferHandle, uint32_t *outNumFds,
                                      uint32_t *outNumInts) const {
    mMapper->v5.getTransportSize(bufferHandle, outNumFds, outNumInts);
}

status_t Gralloc5Mapper::lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect &bounds,
                              int acquireFence, void **outData, int32_t *outBytesPerPixel,
                              int32_t *outBytesPerStride) const {
    std::vector<ui::PlaneLayout> planeLayouts;
    status_t err = getPlaneLayouts(bufferHandle, &planeLayouts);

    if (err == NO_ERROR && !planeLayouts.empty()) {
        if (outBytesPerPixel) {
            int32_t bitsPerPixel = planeLayouts.front().sampleIncrementInBits;
            for (const auto &planeLayout : planeLayouts) {
                if (bitsPerPixel != planeLayout.sampleIncrementInBits) {
                    bitsPerPixel = -1;
                }
            }
            if (bitsPerPixel >= 0 && bitsPerPixel % 8 == 0) {
                *outBytesPerPixel = bitsPerPixel / 8;
            } else {
                *outBytesPerPixel = -1;
            }
        }
        if (outBytesPerStride) {
            int32_t bytesPerStride = planeLayouts.front().strideInBytes;
            for (const auto &planeLayout : planeLayouts) {
                if (bytesPerStride != planeLayout.strideInBytes) {
                    bytesPerStride = -1;
                }
            }
            if (bytesPerStride >= 0) {
                *outBytesPerStride = bytesPerStride;
            } else {
                *outBytesPerStride = -1;
            }
        }
    }

    auto status = mMapper->v5.lock(bufferHandle, usage, bounds, acquireFence, outData);

    ALOGW_IF(status != AIMAPPER_ERROR_NONE, "lock(%p, ...) failed: %d", bufferHandle, status);
    return static_cast<status_t>(status);
}

status_t Gralloc5Mapper::lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect &bounds,
                              int acquireFence, android_ycbcr *outYcbcr) const {
    if (!outYcbcr) {
        return BAD_VALUE;
    }

    // TODO(b/262279301): Change the return type of ::unlock to unique_fd instead of int so that
    //  ignoring the return value "just works" instead
    auto unlock = [this](buffer_handle_t bufferHandle) {
        int fence = this->unlock(bufferHandle);
        if (fence != -1) {
            ::close(fence);
        }
    };

    std::vector<ui::PlaneLayout> planeLayouts;
    status_t error = getPlaneLayouts(bufferHandle, &planeLayouts);
    if (error != NO_ERROR) {
        return error;
    }

    void *data = nullptr;
    error = lock(bufferHandle, usage, bounds, acquireFence, &data, nullptr, nullptr);
    if (error != NO_ERROR) {
        return error;
    }

    android_ycbcr ycbcr;

    ycbcr.y = nullptr;
    ycbcr.cb = nullptr;
    ycbcr.cr = nullptr;
    ycbcr.ystride = 0;
    ycbcr.cstride = 0;
    ycbcr.chroma_step = 0;

    for (const auto &planeLayout : planeLayouts) {
        for (const auto &planeLayoutComponent : planeLayout.components) {
            if (!gralloc4::isStandardPlaneLayoutComponentType(planeLayoutComponent.type)) {
                continue;
            }

            uint8_t *tmpData = static_cast<uint8_t *>(data) + planeLayout.offsetInBytes;

            // Note that `offsetInBits` may not be a multiple of 8 for packed formats (e.g. P010)
            // but we still want to point to the start of the first byte.
            tmpData += (planeLayoutComponent.offsetInBits / 8);

            uint64_t sampleIncrementInBytes;

            auto type = static_cast<PlaneLayoutComponentType>(planeLayoutComponent.type.value);
            switch (type) {
                case PlaneLayoutComponentType::Y:
                    if ((ycbcr.y != nullptr) || (planeLayout.sampleIncrementInBits % 8 != 0)) {
                        unlock(bufferHandle);
                        return BAD_VALUE;
                    }
                    ycbcr.y = tmpData;
                    ycbcr.ystride = planeLayout.strideInBytes;
                    break;

                case PlaneLayoutComponentType::CB:
                case PlaneLayoutComponentType::CR:
                    if (planeLayout.sampleIncrementInBits % 8 != 0) {
                        unlock(bufferHandle);
                        return BAD_VALUE;
                    }

                    sampleIncrementInBytes = planeLayout.sampleIncrementInBits / 8;
                    if ((sampleIncrementInBytes != 1) && (sampleIncrementInBytes != 2) &&
                        (sampleIncrementInBytes != 4)) {
                        unlock(bufferHandle);
                        return BAD_VALUE;
                    }

                    if (ycbcr.cstride == 0 && ycbcr.chroma_step == 0) {
                        ycbcr.cstride = planeLayout.strideInBytes;
                        ycbcr.chroma_step = sampleIncrementInBytes;
                    } else {
                        if ((static_cast<int64_t>(ycbcr.cstride) != planeLayout.strideInBytes) ||
                            (ycbcr.chroma_step != sampleIncrementInBytes)) {
                            unlock(bufferHandle);
                            return BAD_VALUE;
                        }
                    }

                    if (type == PlaneLayoutComponentType::CB) {
                        if (ycbcr.cb != nullptr) {
                            unlock(bufferHandle);
                            return BAD_VALUE;
                        }
                        ycbcr.cb = tmpData;
                    } else {
                        if (ycbcr.cr != nullptr) {
                            unlock(bufferHandle);
                            return BAD_VALUE;
                        }
                        ycbcr.cr = tmpData;
                    }
                    break;
                default:
                    break;
            };
        }
    }

    *outYcbcr = ycbcr;
    return OK;
}

int Gralloc5Mapper::unlock(buffer_handle_t bufferHandle) const {
    int fence = -1;
    AIMapper_Error error = mMapper->v5.unlock(bufferHandle, &fence);
    if (error != AIMAPPER_ERROR_NONE) {
        ALOGW("unlock failed with error %d", error);
    }
    return fence;
}

status_t Gralloc5Mapper::isSupported(uint32_t width, uint32_t height, PixelFormat format,
                                     uint32_t layerCount, uint64_t usage,
                                     bool *outSupported) const {
    auto descriptorInfo = makeDescriptor("", width, height, format, layerCount, usage);
    if (!descriptorInfo) {
        *outSupported = false;
        return OK;
    }
    auto status = getInstance().allocator->isSupported(*descriptorInfo, outSupported);
    if (!status.isOk()) {
        ALOGW("IAllocator::isSupported error %d (%s)", status.getStatus(), status.getMessage());
        *outSupported = false;
    }
    return OK;
}

status_t Gralloc5Mapper::getBufferId(buffer_handle_t bufferHandle, uint64_t *outBufferId) const {
    auto value = getStandardMetadata<StandardMetadataType::BUFFER_ID>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outBufferId = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getName(buffer_handle_t bufferHandle, std::string *outName) const {
    auto value = getStandardMetadata<StandardMetadataType::NAME>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outName = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getWidth(buffer_handle_t bufferHandle, uint64_t *outWidth) const {
    auto value = getStandardMetadata<StandardMetadataType::WIDTH>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outWidth = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getHeight(buffer_handle_t bufferHandle, uint64_t *outHeight) const {
    auto value = getStandardMetadata<StandardMetadataType::HEIGHT>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outHeight = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getLayerCount(buffer_handle_t bufferHandle,
                                       uint64_t *outLayerCount) const {
    auto value = getStandardMetadata<StandardMetadataType::LAYER_COUNT>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outLayerCount = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getPixelFormatRequested(buffer_handle_t bufferHandle,
                                                 ui::PixelFormat *outPixelFormatRequested) const {
    auto value = getStandardMetadata<StandardMetadataType::PIXEL_FORMAT_REQUESTED>(mMapper,
                                                                                   bufferHandle);
    if (value.has_value()) {
        *outPixelFormatRequested = static_cast<ui::PixelFormat>(*value);
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getPixelFormatFourCC(buffer_handle_t bufferHandle,
                                              uint32_t *outPixelFormatFourCC) const {
    auto value =
            getStandardMetadata<StandardMetadataType::PIXEL_FORMAT_FOURCC>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outPixelFormatFourCC = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getPixelFormatModifier(buffer_handle_t bufferHandle,
                                                uint64_t *outPixelFormatModifier) const {
    auto value =
            getStandardMetadata<StandardMetadataType::PIXEL_FORMAT_MODIFIER>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outPixelFormatModifier = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getUsage(buffer_handle_t bufferHandle, uint64_t *outUsage) const {
    auto value = getStandardMetadata<StandardMetadataType::USAGE>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outUsage = static_cast<uint64_t>(*value);
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getAllocationSize(buffer_handle_t bufferHandle,
                                           uint64_t *outAllocationSize) const {
    auto value = getStandardMetadata<StandardMetadataType::ALLOCATION_SIZE>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outAllocationSize = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getProtectedContent(buffer_handle_t bufferHandle,
                                             uint64_t *outProtectedContent) const {
    auto value =
            getStandardMetadata<StandardMetadataType::PROTECTED_CONTENT>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outProtectedContent = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getCompression(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType *outCompression) const {
    auto value = getStandardMetadata<StandardMetadataType::COMPRESSION>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outCompression = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getCompression(buffer_handle_t bufferHandle,
                                        ui::Compression *outCompression) const {
    auto value = getStandardMetadata<StandardMetadataType::COMPRESSION>(mMapper, bufferHandle);
    if (!value.has_value()) {
        return UNKNOWN_TRANSACTION;
    }
    if (!gralloc4::isStandardCompression(*value)) {
        return BAD_TYPE;
    }
    *outCompression = gralloc4::getStandardCompressionValue(*value);
    return OK;
}

status_t Gralloc5Mapper::getInterlaced(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType *outInterlaced) const {
    auto value = getStandardMetadata<StandardMetadataType::INTERLACED>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outInterlaced = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getInterlaced(buffer_handle_t bufferHandle,
                                       ui::Interlaced *outInterlaced) const {
    if (!outInterlaced) {
        return BAD_VALUE;
    }
    ExtendableType interlaced;
    status_t error = getInterlaced(bufferHandle, &interlaced);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardInterlaced(interlaced)) {
        return BAD_TYPE;
    }
    *outInterlaced = gralloc4::getStandardInterlacedValue(interlaced);
    return NO_ERROR;
}

status_t Gralloc5Mapper::getChromaSiting(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType *outChromaSiting) const {
    auto value = getStandardMetadata<StandardMetadataType::CHROMA_SITING>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outChromaSiting = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getChromaSiting(buffer_handle_t bufferHandle,
                                         ui::ChromaSiting *outChromaSiting) const {
    if (!outChromaSiting) {
        return BAD_VALUE;
    }
    ExtendableType chromaSiting;
    status_t error = getChromaSiting(bufferHandle, &chromaSiting);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardChromaSiting(chromaSiting)) {
        return BAD_TYPE;
    }
    *outChromaSiting = gralloc4::getStandardChromaSitingValue(chromaSiting);
    return NO_ERROR;
}

status_t Gralloc5Mapper::getPlaneLayouts(buffer_handle_t bufferHandle,
                                         std::vector<ui::PlaneLayout> *outPlaneLayouts) const {
    auto value = getStandardMetadata<StandardMetadataType::PLANE_LAYOUTS>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outPlaneLayouts = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getDataspace(buffer_handle_t bufferHandle,
                                      ui::Dataspace *outDataspace) const {
    auto value = getStandardMetadata<StandardMetadataType::DATASPACE>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outDataspace = static_cast<ui::Dataspace>(*value);
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::setDataspace(buffer_handle_t bufferHandle, ui::Dataspace dataspace) const {
    return setStandardMetadata<StandardMetadataType::DATASPACE>(mMapper, bufferHandle,
                                                                static_cast<Dataspace>(dataspace));
}

status_t Gralloc5Mapper::getBlendMode(buffer_handle_t bufferHandle,
                                      ui::BlendMode *outBlendMode) const {
    auto value = getStandardMetadata<StandardMetadataType::BLEND_MODE>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outBlendMode = static_cast<ui::BlendMode>(*value);
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::getSmpte2086(buffer_handle_t bufferHandle,
                                      std::optional<ui::Smpte2086> *outSmpte2086) const {
    auto value = getStandardMetadata<StandardMetadataType::SMPTE2086>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outSmpte2086 = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::setSmpte2086(buffer_handle_t bufferHandle,
                                      std::optional<ui::Smpte2086> smpte2086) const {
    return setStandardMetadata<StandardMetadataType::SMPTE2086>(mMapper, bufferHandle, smpte2086);
}

status_t Gralloc5Mapper::getCta861_3(buffer_handle_t bufferHandle,
                                     std::optional<ui::Cta861_3> *outCta861_3) const {
    auto value = getStandardMetadata<StandardMetadataType::CTA861_3>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outCta861_3 = *value;
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::setCta861_3(buffer_handle_t bufferHandle,
                                     std::optional<ui::Cta861_3> cta861_3) const {
    return setStandardMetadata<StandardMetadataType::CTA861_3>(mMapper, bufferHandle, cta861_3);
}

status_t Gralloc5Mapper::getSmpte2094_40(
        buffer_handle_t bufferHandle, std::optional<std::vector<uint8_t>> *outSmpte2094_40) const {
    auto value = getStandardMetadata<StandardMetadataType::SMPTE2094_40>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outSmpte2094_40 = std::move(*value);
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::setSmpte2094_40(buffer_handle_t bufferHandle,
                                         std::optional<std::vector<uint8_t>> smpte2094_40) const {
    return setStandardMetadata<StandardMetadataType::SMPTE2094_40>(mMapper, bufferHandle,
                                                                   smpte2094_40);
}

status_t Gralloc5Mapper::getSmpte2094_10(
        buffer_handle_t bufferHandle, std::optional<std::vector<uint8_t>> *outSmpte2094_10) const {
    auto value = getStandardMetadata<StandardMetadataType::SMPTE2094_10>(mMapper, bufferHandle);
    if (value.has_value()) {
        *outSmpte2094_10 = std::move(*value);
        return OK;
    }
    return UNKNOWN_TRANSACTION;
}

status_t Gralloc5Mapper::setSmpte2094_10(buffer_handle_t bufferHandle,
                                         std::optional<std::vector<uint8_t>> smpte2094_10) const {
    return setStandardMetadata<StandardMetadataType::SMPTE2094_10>(mMapper, bufferHandle,
                                                                   smpte2094_10);
}

} // namespace android