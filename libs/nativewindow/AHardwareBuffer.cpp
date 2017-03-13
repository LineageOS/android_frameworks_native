/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "AHardwareBuffer"

#include <android/hardware_buffer.h>

#include <errno.h>
#include <sys/socket.h>
#include <memory>

#include <cutils/native_handle.h>
#include <log/log.h>
#include <utils/StrongPointer.h>
#include <ui/GraphicBuffer.h>
#include <system/graphics.h>
#include <hardware/gralloc1.h>

#include <private/android/AHardwareBufferHelpers.h>


static constexpr int kDataBufferSize = 64 * sizeof(int);  // 64 ints

using namespace android;

// ----------------------------------------------------------------------------
// Public functions
// ----------------------------------------------------------------------------

int AHardwareBuffer_allocate(const AHardwareBuffer_Desc* desc, AHardwareBuffer** outBuffer) {
    if (!outBuffer || !desc)
        return BAD_VALUE;

    int format = AHardwareBuffer_convertToPixelFormat(desc->format);
    if (format == 0) {
        ALOGE("Invalid pixel format %u", desc->format);
        return BAD_VALUE;
    }

    if (desc->format == AHARDWAREBUFFER_FORMAT_BLOB && desc->height != 1) {
        ALOGE("Height must be 1 when using the AHARDWAREBUFFER_FORMAT_BLOB format");
        return BAD_VALUE;
    }

    uint64_t producerUsage = 0;
    uint64_t consumerUsage = 0;
    AHardwareBuffer_convertToGrallocUsageBits(&producerUsage, &consumerUsage, desc->usage0,
            desc->usage1);

    sp<GraphicBuffer> gbuffer(new GraphicBuffer(
            desc->width, desc->height, format, desc->layers, producerUsage, consumerUsage,
            std::string("AHardwareBuffer pid [") + std::to_string(getpid()) + "]"));

    status_t err = gbuffer->initCheck();
    if (err != 0 || gbuffer->handle == 0) {
        if (err == NO_MEMORY) {
            GraphicBuffer::dumpAllocationsToSystemLog();
        }
        ALOGE("GraphicBufferAlloc::createGraphicBuffer(w=%u, h=%u, lc=%u) failed (%s), handle=%p",
                desc->width, desc->height, desc->layers, strerror(-err), gbuffer->handle);
        return err;
    }

    *outBuffer = AHardwareBuffer_from_GraphicBuffer(gbuffer.get());

    // Ensure the buffer doesn't get destroyed when the sp<> goes away.
    AHardwareBuffer_acquire(*outBuffer);
    return NO_ERROR;
}

void AHardwareBuffer_acquire(AHardwareBuffer* buffer) {
    AHardwareBuffer_to_GraphicBuffer(buffer)->incStrong((void*)AHardwareBuffer_acquire);
}

void AHardwareBuffer_release(AHardwareBuffer* buffer) {
    AHardwareBuffer_to_GraphicBuffer(buffer)->decStrong((void*)AHardwareBuffer_release);
}

void AHardwareBuffer_describe(const AHardwareBuffer* buffer,
        AHardwareBuffer_Desc* outDesc) {
    if (!buffer || !outDesc) return;

    const GraphicBuffer* gbuffer = AHardwareBuffer_to_GraphicBuffer(buffer);

    outDesc->width = gbuffer->getWidth();
    outDesc->height = gbuffer->getHeight();
    outDesc->layers = gbuffer->getLayerCount();
    AHardwareBuffer_convertFromGrallocUsageBits(&outDesc->usage0, &outDesc->usage1,
            gbuffer->getUsage(), gbuffer->getUsage());
    outDesc->format = AHardwareBuffer_convertFromPixelFormat(
            static_cast<uint32_t>(gbuffer->getPixelFormat()));
}

int AHardwareBuffer_lock(AHardwareBuffer* buffer, uint64_t usage0,
        int32_t fence, const ARect* rect, void** outVirtualAddress) {
    if (!buffer) return BAD_VALUE;

    if (usage0 & ~(AHARDWAREBUFFER_USAGE0_CPU_READ_OFTEN |
                   AHARDWAREBUFFER_USAGE0_CPU_WRITE_OFTEN)) {
        ALOGE("Invalid usage flags passed to AHardwareBuffer_lock; only "
                " AHARDWAREBUFFER_USAGE0_CPU_* flags are allowed");
        return BAD_VALUE;
    }

    uint64_t producerUsage = 0;
    uint64_t consumerUsage = 0;
    AHardwareBuffer_convertToGrallocUsageBits(&producerUsage, &consumerUsage, usage0, 0);
    GraphicBuffer* gBuffer = AHardwareBuffer_to_GraphicBuffer(buffer);
    Rect bounds;
    if (!rect) {
        bounds.set(Rect(gBuffer->getWidth(), gBuffer->getHeight()));
    } else {
        bounds.set(Rect(rect->left, rect->top, rect->right, rect->bottom));
    }
    return gBuffer->lockAsync(producerUsage, consumerUsage, bounds,
            outVirtualAddress, fence);
}

int AHardwareBuffer_unlock(AHardwareBuffer* buffer, int32_t* fence) {
    if (!buffer) return BAD_VALUE;

    GraphicBuffer* gBuffer = AHardwareBuffer_to_GraphicBuffer(buffer);
    return gBuffer->unlockAsync(fence);
}

int AHardwareBuffer_sendHandleToUnixSocket(const AHardwareBuffer* buffer,
        int socketFd) {
    if (!buffer) return BAD_VALUE;
    const GraphicBuffer* gBuffer = AHardwareBuffer_to_GraphicBuffer(buffer);

    size_t flattenedSize = gBuffer->getFlattenedSize();
    size_t fdCount = gBuffer->getFdCount();

    std::unique_ptr<uint8_t[]> data(new uint8_t[flattenedSize]);
    std::unique_ptr<int[]> fds(new int[fdCount]);

    // Make copies of needed items since flatten modifies them, and we don't
    // want to send anything if there's an error during flatten.
    size_t flattenedSizeCopy = flattenedSize;
    size_t fdCountCopy = fdCount;
    void* dataStart = data.get();
    int* fdsStart = fds.get();
    status_t err = gBuffer->flatten(dataStart, flattenedSizeCopy, fdsStart,
            fdCountCopy);
    if (err != NO_ERROR) {
        return err;
    }

    struct iovec iov[1];
    iov[0].iov_base = data.get();
    iov[0].iov_len = flattenedSize;

    char buf[CMSG_SPACE(kDataBufferSize)];
    struct msghdr msg = {
            .msg_control = buf,
            .msg_controllen = sizeof(buf),
            .msg_iov = &iov[0],
            .msg_iovlen = 1,
    };

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fdCount);
    int* fdData = reinterpret_cast<int*>(CMSG_DATA(cmsg));
    memcpy(fdData, fds.get(), sizeof(int) * fdCount);
    msg.msg_controllen = cmsg->cmsg_len;

    int result = sendmsg(socketFd, &msg, 0);
    if (result <= 0) {
        ALOGE("Error writing AHardwareBuffer to socket: error %#x (%s)",
                result, strerror(errno));
        return result;
    }
    return NO_ERROR;
}

int AHardwareBuffer_recvHandleFromUnixSocket(int socketFd,
        AHardwareBuffer** outBuffer) {
    if (!outBuffer) return BAD_VALUE;

    char dataBuf[CMSG_SPACE(kDataBufferSize)];
    char fdBuf[CMSG_SPACE(kDataBufferSize)];
    struct iovec iov[1];
    iov[0].iov_base = dataBuf;
    iov[0].iov_len = sizeof(dataBuf);

    struct msghdr msg = {
            .msg_control = fdBuf,
            .msg_controllen = sizeof(fdBuf),
            .msg_iov = &iov[0],
            .msg_iovlen = 1,
    };

    int result = recvmsg(socketFd, &msg, 0);
    if (result <= 0) {
        ALOGE("Error reading AHardwareBuffer from socket: error %#x (%s)",
                result, strerror(errno));
        return result;
    }

    if (msg.msg_iovlen != 1) {
        ALOGE("Error reading AHardwareBuffer from socket: bad data length");
        return INVALID_OPERATION;
    }

    if (msg.msg_controllen % sizeof(int) != 0) {
        ALOGE("Error reading AHardwareBuffer from socket: bad fd length");
        return INVALID_OPERATION;
    }

    size_t dataLen = msg.msg_iov[0].iov_len;
    const void* data = static_cast<const void*>(msg.msg_iov[0].iov_base);
    if (!data) {
        ALOGE("Error reading AHardwareBuffer from socket: no buffer data");
        return INVALID_OPERATION;
    }

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) {
        ALOGE("Error reading AHardwareBuffer from socket: no fd header");
        return INVALID_OPERATION;
    }

    size_t fdCount = msg.msg_controllen >> 2;
    const int* fdData = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
    if (!fdData) {
        ALOGE("Error reading AHardwareBuffer from socket: no fd data");
        return INVALID_OPERATION;
    }

    GraphicBuffer* gBuffer = new GraphicBuffer();
    status_t err = gBuffer->unflatten(data, dataLen, fdData, fdCount);
    if (err != NO_ERROR) {
        return err;
    }
    *outBuffer = AHardwareBuffer_from_GraphicBuffer(gBuffer);
    // Ensure the buffer has a positive ref-count.
    AHardwareBuffer_acquire(*outBuffer);

    return NO_ERROR;
}

const struct native_handle* AHardwareBuffer_getNativeHandle(
        const AHardwareBuffer* buffer) {
    if (!buffer) return nullptr;
    const GraphicBuffer* gbuffer = AHardwareBuffer_to_GraphicBuffer(buffer);
    return gbuffer->handle;
}


// ----------------------------------------------------------------------------
// Helpers implementation
// ----------------------------------------------------------------------------

namespace android {

// A 1:1 mapping of AHardwaqreBuffer bitmasks to gralloc1 bitmasks.
struct UsageMaskMapping {
    uint64_t hardwareBufferMask;
    uint64_t grallocMask;
};

static constexpr UsageMaskMapping kUsage0ProducerMapping[] = {
    { AHARDWAREBUFFER_USAGE0_CPU_WRITE, GRALLOC1_PRODUCER_USAGE_CPU_WRITE },
    { AHARDWAREBUFFER_USAGE0_CPU_WRITE_OFTEN, GRALLOC1_PRODUCER_USAGE_CPU_WRITE_OFTEN },
    { AHARDWAREBUFFER_USAGE0_GPU_COLOR_OUTPUT, GRALLOC1_PRODUCER_USAGE_GPU_RENDER_TARGET },
    { AHARDWAREBUFFER_USAGE0_PROTECTED_CONTENT, GRALLOC1_PRODUCER_USAGE_PROTECTED },
    { AHARDWAREBUFFER_USAGE0_SENSOR_DIRECT_DATA, GRALLOC1_PRODUCER_USAGE_SENSOR_DIRECT_DATA },
};

static constexpr UsageMaskMapping kUsage1ProducerMapping[] = {
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_0, GRALLOC1_PRODUCER_USAGE_PRIVATE_0 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_1, GRALLOC1_PRODUCER_USAGE_PRIVATE_1 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_2, GRALLOC1_PRODUCER_USAGE_PRIVATE_2 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_3, GRALLOC1_PRODUCER_USAGE_PRIVATE_3 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_4, GRALLOC1_PRODUCER_USAGE_PRIVATE_4 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_5, GRALLOC1_PRODUCER_USAGE_PRIVATE_5 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_6, GRALLOC1_PRODUCER_USAGE_PRIVATE_6 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_7, GRALLOC1_PRODUCER_USAGE_PRIVATE_7 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_8, GRALLOC1_PRODUCER_USAGE_PRIVATE_8 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_9, GRALLOC1_PRODUCER_USAGE_PRIVATE_9 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_10, GRALLOC1_PRODUCER_USAGE_PRIVATE_10 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_11, GRALLOC1_PRODUCER_USAGE_PRIVATE_11 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_12, GRALLOC1_PRODUCER_USAGE_PRIVATE_12 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_13, GRALLOC1_PRODUCER_USAGE_PRIVATE_13 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_14, GRALLOC1_PRODUCER_USAGE_PRIVATE_14 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_15, GRALLOC1_PRODUCER_USAGE_PRIVATE_15 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_16, GRALLOC1_PRODUCER_USAGE_PRIVATE_16 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_17, GRALLOC1_PRODUCER_USAGE_PRIVATE_17 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_18, GRALLOC1_PRODUCER_USAGE_PRIVATE_18 },
    { AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_19, GRALLOC1_PRODUCER_USAGE_PRIVATE_19 },
};

static constexpr UsageMaskMapping kUsage0ConsumerMapping[] = {
    { AHARDWAREBUFFER_USAGE0_CPU_READ, GRALLOC1_CONSUMER_USAGE_CPU_READ },
    { AHARDWAREBUFFER_USAGE0_CPU_READ_OFTEN, GRALLOC1_CONSUMER_USAGE_CPU_READ_OFTEN },
    { AHARDWAREBUFFER_USAGE0_GPU_SAMPLED_IMAGE, GRALLOC1_CONSUMER_USAGE_GPU_TEXTURE },
    { AHARDWAREBUFFER_USAGE0_GPU_DATA_BUFFER, GRALLOC1_CONSUMER_USAGE_GPU_DATA_BUFFER },
    { AHARDWAREBUFFER_USAGE0_VIDEO_ENCODE, GRALLOC1_CONSUMER_USAGE_VIDEO_ENCODER },
};

static constexpr UsageMaskMapping kUsage1ConsumerMapping[] = {
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_0, GRALLOC1_CONSUMER_USAGE_PRIVATE_0 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_1, GRALLOC1_CONSUMER_USAGE_PRIVATE_1 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_2, GRALLOC1_CONSUMER_USAGE_PRIVATE_2 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_3, GRALLOC1_CONSUMER_USAGE_PRIVATE_3 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_4, GRALLOC1_CONSUMER_USAGE_PRIVATE_4 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_5, GRALLOC1_CONSUMER_USAGE_PRIVATE_5 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_6, GRALLOC1_CONSUMER_USAGE_PRIVATE_6 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_7, GRALLOC1_CONSUMER_USAGE_PRIVATE_7 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_8, GRALLOC1_CONSUMER_USAGE_PRIVATE_8 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_9, GRALLOC1_CONSUMER_USAGE_PRIVATE_9 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_10, GRALLOC1_CONSUMER_USAGE_PRIVATE_10 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_11, GRALLOC1_CONSUMER_USAGE_PRIVATE_11 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_12, GRALLOC1_CONSUMER_USAGE_PRIVATE_12 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_13, GRALLOC1_CONSUMER_USAGE_PRIVATE_13 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_14, GRALLOC1_CONSUMER_USAGE_PRIVATE_14 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_15, GRALLOC1_CONSUMER_USAGE_PRIVATE_15 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_16, GRALLOC1_CONSUMER_USAGE_PRIVATE_16 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_17, GRALLOC1_CONSUMER_USAGE_PRIVATE_17 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_18, GRALLOC1_CONSUMER_USAGE_PRIVATE_18 },
    { AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_19, GRALLOC1_CONSUMER_USAGE_PRIVATE_19 },
};

static inline bool containsBits(uint64_t mask, uint64_t bitsToCheck) {
    return (mask & bitsToCheck) == bitsToCheck && bitsToCheck;
}

uint32_t AHardwareBuffer_convertFromPixelFormat(uint32_t format) {
    switch (format) {
        case HAL_PIXEL_FORMAT_RGBA_8888:    return AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM;
        case HAL_PIXEL_FORMAT_RGBX_8888:    return AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM;
        case HAL_PIXEL_FORMAT_RGB_565:      return AHARDWAREBUFFER_FORMAT_R5G6B5_UNORM;
        case HAL_PIXEL_FORMAT_RGB_888:      return AHARDWAREBUFFER_FORMAT_R8G8B8_UNORM;
        case HAL_PIXEL_FORMAT_RGBA_FP16:    return AHARDWAREBUFFER_FORMAT_R16G16B16A16_SFLOAT;
        case HAL_PIXEL_FORMAT_RGBA_1010102: return AHARDWAREBUFFER_FORMAT_A2R10G10B10_UNORM_PACK32;
        case HAL_PIXEL_FORMAT_BLOB:         return AHARDWAREBUFFER_FORMAT_BLOB;
        default:ALOGE("Unknown pixel format %u", format);
            return 0;
    }
}

uint32_t AHardwareBuffer_convertToPixelFormat(uint32_t format) {
    switch (format) {
        case AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM:         return HAL_PIXEL_FORMAT_RGBA_8888;
        case AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM:         return HAL_PIXEL_FORMAT_RGBX_8888;
        case AHARDWAREBUFFER_FORMAT_R5G6B5_UNORM:           return HAL_PIXEL_FORMAT_RGB_565;
        case AHARDWAREBUFFER_FORMAT_R8G8B8_UNORM:           return HAL_PIXEL_FORMAT_RGB_888;
        case AHARDWAREBUFFER_FORMAT_R16G16B16A16_SFLOAT:    return HAL_PIXEL_FORMAT_RGBA_FP16;
        case AHARDWAREBUFFER_FORMAT_A2R10G10B10_UNORM_PACK32: return HAL_PIXEL_FORMAT_RGBA_1010102;
        case AHARDWAREBUFFER_FORMAT_BLOB:                   return HAL_PIXEL_FORMAT_BLOB;
        default:ALOGE("Unknown AHardwareBuffer format %u", format);
            return 0;
    }
}

void AHardwareBuffer_convertToGrallocUsageBits(uint64_t* outProducerUsage,
    uint64_t* outConsumerUsage, uint64_t usage0, uint64_t usage1) {
    *outProducerUsage = 0;
    *outConsumerUsage = 0;
    for (const UsageMaskMapping& mapping : kUsage0ProducerMapping) {
        if (containsBits(usage0, mapping.hardwareBufferMask)) {
            *outProducerUsage |= mapping.grallocMask;
        }
    }
    for (const UsageMaskMapping& mapping : kUsage1ProducerMapping) {
        if (containsBits(usage1, mapping.hardwareBufferMask)) {
            *outProducerUsage |= mapping.grallocMask;
        }
    }
    for (const UsageMaskMapping& mapping : kUsage0ConsumerMapping) {
        if (containsBits(usage0, mapping.hardwareBufferMask)) {
            *outConsumerUsage |= mapping.grallocMask;
        }
    }
    for (const UsageMaskMapping& mapping : kUsage1ConsumerMapping) {
        if (containsBits(usage1, mapping.hardwareBufferMask)) {
            *outConsumerUsage |= mapping.grallocMask;
        }
    }
}

void AHardwareBuffer_convertFromGrallocUsageBits(uint64_t* outUsage0, uint64_t* outUsage1,
        uint64_t producerUsage, uint64_t consumerUsage) {
    *outUsage0 = 0;
    *outUsage1 = 0;
    for (const UsageMaskMapping& mapping : kUsage0ProducerMapping) {
        if (containsBits(producerUsage, mapping.grallocMask)) {
            *outUsage0 |= mapping.hardwareBufferMask;
        }
    }
    for (const UsageMaskMapping& mapping : kUsage1ProducerMapping) {
        if (containsBits(producerUsage, mapping.grallocMask)) {
            *outUsage1 |= mapping.hardwareBufferMask;
        }
    }
    for (const UsageMaskMapping& mapping : kUsage0ConsumerMapping) {
        if (containsBits(consumerUsage, mapping.grallocMask)) {
            *outUsage0 |= mapping.hardwareBufferMask;
        }
    }
    for (const UsageMaskMapping& mapping : kUsage1ConsumerMapping) {
        if (containsBits(consumerUsage, mapping.grallocMask)) {
            *outUsage1 |= mapping.hardwareBufferMask;
        }
    }
}

const GraphicBuffer* AHardwareBuffer_to_GraphicBuffer(const AHardwareBuffer* buffer) {
    return reinterpret_cast<const GraphicBuffer*>(buffer);
}

GraphicBuffer* AHardwareBuffer_to_GraphicBuffer(AHardwareBuffer* buffer) {
    return reinterpret_cast<GraphicBuffer*>(buffer);
}

const ANativeWindowBuffer* AHardwareBuffer_to_ANativeWindowBuffer(const AHardwareBuffer* buffer) {
    return AHardwareBuffer_to_GraphicBuffer(buffer)->getNativeBuffer();
}

ANativeWindowBuffer* AHardwareBuffer_to_ANativeWindowBuffer(AHardwareBuffer* buffer) {
    return AHardwareBuffer_to_GraphicBuffer(buffer)->getNativeBuffer();
}

AHardwareBuffer* AHardwareBuffer_from_GraphicBuffer(GraphicBuffer* buffer) {
    return reinterpret_cast<AHardwareBuffer*>(buffer);
}

} // namespace android
