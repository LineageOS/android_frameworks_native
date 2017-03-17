/*
 * Copyright 2017 The Android Open Source Project
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

/**
 * @file hardware_buffer.h
 */

#ifndef ANDROID_HARDWARE_BUFFER_H
#define ANDROID_HARDWARE_BUFFER_H

#include <inttypes.h>

#include <sys/cdefs.h>

#include <android/rect.h>

__BEGIN_DECLS

/**
 * Buffer pixel formats.
 */
enum {
    /**
     * Corresponding formats:
     *   Vulkan: VK_FORMAT_R8G8B8A8_UNORM
     *   OpenGL ES: GL_RGBA8
     */
    AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM           = 1,

    /**
     * Corresponding formats:
     *   Vulkan: VK_FORMAT_R8G8B8A8_UNORM
     *   OpenGL ES: GL_RGBA8
     */
    AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM           = 2,

    /**
     * Corresponding formats:
     *   Vulkan: VK_FORMAT_R8G8B8_UNORM
     *   OpenGL ES: GL_RGB8
     */
    AHARDWAREBUFFER_FORMAT_R8G8B8_UNORM             = 3,

    /**
     * Corresponding formats:
     *   Vulkan: VK_FORMAT_R5G6B5_UNORM_PACK16
     *   OpenGL ES: GL_RGB565
     */
    AHARDWAREBUFFER_FORMAT_R5G6B5_UNORM             = 4,

    /**
     * Corresponding formats:
     *   Vulkan: VK_FORMAT_R16G16B16A16_SFLOAT
     *   OpenGL ES: GL_RGBA16F
     */
    AHARDWAREBUFFER_FORMAT_R16G16B16A16_SFLOAT      = 0x16,

    /**
     * Corresponding formats:
     *   Vulkan: VK_FORMAT_A2R10G10B10_UNORM_PACK32
     *   OpenGL ES: GL_RGB10_A2
     */
    AHARDWAREBUFFER_FORMAT_A2R10G10B10_UNORM_PACK32 = 0x2b,

    /**
     * An opaque binary blob format that must have height 1, with width equal to
     * the buffer size in bytes.
     */
    AHARDWAREBUFFER_FORMAT_BLOB                     = 0x21,
};

enum {
    /* The buffer will sometimes be read by the CPU */
    AHARDWAREBUFFER_USAGE0_CPU_READ               = 1ULL << 1,
    /* The buffer will often be read by the CPU*/
    AHARDWAREBUFFER_USAGE0_CPU_READ_OFTEN         = 1ULL << 2 |
            AHARDWAREBUFFER_USAGE0_CPU_READ,
    /* The buffer will sometimes be written to by the CPU */
    AHARDWAREBUFFER_USAGE0_CPU_WRITE              = 1ULL << 5,
    /* The buffer will often be written to by the CPU */
    AHARDWAREBUFFER_USAGE0_CPU_WRITE_OFTEN        = 1ULL << 6 |
            AHARDWAREBUFFER_USAGE0_CPU_WRITE,
    /* The buffer will be read from by the GPU */
    AHARDWAREBUFFER_USAGE0_GPU_SAMPLED_IMAGE      = 1ULL << 10,
    /* The buffer will be written to by the GPU */
    AHARDWAREBUFFER_USAGE0_GPU_COLOR_OUTPUT       = 1ULL << 11,
    /* The buffer will be used as a shader storage or uniform buffer object*/
    AHARDWAREBUFFER_USAGE0_GPU_DATA_BUFFER        = 1ULL << 14,
    /* The buffer must not be used outside of a protected hardware path */
    AHARDWAREBUFFER_USAGE0_PROTECTED_CONTENT      = 1ULL << 18,
    /** The buffer will be used for sensor direct data */
    AHARDWAREBUFFER_USAGE0_SENSOR_DIRECT_DATA     = 1ULL << 29,
    /* The buffer will be read by a hardware video encoder */
    AHARDWAREBUFFER_USAGE0_VIDEO_ENCODE           = 1ULL << 21,
};

/* These flags are intended only for use by device-specific graphics drivers. */
enum {
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_19 = 1ULL << 24,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_19 = 1ULL << 25,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_18 = 1ULL << 26,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_18 = 1ULL << 27,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_17 = 1ULL << 28,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_17 = 1ULL << 29,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_16 = 1ULL << 30,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_16 = 1ULL << 31,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_15 = 1ULL << 32,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_15 = 1ULL << 33,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_14 = 1ULL << 34,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_14 = 1ULL << 35,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_13 = 1ULL << 36,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_13 = 1ULL << 37,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_12 = 1ULL << 38,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_12 = 1ULL << 39,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_11 = 1ULL << 40,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_11 = 1ULL << 41,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_10 = 1ULL << 42,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_10 = 1ULL << 43,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_9 = 1ULL << 44,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_9 = 1ULL << 45,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_8 = 1ULL << 46,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_8 = 1ULL << 47,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_7 = 1ULL << 48,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_7 = 1ULL << 49,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_6 = 1ULL << 50,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_6 = 1ULL << 51,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_5 = 1ULL << 52,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_5 = 1ULL << 53,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_4 = 1ULL << 54,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_4 = 1ULL << 55,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_3 = 1ULL << 56,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_3 = 1ULL << 57,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_2 = 1ULL << 58,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_2 = 1ULL << 59,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_1 = 1ULL << 60,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_1 = 1ULL << 61,
    AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_0 = 1ULL << 62,
    AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_0 = 1ULL << 63,
};

typedef struct AHardwareBuffer_Desc {
    uint32_t    width;
    uint32_t    height;
    uint32_t    layers;
    uint32_t    format;     // One of AHARDWAREBUFFER_FORMAT_*
    uint64_t    usage0;     // Combination of AHARDWAREBUFFER_USAGE0_*
    uint64_t    usage1;     // Initialize to zero, reserved for future use
} AHardwareBuffer_Desc;

typedef struct AHardwareBuffer AHardwareBuffer;

/**
 * Allocates a buffer that backs an AHardwareBuffer using the passed
 * AHardwareBuffer_Desc.
 *
 * Returns NO_ERROR on success, or an error number of the allocation fails for
 * any reason.
 */
int AHardwareBuffer_allocate(const AHardwareBuffer_Desc* desc,
        AHardwareBuffer** outBuffer);
/**
 * Acquire a reference on the given AHardwareBuffer object.  This prevents the
 * object from being deleted until the last reference is removed.
 */
void AHardwareBuffer_acquire(AHardwareBuffer* buffer);

/**
 * Remove a reference that was previously acquired with
 * AHardwareBuffer_acquire().
 */
void AHardwareBuffer_release(AHardwareBuffer* buffer);

/**
 * Return a description of the AHardwareBuffer in the passed
 * AHardwareBuffer_Desc struct.
 */
void AHardwareBuffer_describe(const AHardwareBuffer* buffer,
        AHardwareBuffer_Desc* outDesc);

/*
 * Lock the AHardwareBuffer for reading or writing, depending on the usage flags
 * passed.  This call may block if the hardware needs to finish rendering or if
 * CPU caches need to be synchronized, or possibly for other implementation-
 * specific reasons.  If fence is not negative, then it specifies a fence file
 * descriptor that will be signaled when the buffer is locked, otherwise the
 * caller will block until the buffer is available.
 *
 * If rect is not NULL, the caller promises to modify only data in the area
 * specified by rect. If rect is NULL, the caller may modify the contents of the
 * entire buffer.
 *
 * The content of the buffer outside of the specified rect is NOT modified
 * by this call.
 *
 * The buffer usage may only specify AHARDWAREBUFFER_USAGE0_CPU_*. If set, then
 * outVirtualAddress is filled with the address of the buffer in virtual memory,
 * otherwise this function will fail.
 *
 * THREADING CONSIDERATIONS:
 *
 * It is legal for several different threads to lock a buffer for read access;
 * none of the threads are blocked.
 *
 * Locking a buffer simultaneously for write or read/write is undefined, but
 * will neither terminate the process nor block the caller; AHardwareBuffer_lock
 * may return an error or leave the buffer's content into an indeterminate
 * state.
 *
 * Returns NO_ERROR on success, BAD_VALUE if the buffer is NULL or if the usage0
 * flags are not a combination of AHARDWAREBUFFER_USAGE0_CPU_*, or an error
 * number of the lock fails for any reason.
 */
int AHardwareBuffer_lock(AHardwareBuffer* buffer, uint64_t usage0,
        int32_t fence, const ARect* rect, void** outVirtualAddress);

/*
 * Unlock the AHardwareBuffer; must be called after all changes to the buffer
 * are completed by the caller. If fence is not NULL then it will be set to a
 * file descriptor that is signaled when all pending work on the buffer is
 * completed. The caller is responsible for closing the fence when it is no
 * longer needed.
 *
 * Returns NO_ERROR on success, BAD_VALUE if the buffer is NULL, or an error
 * number of the lock fails for any reason.
 */
int AHardwareBuffer_unlock(AHardwareBuffer* buffer, int32_t* fence);

/*
 * Send the AHardwareBuffer to an AF_UNIX socket.
 *
 * Returns NO_ERROR on success, BAD_VALUE if the buffer is NULL, or an error
 * number of the lock fails for any reason.
 */
int AHardwareBuffer_sendHandleToUnixSocket(const AHardwareBuffer* buffer,
        int socketFd);

/*
 * Receive the AHardwareBuffer from an AF_UNIX socket.
 *
 * Returns NO_ERROR on success, BAD_VALUE if the buffer is NULL, or an error
 * number of the lock fails for any reason.
 */
int AHardwareBuffer_recvHandleFromUnixSocket(int socketFd,
        AHardwareBuffer** outBuffer);

// ----------------------------------------------------------------------------
// Everything below here is part of the public NDK API, but is intended only
// for use by device-specific graphics drivers.
struct native_handle;
const struct native_handle* AHardwareBuffer_getNativeHandle(
        const AHardwareBuffer* buffer);

__END_DECLS

#endif // ANDROID_HARDWARE_BUFFER_H
