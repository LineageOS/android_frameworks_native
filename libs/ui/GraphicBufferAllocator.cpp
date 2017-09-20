/*
**
** Copyright 2009, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "GraphicBufferAllocator"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <ui/GraphicBufferAllocator.h>

#include <stdio.h>

#include <grallocusage/GrallocUsageConversion.h>

#include <log/log.h>
#include <utils/Singleton.h>
#include <utils/String8.h>
#include <utils/Trace.h>

#include <ui/Gralloc2.h>
#include <ui/GraphicBufferMapper.h>

namespace android {
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE( GraphicBufferAllocator )

Mutex GraphicBufferAllocator::sLock;
KeyedVector<buffer_handle_t,
    GraphicBufferAllocator::alloc_rec_t> GraphicBufferAllocator::sAllocList;

GraphicBufferAllocator::GraphicBufferAllocator()
  : mMapper(GraphicBufferMapper::getInstance()),
    mAllocator(std::make_unique<Gralloc2::Allocator>(
                mMapper.getGrallocMapper()))
{
    if (!mAllocator->valid()) {
        mLoader = std::make_unique<Gralloc1::Loader>();
        mDevice = mLoader->getDevice();
    }
}

GraphicBufferAllocator::~GraphicBufferAllocator() {}

void GraphicBufferAllocator::dump(String8& result) const
{
    Mutex::Autolock _l(sLock);
    KeyedVector<buffer_handle_t, alloc_rec_t>& list(sAllocList);
    size_t total = 0;
    const size_t SIZE = 4096;
    char buffer[SIZE];
    snprintf(buffer, SIZE, "Allocated buffers:\n");
    result.append(buffer);
    const size_t c = list.size();
    for (size_t i=0 ; i<c ; i++) {
        const alloc_rec_t& rec(list.valueAt(i));
        if (rec.size) {
            snprintf(buffer, SIZE, "%10p: %7.2f KiB | %4u (%4u) x %4u | %4u | %8X | 0x%" PRIx64
                    " | %s\n",
                    list.keyAt(i), rec.size/1024.0,
                    rec.width, rec.stride, rec.height, rec.layerCount, rec.format,
                    rec.usage, rec.requestorName.c_str());
        } else {
            snprintf(buffer, SIZE, "%10p: unknown     | %4u (%4u) x %4u | %4u | %8X | 0x%" PRIx64
                    " | %s\n",
                    list.keyAt(i),
                    rec.width, rec.stride, rec.height, rec.layerCount, rec.format,
                    rec.usage, rec.requestorName.c_str());
        }
        result.append(buffer);
        total += rec.size;
    }
    snprintf(buffer, SIZE, "Total allocated (estimate): %.2f KB\n", total/1024.0);
    result.append(buffer);

    std::string deviceDump;
    if (mAllocator->valid()) {
        deviceDump = mAllocator->dumpDebugInfo();
    } else {
        deviceDump = mDevice->dump();
    }

    result.append(deviceDump.c_str(), deviceDump.size());
}

void GraphicBufferAllocator::dumpToSystemLog()
{
    String8 s;
    GraphicBufferAllocator::getInstance().dump(s);
    ALOGD("%s", s.string());
}

status_t GraphicBufferAllocator::allocate(uint32_t width, uint32_t height,
        PixelFormat format, uint32_t layerCount, uint64_t usage,
        buffer_handle_t* handle, uint32_t* stride,
        uint64_t graphicBufferId, std::string requestorName)
{
    ATRACE_CALL();

    // make sure to not allocate a N x 0 or 0 x N buffer, since this is
    // allowed from an API stand-point allocate a 1x1 buffer instead.
    if (!width || !height)
        width = height = 1;

    // Ensure that layerCount is valid.
    if (layerCount < 1)
        layerCount = 1;

    gralloc1_error_t error;
    if (mAllocator->valid()) {
        Gralloc2::IMapper::BufferDescriptorInfo info = {};
        info.width = width;
        info.height = height;
        info.layerCount = layerCount;
        info.format = static_cast<Gralloc2::PixelFormat>(format);
        info.usage = usage;
        error = static_cast<gralloc1_error_t>(mAllocator->allocate(info,
                    stride, handle));
        if (error != GRALLOC1_ERROR_NONE) {
            return NO_MEMORY;
        }
    } else {
        uint64_t producerUsage, consumerUsage;
        android_convertGralloc0To1Usage(static_cast<int32_t>(usage), &producerUsage, &consumerUsage);

        auto descriptor = mDevice->createDescriptor();
        error = descriptor->setDimensions(width, height);
        if (error != GRALLOC1_ERROR_NONE) {
            ALOGE("Failed to set dimensions to (%u, %u): %d",
                    width, height, error);
            return BAD_VALUE;
        }
        error = descriptor->setFormat(
                static_cast<android_pixel_format_t>(format));
        if (error != GRALLOC1_ERROR_NONE) {
            ALOGE("Failed to set format to %d: %d", format, error);
            return BAD_VALUE;
        }
        if (mDevice->hasCapability(GRALLOC1_CAPABILITY_LAYERED_BUFFERS)) {
            error = descriptor->setLayerCount(layerCount);
            if (error != GRALLOC1_ERROR_NONE) {
                ALOGE("Failed to set layer count to %u: %d", layerCount, error);
                return BAD_VALUE;
            }
        } else if (layerCount > 1) {
            ALOGE("Failed to set layer count to %u: capability unsupported",
                    layerCount);
            return BAD_VALUE;
        }
        error = descriptor->setProducerUsage(
                static_cast<gralloc1_producer_usage_t>(producerUsage));
        if (error != GRALLOC1_ERROR_NONE) {
            ALOGE("Failed to set producer usage to %" PRIx64 ": %d",
                    producerUsage, error);
            return BAD_VALUE;
        }
        error = descriptor->setConsumerUsage(
                static_cast<gralloc1_consumer_usage_t>(consumerUsage));
        if (error != GRALLOC1_ERROR_NONE) {
            ALOGE("Failed to set consumer usage to %" PRIx64 ": %d",
                    consumerUsage, error);
            return BAD_VALUE;
        }

        error = mDevice->allocate(descriptor, graphicBufferId, handle);
        if (error != GRALLOC1_ERROR_NONE) {
            ALOGE("Failed to allocate (%u x %u) layerCount %u format %d "
                    "producerUsage %" PRIx64 " consumerUsage %" PRIx64 ": %d",
                    width, height, layerCount, format, producerUsage,
                    consumerUsage, error);
            return NO_MEMORY;
        }

        error = mDevice->getStride(*handle, stride);
        if (error != GRALLOC1_ERROR_NONE) {
            ALOGW("Failed to get stride from buffer: %d", error);
        }
    }

    if (error == NO_ERROR) {
        Mutex::Autolock _l(sLock);
        KeyedVector<buffer_handle_t, alloc_rec_t>& list(sAllocList);
        uint32_t bpp = bytesPerPixel(format);
        alloc_rec_t rec;
        rec.width = width;
        rec.height = height;
        rec.stride = *stride;
        rec.format = format;
        rec.layerCount = layerCount;
        rec.usage = usage;
        rec.size = static_cast<size_t>(height * (*stride) * bpp);
        rec.requestorName = std::move(requestorName);
        list.add(*handle, rec);

        return NO_ERROR;
    } else {
        ALOGE("Failed to allocate (%u x %u) layerCount %u format %d "
                "usage %" PRIx64 ": %d",
                width, height, layerCount, format, usage,
                error);
        return NO_MEMORY;
    }
}

status_t GraphicBufferAllocator::free(buffer_handle_t handle)
{
    ATRACE_CALL();

    gralloc1_error_t error;
    if (mAllocator->valid()) {
        error = static_cast<gralloc1_error_t>(mMapper.freeBuffer(handle));
    } else {
        error = mDevice->release(handle);
    }

    if (error != GRALLOC1_ERROR_NONE) {
        ALOGE("Failed to free buffer: %d", error);
    }

    Mutex::Autolock _l(sLock);
    KeyedVector<buffer_handle_t, alloc_rec_t>& list(sAllocList);
    list.removeItem(handle);

    return NO_ERROR;
}

// ---------------------------------------------------------------------------
}; // namespace android
