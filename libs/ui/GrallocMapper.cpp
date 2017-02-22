/*
 * Copyright 2016 The Android Open Source Project
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

#define LOG_TAG "GrallocMapper"

#include <ui/GrallocMapper.h>

#include <log/log.h>

namespace android {

namespace Gralloc2 {

static constexpr Error kDefaultError = Error::NO_RESOURCES;

Mapper::Mapper()
{
    mMapper = IMapper::getService("gralloc-mapper");
    if (mMapper != nullptr && mMapper->isRemote()) {
        LOG_ALWAYS_FATAL("gralloc-mapper must be in passthrough mode");
    }
}

Error Mapper::retain(buffer_handle_t handle) const
{
    auto ret = mMapper->retain(handle);
    return (ret.isOk()) ? static_cast<Error>(ret) : kDefaultError;
}

void Mapper::release(buffer_handle_t handle) const
{
    auto ret = mMapper->release(handle);

    auto error = (ret.isOk()) ? static_cast<Error>(ret) : kDefaultError;
    ALOGE_IF(error != Error::NONE,
            "release(%p) failed with %d", handle, error);
}

Error Mapper::getDimensions(buffer_handle_t handle,
        uint32_t* outWidth, uint32_t* outHeight) const
{
    Error error = kDefaultError;
    mMapper->getDimensions(handle,
            [&](const auto& tmpError, const auto& tmpWidth,
                    const auto& tmpHeight)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outWidth = tmpWidth;
                *outHeight = tmpHeight;
            });

    return error;
}

Error Mapper::getFormat(buffer_handle_t handle, int32_t* outFormat) const
{
    Error error = kDefaultError;
    mMapper->getFormat(handle,
            [&](const auto& tmpError, const auto& tmpFormat)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outFormat = static_cast<int32_t>(tmpFormat);
            });

    return error;
}

Error Mapper::getLayerCount(buffer_handle_t handle,
        uint32_t* outLayerCount) const
{
    Error error = kDefaultError;
    mMapper->getLayerCount(handle,
            [&](const auto& tmpError, const auto& tmpLayerCount)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outLayerCount = tmpLayerCount;
            });

    return error;
}

Error Mapper::getProducerUsage(buffer_handle_t handle,
    uint64_t* outProducerUsage) const
{
    Error error = kDefaultError;
    mMapper->getProducerUsageMask(handle,
            [&](const auto& tmpError, const auto& tmpProducerUsage)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outProducerUsage = tmpProducerUsage;
            });

    return error;
}

Error Mapper::getConsumerUsage(buffer_handle_t handle,
        uint64_t* outConsumerUsage) const
{
    Error error = kDefaultError;
    mMapper->getConsumerUsageMask(handle,
            [&](const auto& tmpError, const auto& tmpConsumerUsage)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outConsumerUsage = tmpConsumerUsage;
            });

    return error;
}

Error Mapper::getBackingStore(buffer_handle_t handle,
        uint64_t* outBackingStore) const
{
    Error error = kDefaultError;
    mMapper->getBackingStore(handle,
            [&](const auto& tmpError, const auto& tmpStore)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outBackingStore = tmpStore;
            });

    return error;
}

Error Mapper::getStride(buffer_handle_t handle, uint32_t* outStride) const
{
    Error error = kDefaultError;
    mMapper->getStride(handle,
            [&](const auto& tmpError, const auto& tmpStride)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outStride = tmpStride;
            });

    return error;
}

Error Mapper::lock(buffer_handle_t handle,
        uint64_t producerUsage,
        uint64_t consumerUsage,
        const IMapper::Rect& accessRegion,
        int acquireFence, void** outData) const
{
    hardware::hidl_handle acquireFenceHandle;

    NATIVE_HANDLE_DECLARE_STORAGE(acquireFenceStorage, 1, 0);
    if (acquireFence >= 0) {
        auto h = native_handle_init(acquireFenceStorage, 1, 0);
        h->data[0] = acquireFence;
        acquireFenceHandle = h;
    }

    Error error = kDefaultError;
    mMapper->lock(handle, producerUsage, consumerUsage,
            accessRegion, acquireFenceHandle,
            [&](const auto& tmpError, const auto& tmpData)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outData = tmpData;
            });

    if (error == Error::NONE && acquireFence >= 0) {
        close(acquireFence);
    }

    return error;
}

Error Mapper::lock(buffer_handle_t handle,
        uint64_t producerUsage,
        uint64_t consumerUsage,
        const IMapper::Rect& accessRegion,
        int acquireFence, FlexLayout* outLayout) const
{
    hardware::hidl_handle acquireFenceHandle;

    NATIVE_HANDLE_DECLARE_STORAGE(acquireFenceStorage, 1, 0);
    if (acquireFence >= 0) {
        auto h = native_handle_init(acquireFenceStorage, 1, 0);
        h->data[0] = acquireFence;
        acquireFenceHandle = h;
    }

    Error error = kDefaultError;
    mMapper->lockFlex(handle, producerUsage, consumerUsage,
            accessRegion, acquireFenceHandle,
            [&](const auto& tmpError, const auto& tmpLayout)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                *outLayout = tmpLayout;
            });

    if (error == Error::NONE && acquireFence >= 0) {
        close(acquireFence);
    }

    return error;
}

int Mapper::unlock(buffer_handle_t handle) const
{
    int releaseFence = -1;

    Error error = kDefaultError;
    mMapper->unlock(handle,
            [&](const auto& tmpError, const auto& tmpReleaseFence)
            {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                auto fenceHandle = tmpReleaseFence.getNativeHandle();
                if (fenceHandle && fenceHandle->numFds == 1) {
                    int fd = dup(fenceHandle->data[0]);
                    if (fd >= 0) {
                        releaseFence = fd;
                    } else {
                        error = Error::NO_RESOURCES;
                    }
                } else {
                    releaseFence = -1;
                }
            });

    if (error != Error::NONE) {
        ALOGE("unlock(%p) failed with %d", handle, error);
        releaseFence = -1;
    }

    return releaseFence;
}

} // namespace Gralloc2

} // namespace android
