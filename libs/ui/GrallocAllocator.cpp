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

#define LOG_TAG "GrallocAllocator"

#include <log/log.h>
#include <ui/GrallocAllocator.h>

namespace android {

namespace Gralloc2 {

// assume NO_RESOURCES when Status::isOk returns false
constexpr Error kDefaultError = Error::NO_RESOURCES;

Allocator::Allocator()
{
    mAllocator = IAllocator::getService("gralloc");
    if (mAllocator != nullptr) {
        mAllocator->createClient(
                [&](const auto& tmpError, const auto& tmpClient) {
                    if (tmpError == Error::NONE) {
                        mClient = tmpClient;
                    }
                });
        if (mClient == nullptr) {
            mAllocator.clear();
        }
    }
}

std::string Allocator::dumpDebugInfo() const
{
    std::string info;

    mAllocator->dumpDebugInfo([&](const auto& tmpInfo) {
        info = tmpInfo.c_str();
    });

    return info;
}

Error Allocator::createBufferDescriptor(
        const IAllocatorClient::BufferDescriptorInfo& descriptorInfo,
        BufferDescriptor& descriptor) const
{
    Error error = kDefaultError;
    mClient->createDescriptor(descriptorInfo,
            [&](const auto& tmpError, const auto& tmpDescriptor) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                descriptor = tmpDescriptor;
            });

    return error;
}

void Allocator::destroyBufferDescriptor(BufferDescriptor descriptor) const
{
    mClient->destroyDescriptor(descriptor);
}

Error Allocator::allocate(BufferDescriptor descriptor, Buffer& buffer) const
{
    hardware::hidl_vec<BufferDescriptor> descriptors;
    descriptors.setToExternal(&descriptor, 1);

    Error error = kDefaultError;
    auto status = mClient->allocate(descriptors,
            [&](const auto& tmpError, const auto& tmpBuffers) {
                error = tmpError;
                if (tmpError != Error::NONE) {
                    return;
                }

                buffer = tmpBuffers[0];
            });

    return error;
}

void Allocator::free(Buffer buffer) const
{
    mClient->free(buffer);
}

Error Allocator::exportHandle(BufferDescriptor descriptor, Buffer buffer,
        native_handle_t*& bufferHandle) const
{
    Error error = kDefaultError;
    auto status = mClient->exportHandle(descriptor, buffer,
            [&](const auto& tmpError, const auto& tmpBufferHandle) {
                error = tmpError;
                if (tmpError != Error::NONE) {
                    return;
                }

                bufferHandle = native_handle_clone(tmpBufferHandle);
                if (!bufferHandle) {
                    error = Error::NO_RESOURCES;
                }
            });

    return error;
}

} // namespace Gralloc2

} // namespace android
