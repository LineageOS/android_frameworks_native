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

#ifndef ANDROID_UI_GRALLOC_ALLOCATOR_H
#define ANDROID_UI_GRALLOC_ALLOCATOR_H

#include <string>

#include <android/hardware/graphics/allocator/2.0/IAllocator.h>
#include <utils/StrongPointer.h>

namespace android {

namespace Gralloc2 {

using hardware::graphics::allocator::V2_0::Error;
using hardware::graphics::allocator::V2_0::ProducerUsage;
using hardware::graphics::allocator::V2_0::ConsumerUsage;
using hardware::graphics::allocator::V2_0::BufferDescriptor;
using hardware::graphics::allocator::V2_0::Buffer;
using hardware::graphics::allocator::V2_0::IAllocator;
using hardware::graphics::allocator::V2_0::IAllocatorClient;
using hardware::graphics::common::V1_0::PixelFormat;

// Allocator is a wrapper to IAllocator, a proxy to server-side allocator.
class Allocator {
public:
    Allocator();

    // this will be removed and Allocator will be always valid
    bool valid() const { return (mAllocator != nullptr); }

    std::string dumpDebugInfo() const;

    Error createBufferDescriptor(
            const IAllocatorClient::BufferDescriptorInfo& descriptorInfo,
            BufferDescriptor& descriptor) const;
    void destroyBufferDescriptor(BufferDescriptor descriptor) const;

    Error allocate(BufferDescriptor descriptor, Buffer& buffer) const;
    void free(Buffer buffer) const;

    Error exportHandle(BufferDescriptor descriptor, Buffer buffer,
            native_handle_t*& bufferHandle) const;

private:
    sp<IAllocator> mAllocator;
    sp<IAllocatorClient> mClient;
};

} // namespace Gralloc2

} // namespace android

#endif // ANDROID_UI_GRALLOC_ALLOCATOR_H
