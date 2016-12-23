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

#ifndef ANDROID_UI_GRALLOC_MAPPER_H
#define ANDROID_UI_GRALLOC_MAPPER_H

#include <memory>

#include <android/hardware/graphics/mapper/2.0/IMapper.h>
#include <system/window.h>

namespace android {

namespace Gralloc2 {

using hardware::graphics::allocator::V2_0::Error;
using hardware::graphics::allocator::V2_0::ProducerUsage;
using hardware::graphics::allocator::V2_0::ConsumerUsage;
using hardware::graphics::common::V1_0::PixelFormat;
using hardware::graphics::mapper::V2_0::FlexLayout;
using hardware::graphics::mapper::V2_0::BackingStore;
using hardware::graphics::mapper::V2_0::IMapper;

// Mapper is a wrapper to IMapper, a client-side graphics buffer mapper.
class Mapper {
public:
    Mapper();

    // this will be removed and Mapper will be always valid
    bool valid() const { return (mMapper != nullptr); }

    Error retain(buffer_handle_t handle) const;
    void release(buffer_handle_t handle) const;

    Error getStride(buffer_handle_t handle, uint32_t* outStride) const;

    Error lock(buffer_handle_t handle,
            uint64_t producerUsageMask,
            uint64_t consumerUsageMask,
            const IMapper::Rect& accessRegion,
            int acquireFence, void** outData) const;
    Error lock(buffer_handle_t handle,
            uint64_t producerUsageMask,
            uint64_t consumerUsageMask,
            const IMapper::Rect& accessRegion,
            int acquireFence, FlexLayout* outLayout) const;
    int unlock(buffer_handle_t handle) const;

private:
    sp<IMapper> mMapper;
};

} // namespace Gralloc2

} // namespace android

#endif // ANDROID_UI_GRALLOC_MAPPER_H
