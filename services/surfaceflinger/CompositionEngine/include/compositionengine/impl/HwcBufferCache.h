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

#pragma once

#include <cstdint>
#include <stack>
#include <unordered_map>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <gui/BufferQueue.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

#include <utils/StrongPointer.h>

namespace android {

class GraphicBuffer;

namespace compositionengine::impl {

// The buffer cache returns both a slot and the buffer that should be sent to HWC. In cases
// where the buffer is already cached, the buffer is a nullptr and will not be sent to HWC as
// an optimization.
struct HwcSlotAndBuffer {
    uint32_t slot;
    sp<GraphicBuffer> buffer;
};

//
// Manages the slot assignments for a buffers stored in Composer HAL's cache.
//
// Cache slots are an optimization when communicating buffer handles to Composer
// HAL. When updating a layer's buffer, we can either send a new buffer handle
// along with it's slot assignment or request the HAL to reuse a buffer handle
// that we've already sent by using the slot assignment. The latter is cheaper
// since it eliminates the overhead to transfer the buffer handle over IPC and
// the overhead for the HAL to clone the handle.
//
class HwcBufferCache {
private:
    static const constexpr size_t kMaxLayerBufferCount = BufferQueue::NUM_BUFFER_SLOTS;

public:
    // public for testing
    // Override buffers don't use the normal cache slots because we don't want them to evict client
    // buffers from the cache. We add an extra slot at the end for the override buffers.
    static const constexpr size_t kOverrideBufferSlot = kMaxLayerBufferCount;

    HwcBufferCache();

    //
    // Given a buffer, return the HWC cache slot and buffer to send to HWC.
    //
    // If the buffer is already in the cache, the buffer is null to optimize away sending HWC the
    // buffer handle.
    //
    HwcSlotAndBuffer getHwcSlotAndBuffer(const sp<GraphicBuffer>& buffer);
    //
    // Given a buffer, return the HWC cache slot and buffer to send to HWC.
    //
    // A special slot number is used for override buffers.
    //
    // If the buffer is already in the cache, the buffer is null to optimize away sending HWC the
    // buffer handle.
    //
    HwcSlotAndBuffer getOverrideHwcSlotAndBuffer(const sp<GraphicBuffer>& buffer);

    //
    // When a client process discards a buffer, it needs to be purged from the HWC cache.
    //
    // Returns the slot number of the buffer, or UINT32_MAX if it wasn't found in the cache.
    //
    uint32_t uncache(uint64_t graphicBufferId);

private:
    uint32_t cache(const sp<GraphicBuffer>& buffer);
    uint32_t getLeastRecentlyUsedSlot();

    struct Cache {
        sp<GraphicBuffer> buffer;
        uint32_t slot;
        // Cache entries are evicted according to least-recently-used when more than
        // kMaxLayerBufferCount unique buffers have been sent to a layer.
        uint64_t lruCounter;
    };

    std::unordered_map<uint64_t, Cache> mCacheByBufferId;
    sp<GraphicBuffer> mLastOverrideBuffer;
    std::stack<uint32_t> mFreeSlots;
    uint64_t mLeastRecentlyUsedCounter;
};

} // namespace compositionengine::impl
} // namespace android
