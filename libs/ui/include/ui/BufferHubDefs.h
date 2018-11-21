/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_BUFFER_HUB_DEFS_H_
#define ANDROID_BUFFER_HUB_DEFS_H_

#include <atomic>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpacked"
// TODO(b/118893702): remove dependency once DvrNativeBufferMetadata moved out of libdvr
#include <dvr/dvr_api.h>
#pragma clang diagnostic pop

namespace android {

namespace BufferHubDefs {

struct __attribute__((aligned(8))) MetadataHeader {
    // Internal data format, which can be updated as long as the size, padding and field alignment
    // of the struct is consistent within the same ABI. As this part is subject for future updates,
    // it's not stable cross Android version, so don't have it visible from outside of the Android
    // platform (include Apps and vendor HAL).

    // Every client takes up one bit from the higher 32 bits and one bit from the lower 32 bits in
    // buffer_state.
    std::atomic<uint64_t> buffer_state;

    // Every client takes up one bit in fence_state. Only the lower 32 bits are valid. The upper 32
    // bits are there for easier manipulation, but the value should be ignored.
    std::atomic<uint64_t> fence_state;

    // Every client takes up one bit from the higher 32 bits and one bit from the lower 32 bits in
    // active_clients_bit_mask.
    std::atomic<uint64_t> active_clients_bit_mask;

    // The index of the buffer queue where the buffer belongs to.
    uint64_t queue_index;

    // Public data format, which should be updated with caution. See more details in dvr_api.h
    DvrNativeBufferMetadata metadata;
};

static_assert(sizeof(MetadataHeader) == 136, "Unexpected MetadataHeader size");
static constexpr size_t kMetadataHeaderSize = sizeof(MetadataHeader);

} // namespace BufferHubDefs

} // namespace android

#endif // ANDROID_BUFFER_HUB_DEFS_H_
