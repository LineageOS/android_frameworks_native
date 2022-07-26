/*
 * Copyright 2022 The Android Open Source Project
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

#include <functional>
#include <mutex>
#include <stack>
#include <unordered_map>

#include "ClientCache.h"

namespace android {

class HwcSlotGenerator : public ClientCache::ErasedRecipient {
public:
    HwcSlotGenerator();
    void bufferErased(const client_cache_t& clientCacheId);
    int getHwcCacheSlot(const client_cache_t& clientCacheId);

private:
    friend class SlotGenerationTest;
    int addCachedBuffer(const client_cache_t& clientCacheId) REQUIRES(mMutex);
    int getFreeHwcCacheSlot() REQUIRES(mMutex);
    void evictLeastRecentlyUsed() REQUIRES(mMutex);
    void eraseBufferLocked(const client_cache_t& clientCacheId) REQUIRES(mMutex);

    struct CachedBufferHash {
        std::size_t operator()(const client_cache_t& clientCacheId) const {
            return std::hash<uint64_t>{}(clientCacheId.id);
        }
    };

    std::mutex mMutex;

    std::unordered_map<client_cache_t, std::pair<int /*HwcCacheSlot*/, uint64_t /*counter*/>,
                       CachedBufferHash>
            mCachedBuffers GUARDED_BY(mMutex);
    std::stack<int /*HwcCacheSlot*/> mFreeHwcCacheSlots GUARDED_BY(mMutex);

    // The cache increments this counter value when a slot is updated or used.
    // Used to track the least recently-used buffer
    uint64_t mCounter = 0;
};
} // namespace android
