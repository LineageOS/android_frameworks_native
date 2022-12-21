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

#include <compositionengine/impl/HwcBufferCache.h>

#include <gui/BufferQueue.h>
#include <ui/GraphicBuffer.h>

namespace android::compositionengine::impl {

HwcBufferCache::HwcBufferCache() {
    for (uint32_t i = kMaxLayerBufferCount; i-- > 0;) {
        mFreeSlots.push(i);
    }
}

HwcSlotAndBuffer HwcBufferCache::getHwcSlotAndBuffer(const sp<GraphicBuffer>& buffer) {
    if (auto i = mCacheByBufferId.find(buffer->getId()); i != mCacheByBufferId.end()) {
        Cache& cache = i->second;
        // mark this cache slot as more recently used so it won't get evicted anytime soon
        cache.lruCounter = mLeastRecentlyUsedCounter++;
        return {cache.slot, nullptr};
    }
    return {cache(buffer), buffer};
}

HwcSlotAndBuffer HwcBufferCache::getOverrideHwcSlotAndBuffer(const sp<GraphicBuffer>& buffer) {
    if (buffer == mLastOverrideBuffer) {
        return {kOverrideBufferSlot, nullptr};
    }
    mLastOverrideBuffer = buffer;
    return {kOverrideBufferSlot, buffer};
}

uint32_t HwcBufferCache::uncache(uint64_t bufferId) {
    if (auto i = mCacheByBufferId.find(bufferId); i != mCacheByBufferId.end()) {
        uint32_t slot = i->second.slot;
        mCacheByBufferId.erase(i);
        mFreeSlots.push(slot);
        return slot;
    }
    if (mLastOverrideBuffer && bufferId == mLastOverrideBuffer->getId()) {
        mLastOverrideBuffer = nullptr;
        return kOverrideBufferSlot;
    }
    return UINT32_MAX;
}

uint32_t HwcBufferCache::cache(const sp<GraphicBuffer>& buffer) {
    Cache cache;
    cache.slot = getLeastRecentlyUsedSlot();
    cache.lruCounter = mLeastRecentlyUsedCounter++;
    cache.buffer = buffer;
    mCacheByBufferId.emplace(buffer->getId(), cache);
    return cache.slot;
}

uint32_t HwcBufferCache::getLeastRecentlyUsedSlot() {
    if (mFreeSlots.empty()) {
        assert(!mCacheByBufferId.empty());
        // evict the least recently used cache entry
        auto cacheToErase = mCacheByBufferId.begin();
        for (auto i = cacheToErase; i != mCacheByBufferId.end(); ++i) {
            if (i->second.lruCounter < cacheToErase->second.lruCounter) {
                cacheToErase = i;
            }
        }
        uint32_t slot = cacheToErase->second.slot;
        mCacheByBufferId.erase(cacheToErase);
        mFreeSlots.push(slot);
    }
    uint32_t slot = mFreeSlots.top();
    mFreeSlots.pop();
    return slot;
}

} // namespace android::compositionengine::impl
