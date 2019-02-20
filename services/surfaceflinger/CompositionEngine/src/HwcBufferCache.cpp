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
    std::fill(std::begin(mBuffers), std::end(mBuffers),
              std::pair<uint64_t, wp<GraphicBuffer>>(0, nullptr));
}
int HwcBufferCache::getSlot(const sp<GraphicBuffer>& buffer) {
    // search for cached buffer first
    for (int i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
        if (mBuffers[i].second == buffer) {
            return i;
        }
    }

    // use the least-recently used slot
    return getLeastRecentlyUsedSlot();
}

int HwcBufferCache::getLeastRecentlyUsedSlot() {
    auto iter = std::min_element(std::begin(mBuffers), std::end(mBuffers));
    return std::distance(std::begin(mBuffers), iter);
}

void HwcBufferCache::getHwcBuffer(const sp<GraphicBuffer>& buffer, uint32_t* outSlot,
                                  sp<GraphicBuffer>* outBuffer) {
    *outSlot = getSlot(buffer);

    auto& [currentCounter, currentBuffer] = mBuffers[*outSlot];
    if (currentBuffer == buffer) {
        // already cached in HWC, skip sending the buffer
        *outBuffer = nullptr;
        currentCounter = getCounter();
    } else {
        *outBuffer = buffer;

        // update cache
        currentBuffer = buffer;
        currentCounter = getCounter();
    }
}

uint64_t HwcBufferCache::getCounter() {
    return mCounter++;
}
} // namespace android::compositionengine::impl
