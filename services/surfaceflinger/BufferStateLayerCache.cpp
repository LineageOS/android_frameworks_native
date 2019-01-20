/*
 * Copyright 2019 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "BufferStateLayerCache"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "BufferStateLayerCache.h"

#define MAX_CACHE_SIZE 64

namespace android {

int32_t BufferStateLayerCache::add(const sp<IBinder>& processToken,
                                   const sp<GraphicBuffer>& buffer) {
    std::lock_guard lock(mMutex);

    auto& processCache = getProccessCache(processToken);

    int32_t slot = findSlot(processCache);
    if (slot < 0) {
        return slot;
    }

    processCache[slot] = buffer;

    return slot;
}

void BufferStateLayerCache::release(const sp<IBinder>& processToken, int32_t id) {
    if (id < 0) {
        ALOGE("invalid buffer id");
        return;
    }

    std::lock_guard lock(mMutex);
    auto& processCache = getProccessCache(processToken);

    if (id >= processCache.size()) {
        ALOGE("invalid buffer id");
        return;
    }
    processCache[id] = nullptr;
}

sp<GraphicBuffer> BufferStateLayerCache::get(const sp<IBinder>& processToken, int32_t id) {
    if (id < 0) {
        ALOGE("invalid buffer id");
        return nullptr;
    }

    std::lock_guard lock(mMutex);
    auto& processCache = getProccessCache(processToken);

    if (id >= processCache.size()) {
        ALOGE("invalid buffer id");
        return nullptr;
    }
    return processCache[id];
}

std::vector<sp<GraphicBuffer>>& BufferStateLayerCache::getProccessCache(
        const sp<IBinder>& processToken) {
    return mBuffers[processToken];
}

int32_t BufferStateLayerCache::findSlot(std::vector<sp<GraphicBuffer>>& processCache) {
    int32_t slot = 0;

    for (const sp<GraphicBuffer> buffer : processCache) {
        if (!buffer) {
            return slot;
        }
        slot++;
    }

    if (processCache.size() < MAX_CACHE_SIZE) {
        processCache.push_back(nullptr);
        return slot;
    }

    return -1;
}

}; // namespace android
