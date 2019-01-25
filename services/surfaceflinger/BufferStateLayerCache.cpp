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

#include <cinttypes>

#include "BufferStateLayerCache.h"

#define VALID_CACHE_ID(id) ((id) >= 0 || (id) < (BUFFER_CACHE_MAX_SIZE))

namespace android {

ANDROID_SINGLETON_STATIC_INSTANCE(BufferStateLayerCache);

BufferStateLayerCache::BufferStateLayerCache() : mDeathRecipient(new CacheDeathRecipient) {}

void BufferStateLayerCache::add(sp<IBinder> processToken, int32_t id,
                                const sp<GraphicBuffer>& buffer) {
    if (!VALID_CACHE_ID(id)) {
        ALOGE("failed to cache buffer: invalid buffer id");
        return;
    }

    if (!processToken) {
        ALOGE("failed to cache buffer: invalid process token");
        return;
    }

    if (!buffer) {
        ALOGE("failed to cache buffer: invalid buffer");
        return;
    }

    std::lock_guard lock(mMutex);

    // If this is a new process token, set a death recipient. If the client process dies, we will
    // get a callback through binderDied.
    if (mBuffers.find(processToken) == mBuffers.end()) {
        status_t err = processToken->linkToDeath(mDeathRecipient);
        if (err != NO_ERROR) {
            ALOGE("failed to cache buffer: could not link to death");
            return;
        }
    }

    auto& processBuffers = mBuffers[processToken];
    processBuffers[id] = buffer;
}

sp<GraphicBuffer> BufferStateLayerCache::get(sp<IBinder> processToken, int32_t id) {
    if (!VALID_CACHE_ID(id)) {
        ALOGE("failed to get buffer: invalid buffer id");
        return nullptr;
    }

    if (!processToken) {
        ALOGE("failed to cache buffer: invalid process token");
        return nullptr;
    }

    std::lock_guard lock(mMutex);
    auto itr = mBuffers.find(processToken);
    if (itr == mBuffers.end()) {
        ALOGE("failed to get buffer: process token not found");
        return nullptr;
    }

    if (id >= itr->second.size()) {
        ALOGE("failed to get buffer: id outside the bounds of the cache");
        return nullptr;
    }

    return itr->second[id];
}

void BufferStateLayerCache::removeProcess(const wp<IBinder>& processToken) {
    std::lock_guard lock(mMutex);
    mBuffers.erase(processToken);
}

void BufferStateLayerCache::CacheDeathRecipient::binderDied(const wp<IBinder>& who) {
    BufferStateLayerCache::getInstance().removeProcess(who);
}

}; // namespace android
