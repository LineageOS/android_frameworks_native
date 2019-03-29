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

namespace android {

ANDROID_SINGLETON_STATIC_INSTANCE(BufferStateLayerCache);

BufferStateLayerCache::BufferStateLayerCache() : mDeathRecipient(new CacheDeathRecipient) {}

void BufferStateLayerCache::add(const sp<IBinder>& processToken, uint64_t id,
                                const sp<GraphicBuffer>& buffer) {
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

    if (processBuffers.size() > BUFFER_CACHE_MAX_SIZE) {
        ALOGE("failed to cache buffer: cache is full");
        return;
    }

    processBuffers[id] = buffer;
}

void BufferStateLayerCache::erase(const sp<IBinder>& processToken, uint64_t id) {
    if (!processToken) {
        ALOGE("failed to uncache buffer: invalid process token");
        return;
    }

    std::lock_guard lock(mMutex);

    if (mBuffers.find(processToken) == mBuffers.end()) {
        ALOGE("failed to uncache buffer: process token not found");
        return;
    }

    auto& processBuffers = mBuffers[processToken];
    processBuffers.erase(id);
}

sp<GraphicBuffer> BufferStateLayerCache::get(const sp<IBinder>& processToken, uint64_t id) {
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

    if (itr->second.find(id) == itr->second.end()) {
        ALOGE("failed to get buffer: buffer not found");
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
