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

#pragma once

#include <android-base/thread_annotations.h>
#include <binder/IBinder.h>
#include <ui/GraphicBuffer.h>
#include <utils/RefBase.h>
#include <utils/Singleton.h>

#include <array>
#include <map>
#include <mutex>

#define BUFFER_CACHE_MAX_SIZE 64

namespace android {

class BufferStateLayerCache : public Singleton<BufferStateLayerCache> {
public:
    BufferStateLayerCache();

    void add(const sp<IBinder>& processToken, uint64_t id, const sp<GraphicBuffer>& buffer);
    void erase(const sp<IBinder>& processToken, uint64_t id);

    sp<GraphicBuffer> get(const sp<IBinder>& processToken, uint64_t id);

    void removeProcess(const wp<IBinder>& processToken);

private:
    std::mutex mMutex;
    std::map<wp<IBinder> /*caching process*/, std::map<uint64_t /*Cache id*/, sp<GraphicBuffer>>>
            mBuffers GUARDED_BY(mMutex);

    class CacheDeathRecipient : public IBinder::DeathRecipient {
    public:
        void binderDied(const wp<IBinder>& who) override;
    };

    sp<CacheDeathRecipient> mDeathRecipient;
};

}; // namespace android
