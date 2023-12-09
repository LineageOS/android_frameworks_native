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
#include <gui/LayerState.h>
#include <renderengine/RenderEngine.h>
#include <ui/GraphicBuffer.h>
#include <utils/RefBase.h>
#include <utils/Singleton.h>

#include <map>
#include <mutex>
#include <set>
#include <unordered_map>

// 4096 is based on 64 buffers * 64 layers. Once this limit is reached, the least recently used
// buffer is uncached before the new buffer is cached.
#define BUFFER_CACHE_MAX_SIZE 4096

namespace android {

// This class manages a cache of buffer handles between SurfaceFlinger clients
// and the SurfaceFlinger process which optimizes away some of the cost of
// sending buffer handles across processes.
//
// Buffers are explicitly cached and uncached by the SurfaceFlinger client. When
// a buffer is uncached, it is not only purged from this cache, but the buffer
// ID is also passed down to CompositionEngine to purge it from a similar cache
// used between SurfaceFlinger and Composer HAL. The buffer ID used to purge
// both the SurfaceFlinger side of this other cache, as well as Composer HAL's
// side of the cache.
//
class ClientCache : public Singleton<ClientCache> {
public:
    ClientCache();

    enum class AddError { CacheFull, Unspecified };

    base::expected<std::shared_ptr<renderengine::ExternalTexture>, AddError> add(
            const client_cache_t& cacheId, const sp<GraphicBuffer>& buffer);

    sp<GraphicBuffer> erase(const client_cache_t& cacheId);

    std::shared_ptr<renderengine::ExternalTexture> get(const client_cache_t& cacheId);

    // Always called immediately after setup. Will be set to non-null, and then should never be
    // called again.
    void setRenderEngine(renderengine::RenderEngine* renderEngine) { mRenderEngine = renderEngine; }

    void removeProcess(const wp<IBinder>& processToken);

    class ErasedRecipient : public virtual RefBase {
    public:
        virtual void bufferErased(const client_cache_t& clientCacheId) = 0;
    };

    bool registerErasedRecipient(const client_cache_t& cacheId,
                                 const wp<ErasedRecipient>& recipient);
    void unregisterErasedRecipient(const client_cache_t& cacheId,
                                   const wp<ErasedRecipient>& recipient);

    void dump(std::string& result);

private:
    std::mutex mMutex;

    struct ClientCacheBuffer {
        std::shared_ptr<renderengine::ExternalTexture> buffer;
        std::set<wp<ErasedRecipient>> recipients;
    };
    std::map<wp<IBinder> /*caching process*/,
             std::pair<sp<IBinder> /*strong ref to caching process*/,
                       std::unordered_map<uint64_t /*cache id*/, ClientCacheBuffer>>>
            mBuffers GUARDED_BY(mMutex);

    class CacheDeathRecipient : public IBinder::DeathRecipient {
    public:
        void binderDied(const wp<IBinder>& who) override;
    };

    sp<CacheDeathRecipient> mDeathRecipient;
    renderengine::RenderEngine* mRenderEngine = nullptr;

    bool getBuffer(const client_cache_t& cacheId, ClientCacheBuffer** outClientCacheBuffer)
            REQUIRES(mMutex);
};

}; // namespace android
