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

#include <mutex>
#include <unordered_map>
#include <vector>

namespace android {

class BufferStateLayerCache {
public:
    int32_t add(const sp<IBinder>& processToken, const sp<GraphicBuffer>& buffer);
    void release(const sp<IBinder>& processToken, int32_t id);

    sp<GraphicBuffer> get(const sp<IBinder>& processToken, int32_t id);

private:
    std::mutex mMutex;

    std::vector<sp<GraphicBuffer>>& getProccessCache(const sp<IBinder>& processToken)
            REQUIRES(mMutex);

    int32_t findSlot(std::vector<sp<GraphicBuffer>>& proccessCache) REQUIRES(mMutex);

    struct IBinderHash {
        std::size_t operator()(const sp<IBinder>& strongPointer) const {
            return std::hash<IBinder*>{}(strongPointer.get());
        }
    };

    std::unordered_map<sp<IBinder> /*caching process*/, std::vector<sp<GraphicBuffer>>, IBinderHash>
            mBuffers GUARDED_BY(mMutex);
};

}; // namespace android
