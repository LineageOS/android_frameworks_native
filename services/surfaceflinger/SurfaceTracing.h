/*
 * Copyright 2017 The Android Open Source Project
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

#include <layerproto/LayerProtoHeader.h>
#include <utils/Errors.h>

#include <memory>
#include <mutex>
#include <queue>

using namespace android::surfaceflinger;

namespace android {

constexpr auto operator""_MB(unsigned long long const num) {
    return num * 1024 * 1024;
}

/*
 * SurfaceTracing records layer states during surface flinging.
 */
class SurfaceTracing {
public:
    void enable() { enable(kDefaultBufferCapInByte); }
    void enable(size_t bufferSizeInByte);
    status_t disable();
    void traceLayers(const char* where, LayersProto);

    bool isEnabled() const;
    void dump(std::string& result) const;

private:
    static constexpr auto kDefaultBufferCapInByte = 100_MB;
    static constexpr auto kDefaultFileName = "/data/misc/wmtrace/layers_trace.pb";

    class LayersTraceBuffer { // ring buffer
    public:
        size_t size() const { return mSizeInBytes; }
        size_t used() const { return mUsedInBytes; }
        size_t frameCount() const { return mStorage.size(); }

        void reset(size_t newSize);
        void emplace(LayersTraceProto&& proto);
        void flush(LayersTraceFileProto* fileProto);

    private:
        size_t mUsedInBytes = 0U;
        size_t mSizeInBytes = 0U;
        std::queue<LayersTraceProto> mStorage;
    };

    status_t writeProtoFileLocked();

    bool mEnabled = false;
    mutable std::mutex mTraceMutex;
    LayersTraceBuffer mBuffer;
};

} // namespace android
