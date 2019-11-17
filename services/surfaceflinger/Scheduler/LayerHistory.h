/*
 * Copyright 2018 The Android Open Source Project
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
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace android {

class Layer;
class TestableScheduler;

namespace scheduler {

class LayerInfo;

// Records per-layer history of scheduling-related information (primarily present time),
// heuristically categorizes layers as active or inactive, and summarizes stats about
// active layers (primarily maximum refresh rate). See go/content-fps-detection-in-scheduler.
class LayerHistory {
public:
    LayerHistory();
    ~LayerHistory();

    // Layers are unregistered when the weak reference expires.
    void registerLayer(Layer*, float lowRefreshRate, float highRefreshRate);

    // Marks the layer as active, and records the given state to its history.
    void record(Layer*, nsecs_t presentTime, bool isHDR, nsecs_t now);

    struct Summary {
        float maxRefreshRate; // Maximum refresh rate among recently active layers.
        bool isHDR;           // True if any recently active layer has HDR content.
    };

    // Rebuilds sets of active/inactive layers, and accumulates stats for active layers.
    Summary summarize(nsecs_t now);

    void clear();

private:
    friend class LayerHistoryTest;
    friend TestableScheduler;

    using LayerPair = std::pair<wp<Layer>, std::unique_ptr<LayerInfo>>;
    using LayerInfos = std::vector<LayerPair>;

    struct ActiveLayers {
        LayerInfos& infos;
        const size_t index;

        auto begin() { return infos.begin(); }
        auto end() { return begin() + index; }
    };

    ActiveLayers activeLayers() REQUIRES(mLock) { return {mLayerInfos, mActiveLayersEnd}; }

    // Iterates over layers in a single pass, swapping pairs such that active layers precede
    // inactive layers, and inactive layers precede expired layers. Removes expired layers by
    // truncating after inactive layers.
    void partitionLayers(nsecs_t now) REQUIRES(mLock);

    mutable std::mutex mLock;

    // Partitioned such that active layers precede inactive layers. For fast lookup, the few active
    // layers are at the front, and weak pointers are stored in contiguous memory to hit the cache.
    LayerInfos mLayerInfos GUARDED_BY(mLock);
    size_t mActiveLayersEnd GUARDED_BY(mLock) = 0;

    // Whether to emit systrace output and debug logs.
    const bool mTraceEnabled;
};

} // namespace scheduler
} // namespace android
