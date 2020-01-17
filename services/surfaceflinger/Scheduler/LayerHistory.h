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

class LayerHistoryTest;
class LayerInfo;

class LayerHistory {
public:
    virtual ~LayerHistory() = default;

    // Layers are unregistered when the weak reference expires.
    virtual void registerLayer(Layer*, float lowRefreshRate, float highRefreshRate) = 0;

    // Marks the layer as active, and records the given state to its history.
    virtual void record(Layer*, nsecs_t presentTime, nsecs_t now) = 0;

    struct Summary {
        float maxRefreshRate; // Maximum refresh rate among recently active layers.
    };

    // Rebuilds sets of active/inactive layers, and accumulates stats for active layers.
    virtual Summary summarize(nsecs_t now) = 0;

    virtual void clear() = 0;

    // Checks whether any of the active layers have a desired frame rate bit set on them.
    virtual bool hasClientSpecifiedFrameRate() = 0;
};

namespace impl {
// Records per-layer history of scheduling-related information (primarily present time),
// heuristically categorizes layers as active or inactive, and summarizes stats about
// active layers (primarily maximum refresh rate). See go/content-fps-detection-in-scheduler.
class LayerHistory : public android::scheduler::LayerHistory {
public:
    LayerHistory();
    virtual ~LayerHistory();

    // Layers are unregistered when the weak reference expires.
    void registerLayer(Layer*, float lowRefreshRate, float highRefreshRate) override;

    // Marks the layer as active, and records the given state to its history.
    void record(Layer*, nsecs_t presentTime, nsecs_t now) override;

    // Rebuilds sets of active/inactive layers, and accumulates stats for active layers.
    android::scheduler::LayerHistory::Summary summarize(nsecs_t now) override;

    void clear() override;

    // Traverses all active layers and checks whether any of them have a desired frame
    // rate bit set on them.
    bool hasClientSpecifiedFrameRate() override;

private:
    friend class android::scheduler::LayerHistoryTest;
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

    // Whether to use priority sent from WindowManager to determine the relevancy of the layer.
    const bool mUseFrameRatePriority;
};

} // namespace impl
} // namespace scheduler
} // namespace android
