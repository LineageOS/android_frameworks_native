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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "LayerHistory"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "LayerHistory.h"

#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>

#include "../Layer.h"
#include "LayerInfo.h"
#include "SchedulerUtils.h"

namespace android::scheduler::impl {

namespace {

bool isLayerActive(const Layer& layer, const LayerInfo& info, nsecs_t threshold) {
    if (layer.getFrameRate() > .0f) {
        return layer.isVisible();
    }
    return layer.isVisible() && info.getLastUpdatedTime() >= threshold;
}

bool traceEnabled() {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.layer_history_trace", value, "0");
    return atoi(value);
}

bool useFrameRatePriority() {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.use_frame_rate_priority", value, "1");
    return atoi(value);
}

void trace(const wp<Layer>& weak, int fps) {
    const auto layer = weak.promote();
    if (!layer) return;

    const auto& name = layer->getName();
    const auto tag = "LFPS " + name;
    ATRACE_INT(tag.c_str(), fps);
    ALOGD("%s: %s @ %d Hz", __FUNCTION__, name.c_str(), fps);
}

} // namespace

LayerHistory::LayerHistory()
      : mTraceEnabled(traceEnabled()), mUseFrameRatePriority(useFrameRatePriority()) {}
LayerHistory::~LayerHistory() = default;

void LayerHistory::registerLayer(Layer* layer, float lowRefreshRate, float highRefreshRate) {
    auto info = std::make_unique<LayerInfo>(lowRefreshRate, highRefreshRate);
    std::lock_guard lock(mLock);
    mLayerInfos.emplace_back(layer, std::move(info));
}

void LayerHistory::record(Layer* layer, nsecs_t presentTime, nsecs_t now) {
    std::lock_guard lock(mLock);

    const auto it = std::find_if(mLayerInfos.begin(), mLayerInfos.end(),
                                 [layer](const auto& pair) { return pair.first == layer; });
    LOG_FATAL_IF(it == mLayerInfos.end(), "%s: unknown layer %p", __FUNCTION__, layer);

    const auto& info = it->second;
    info->setLastPresentTime(presentTime, now);

    // Activate layer if inactive.
    if (const auto end = activeLayers().end(); it >= end) {
        std::iter_swap(it, end);
        mActiveLayersEnd++;
    }
}

LayerHistory::Summary LayerHistory::summarize(nsecs_t now) {
    float maxRefreshRate = 0;

    std::lock_guard lock(mLock);

    partitionLayers(now);

    // Find the maximum refresh rate among recently active layers.
    for (const auto& [activeLayer, info] : activeLayers()) {
        const bool recent = info->isRecentlyActive(now);

        if (recent || CC_UNLIKELY(mTraceEnabled)) {
            const float refreshRate = info->getRefreshRate(now);
            if (recent && refreshRate > maxRefreshRate) {
                if (const auto layer = activeLayer.promote(); layer) {
                    const int32_t priority = layer->getFrameRateSelectionPriority();
                    // TODO(b/142507166): This is where the scoring algorithm should live.
                    // Layers should be organized by priority
                    ALOGD("Layer has priority: %d", priority);
                }
            }
        }
    }

    for (const auto& [weakLayer, info] : activeLayers()) {
        const bool recent = info->isRecentlyActive(now);
        auto layer = weakLayer.promote();
        // Only use the layer if the reference still exists.
        if (layer || CC_UNLIKELY(mTraceEnabled)) {
            float refreshRate = 0.f;
            // Default content refresh rate is only used when dealing with recent layers.
            if (recent) {
                refreshRate = info->getRefreshRate(now);
            }
            // Check if frame rate was set on layer.
            float frameRate = layer->getFrameRate();
            if (frameRate > 0.f) {
                // Override content detection refresh rate, if it was set.
                refreshRate = frameRate;
            }
            if (refreshRate > maxRefreshRate) {
                maxRefreshRate = refreshRate;
            }

            if (CC_UNLIKELY(mTraceEnabled)) {
                trace(weakLayer, std::round(refreshRate));
            }
        }
    }
    if (CC_UNLIKELY(mTraceEnabled)) {
        ALOGD("%s: maxRefreshRate=%.2f", __FUNCTION__, maxRefreshRate);
    }

    return {maxRefreshRate};
}

void LayerHistory::partitionLayers(nsecs_t now) {
    const nsecs_t threshold = getActiveLayerThreshold(now);

    // Collect expired and inactive layers after active layers.
    size_t i = 0;
    while (i < mActiveLayersEnd) {
        auto& [weak, info] = mLayerInfos[i];
        if (const auto layer = weak.promote(); layer && isLayerActive(*layer, *info, threshold)) {
            i++;
            continue;
        }

        if (CC_UNLIKELY(mTraceEnabled)) {
            trace(weak, 0);
        }

        info->clearHistory();
        std::swap(mLayerInfos[i], mLayerInfos[--mActiveLayersEnd]);
    }

    // Collect expired layers after inactive layers.
    size_t end = mLayerInfos.size();
    while (i < end) {
        if (mLayerInfos[i].first.promote()) {
            i++;
        } else {
            std::swap(mLayerInfos[i], mLayerInfos[--end]);
        }
    }

    mLayerInfos.erase(mLayerInfos.begin() + end, mLayerInfos.end());
}

void LayerHistory::clear() {
    std::lock_guard lock(mLock);

    for (const auto& [layer, info] : activeLayers()) {
        info->clearHistory();
    }

    mActiveLayersEnd = 0;
}

bool LayerHistory::hasClientSpecifiedFrameRate() {
    std::lock_guard lock(mLock);
    for (const auto& [weakLayer, info] : activeLayers()) {
        auto layer = weakLayer.promote();
        if (layer) {
            float frameRate = layer->getFrameRate();
            // Found a layer that has a frame rate set on it.
            if (fabs(frameRate) > 0.f) {
                return true;
            }
        }
    }
    // Did not find any layers that have frame rate.
    return false;
}

} // namespace android::scheduler::impl

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
