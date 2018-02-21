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
#undef LOG_TAG
#define LOG_TAG "LayerStats"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "LayerStats.h"
#include "DisplayHardware/HWComposer.h"

#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/String8.h>
#include <utils/Trace.h>

namespace android {

void LayerStats::enable() {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mMutex);
    if (mEnabled) return;
    mLayerStatsMap.clear();
    mEnabled = true;
    ALOGD("Logging enabled");
}

void LayerStats::disable() {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mEnabled) return;
    mEnabled = false;
    ALOGD("Logging disabled");
}

void LayerStats::clear() {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mMutex);
    mLayerStatsMap.clear();
    ALOGD("Cleared current layer stats");
}

bool LayerStats::isEnabled() {
    return mEnabled;
}

void LayerStats::traverseLayerTreeStatsLocked(
        std::vector<std::unique_ptr<LayerProtoParser::Layer>> layerTree,
        const LayerProtoParser::LayerGlobal* layerGlobal) {
    for (std::unique_ptr<LayerProtoParser::Layer>& layer : layerTree) {
        if (!layer) continue;
        traverseLayerTreeStatsLocked(std::move(layer->children), layerGlobal);
        std::string key =
                base::StringPrintf("%s,%s,%s,%s,%s,%s,%s,%s,%s",
                                   destinationLocation(layer->hwcFrame.left,
                                                       layerGlobal->resolution[0], true),
                                   destinationLocation(layer->hwcFrame.top,
                                                       layerGlobal->resolution[1], false),
                                   destinationSize(layer->hwcFrame.right - layer->hwcFrame.left,
                                                   layerGlobal->resolution[0], true),
                                   destinationSize(layer->hwcFrame.bottom - layer->hwcFrame.top,
                                                   layerGlobal->resolution[1], false),
                                   layer->type.c_str(), scaleRatioWH(layer.get()).c_str(),
                                   layerTransform(layer->hwcTransform), layer->pixelFormat.c_str(),
                                   layer->dataspace.c_str());
        mLayerStatsMap[key]++;
    }
}

void LayerStats::logLayerStats(const LayersProto& layersProto) {
    ATRACE_CALL();
    auto layerGlobal = LayerProtoParser::generateLayerGlobalInfo(layersProto);
    auto layerTree = LayerProtoParser::generateLayerTree(layersProto);
    std::lock_guard<std::mutex> lock(mMutex);
    traverseLayerTreeStatsLocked(std::move(layerTree), &layerGlobal);
}

void LayerStats::dump(String8& result) {
    ATRACE_CALL();
    ALOGD("Dumping");
    result.append("Count,DstPosX,DstPosY,DstWidth,DstHeight,LayerType,WScale,HScale,");
    result.append("Transform,PixelFormat,Dataspace\n");
    std::lock_guard<std::mutex> lock(mMutex);
    for (auto& u : mLayerStatsMap) {
        result.appendFormat("%u,%s\n", u.second, u.first.c_str());
    }
}

const char* LayerStats::destinationLocation(int32_t location, int32_t range, bool isHorizontal) {
    static const char* locationArray[8] = {"0", "1/8", "1/4", "3/8", "1/2", "5/8", "3/4", "7/8"};
    int32_t ratio = location * 8 / range;
    if (ratio < 0) return "N/A";
    if (isHorizontal) {
        // X location is divided into 4 buckets {"0", "1/4", "1/2", "3/4"}
        if (ratio > 6) return "3/4";
        // use index 0, 2, 4, 6
        return locationArray[ratio & ~1];
    }
    if (ratio > 7) return "7/8";
    return locationArray[ratio];
}

const char* LayerStats::destinationSize(int32_t size, int32_t range, bool isWidth) {
    static const char* sizeArray[8] = {"1/8", "1/4", "3/8", "1/2", "5/8", "3/4", "7/8", "1"};
    int32_t ratio = size * 8 / range;
    if (ratio < 0) return "N/A";
    if (isWidth) {
        // width is divided into 4 buckets {"1/4", "1/2", "3/4", "1"}
        if (ratio > 6) return "1";
        // use index 1, 3, 5, 7
        return sizeArray[ratio | 1];
    }
    if (ratio > 7) return "1";
    return sizeArray[ratio];
}

const char* LayerStats::layerTransform(int32_t transform) {
    return getTransformName(static_cast<hwc_transform_t>(transform));
}

std::string LayerStats::scaleRatioWH(const LayerProtoParser::Layer* layer) {
    if (!layer->type.compare("ColorLayer")) return "N/A,N/A";
    std::string ret = "";
    if (isRotated(layer->hwcTransform)) {
        ret += scaleRatio(layer->hwcFrame.right - layer->hwcFrame.left,
                          static_cast<int32_t>(layer->hwcCrop.bottom - layer->hwcCrop.top));
        ret += ",";
        ret += scaleRatio(layer->hwcFrame.bottom - layer->hwcFrame.top,
                          static_cast<int32_t>(layer->hwcCrop.right - layer->hwcCrop.left));
    } else {
        ret += scaleRatio(layer->hwcFrame.right - layer->hwcFrame.left,
                          static_cast<int32_t>(layer->hwcCrop.right - layer->hwcCrop.left));
        ret += ",";
        ret += scaleRatio(layer->hwcFrame.bottom - layer->hwcFrame.top,
                          static_cast<int32_t>(layer->hwcCrop.bottom - layer->hwcCrop.top));
    }
    return ret;
}

const char* LayerStats::scaleRatio(int32_t destinationScale, int32_t sourceScale) {
    // Make scale buckets from <1/64 to >= 16, to avoid floating point
    // calculation, x64 on destinationScale first
    int32_t scale = destinationScale * 64 / sourceScale;
    if (!scale) return "<1/64";
    if (scale < 2) return "1/64";
    if (scale < 4) return "1/32";
    if (scale < 8) return "1/16";
    if (scale < 16) return "1/8";
    if (scale < 32) return "1/4";
    if (scale < 64) return "1/2";
    if (scale < 128) return "1";
    if (scale < 256) return "2";
    if (scale < 512) return "4";
    if (scale < 1024) return "8";
    return ">=16";
}

bool LayerStats::isRotated(int32_t transform) {
    return transform & HWC_TRANSFORM_ROT_90;
}

bool LayerStats::isVFlipped(int32_t transform) {
    return transform & HWC_TRANSFORM_FLIP_V;
}

bool LayerStats::isHFlipped(int32_t transform) {
    return transform & HWC_TRANSFORM_FLIP_H;
}

} // namespace android
