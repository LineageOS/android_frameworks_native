/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_SURFACEINTERCEPTOR_H
#define ANDROID_SURFACEINTERCEPTOR_H

#include <frameworks/native/cmds/surfacereplayer/proto/src/trace.pb.h>

#include <mutex>

namespace android {

class BufferItem;
class Layer;
struct layer_state_t;

constexpr auto DEFAULT_FILENAME = "/data/SurfaceTrace.dat";

/*
 * SurfaceInterceptor intercepts and stores incoming streams of window
 * properties on SurfaceFlinger.
 */
class SurfaceInterceptor {
public:
    // The layer vector is used to capture the inital snapshot in the trace
    void enable(const SortedVector<sp<Layer>>& layers);
    void disable();
    void setOutputFileName(const std::string& OutputFileName);

    void saveLayerUpdates(const Vector<ComposerState>& state, uint32_t flags);
    void saveLayerCreate(const sp<const Layer>& layer);
    void saveLayerDelete(const sp<const Layer>& layer);
    void saveBufferUpdate(const sp<const Layer>& layer, uint32_t width, uint32_t height,
            uint64_t frameNumber);
    void saveVSyncEvent(nsecs_t timestamp);

private:
    void saveExistingLayers(const SortedVector<sp<Layer>>& layers);
    void saveInitialLayerStateLocked(const sp<const Layer>& layer);
    void saveLayerCreateLocked(const sp<const Layer>& layer);
    status_t writeProtoFileLocked();
    const sp<const Layer> getLayer(const sp<const IBinder>& handle);
    const std::string getLayerName(const sp<const Layer>& layer);
    int32_t getLayerId(const sp<const Layer>& layer);
    Increment* addTraceIncrementLocked();

    void addUpdatedLayersLocked(Increment* increment, uint32_t flags,
            const Vector<ComposerState>& stateUpdates);
    void addCreatedLayerLocked(Increment* increment, const sp<const Layer>& layer);
    void addDeletedLayerLocked(Increment* increment, const sp<const Layer>& layer);
    void addUpdatedBufferLocked(Increment* increment, const sp<const Layer>& layer, uint32_t width,
            uint32_t height, uint64_t frameNumber);
    void addUpdatedVsyncLocked(Increment* increment, nsecs_t timestamp);

    Change* addChangeLocked(Transaction* transaction, int32_t layerId);
    void setProtoRectLocked(Rectangle* protoRect, const Rect& rect);
    void addPositionLocked(Transaction* transaction, int32_t layerId, float x, float y);
    void addDepthLocked(Transaction* transaction, int32_t layerId, uint32_t z);
    void addSizeLocked(Transaction* transaction, int32_t layerId, uint32_t w, uint32_t h);
    void addAlphaLocked(Transaction* transaction, int32_t layerId, float alpha);
    void addMatrixLocked(Transaction* transaction, int32_t layerId,
            const layer_state_t::matrix22_t& matrix);
    void addTransparentRegionLocked(Transaction* transaction, int32_t layerId,
            const Region& transRegion);
    void addFlagsLocked(Transaction* transaction, int32_t layerId, uint8_t flags);
    void addLayerStackLocked(Transaction* transaction, int32_t layerId, uint32_t layerStack);
    void addCropLocked(Transaction* transaction, int32_t layerId, const Rect& rect);
    void addDeferTransactionLocked(Transaction* transaction, int32_t layerId,
            const sp<const IBinder>& handle, uint64_t frameNumber);
    void addFinalCropLocked(Transaction* transaction, int32_t layerId, const Rect& rect);
    void addOverrideScalingModeLocked(Transaction* transaction, int32_t layerId,
            int32_t overrideScalingMode);
    void addChangedPropertiesLocked(Transaction* transaction, const layer_state_t& state);

    bool mEnabled {false};
    std::string mOutputFileName {DEFAULT_FILENAME};
    std::mutex mTraceMutex {};
    Trace mTrace {};
};

}

#endif // ANDROID_SURFACEINTERCEPTOR_H
