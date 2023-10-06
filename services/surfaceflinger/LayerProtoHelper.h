/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <layerproto/LayerProtoHeader.h>
#include <renderengine/ExternalTexture.h>

#include <Layer.h>
#include <gui/WindowInfo.h>
#include <math/vec4.h>
#include <ui/BlurRegion.h>
#include <ui/GraphicBuffer.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Transform.h>
#include <cstdint>
#include "FrontEnd/LayerHierarchy.h"
#include "FrontEnd/LayerSnapshot.h"

namespace android {
namespace surfaceflinger {
class LayerProtoHelper {
public:
    static void writePositionToProto(const float x, const float y,
                                     std::function<PositionProto*()> getPositionProto);
    static void writeSizeToProto(const uint32_t w, const uint32_t h,
                                 std::function<SizeProto*()> getSizeProto);
    static void writeToProto(const Rect& rect, std::function<RectProto*()> getRectProto);
    static void writeToProto(const Rect& rect, RectProto* rectProto);
    static void readFromProto(const RectProto& proto, Rect& outRect);
    static void writeToProto(const FloatRect& rect,
                             std::function<FloatRectProto*()> getFloatRectProto);
    static void writeToProto(const Region& region, std::function<RegionProto*()> getRegionProto);
    static void writeToProto(const Region& region, RegionProto* regionProto);
    static void readFromProto(const RegionProto& regionProto, Region& outRegion);
    static void writeToProto(const half4 color, std::function<ColorProto*()> getColorProto);
    // This writeToProto for transform is incorrect, but due to backwards compatibility, we can't
    // update Layers to use it. Use writeTransformToProto for any new transform proto data.
    static void writeToProtoDeprecated(const ui::Transform& transform,
                                       TransformProto* transformProto);
    static void writeTransformToProto(const ui::Transform& transform,
                                      TransformProto* transformProto);
    static void writeToProto(const renderengine::ExternalTexture& buffer,
                             std::function<ActiveBufferProto*()> getActiveBufferProto);
    static void writeToProto(const gui::WindowInfo& inputInfo,
                             const wp<Layer>& touchableRegionBounds,
                             std::function<InputWindowInfoProto*()> getInputWindowInfoProto);
    static void writeToProto(const mat4 matrix, ColorTransformProto* colorTransformProto);
    static void readFromProto(const ColorTransformProto& colorTransformProto, mat4& matrix);
    static void writeToProto(const android::BlurRegion region, BlurRegion*);
    static void readFromProto(const BlurRegion& proto, android::BlurRegion& outRegion);
    static void writeSnapshotToProto(LayerProto* outProto,
                                     const frontend::RequestedLayerState& requestedState,
                                     const frontend::LayerSnapshot& snapshot, uint32_t traceFlags);
    static google::protobuf::RepeatedPtrField<DisplayProto> writeDisplayInfoToProto(
            const display::DisplayMap<ui::LayerStack, frontend::DisplayInfo>& displayInfos);
};

class LayerProtoFromSnapshotGenerator {
public:
    LayerProtoFromSnapshotGenerator(
            const frontend::LayerSnapshotBuilder& snapshotBuilder,
            const display::DisplayMap<ui::LayerStack, frontend::DisplayInfo>& displayInfos,
            const std::unordered_map<uint32_t, sp<Layer>>& legacyLayers, uint32_t traceFlags)
          : mSnapshotBuilder(snapshotBuilder),
            mLegacyLayers(legacyLayers),
            mDisplayInfos(displayInfos),
            mTraceFlags(traceFlags) {}
    LayersProto generate(const frontend::LayerHierarchy& root);

private:
    void writeHierarchyToProto(const frontend::LayerHierarchy& root,
                               frontend::LayerHierarchy::TraversalPath& path);
    frontend::LayerSnapshot* getSnapshot(frontend::LayerHierarchy::TraversalPath& path,
                                         const frontend::RequestedLayerState& layer);

    const frontend::LayerSnapshotBuilder& mSnapshotBuilder;
    const std::unordered_map<uint32_t, sp<Layer>>& mLegacyLayers;
    const display::DisplayMap<ui::LayerStack, frontend::DisplayInfo>& mDisplayInfos;
    uint32_t mTraceFlags;
    LayersProto mLayersProto;
    // winscope expects all the layers, so provide a snapshot even if it not currently drawing
    std::unordered_map<frontend::LayerHierarchy::TraversalPath, frontend::LayerSnapshot,
                       frontend::LayerHierarchy::TraversalPathHash>
            mDefaultSnapshots;
    std::unordered_map<uint32_t /* child unique seq*/, uint32_t /* relative parent unique seq*/>
            mChildToRelativeParent;
    std::unordered_map<uint32_t /* child unique seq*/, uint32_t /* parent unique seq*/>
            mChildToParent;
};

} // namespace surfaceflinger
} // namespace android
