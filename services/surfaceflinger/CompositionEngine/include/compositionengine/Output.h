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

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include <renderengine/LayerSettings.h>
#include <ui/Fence.h>
#include <ui/GraphicTypes.h>
#include <ui/Region.h>
#include <ui/Transform.h>
#include <utils/StrongPointer.h>

#include "DisplayHardware/DisplayIdentification.h"

namespace HWC2 {
class Layer;
} // namespace HWC2

namespace android::compositionengine {

class DisplayColorProfile;
class Layer;
class LayerFE;
class RenderSurface;
class OutputLayer;

struct CompositionRefreshArgs;
struct LayerFECompositionState;

namespace impl {
struct OutputCompositionState;
} // namespace impl

/**
 * Encapsulates all the state involved with composing layers for an output
 */
class Output {
public:
    using OutputLayers = std::vector<std::unique_ptr<compositionengine::OutputLayer>>;
    using ReleasedLayers = std::vector<wp<LayerFE>>;
    using UniqueFELayerStateMap = std::unordered_map<LayerFE*, LayerFECompositionState*>;

    struct FrameFences {
        sp<Fence> presentFence{Fence::NO_FENCE};
        sp<Fence> clientTargetAcquireFence{Fence::NO_FENCE};
        std::unordered_map<HWC2::Layer*, sp<Fence>> layerFences;
    };

    struct ColorProfile {
        ui::ColorMode mode{ui::ColorMode::NATIVE};
        ui::Dataspace dataspace{ui::Dataspace::UNKNOWN};
        ui::RenderIntent renderIntent{ui::RenderIntent::COLORIMETRIC};
        ui::Dataspace colorSpaceAgnosticDataspace{ui::Dataspace::UNKNOWN};
    };

    virtual ~Output();

    // Returns true if the output is valid. This is meant to be checked post-
    // construction and prior to use, as not everything is set up by the
    // constructor.
    virtual bool isValid() const = 0;

    // Enables (or disables) composition on this output
    virtual void setCompositionEnabled(bool) = 0;

    // Sets the projection state to use
    virtual void setProjection(const ui::Transform&, int32_t orientation, const Rect& frame,
                               const Rect& viewport, const Rect& scissor, bool needsFiltering) = 0;
    // Sets the bounds to use
    virtual void setBounds(const ui::Size&) = 0;

    // Sets the layer stack filtering settings for this output. See
    // belongsInOutput for full details.
    virtual void setLayerStackFilter(uint32_t layerStackId, bool isInternal) = 0;

    // Sets the output color mode
    virtual void setColorProfile(const ColorProfile&) = 0;

    // Outputs a string with a state dump
    virtual void dump(std::string&) const = 0;

    // Gets the debug name for the output
    virtual const std::string& getName() const = 0;

    // Sets a debug name for the output
    virtual void setName(const std::string&) = 0;

    // Gets the current render color mode for the output
    virtual DisplayColorProfile* getDisplayColorProfile() const = 0;

    // Gets the current render surface for the output
    virtual RenderSurface* getRenderSurface() const = 0;

    using OutputCompositionState = compositionengine::impl::OutputCompositionState;

    // Gets the raw composition state data for the output
    // TODO(lpique): Make this protected once it is only internally called.
    virtual const OutputCompositionState& getState() const = 0;

    // Allows mutable access to the raw composition state data for the output.
    // This is meant to be used by the various functions that are part of the
    // composition process.
    // TODO(lpique): Make this protected once it is only internally called.
    virtual OutputCompositionState& editState() = 0;

    // Gets the dirty region in layer stack space.
    // If repaintEverything is true, this will be the full display bounds.
    virtual Region getDirtyRegion(bool repaintEverything) const = 0;

    // Tests whether a given layerStackId belongs in this output.
    // A layer belongs to the output if its layerStackId matches the of the output layerStackId,
    // unless the layer should display on the primary output only and this is not the primary output

    // A layer belongs to the output if its layerStackId matches. Additionally
    // if the layer should only show in the internal (primary) display only and
    // this output allows that.
    virtual bool belongsInOutput(std::optional<uint32_t> layerStackId, bool internalOnly) const = 0;

    // Returns a pointer to the output layer corresponding to the given layer on
    // this output, or nullptr if the layer does not have one
    virtual OutputLayer* getOutputLayerForLayer(Layer*) const = 0;

    // Creates an OutputLayer instance for this output
    virtual std::unique_ptr<OutputLayer> createOutputLayer(const std::shared_ptr<Layer>&,
                                                           const sp<LayerFE>&) const = 0;

    // Gets the OutputLayer corresponding to the input Layer instance from the
    // current ordered set of output layers. If there is no such layer, a new
    // one is created and returned.
    virtual std::unique_ptr<OutputLayer> getOrCreateOutputLayer(std::shared_ptr<Layer>,
                                                                sp<LayerFE>) = 0;

    // Sets the new ordered set of output layers for this output
    virtual void setOutputLayersOrderedByZ(OutputLayers&&) = 0;

    // Gets the ordered set of output layers for this output
    virtual const OutputLayers& getOutputLayersOrderedByZ() const = 0;

    // Sets the new set of layers being released this frame
    virtual void setReleasedLayers(ReleasedLayers&&) = 0;

    // Takes (moves) the set of layers being released this frame.
    virtual ReleasedLayers takeReleasedLayers() = 0;

    // Prepare the output, updating the OutputLayers used in the output
    virtual void prepare(CompositionRefreshArgs&) = 0;

    // Presents the output, finalizing all composition details
    virtual void present(const CompositionRefreshArgs&) = 0;

    // Latches the front-end layer state for each output layer
    virtual void updateLayerStateFromFE(const CompositionRefreshArgs&) const = 0;

protected:
    virtual void setDisplayColorProfile(std::unique_ptr<DisplayColorProfile>) = 0;
    virtual void setRenderSurface(std::unique_ptr<RenderSurface>) = 0;

    virtual void updateAndWriteCompositionState(const CompositionRefreshArgs&) = 0;
    virtual void setColorTransform(const CompositionRefreshArgs&) = 0;
    virtual void updateColorProfile(const CompositionRefreshArgs&) = 0;
    virtual void beginFrame() = 0;
    virtual void prepareFrame() = 0;
    virtual void devOptRepaintFlash(const CompositionRefreshArgs&) = 0;
    virtual void finishFrame(const CompositionRefreshArgs&) = 0;
    virtual std::optional<base::unique_fd> composeSurfaces(const Region&) = 0;
    virtual void postFramebuffer() = 0;
    virtual void chooseCompositionStrategy() = 0;
    virtual bool getSkipColorTransform() const = 0;
    virtual FrameFences presentAndGetFrameFences() = 0;
    virtual std::vector<renderengine::LayerSettings> generateClientCompositionRequests(
            bool supportsProtectedContent, Region& clearRegion) = 0;
    virtual void appendRegionFlashRequests(
            const Region& flashRegion,
            std::vector<renderengine::LayerSettings>& clientCompositionLayers) = 0;
    virtual void setExpensiveRenderingExpected(bool enabled) = 0;
};

} // namespace android::compositionengine
