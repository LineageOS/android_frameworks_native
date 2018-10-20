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
#include <string>

#include <math/mat4.h>
#include <ui/GraphicTypes.h>
#include <ui/Region.h>
#include <ui/Transform.h>

namespace android::compositionengine {

class RenderSurface;

namespace impl {
struct OutputCompositionState;
} // namespace impl

/**
 * Encapsulates all the state involved with composing layers for an output
 */
class Output {
public:
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

    // Sets the layer stack filter for this output. If singleLayerStack is true,
    // this output displays just the single layer stack specified by
    // singleLayerStackId. Otherwise all layer stacks will be visible on this
    // output.
    virtual void setLayerStackFilter(bool singleLayerStack, uint32_t singleLayerStackId) = 0;

    // Sets the color transform matrix to use
    virtual void setColorTransform(const mat4&) = 0;

    // Sets the output color mode
    virtual void setColorMode(ui::ColorMode, ui::Dataspace, ui::RenderIntent) = 0;

    // Outputs a string with a state dump
    virtual void dump(std::string&) const = 0;

    // Gets the debug name for the output
    virtual const std::string& getName() const = 0;

    // Sets a debug name for the output
    virtual void setName(const std::string&) = 0;

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

    // Gets the physical space dirty region. If repaintEverything is true, this
    // will be the full display bounds. Internally the dirty region is stored in
    // logical (aka layer stack) space.
    virtual Region getPhysicalSpaceDirtyRegion(bool repaintEverything) const = 0;

    // Tests whether a given layerStackId belongs in this output
    virtual bool belongsInOutput(uint32_t layerStackId) const = 0;

protected:
    ~Output() = default;

    virtual void setRenderSurface(std::unique_ptr<RenderSurface> surface) = 0;
};

} // namespace android::compositionengine
