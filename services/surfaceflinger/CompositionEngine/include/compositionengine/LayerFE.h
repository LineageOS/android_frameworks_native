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

#include <optional>

#include <renderengine/LayerSettings.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

namespace android {

class Fence;

namespace compositionengine {

struct LayerFECompositionState;

// Defines the interface used by the CompositionEngine to make requests
// of the front-end layer
class LayerFE : public virtual RefBase {
public:
    // Called before composition starts. Should return true if this layer has
    // pending updates which would require an extra display refresh cycle to
    // process.
    virtual bool onPreComposition(nsecs_t refreshStartTime) = 0;

    // Latches the output-independent state. If includeGeometry is false, the
    // geometry state can be skipped.
    virtual void latchCompositionState(LayerFECompositionState&, bool includeGeometry) const = 0;

    struct ClientCompositionTargetSettings {
        // The clip region, or visible region that is being rendered to
        const Region& clip;

        // If true, the layer should use an identity transform for its position
        // transform. Used only by the captureScreen API call.
        const bool useIdentityTransform;

        // If set to true, the layer should enable filtering when rendering.
        const bool needsFiltering;

        // If set to true, the buffer is being sent to a destination that is
        // expected to treat the buffer contents as secure.
        const bool isSecure;

        // If set to true, the target buffer has protected content support.
        const bool supportProtectedContent;

        // Modified by each call to prepareClientComposition to indicate the
        // region of the target buffer that should be cleared.
        Region& clearRegion;
    };

    // Returns the LayerSettings to pass to RenderEngine::drawLayers, or
    // nullopt_t if the layer does not render
    virtual std::optional<renderengine::LayerSettings> prepareClientComposition(
            ClientCompositionTargetSettings&) = 0;

    // Called after the layer is displayed to update the presentation fence
    virtual void onLayerDisplayed(const sp<Fence>&) = 0;

    // Gets some kind of identifier for the layer for debug purposes.
    virtual const char* getDebugName() const = 0;
};

} // namespace compositionengine
} // namespace android
