/*
 * Copyright 2022 The Android Open Source Project
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

#include <gui/LayerMetadata.h>

#include "compositionengine/LayerFE.h"
#include "compositionengine/LayerFECompositionState.h"
#include "renderengine/LayerSettings.h"

namespace android {
struct RoundedCornerState {
    RoundedCornerState() = default;
    RoundedCornerState(const FloatRect& cropRect, const vec2& radius)
          : cropRect(cropRect), radius(radius) {}

    // Rounded rectangle in local layer coordinate space.
    FloatRect cropRect = FloatRect();
    // Radius of the rounded rectangle.
    vec2 radius;
    bool hasRoundedCorners() const { return radius.x > 0.0f && radius.y > 0.0f; }
};

// LayerSnapshot stores Layer state used by CompositionEngine and RenderEngine. Composition
// Engine uses a pointer to LayerSnapshot (as LayerFECompositionState*) and the LayerSettings
// passed to Render Engine are created using properties stored on this struct.
struct LayerSnapshot : public compositionengine::LayerFECompositionState {
    int32_t sequence;
    std::string name;
    uint32_t textureName;
    bool contentOpaque;
    RoundedCornerState roundedCorner;
    StretchEffect stretchEffect;
    FloatRect transformedBounds;
    renderengine::ShadowSettings shadowSettings;
    bool premultipliedAlpha;
    bool isHdrY410;
    bool bufferNeedsFiltering;
    ui::Transform transform;
    Rect bufferSize;
    std::shared_ptr<renderengine::ExternalTexture> externalTexture;
    gui::LayerMetadata layerMetadata;
    gui::LayerMetadata relativeLayerMetadata;
    bool contentDirty;
    bool hasReadyFrame;
};

struct CompositionResult {
    // TODO(b/238781169) update CE to no longer pass refreshStartTime to LayerFE::onPreComposition
    // and remove this field.
    nsecs_t refreshStartTime = 0;
    std::vector<ftl::SharedFuture<FenceResult>> releaseFences;
    sp<Fence> lastClientCompositionFence = nullptr;
};

class LayerFE : public virtual RefBase, public virtual compositionengine::LayerFE {
public:
    LayerFE(const std::string& name);

    // compositionengine::LayerFE overrides
    const compositionengine::LayerFECompositionState* getCompositionState() const override;
    bool onPreComposition(nsecs_t refreshStartTime, bool updatingOutputGeometryThisFrame) override;
    void onLayerDisplayed(ftl::SharedFuture<FenceResult>) override;
    const char* getDebugName() const override;
    int32_t getSequence() const override;
    bool hasRoundedCorners() const override;
    void setWasClientComposed(const sp<Fence>&) override;
    const gui::LayerMetadata* getMetadata() const override;
    const gui::LayerMetadata* getRelativeMetadata() const override;
    std::optional<compositionengine::LayerFE::LayerSettings> prepareClientComposition(
            compositionengine::LayerFE::ClientCompositionTargetSettings&) const;
    CompositionResult&& stealCompositionResult();

    std::unique_ptr<LayerSnapshot> mSnapshot;

private:
    std::optional<compositionengine::LayerFE::LayerSettings> prepareClientCompositionInternal(
            compositionengine::LayerFE::ClientCompositionTargetSettings&) const;
    // Modifies the passed in layer settings to clear the contents. If the blackout flag is set,
    // the settings clears the content with a solid black fill.
    void prepareClearClientComposition(LayerFE::LayerSettings&, bool blackout) const;
    void prepareShadowClientComposition(LayerFE::LayerSettings& caster,
                                        const Rect& layerStackRect) const;
    void prepareBufferStateClientComposition(
            compositionengine::LayerFE::LayerSettings&,
            compositionengine::LayerFE::ClientCompositionTargetSettings&) const;
    void prepareEffectsClientComposition(
            compositionengine::LayerFE::LayerSettings&,
            compositionengine::LayerFE::ClientCompositionTargetSettings&) const;

    bool hasEffect() const { return fillsColor() || drawShadows() || hasBlur(); }
    bool hasBufferOrSidebandStream() const;

    bool fillsColor() const;
    bool hasBlur() const;
    bool drawShadows() const;

    const sp<GraphicBuffer> getBuffer() const;

    CompositionResult mCompositionResult;
    std::string mName;
};

} // namespace android
