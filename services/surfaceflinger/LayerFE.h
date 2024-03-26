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

#include <android/gui/CachingHint.h>
#include <gui/LayerMetadata.h>
#include "FrontEnd/LayerSnapshot.h"
#include "compositionengine/LayerFE.h"
#include "compositionengine/LayerFECompositionState.h"
#include "renderengine/LayerSettings.h"
#include "ui/LayerStack.h"

#include <ftl/future.h>

namespace android {

struct CompositionResult {
    std::vector<std::pair<ftl::SharedFuture<FenceResult>, ui::LayerStack>> releaseFences;
    sp<Fence> lastClientCompositionFence = nullptr;
};

class LayerFE : public virtual RefBase, public virtual compositionengine::LayerFE {
public:
    LayerFE(const std::string& name);
    virtual ~LayerFE();

    // compositionengine::LayerFE overrides
    const compositionengine::LayerFECompositionState* getCompositionState() const override;
    bool onPreComposition(bool updatingOutputGeometryThisFrame) override;
    void onLayerDisplayed(ftl::SharedFuture<FenceResult>, ui::LayerStack) override;
    const char* getDebugName() const override;
    int32_t getSequence() const override;
    bool hasRoundedCorners() const override;
    void setWasClientComposed(const sp<Fence>&) override;
    const gui::LayerMetadata* getMetadata() const override;
    const gui::LayerMetadata* getRelativeMetadata() const override;
    std::optional<compositionengine::LayerFE::LayerSettings> prepareClientComposition(
            compositionengine::LayerFE::ClientCompositionTargetSettings&) const;
    CompositionResult&& stealCompositionResult();
    ftl::Future<FenceResult> createReleaseFenceFuture() override;
    void setReleaseFence(const FenceResult& releaseFence) override;
    LayerFE::ReleaseFencePromiseStatus getReleaseFencePromiseStatus() override;

    std::unique_ptr<surfaceflinger::frontend::LayerSnapshot> mSnapshot;

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
    std::promise<FenceResult> mReleaseFence;
    ReleaseFencePromiseStatus mReleaseFencePromiseStatus = ReleaseFencePromiseStatus::UNINITIALIZED;
};

} // namespace android
