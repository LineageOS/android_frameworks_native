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

#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/impl/Output.h>
#include <ui/Rect.h>

#include "RenderArea.h"

namespace android {

struct ScreenCaptureOutputArgs {
    const compositionengine::CompositionEngine& compositionEngine;
    const compositionengine::Output::ColorProfile& colorProfile;
    const RenderArea& renderArea;
    ui::LayerStack layerStack;
    std::shared_ptr<renderengine::ExternalTexture> buffer;
    float sdrWhitePointNits;
    float displayBrightnessNits;
    // Counterintuitively, when targetBrightness > 1.0 then dim the scene.
    float targetBrightness;
    bool regionSampling;
    bool treat170mAsSrgb;
    bool dimInGammaSpaceForEnhancedScreenshots;
    bool isProtected = false;
    bool enableLocalTonemapping = false;
};

// ScreenCaptureOutput is used to compose a set of layers into a preallocated buffer.
//
// SurfaceFlinger passes instances of ScreenCaptureOutput to CompositionEngine in calls to
// SurfaceFlinger::captureLayers and SurfaceFlinger::captureDisplay.
class ScreenCaptureOutput : public compositionengine::impl::Output {
public:
    ScreenCaptureOutput(const RenderArea& renderArea,
                        const compositionengine::Output::ColorProfile& colorProfile,
                        bool regionSampling, bool dimInGammaSpaceForEnhancedScreenshots,
                        bool enableLocalTonemapping);

    void updateColorProfile(const compositionengine::CompositionRefreshArgs&) override;

    std::vector<compositionengine::LayerFE::LayerSettings> generateClientCompositionRequests(
            bool supportsProtectedContent, ui::Dataspace outputDataspace,
            std::vector<compositionengine::LayerFE*>& outLayerFEs) override;

protected:
    bool getSkipColorTransform() const override { return false; }
    renderengine::DisplaySettings generateClientCompositionDisplaySettings(
            const std::shared_ptr<renderengine::ExternalTexture>& buffer) const override;

private:
    const RenderArea& mRenderArea;
    const compositionengine::Output::ColorProfile& mColorProfile;
    const bool mRegionSampling;
    const bool mDimInGammaSpaceForEnhancedScreenshots;
    const bool mEnableLocalTonemapping;
};

std::shared_ptr<ScreenCaptureOutput> createScreenCaptureOutput(ScreenCaptureOutputArgs);

} // namespace android
