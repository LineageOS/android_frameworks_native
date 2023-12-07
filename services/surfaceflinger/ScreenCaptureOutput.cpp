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

#include "ScreenCaptureOutput.h"
#include "ScreenCaptureRenderSurface.h"
#include "ui/Rotation.h"

#include <compositionengine/CompositionEngine.h>
#include <compositionengine/DisplayColorProfileCreationArgs.h>
#include <compositionengine/impl/DisplayColorProfile.h>
#include <ui/Rotation.h>

namespace android {

std::shared_ptr<ScreenCaptureOutput> createScreenCaptureOutput(ScreenCaptureOutputArgs args) {
    std::shared_ptr<ScreenCaptureOutput> output = compositionengine::impl::createOutputTemplated<
            ScreenCaptureOutput, compositionengine::CompositionEngine, const RenderArea&,
            const compositionengine::Output::ColorProfile&,
            bool>(args.compositionEngine, args.renderArea, args.colorProfile, args.regionSampling,
                  args.dimInGammaSpaceForEnhancedScreenshots);
    output->editState().isSecure = args.renderArea.isSecure();
    output->editState().isProtected = args.isProtected;
    output->setCompositionEnabled(true);
    output->setLayerFilter({args.layerStack});
    output->setRenderSurface(std::make_unique<ScreenCaptureRenderSurface>(std::move(args.buffer)));
    output->setDisplayBrightness(args.sdrWhitePointNits, args.displayBrightnessNits);
    output->editState().clientTargetBrightness = args.targetBrightness;
    output->editState().treat170mAsSrgb = args.treat170mAsSrgb;

    output->setDisplayColorProfile(std::make_unique<compositionengine::impl::DisplayColorProfile>(
            compositionengine::DisplayColorProfileCreationArgsBuilder()
                    .setHasWideColorGamut(true)
                    .Build()));

    const Rect& sourceCrop = args.renderArea.getSourceCrop();
    const ui::Rotation orientation = ui::ROTATION_0;
    output->setDisplaySize({sourceCrop.getWidth(), sourceCrop.getHeight()});
    output->setProjection(orientation, sourceCrop,
                          {args.renderArea.getReqWidth(), args.renderArea.getReqHeight()});

    {
        std::string name = args.regionSampling ? "RegionSampling" : "ScreenCaptureOutput";
        if (auto displayDevice = args.renderArea.getDisplayDevice()) {
            base::StringAppendF(&name, " for %" PRIu64, displayDevice->getId().value);
        }
        output->setName(name);
    }
    return output;
}

ScreenCaptureOutput::ScreenCaptureOutput(
        const RenderArea& renderArea, const compositionengine::Output::ColorProfile& colorProfile,
        bool regionSampling, bool dimInGammaSpaceForEnhancedScreenshots)
      : mRenderArea(renderArea),
        mColorProfile(colorProfile),
        mRegionSampling(regionSampling),
        mDimInGammaSpaceForEnhancedScreenshots(dimInGammaSpaceForEnhancedScreenshots) {}

void ScreenCaptureOutput::updateColorProfile(const compositionengine::CompositionRefreshArgs&) {
    auto& outputState = editState();
    outputState.dataspace = mColorProfile.dataspace;
    outputState.renderIntent = mColorProfile.renderIntent;
}

renderengine::DisplaySettings ScreenCaptureOutput::generateClientCompositionDisplaySettings(
        const std::shared_ptr<renderengine::ExternalTexture>& buffer) const {
    auto clientCompositionDisplay =
            compositionengine::impl::Output::generateClientCompositionDisplaySettings(buffer);
    clientCompositionDisplay.clip = mRenderArea.getSourceCrop();

    auto renderIntent = static_cast<ui::RenderIntent>(clientCompositionDisplay.renderIntent);
    if (mDimInGammaSpaceForEnhancedScreenshots && renderIntent != ui::RenderIntent::COLORIMETRIC &&
        renderIntent != ui::RenderIntent::TONE_MAP_COLORIMETRIC) {
        clientCompositionDisplay.dimmingStage =
                aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF;
    }

    return clientCompositionDisplay;
}

std::vector<compositionengine::LayerFE::LayerSettings>
ScreenCaptureOutput::generateClientCompositionRequests(
        bool supportsProtectedContent, ui::Dataspace outputDataspace,
        std::vector<compositionengine::LayerFE*>& outLayerFEs) {
    auto clientCompositionLayers = compositionengine::impl::Output::
            generateClientCompositionRequests(supportsProtectedContent, outputDataspace,
                                              outLayerFEs);

    if (mRegionSampling) {
        for (auto& layer : clientCompositionLayers) {
            layer.backgroundBlurRadius = 0;
            layer.blurRegions.clear();
        }
    }

    if (outputDataspace == ui::Dataspace::BT2020_HLG) {
        for (auto& layer : clientCompositionLayers) {
            auto transfer = layer.sourceDataspace & ui::Dataspace::TRANSFER_MASK;
            if (transfer != static_cast<int32_t>(ui::Dataspace::TRANSFER_HLG) &&
                transfer != static_cast<int32_t>(ui::Dataspace::TRANSFER_ST2084)) {
                layer.whitePointNits *= (1000.0f / 203.0f);
            }
        }
    }

    Rect sourceCrop = mRenderArea.getSourceCrop();
    compositionengine::LayerFE::LayerSettings fillLayer;
    fillLayer.source.buffer.buffer = nullptr;
    fillLayer.source.solidColor = half3(0.0f, 0.0f, 0.0f);
    fillLayer.geometry.boundaries =
            FloatRect(static_cast<float>(sourceCrop.left), static_cast<float>(sourceCrop.top),
                      static_cast<float>(sourceCrop.right), static_cast<float>(sourceCrop.bottom));
    fillLayer.alpha = half(RenderArea::getCaptureFillValue(mRenderArea.getCaptureFill()));
    clientCompositionLayers.insert(clientCompositionLayers.begin(), fillLayer);

    return clientCompositionLayers;
}

} // namespace android
