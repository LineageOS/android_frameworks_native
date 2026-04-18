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
#include "common/include/common/FlagManager.h"
#include "ui/Rotation.h"

#include <compositionengine/CompositionEngine.h>
#include <compositionengine/DisplayColorProfileCreationArgs.h>
#include <compositionengine/impl/DisplayColorProfile.h>
#include <ui/HdrRenderTypeUtils.h>
#include <ui/Rotation.h>

namespace android {

std::shared_ptr<ScreenCaptureOutput> createScreenCaptureOutput(ScreenCaptureOutputArgs args) {
    if (args.buffer == nullptr) {
        ALOGW("createScreenCaptureOutput called with null buffer; returning null");
        return nullptr;
    }

    std::shared_ptr<ScreenCaptureOutput> output = compositionengine::impl::createOutputTemplated<
            ScreenCaptureOutput, compositionengine::CompositionEngine,
            /* sourceCrop */ const Rect, ftl::Optional<DisplayIdVariant>,
            const compositionengine::Output::ColorProfile&,
            /* layerAlpha */ float,
            /* disableBlur */ bool>(args.compositionEngine, args.sourceCrop, args.displayIdVariant,
                                    args.colorProfile, args.layerAlpha, args.disableBlur,
                                    args.dimInGammaSpaceForEnhancedScreenshots,
                                    args.enableLocalTonemapping);
    if (output == nullptr) {
        ALOGW("createOutputTemplated returned null; aborting screen capture");
        return nullptr;
    }
    output->editState().isSecure = args.isSecure;
    output->editState().isProtected = args.buffer->getUsage() & GRALLOC_USAGE_PROTECTED;
    output->setCompositionEnabled(true);
    output->setLayerFilter(
            {.layerStack = args.layerStack, .toInternalDisplay = false, .skipScreenshot = true});
    output->setRenderSurface(std::make_unique<ScreenCaptureRenderSurface>(std::move(args.buffer)));
    output->setDisplayBrightness(args.sdrWhitePointNits, args.displayBrightnessNits);
    output->editState().clientTargetBrightness = args.targetBrightness;
    output->editState().treat170mAsSrgb = args.treat170mAsSrgb;

    output->setDisplayColorProfile(std::make_unique<compositionengine::impl::DisplayColorProfile>(
            compositionengine::DisplayColorProfileCreationArgsBuilder()
                    .setHasWideColorGamut(true)
                    .Build()));

    const Rect& sourceCrop = args.sourceCrop;
    const ui::Rotation orientation = ui::ROTATION_0;
    output->setDisplaySize({sourceCrop.getWidth(), sourceCrop.getHeight()});
    output->setProjection(orientation, sourceCrop,
                          {args.reqBufferSize.width, args.reqBufferSize.height});
    output->setName(args.debugName);
    return output;
}

ScreenCaptureOutput::ScreenCaptureOutput(
        const Rect sourceCrop, ftl::Optional<DisplayIdVariant> displayIdVariant,
        const compositionengine::Output::ColorProfile& colorProfile, float layerAlpha,
        bool disableBlur, bool dimInGammaSpaceForEnhancedScreenshots, bool enableLocalTonemapping)
      : mSourceCrop(sourceCrop),
        mDisplayIdVariant(displayIdVariant),
        mColorProfile(colorProfile),
        mLayerAlpha(layerAlpha),
        mDisableBlur(disableBlur),
        mDimInGammaSpaceForEnhancedScreenshots(dimInGammaSpaceForEnhancedScreenshots),
        mEnableLocalTonemapping(enableLocalTonemapping) {}

void ScreenCaptureOutput::updateColorProfile(const compositionengine::CompositionRefreshArgs&) {
    auto& outputState = editState();
    outputState.dataspace = mColorProfile.dataspace;
    outputState.renderIntent = mColorProfile.renderIntent;
}

renderengine::DisplaySettings ScreenCaptureOutput::generateClientCompositionDisplaySettings(
        const std::shared_ptr<renderengine::ExternalTexture>& buffer) const {
    auto clientCompositionDisplay =
            compositionengine::impl::Output::generateClientCompositionDisplaySettings(buffer);
    clientCompositionDisplay.clip = mSourceCrop;

    auto renderIntent = static_cast<ui::RenderIntent>(clientCompositionDisplay.renderIntent);
    if (mDimInGammaSpaceForEnhancedScreenshots && renderIntent != ui::RenderIntent::COLORIMETRIC &&
        renderIntent != ui::RenderIntent::TONE_MAP_COLORIMETRIC) {
        clientCompositionDisplay.dimmingStage =
                aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF;
    }

    if (mEnableLocalTonemapping) {
        clientCompositionDisplay.tonemapStrategy =
                renderengine::DisplaySettings::TonemapStrategy::Local;
        if (static_cast<ui::PixelFormat>(buffer->getPixelFormat()) == ui::PixelFormat::RGBA_FP16) {
            clientCompositionDisplay.targetHdrSdrRatio =
                    getState().displayBrightnessNits / getState().sdrWhitePointNits;
        } else {
            clientCompositionDisplay.targetHdrSdrRatio = 1.f;
        }
    }

    return clientCompositionDisplay;
}

std::unordered_map<int32_t, aidl::android::hardware::graphics::composer3::Luts>
ScreenCaptureOutput::generateLuts() {
    std::unordered_map<int32_t, aidl::android::hardware::graphics::composer3::Luts> lutsMapper;
    if (FlagManager::getInstance().luts_api()) {
        std::vector<sp<GraphicBuffer>> buffers;
        std::vector<int32_t> layerIds;

        for (const auto* layer : getOutputLayersOrderedByZ()) {
            const auto& layerState = layer->getState();
            const auto* layerFEState = layer->getLayerFE().getCompositionState();
            auto pixelFormat = layerFEState->buffer
                    ? std::make_optional(
                              static_cast<ui::PixelFormat>(layerFEState->buffer->getPixelFormat()))
                    : std::nullopt;
            const auto hdrType = getHdrRenderType(layerState.dataspace, pixelFormat,
                                                  layerFEState->desiredHdrSdrRatio);
            if (layerFEState->buffer && !layerFEState->luts &&
                hdrType == HdrRenderType::GENERIC_HDR) {
                buffers.push_back(layerFEState->buffer);
                layerIds.push_back(layer->getLayerFE().getSequence());
            }
        }

        // only call getLuts if buffers are not empty
        if (!buffers.empty()) {
            std::vector<aidl::android::hardware::graphics::composer3::Luts> luts;
            if (const auto physicalDisplayId = mDisplayIdVariant.and_then(asPhysicalDisplayId)) {
                auto& hwc = getCompositionEngine().getHwComposer();
                hwc.getLuts(*physicalDisplayId, buffers, &luts);
            }

            if (buffers.size() == luts.size()) {
                for (size_t i = 0; i < luts.size(); i++) {
                    lutsMapper[layerIds[i]] = std::move(luts[i]);
                }
            }
        }
    }
    return lutsMapper;
}

std::vector<compositionengine::LayerFE::LayerSettings>
ScreenCaptureOutput::generateClientCompositionRequests(
        bool supportsProtectedContent, ui::Dataspace outputDataspace,
        std::vector<compositionengine::LayerFE*>& outLayerFEs) {
    // This map maps the layer unique id to a Lut
    std::unordered_map<int32_t, aidl::android::hardware::graphics::composer3::Luts> lutsMapper =
            generateLuts();

    auto clientCompositionLayers = compositionengine::impl::Output::
            generateClientCompositionRequests(supportsProtectedContent, outputDataspace,
                                              outLayerFEs);

    for (auto& layer : clientCompositionLayers) {
        if (lutsMapper.find(layer.sequence) != lutsMapper.end()) {
            auto& aidlLuts = lutsMapper[layer.sequence];
            if (aidlLuts.pfd.get() >= 0 && aidlLuts.offsets) {
                std::vector<int32_t> offsets = *aidlLuts.offsets;
                std::vector<int32_t> dimensions;
                dimensions.reserve(offsets.size());
                std::vector<int32_t> sizes;
                sizes.reserve(offsets.size());
                std::vector<int32_t> keys;
                keys.reserve(offsets.size());
                for (size_t j = 0; j < offsets.size(); j++) {
                    dimensions.emplace_back(
                            static_cast<int32_t>(aidlLuts.lutProperties[j].dimension));
                    sizes.emplace_back(aidlLuts.lutProperties[j].size);
                    keys.emplace_back(
                            static_cast<int32_t>(aidlLuts.lutProperties[j].samplingKeys[0]));
                }
                layer.luts = std::make_shared<gui::DisplayLuts>(base::unique_fd(
                                                                        aidlLuts.pfd.release()),
                                                                offsets, dimensions, sizes, keys);
            }
        }
    }

    if (mDisableBlur) {
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

    compositionengine::LayerFE::LayerSettings fillLayer;
    fillLayer.name = "ScreenCaptureFillLayer";
    fillLayer.source.buffer.buffer = nullptr;
    fillLayer.source.solidColor = half3(0.0f, 0.0f, 0.0f);
    fillLayer.geometry.boundaries =
            FloatRect(static_cast<float>(mSourceCrop.left), static_cast<float>(mSourceCrop.top),
                      static_cast<float>(mSourceCrop.right),
                      static_cast<float>(mSourceCrop.bottom));

    fillLayer.alpha = half(mLayerAlpha);
    clientCompositionLayers.insert(clientCompositionLayers.begin(), fillLayer);

    return clientCompositionLayers;
}

} // namespace android
