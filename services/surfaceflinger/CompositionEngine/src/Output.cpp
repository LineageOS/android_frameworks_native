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

#include <android-base/stringprintf.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/Layer.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/impl/LayerCompositionState.h>
#include <compositionengine/impl/Output.h>
#include <compositionengine/impl/OutputLayer.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/RenderEngine.h>
#include <ui/DebugUtils.h>
#include <ui/HdrCapabilities.h>
#include <utils/Trace.h>

#include "TracedOrdinal.h"

namespace android::compositionengine {

Output::~Output() = default;

namespace impl {

Output::Output(const CompositionEngine& compositionEngine)
      : mCompositionEngine(compositionEngine) {}

Output::~Output() = default;

const CompositionEngine& Output::getCompositionEngine() const {
    return mCompositionEngine;
}

bool Output::isValid() const {
    return mDisplayColorProfile && mDisplayColorProfile->isValid() && mRenderSurface &&
            mRenderSurface->isValid();
}

const std::string& Output::getName() const {
    return mName;
}

void Output::setName(const std::string& name) {
    mName = name;
}

void Output::setCompositionEnabled(bool enabled) {
    if (mState.isEnabled == enabled) {
        return;
    }

    mState.isEnabled = enabled;
    dirtyEntireOutput();
}

void Output::setProjection(const ui::Transform& transform, int32_t orientation, const Rect& frame,
                           const Rect& viewport, const Rect& scissor, bool needsFiltering) {
    mState.transform = transform;
    mState.orientation = orientation;
    mState.scissor = scissor;
    mState.frame = frame;
    mState.viewport = viewport;
    mState.needsFiltering = needsFiltering;

    dirtyEntireOutput();
}

// TODO(b/121291683): Rename setSize() once more is moved.
void Output::setBounds(const ui::Size& size) {
    mRenderSurface->setDisplaySize(size);
    // TODO(b/121291683): Rename mState.size once more is moved.
    mState.bounds = Rect(mRenderSurface->getSize());

    dirtyEntireOutput();
}

void Output::setLayerStackFilter(uint32_t layerStackId, bool isInternal) {
    mState.layerStackId = layerStackId;
    mState.layerStackInternal = isInternal;

    dirtyEntireOutput();
}

void Output::setColorTransform(const mat4& transform) {
    if (mState.colorTransformMat == transform) {
        return;
    }

    const bool isIdentity = (transform == mat4());
    const auto newColorTransform =
            isIdentity ? HAL_COLOR_TRANSFORM_IDENTITY : HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX;

    mState.colorTransform = newColorTransform;
    mState.colorTransformMat = transform;

    dirtyEntireOutput();
}

void Output::setColorMode(ui::ColorMode mode, ui::Dataspace dataspace,
                          ui::RenderIntent renderIntent,
                          ui::Dataspace colorSpaceAgnosticDataspace) {
    ui::Dataspace targetDataspace =
            getDisplayColorProfile()->getTargetDataspace(mode, dataspace,
                                                         colorSpaceAgnosticDataspace);

    if (mState.colorMode == mode && mState.dataspace == dataspace &&
        mState.renderIntent == renderIntent && mState.targetDataspace == targetDataspace) {
        return;
    }

    mState.colorMode = mode;
    mState.dataspace = dataspace;
    mState.renderIntent = renderIntent;
    mState.targetDataspace = targetDataspace;

    mRenderSurface->setBufferDataspace(dataspace);

    ALOGV("Set active color mode: %s (%d), active render intent: %s (%d)",
          decodeColorMode(mode).c_str(), mode, decodeRenderIntent(renderIntent).c_str(),
          renderIntent);

    dirtyEntireOutput();
}

void Output::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "   Composition Output State: [\"%s\"]", mName.c_str());

    out.append("\n   ");

    dumpBase(out);
}

void Output::dumpBase(std::string& out) const {
    mState.dump(out);

    if (mDisplayColorProfile) {
        mDisplayColorProfile->dump(out);
    } else {
        out.append("    No display color profile!\n");
    }

    if (mRenderSurface) {
        mRenderSurface->dump(out);
    } else {
        out.append("    No render surface!\n");
    }

    android::base::StringAppendF(&out, "\n   %zu Layers\b", mOutputLayersOrderedByZ.size());
    for (const auto& outputLayer : mOutputLayersOrderedByZ) {
        if (!outputLayer) {
            continue;
        }
        outputLayer->dump(out);
    }
}

compositionengine::DisplayColorProfile* Output::getDisplayColorProfile() const {
    return mDisplayColorProfile.get();
}

void Output::setDisplayColorProfile(std::unique_ptr<compositionengine::DisplayColorProfile> mode) {
    mDisplayColorProfile = std::move(mode);
}

void Output::setDisplayColorProfileForTest(
        std::unique_ptr<compositionengine::DisplayColorProfile> mode) {
    mDisplayColorProfile = std::move(mode);
}

compositionengine::RenderSurface* Output::getRenderSurface() const {
    return mRenderSurface.get();
}

void Output::setRenderSurface(std::unique_ptr<compositionengine::RenderSurface> surface) {
    mRenderSurface = std::move(surface);
    mState.bounds = Rect(mRenderSurface->getSize());

    dirtyEntireOutput();
}

void Output::setRenderSurfaceForTest(std::unique_ptr<compositionengine::RenderSurface> surface) {
    mRenderSurface = std::move(surface);
}

const OutputCompositionState& Output::getState() const {
    return mState;
}

OutputCompositionState& Output::editState() {
    return mState;
}

Region Output::getDirtyRegion(bool repaintEverything) const {
    Region dirty(mState.viewport);
    if (!repaintEverything) {
        dirty.andSelf(mState.dirtyRegion);
    }
    return dirty;
}

bool Output::belongsInOutput(uint32_t layerStackId, bool internalOnly) const {
    // The layerStackId's must match, and also the layer must not be internal
    // only when not on an internal output.
    return (layerStackId == mState.layerStackId) && (!internalOnly || mState.layerStackInternal);
}

compositionengine::OutputLayer* Output::getOutputLayerForLayer(
        compositionengine::Layer* layer) const {
    for (const auto& outputLayer : mOutputLayersOrderedByZ) {
        if (outputLayer && &outputLayer->getLayer() == layer) {
            return outputLayer.get();
        }
    }
    return nullptr;
}

std::unique_ptr<compositionengine::OutputLayer> Output::getOrCreateOutputLayer(
        std::optional<DisplayId> displayId, std::shared_ptr<compositionengine::Layer> layer,
        sp<compositionengine::LayerFE> layerFE) {
    for (auto& outputLayer : mOutputLayersOrderedByZ) {
        if (outputLayer && &outputLayer->getLayer() == layer.get()) {
            return std::move(outputLayer);
        }
    }
    return createOutputLayer(mCompositionEngine, displayId, *this, layer, layerFE);
}

void Output::setOutputLayersOrderedByZ(OutputLayers&& layers) {
    mOutputLayersOrderedByZ = std::move(layers);
}

const Output::OutputLayers& Output::getOutputLayersOrderedByZ() const {
    return mOutputLayersOrderedByZ;
}

void Output::setReleasedLayers(Output::ReleasedLayers&& layers) {
    mReleasedLayers = std::move(layers);
}

Output::ReleasedLayers Output::takeReleasedLayers() {
    return std::move(mReleasedLayers);
}

void Output::beginFrame() {
    const bool dirty = !getDirtyRegion(false).isEmpty();
    const bool empty = mOutputLayersOrderedByZ.empty();
    const bool wasEmpty = !mState.lastCompositionHadVisibleLayers;

    // If nothing has changed (!dirty), don't recompose.
    // If something changed, but we don't currently have any visible layers,
    //   and didn't when we last did a composition, then skip it this time.
    // The second rule does two things:
    // - When all layers are removed from a display, we'll emit one black
    //   frame, then nothing more until we get new layers.
    // - When a display is created with a private layer stack, we won't
    //   emit any black frames until a layer is added to the layer stack.
    const bool mustRecompose = dirty && !(empty && wasEmpty);

    const char flagPrefix[] = {'-', '+'};
    static_cast<void>(flagPrefix);
    ALOGV_IF("%s: %s composition for %s (%cdirty %cempty %cwasEmpty)", __FUNCTION__,
             mustRecompose ? "doing" : "skipping", getName().c_str(), flagPrefix[dirty],
             flagPrefix[empty], flagPrefix[wasEmpty]);

    mRenderSurface->beginFrame(mustRecompose);

    if (mustRecompose) {
        mState.lastCompositionHadVisibleLayers = !empty;
    }
}

void Output::prepareFrame() {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!mState.isEnabled) {
        return;
    }

    chooseCompositionStrategy();

    mRenderSurface->prepareFrame(mState.usesClientComposition, mState.usesDeviceComposition);
}

bool Output::composeSurfaces(const Region& debugRegion, base::unique_fd* readyFence) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    const TracedOrdinal<bool> hasClientComposition = {"hasClientComposition",
                                                      mState.usesClientComposition};
    if (!hasClientComposition) {
        return true;
    }

    ALOGV("hasClientComposition");

    auto& renderEngine = mCompositionEngine.getRenderEngine();
    const bool supportsProtectedContent = renderEngine.supportsProtectedContent();

    renderengine::DisplaySettings clientCompositionDisplay;
    clientCompositionDisplay.physicalDisplay = mState.scissor;
    clientCompositionDisplay.clip = mState.scissor;
    clientCompositionDisplay.globalTransform = mState.transform.asMatrix4();
    clientCompositionDisplay.orientation = mState.orientation;
    clientCompositionDisplay.outputDataspace =
            mDisplayColorProfile->hasWideColorGamut() ? mState.dataspace : ui::Dataspace::UNKNOWN;
    clientCompositionDisplay.maxLuminance =
            mDisplayColorProfile->getHdrCapabilities().getDesiredMaxLuminance();

    // Compute the global color transform matrix.
    if (!mState.usesDeviceComposition && !getSkipColorTransform()) {
        clientCompositionDisplay.colorTransform = mState.colorTransformMat;
    }

    // Note: Updated by generateClientCompositionRequests
    clientCompositionDisplay.clearRegion = Region::INVALID_REGION;

    // Generate the client composition requests for the layers on this output.
    std::vector<renderengine::LayerSettings> clientCompositionLayers =
            generateClientCompositionRequests(supportsProtectedContent,
                                              clientCompositionDisplay.clearRegion);
    appendRegionFlashRequests(debugRegion, clientCompositionLayers);

    // If we the display is secure, protected content support is enabled, and at
    // least one layer has protected content, we need to use a secure back
    // buffer.
    if (mState.isSecure && supportsProtectedContent) {
        bool needsProtected =
                std::any_of(mOutputLayersOrderedByZ.begin(), mOutputLayersOrderedByZ.end(),
                            [](auto& layer) {
                                return layer->getLayer().getState().frontEnd.hasProtectedContent;
                            });
        if (needsProtected != renderEngine.isProtected()) {
            renderEngine.useProtectedContext(needsProtected);
        }
        if (needsProtected != mRenderSurface->isProtected() &&
            needsProtected == renderEngine.isProtected()) {
            mRenderSurface->setProtected(needsProtected);
        }
    }

    base::unique_fd fd;
    sp<GraphicBuffer> buf = mRenderSurface->dequeueBuffer(&fd);
    if (buf == nullptr) {
        ALOGW("Dequeuing buffer for display [%s] failed, bailing out of "
              "client composition for this frame",
              mName.c_str());
        return false;
    }

    // We boost GPU frequency here because there will be color spaces conversion
    // and it's expensive. We boost the GPU frequency so that GPU composition can
    // finish in time. We must reset GPU frequency afterwards, because high frequency
    // consumes extra battery.
    const bool expensiveRenderingExpected =
            clientCompositionDisplay.outputDataspace == ui::Dataspace::DISPLAY_P3;
    if (expensiveRenderingExpected) {
        setExpensiveRenderingExpected(true);
    }

    renderEngine.drawLayers(clientCompositionDisplay, clientCompositionLayers,
                            buf->getNativeBuffer(), /*useFramebufferCache=*/true, std::move(fd),
                            readyFence);

    if (expensiveRenderingExpected) {
        setExpensiveRenderingExpected(false);
    }

    return true;
}

std::vector<renderengine::LayerSettings> Output::generateClientCompositionRequests(
        bool supportsProtectedContent, Region& clearRegion) {
    std::vector<renderengine::LayerSettings> clientCompositionLayers;
    ALOGV("Rendering client layers");

    const Region viewportRegion(mState.viewport);
    const bool useIdentityTransform = false;
    bool firstLayer = true;
    // Used when a layer clears part of the buffer.
    Region dummyRegion;

    for (auto& layer : mOutputLayersOrderedByZ) {
        const auto& layerState = layer->getState();
        const auto& layerFEState = layer->getLayer().getState().frontEnd;
        auto& layerFE = layer->getLayerFE();

        const Region clip(viewportRegion.intersect(layer->getState().visibleRegion));
        ALOGV("Layer: %s", layerFE.getDebugName());
        if (clip.isEmpty()) {
            ALOGV("  Skipping for empty clip");
            firstLayer = false;
            continue;
        }

        bool clientComposition = layer->requiresClientComposition();

        // We clear the client target for non-client composed layers if
        // requested by the HWC. We skip this if the layer is not an opaque
        // rectangle, as by definition the layer must blend with whatever is
        // underneath. We also skip the first layer as the buffer target is
        // guaranteed to start out cleared.
        bool clearClientComposition =
                layerState.clearClientTarget && layerFEState.isOpaque && !firstLayer;

        ALOGV("  Composition type: client %d clear %d", clientComposition, clearClientComposition);

        if (clientComposition || clearClientComposition) {
            compositionengine::LayerFE::ClientCompositionTargetSettings targetSettings{
                    clip,
                    useIdentityTransform,
                    layer->needsFiltering() || mState.needsFiltering,
                    mState.isSecure,
                    supportsProtectedContent,
                    clientComposition ? clearRegion : dummyRegion,
            };
            if (auto result = layerFE.prepareClientComposition(targetSettings)) {
                if (clearClientComposition) {
                    auto& layerSettings = *result;
                    layerSettings.source.buffer.buffer = nullptr;
                    layerSettings.source.solidColor = half3(0.0, 0.0, 0.0);
                    layerSettings.alpha = half(0.0);
                    layerSettings.disableBlending = true;
                }

                clientCompositionLayers.push_back(*result);
            }
        }

        firstLayer = false;
    }

    return clientCompositionLayers;
}

void Output::appendRegionFlashRequests(
        const Region& flashRegion,
        std::vector<renderengine::LayerSettings>& clientCompositionLayers) {
    if (flashRegion.isEmpty()) {
        return;
    }

    renderengine::LayerSettings layerSettings;
    layerSettings.source.buffer.buffer = nullptr;
    layerSettings.source.solidColor = half3(1.0, 0.0, 1.0);
    layerSettings.alpha = half(1.0);

    for (const auto& rect : flashRegion) {
        layerSettings.geometry.boundaries = rect.toFloatRect();
        clientCompositionLayers.push_back(layerSettings);
    }
}

void Output::setExpensiveRenderingExpected(bool) {
    // The base class does nothing with this call.
}

void Output::postFramebuffer() {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    auto frame = presentAndGetFrameFences();

    mRenderSurface->onPresentDisplayCompleted();

    for (auto& layer : getOutputLayersOrderedByZ()) {
        // The layer buffer from the previous frame (if any) is released
        // by HWC only when the release fence from this frame (if any) is
        // signaled.  Always get the release fence from HWC first.
        sp<Fence> releaseFence = Fence::NO_FENCE;

        if (auto hwcLayer = layer->getHwcLayer()) {
            if (auto f = frame.layerFences.find(hwcLayer); f != frame.layerFences.end()) {
                releaseFence = f->second;
            }
        }

        // If the layer was client composited in the previous frame, we
        // need to merge with the previous client target acquire fence.
        // Since we do not track that, always merge with the current
        // client target acquire fence when it is available, even though
        // this is suboptimal.
        // TODO(b/121291683): Track previous frame client target acquire fence.
        if (mState.usesClientComposition) {
            releaseFence =
                    Fence::merge("LayerRelease", releaseFence, frame.clientTargetAcquireFence);
        }

        layer->getLayerFE().onLayerDisplayed(releaseFence);
    }

    // We've got a list of layers needing fences, that are disjoint with
    // getOutputLayersOrderedByZ.  The best we can do is to
    // supply them with the present fence.
    for (auto& weakLayer : mReleasedLayers) {
        if (auto layer = weakLayer.promote(); layer != nullptr) {
            layer->onLayerDisplayed(frame.presentFence);
        }
    }

    // Clear out the released layers now that we're done with them.
    mReleasedLayers.clear();
}

void Output::dirtyEntireOutput() {
    mState.dirtyRegion.set(mState.bounds);
}

void Output::chooseCompositionStrategy() {
    // The base output implementation can only do client composition
    mState.usesClientComposition = true;
    mState.usesDeviceComposition = false;
}

bool Output::getSkipColorTransform() const {
    return true;
}

compositionengine::Output::FrameFences Output::presentAndGetFrameFences() {
    compositionengine::Output::FrameFences result;
    if (mState.usesClientComposition) {
        result.clientTargetAcquireFence = mRenderSurface->getClientTargetAcquireFence();
    }
    return result;
}

} // namespace impl
} // namespace android::compositionengine
