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

#include <SurfaceFlingerProperties.sysprop.h>
#include <android-base/stringprintf.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/CompositionRefreshArgs.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/UdfpsExtension.h>
#include <compositionengine/impl/HwcAsyncWorker.h>
#include <compositionengine/impl/Output.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/impl/planner/Planner.h>
#include <ftl/future.h>
#include <gui/TraceUtils.h>

#include <optional>
#include <thread>

#include "renderengine/ExternalTexture.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <renderengine/DisplaySettings.h>
#include <renderengine/RenderEngine.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

#include <android-base/properties.h>
#include <ui/DebugUtils.h>
#include <ui/HdrCapabilities.h>
#include <utils/Trace.h>

#include "TracedOrdinal.h"

using aidl::android::hardware::graphics::composer3::Composition;

namespace android::compositionengine {

Output::~Output() = default;

namespace impl {
using CompositionStrategyPredictionState =
        OutputCompositionState::CompositionStrategyPredictionState;
namespace {

template <typename T>
class Reversed {
public:
    explicit Reversed(const T& container) : mContainer(container) {}
    auto begin() { return mContainer.rbegin(); }
    auto end() { return mContainer.rend(); }

private:
    const T& mContainer;
};

// Helper for enumerating over a container in reverse order
template <typename T>
Reversed<T> reversed(const T& c) {
    return Reversed<T>(c);
}

struct ScaleVector {
    float x;
    float y;
};

// Returns a ScaleVector (x, y) such that from.scale(x, y) = to',
// where to' will have the same size as "to". In the case where "from" and "to"
// start at the origin to'=to.
ScaleVector getScale(const Rect& from, const Rect& to) {
    return {.x = static_cast<float>(to.width()) / from.width(),
            .y = static_cast<float>(to.height()) / from.height()};
}

} // namespace

std::shared_ptr<Output> createOutput(
        const compositionengine::CompositionEngine& compositionEngine) {
    return createOutputTemplated<Output>(compositionEngine);
}

Output::~Output() = default;

bool Output::isValid() const {
    return mDisplayColorProfile && mDisplayColorProfile->isValid() && mRenderSurface &&
            mRenderSurface->isValid();
}

std::optional<DisplayId> Output::getDisplayId() const {
    return {};
}

const std::string& Output::getName() const {
    return mName;
}

void Output::setName(const std::string& name) {
    mName = name;
    auto displayIdOpt = getDisplayId();
    mNamePlusId = displayIdOpt ? base::StringPrintf("%s (%s)", mName.c_str(),
                                     to_string(*displayIdOpt).c_str())
                               : mName;
}

void Output::setCompositionEnabled(bool enabled) {
    auto& outputState = editState();
    if (outputState.isEnabled == enabled) {
        return;
    }

    outputState.isEnabled = enabled;
    dirtyEntireOutput();
}

void Output::setLayerCachingEnabled(bool enabled) {
    if (enabled == (mPlanner != nullptr)) {
        return;
    }

    if (enabled) {
        mPlanner = std::make_unique<planner::Planner>(getCompositionEngine().getRenderEngine());
        if (mRenderSurface) {
            mPlanner->setDisplaySize(mRenderSurface->getSize());
        }
    } else {
        mPlanner.reset();
    }

    for (auto* outputLayer : getOutputLayersOrderedByZ()) {
        if (!outputLayer) {
            continue;
        }

        outputLayer->editState().overrideInfo = {};
    }
}

void Output::setLayerCachingTexturePoolEnabled(bool enabled) {
    if (mPlanner) {
        mPlanner->setTexturePoolEnabled(enabled);
    }
}

void Output::setProjection(ui::Rotation orientation, const Rect& layerStackSpaceRect,
                           const Rect& orientedDisplaySpaceRect) {
    auto& outputState = editState();

    outputState.displaySpace.setOrientation(orientation);
    LOG_FATAL_IF(outputState.displaySpace.getBoundsAsRect() == Rect::INVALID_RECT,
                 "The display bounds are unknown.");

    // Compute orientedDisplaySpace
    ui::Size orientedSize = outputState.displaySpace.getBounds();
    if (orientation == ui::ROTATION_90 || orientation == ui::ROTATION_270) {
        std::swap(orientedSize.width, orientedSize.height);
    }
    outputState.orientedDisplaySpace.setBounds(orientedSize);
    outputState.orientedDisplaySpace.setContent(orientedDisplaySpaceRect);

    // Compute displaySpace.content
    const uint32_t transformOrientationFlags = ui::Transform::toRotationFlags(orientation);
    ui::Transform rotation;
    if (transformOrientationFlags != ui::Transform::ROT_INVALID) {
        const auto displaySize = outputState.displaySpace.getBoundsAsRect();
        rotation.set(transformOrientationFlags, displaySize.width(), displaySize.height());
    }
    outputState.displaySpace.setContent(rotation.transform(orientedDisplaySpaceRect));

    // Compute framebufferSpace
    outputState.framebufferSpace.setOrientation(orientation);
    LOG_FATAL_IF(outputState.framebufferSpace.getBoundsAsRect() == Rect::INVALID_RECT,
                 "The framebuffer bounds are unknown.");
    const auto scale = getScale(outputState.displaySpace.getBoundsAsRect(),
                                outputState.framebufferSpace.getBoundsAsRect());
    outputState.framebufferSpace.setContent(
            outputState.displaySpace.getContent().scale(scale.x, scale.y));

    // Compute layerStackSpace
    outputState.layerStackSpace.setContent(layerStackSpaceRect);
    outputState.layerStackSpace.setBounds(
            ui::Size(layerStackSpaceRect.getWidth(), layerStackSpaceRect.getHeight()));

    outputState.transform = outputState.layerStackSpace.getTransform(outputState.displaySpace);
    outputState.needsFiltering = outputState.transform.needsBilinearFiltering();
    dirtyEntireOutput();
}

void Output::setNextBrightness(float brightness) {
    editState().displayBrightness = brightness;
}

void Output::setDisplaySize(const ui::Size& size) {
    mRenderSurface->setDisplaySize(size);

    auto& state = editState();

    // Update framebuffer space
    const ui::Size newBounds(size);
    state.framebufferSpace.setBounds(newBounds);

    // Update display space
    state.displaySpace.setBounds(newBounds);
    state.transform = state.layerStackSpace.getTransform(state.displaySpace);

    // Update oriented display space
    const auto orientation = state.displaySpace.getOrientation();
    ui::Size orientedSize = size;
    if (orientation == ui::ROTATION_90 || orientation == ui::ROTATION_270) {
        std::swap(orientedSize.width, orientedSize.height);
    }
    const ui::Size newOrientedBounds(orientedSize);
    state.orientedDisplaySpace.setBounds(newOrientedBounds);

    if (mPlanner) {
        mPlanner->setDisplaySize(size);
    }

    dirtyEntireOutput();
}

ui::Transform::RotationFlags Output::getTransformHint() const {
    return static_cast<ui::Transform::RotationFlags>(getState().transform.getOrientation());
}

void Output::setLayerFilter(ui::LayerFilter filter) {
    editState().layerFilter = filter;
    dirtyEntireOutput();
}

void Output::setColorTransform(const compositionengine::CompositionRefreshArgs& args) {
    auto& colorTransformMatrix = editState().colorTransformMatrix;
    if (!args.colorTransformMatrix || colorTransformMatrix == args.colorTransformMatrix) {
        return;
    }

    colorTransformMatrix = *args.colorTransformMatrix;

    dirtyEntireOutput();
}

void Output::setColorProfile(const ColorProfile& colorProfile) {
    auto& outputState = editState();
    if (outputState.colorMode == colorProfile.mode &&
        outputState.dataspace == colorProfile.dataspace &&
        outputState.renderIntent == colorProfile.renderIntent) {
        return;
    }

    outputState.colorMode = colorProfile.mode;
    outputState.dataspace = colorProfile.dataspace;
    outputState.renderIntent = colorProfile.renderIntent;

    mRenderSurface->setBufferDataspace(colorProfile.dataspace);

    ALOGV("Set active color mode: %s (%d), active render intent: %s (%d)",
          decodeColorMode(colorProfile.mode).c_str(), colorProfile.mode,
          decodeRenderIntent(colorProfile.renderIntent).c_str(), colorProfile.renderIntent);

    dirtyEntireOutput();
}

void Output::setDisplayBrightness(float sdrWhitePointNits, float displayBrightnessNits) {
    auto& outputState = editState();
    if (outputState.sdrWhitePointNits == sdrWhitePointNits &&
        outputState.displayBrightnessNits == displayBrightnessNits) {
        // Nothing changed
        return;
    }
    outputState.sdrWhitePointNits = sdrWhitePointNits;
    outputState.displayBrightnessNits = displayBrightnessNits;
    dirtyEntireOutput();
}

void Output::dump(std::string& out) const {
    base::StringAppendF(&out, "Output \"%s\"", mName.c_str());
    out.append("\n   Composition Output State:\n");

    dumpBase(out);
}

void Output::dumpBase(std::string& out) const {
    dumpState(out);
    out += '\n';

    if (mDisplayColorProfile) {
        mDisplayColorProfile->dump(out);
    } else {
        out.append("    No display color profile!\n");
    }

    out += '\n';

    if (mRenderSurface) {
        mRenderSurface->dump(out);
    } else {
        out.append("    No render surface!\n");
    }

    base::StringAppendF(&out, "\n   %zu Layers\n", getOutputLayerCount());
    for (const auto* outputLayer : getOutputLayersOrderedByZ()) {
        if (!outputLayer) {
            continue;
        }
        outputLayer->dump(out);
    }
}

void Output::dumpPlannerInfo(const Vector<String16>& args, std::string& out) const {
    if (!mPlanner) {
        out.append("Planner is disabled\n");
        return;
    }
    base::StringAppendF(&out, "Planner info for display [%s]\n", mName.c_str());
    mPlanner->dump(args, out);
}

compositionengine::DisplayColorProfile* Output::getDisplayColorProfile() const {
    return mDisplayColorProfile.get();
}

void Output::setDisplayColorProfile(std::unique_ptr<compositionengine::DisplayColorProfile> mode) {
    mDisplayColorProfile = std::move(mode);
}

const Output::ReleasedLayers& Output::getReleasedLayersForTest() const {
    return mReleasedLayers;
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
    const auto size = mRenderSurface->getSize();
    editState().framebufferSpace.setBounds(size);
    if (mPlanner) {
        mPlanner->setDisplaySize(size);
    }
    dirtyEntireOutput();
}

void Output::cacheClientCompositionRequests(uint32_t cacheSize) {
    if (cacheSize == 0) {
        mClientCompositionRequestCache.reset();
    } else {
        mClientCompositionRequestCache = std::make_unique<ClientCompositionRequestCache>(cacheSize);
    }
};

void Output::setRenderSurfaceForTest(std::unique_ptr<compositionengine::RenderSurface> surface) {
    mRenderSurface = std::move(surface);
}

Region Output::getDirtyRegion() const {
    const auto& outputState = getState();
    return outputState.dirtyRegion.intersect(outputState.layerStackSpace.getContent());
}

bool Output::includesLayer(ui::LayerFilter filter) const {
    return getState().layerFilter.includes(filter);
}

bool Output::includesLayer(const sp<LayerFE>& layerFE) const {
    const auto* layerFEState = layerFE->getCompositionState();
    return layerFEState && includesLayer(layerFEState->outputFilter);
}

std::unique_ptr<compositionengine::OutputLayer> Output::createOutputLayer(
        const sp<LayerFE>& layerFE) const {
    return impl::createOutputLayer(*this, layerFE);
}

compositionengine::OutputLayer* Output::getOutputLayerForLayer(const sp<LayerFE>& layerFE) const {
    auto index = findCurrentOutputLayerForLayer(layerFE);
    return index ? getOutputLayerOrderedByZByIndex(*index) : nullptr;
}

std::optional<size_t> Output::findCurrentOutputLayerForLayer(
        const sp<compositionengine::LayerFE>& layer) const {
    for (size_t i = 0; i < getOutputLayerCount(); i++) {
        auto outputLayer = getOutputLayerOrderedByZByIndex(i);
        if (outputLayer && &outputLayer->getLayerFE() == layer.get()) {
            return i;
        }
    }
    return std::nullopt;
}

void Output::setReleasedLayers(Output::ReleasedLayers&& layers) {
    mReleasedLayers = std::move(layers);
}

void Output::prepare(const compositionengine::CompositionRefreshArgs& refreshArgs,
                     LayerFESet& geomSnapshots) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    rebuildLayerStacks(refreshArgs, geomSnapshots);
    uncacheBuffers(refreshArgs.bufferIdsToUncache);
}

ftl::Future<std::monostate> Output::present(
        const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_FORMAT("%s for %s", __func__, mNamePlusId.c_str());
    ALOGV(__FUNCTION__);

    updateColorProfile(refreshArgs);
    updateCompositionState(refreshArgs);
    planComposition();
    writeCompositionState(refreshArgs);
    setColorTransform(refreshArgs);
    beginFrame();

    GpuCompositionResult result;
    const bool predictCompositionStrategy = canPredictCompositionStrategy(refreshArgs);
    if (predictCompositionStrategy) {
        result = prepareFrameAsync();
    } else {
        prepareFrame();
    }

    devOptRepaintFlash(refreshArgs);
    finishFrame(std::move(result));
    ftl::Future<std::monostate> future;
    if (mOffloadPresent) {
        future = presentFrameAndReleaseLayersAsync();

        // Only offload for this frame. The next frame will determine whether it
        // needs to be offloaded. Leave the HwcAsyncWorker in place. For one thing,
        // it is currently presenting. Further, it may be needed next frame, and
        // we don't want to churn.
        mOffloadPresent = false;
    } else {
        presentFrameAndReleaseLayers();
        future = ftl::yield<std::monostate>({});
    }
    renderCachedSets(refreshArgs);
    return future;
}

void Output::offloadPresentNextFrame() {
    mOffloadPresent = true;
    updateHwcAsyncWorker();
}

void Output::uncacheBuffers(std::vector<uint64_t> const& bufferIdsToUncache) {
    if (bufferIdsToUncache.empty()) {
        return;
    }
    for (auto outputLayer : getOutputLayersOrderedByZ()) {
        outputLayer->uncacheBuffers(bufferIdsToUncache);
    }
}

void Output::rebuildLayerStacks(const compositionengine::CompositionRefreshArgs& refreshArgs,
                                LayerFESet& layerFESet) {
    auto& outputState = editState();

    // Do nothing if this output is not enabled or there is no need to perform this update
    if (!outputState.isEnabled || CC_LIKELY(!refreshArgs.updatingOutputGeometryThisFrame)) {
        return;
    }
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    // Process the layers to determine visibility and coverage
    compositionengine::Output::CoverageState coverage{layerFESet};
    coverage.aboveCoveredLayersExcludingOverlays = refreshArgs.hasTrustedPresentationListener
            ? std::make_optional<Region>()
            : std::nullopt;
    collectVisibleLayers(refreshArgs, coverage);

    // Compute the resulting coverage for this output, and store it for later
    const ui::Transform& tr = outputState.transform;
    Region undefinedRegion{outputState.displaySpace.getBoundsAsRect()};
    undefinedRegion.subtractSelf(tr.transform(coverage.aboveOpaqueLayers));

    outputState.undefinedRegion = undefinedRegion;
    outputState.dirtyRegion.orSelf(coverage.dirtyRegion);
}

void Output::collectVisibleLayers(const compositionengine::CompositionRefreshArgs& refreshArgs,
                                  compositionengine::Output::CoverageState& coverage) {
    // Evaluate the layers from front to back to determine what is visible. This
    // also incrementally calculates the coverage information for each layer as
    // well as the entire output.
    for (auto layer : reversed(refreshArgs.layers)) {
        // Incrementally process the coverage for each layer
        ensureOutputLayerIfVisible(layer, coverage);

        // TODO(b/121291683): Stop early if the output is completely covered and
        // no more layers could even be visible underneath the ones on top.
    }

    setReleasedLayers(refreshArgs);

    finalizePendingOutputLayers();
}

void Output::ensureOutputLayerIfVisible(sp<compositionengine::LayerFE>& layerFE,
                                        compositionengine::Output::CoverageState& coverage) {
    // Ensure we have a snapshot of the basic geometry layer state. Limit the
    // snapshots to once per frame for each candidate layer, as layers may
    // appear on multiple outputs.
    if (!coverage.latchedLayers.count(layerFE)) {
        coverage.latchedLayers.insert(layerFE);
    }

    // Only consider the layers on this output
    if (!includesLayer(layerFE)) {
        return;
    }

    // Obtain a read-only pointer to the front-end layer state
    const auto* layerFEState = layerFE->getCompositionState();
    if (CC_UNLIKELY(!layerFEState)) {
        return;
    }

    // handle hidden surfaces by setting the visible region to empty
    if (CC_UNLIKELY(!layerFEState->isVisible)) {
        return;
    }

    bool computeAboveCoveredExcludingOverlays = coverage.aboveCoveredLayersExcludingOverlays &&
            !layerFEState->outputFilter.toInternalDisplay;

    /*
     * opaqueRegion: area of a surface that is fully opaque.
     */
    Region opaqueRegion;

    /*
     * visibleRegion: area of a surface that is visible on screen and not fully
     * transparent. This is essentially the layer's footprint minus the opaque
     * regions above it. Areas covered by a translucent surface are considered
     * visible.
     */
    Region visibleRegion;

    /*
     * coveredRegion: area of a surface that is covered by all visible regions
     * above it (which includes the translucent areas).
     */
    Region coveredRegion;

    /*
     * transparentRegion: area of a surface that is hinted to be completely
     * transparent.
     * This is used to tell when the layer has no visible non-transparent
     * regions and can be removed from the layer list. It does not affect the
     * visibleRegion of this layer or any layers beneath it. The hint may not
     * be correct if apps don't respect the SurfaceView restrictions (which,
     * sadly, some don't).
     *
     * In addition, it is used on DISPLAY_DECORATION layers to specify the
     * blockingRegion, allowing the DPU to skip it to save power. Once we have
     * hardware that supports a blockingRegion on frames with AFBC, it may be
     * useful to use this for other layers, too, so long as we can prevent
     * regressions on b/7179570.
     */
    Region transparentRegion;

    /*
     * shadowRegion: Region cast by the layer's shadow.
     */
    Region shadowRegion;

    /**
     * covered region above excluding internal display overlay layers
     */
    std::optional<Region> coveredRegionExcludingDisplayOverlays = std::nullopt;

    const ui::Transform& tr = layerFEState->geomLayerTransform;

    // Get the visible region
    // TODO(b/121291683): Is it worth creating helper methods on LayerFEState
    // for computations like this?
    const Rect visibleRect(tr.transform(layerFEState->geomLayerBounds));
    visibleRegion.set(visibleRect);

    if (layerFEState->shadowSettings.length > 0.0f) {
        // if the layer casts a shadow, offset the layers visible region and
        // calculate the shadow region.
        const auto inset = static_cast<int32_t>(ceilf(layerFEState->shadowSettings.length) * -1.0f);
        Rect visibleRectWithShadows(visibleRect);
        visibleRectWithShadows.inset(inset, inset, inset, inset);
        visibleRegion.set(visibleRectWithShadows);
        shadowRegion = visibleRegion.subtract(visibleRect);
    }

    if (visibleRegion.isEmpty()) {
        return;
    }

    // Remove the transparent area from the visible region
    if (!layerFEState->isOpaque) {
        if (tr.preserveRects()) {
            // Clip the transparent region to geomLayerBounds first
            // The transparent region may be influenced by applications, for
            // instance, by overriding ViewGroup#gatherTransparentRegion with a
            // custom view. Once the layer stack -> display mapping is known, we
            // must guard against very wrong inputs to prevent underflow or
            // overflow errors. We do this here by constraining the transparent
            // region to be within the pre-transform layer bounds, since the
            // layer bounds are expected to play nicely with the full
            // transform.
            const Region clippedTransparentRegionHint =
                    layerFEState->transparentRegionHint.intersect(
                            Rect(layerFEState->geomLayerBounds));

            if (clippedTransparentRegionHint.isEmpty()) {
                if (!layerFEState->transparentRegionHint.isEmpty()) {
                    ALOGD("Layer: %s had an out of bounds transparent region",
                          layerFE->getDebugName());
                    layerFEState->transparentRegionHint.dump("transparentRegionHint");
                }
                transparentRegion.clear();
            } else {
                transparentRegion = tr.transform(clippedTransparentRegionHint);
            }
        } else {
            // transformation too complex, can't do the
            // transparent region optimization.
            transparentRegion.clear();
        }
    }

    // compute the opaque region
    const auto layerOrientation = tr.getOrientation();
    if (layerFEState->isOpaque && ((layerOrientation & ui::Transform::ROT_INVALID) == 0)) {
        // If we one of the simple category of transforms (0/90/180/270 rotation
        // + any flip), then the opaque region is the layer's footprint.
        // Otherwise we don't try and compute the opaque region since there may
        // be errors at the edges, and we treat the entire layer as
        // translucent.
        opaqueRegion.set(visibleRect);
    }

    // Clip the covered region to the visible region
    coveredRegion = coverage.aboveCoveredLayers.intersect(visibleRegion);

    // Update accumAboveCoveredLayers for next (lower) layer
    coverage.aboveCoveredLayers.orSelf(visibleRegion);

    if (CC_UNLIKELY(computeAboveCoveredExcludingOverlays)) {
        coveredRegionExcludingDisplayOverlays =
                coverage.aboveCoveredLayersExcludingOverlays->intersect(visibleRegion);
        coverage.aboveCoveredLayersExcludingOverlays->orSelf(visibleRegion);
    }

    // subtract the opaque region covered by the layers above us
    visibleRegion.subtractSelf(coverage.aboveOpaqueLayers);

    if (visibleRegion.isEmpty()) {
        return;
    }

    // Get coverage information for the layer as previously displayed,
    // also taking over ownership from mOutputLayersorderedByZ.
    auto prevOutputLayerIndex = findCurrentOutputLayerForLayer(layerFE);
    auto prevOutputLayer =
            prevOutputLayerIndex ? getOutputLayerOrderedByZByIndex(*prevOutputLayerIndex) : nullptr;

    //  Get coverage information for the layer as previously displayed
    // TODO(b/121291683): Define kEmptyRegion as a constant in Region.h
    const Region kEmptyRegion;
    const Region& oldVisibleRegion =
            prevOutputLayer ? prevOutputLayer->getState().visibleRegion : kEmptyRegion;
    const Region& oldCoveredRegion =
            prevOutputLayer ? prevOutputLayer->getState().coveredRegion : kEmptyRegion;

    // compute this layer's dirty region
    Region dirty;
    if (layerFEState->contentDirty) {
        // we need to invalidate the whole region
        dirty = visibleRegion;
        // as well, as the old visible region
        dirty.orSelf(oldVisibleRegion);
    } else {
        /* compute the exposed region:
         *   the exposed region consists of two components:
         *   1) what's VISIBLE now and was COVERED before
         *   2) what's EXPOSED now less what was EXPOSED before
         *
         * note that (1) is conservative, we start with the whole visible region
         * but only keep what used to be covered by something -- which mean it
         * may have been exposed.
         *
         * (2) handles areas that were not covered by anything but got exposed
         * because of a resize.
         *
         */
        const Region newExposed = visibleRegion - coveredRegion;
        const Region oldExposed = oldVisibleRegion - oldCoveredRegion;
        dirty = (visibleRegion & oldCoveredRegion) | (newExposed - oldExposed);
    }
    dirty.subtractSelf(coverage.aboveOpaqueLayers);

    // accumulate to the screen dirty region
    coverage.dirtyRegion.orSelf(dirty);

    // Update accumAboveOpaqueLayers for next (lower) layer
    coverage.aboveOpaqueLayers.orSelf(opaqueRegion);

    // Compute the visible non-transparent region
    Region visibleNonTransparentRegion = visibleRegion.subtract(transparentRegion);

    // Perform the final check to see if this layer is visible on this output
    // TODO(b/121291683): Why does this not use visibleRegion? (see outputSpaceVisibleRegion below)
    const auto& outputState = getState();
    Region drawRegion(outputState.transform.transform(visibleNonTransparentRegion));
    drawRegion.andSelf(outputState.displaySpace.getBoundsAsRect());
    if (drawRegion.isEmpty()) {
        return;
    }

    Region visibleNonShadowRegion = visibleRegion.subtract(shadowRegion);

    // The layer is visible. Either reuse the existing outputLayer if we have
    // one, or create a new one if we do not.
    auto result = ensureOutputLayer(prevOutputLayerIndex, layerFE);

    // Store the layer coverage information into the layer state as some of it
    // is useful later.
    auto& outputLayerState = result->editState();
    outputLayerState.visibleRegion = visibleRegion;
    outputLayerState.visibleNonTransparentRegion = visibleNonTransparentRegion;
    outputLayerState.coveredRegion = coveredRegion;
    outputLayerState.outputSpaceVisibleRegion = outputState.transform.transform(
            visibleNonShadowRegion.intersect(outputState.layerStackSpace.getContent()));
    outputLayerState.shadowRegion = shadowRegion;
    outputLayerState.outputSpaceBlockingRegionHint =
            layerFEState->compositionType == Composition::DISPLAY_DECORATION
            ? outputState.transform.transform(
                      transparentRegion.intersect(outputState.layerStackSpace.getContent()))
            : Region();
    if (CC_UNLIKELY(computeAboveCoveredExcludingOverlays)) {
        outputLayerState.coveredRegionExcludingDisplayOverlays =
                std::move(coveredRegionExcludingDisplayOverlays);
    }
}

void Output::setReleasedLayers(const compositionengine::CompositionRefreshArgs&) {
    // The base class does nothing with this call.
}

void Output::updateCompositionState(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    mLayerRequestingBackgroundBlur = findLayerRequestingBackgroundComposition();
    bool forceClientComposition = mLayerRequestingBackgroundBlur != nullptr;

    for (auto* layer : getOutputLayersOrderedByZ()) {
        layer->updateCompositionState(refreshArgs.updatingGeometryThisFrame,
                                      refreshArgs.devOptForceClientComposition ||
                                              forceClientComposition,
                                      refreshArgs.internalDisplayRotationFlags);

        if (mLayerRequestingBackgroundBlur == layer) {
            forceClientComposition = false;
        }
    }

    updateCompositionStateForBorder(refreshArgs);
}

void Output::updateCompositionStateForBorder(
        const compositionengine::CompositionRefreshArgs& refreshArgs) {
    std::unordered_map<int32_t, const Region*> layerVisibleRegionMap;
    // Store a map of layerId to their computed visible region.
    for (auto* layer : getOutputLayersOrderedByZ()) {
        int layerId = (layer->getLayerFE()).getSequence();
        layerVisibleRegionMap[layerId] = &((layer->getState()).visibleRegion);
    }
    OutputCompositionState& outputCompositionState = editState();
    outputCompositionState.borderInfoList.clear();
    bool clientComposeTopLayer = false;
    for (const auto& borderInfo : refreshArgs.borderInfoList) {
        renderengine::BorderRenderInfo info;
        for (const auto& id : borderInfo.layerIds) {
            info.combinedRegion.orSelf(*(layerVisibleRegionMap[id]));
        }

        if (!info.combinedRegion.isEmpty()) {
            info.width = borderInfo.width;
            info.color = borderInfo.color;
            outputCompositionState.borderInfoList.emplace_back(std::move(info));
            clientComposeTopLayer = true;
        }
    }

    // In this situation we must client compose the top layer instead of using hwc
    // because we want to draw the border above all else.
    // This could potentially cause a bit of a performance regression if the top
    // layer would have been rendered using hwc originally.
    // TODO(b/227656283): Measure system's performance before enabling the border feature
    if (clientComposeTopLayer) {
        auto topLayer = getOutputLayerOrderedByZByIndex(getOutputLayerCount() - 1);
        (topLayer->editState()).forceClientComposition = true;
    }
}

void Output::planComposition() {
    if (!mPlanner || !getState().isEnabled) {
        return;
    }

    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    mPlanner->plan(getOutputLayersOrderedByZ());
}

void Output::writeCompositionState(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    editState().earliestPresentTime = refreshArgs.earliestPresentTime;
    editState().expectedPresentTime = refreshArgs.expectedPresentTime;
    editState().frameInterval = refreshArgs.frameInterval;
    editState().powerCallback = refreshArgs.powerCallback;

    compositionengine::OutputLayer* peekThroughLayer = nullptr;
    sp<GraphicBuffer> previousOverride = nullptr;
    bool includeGeometry = refreshArgs.updatingGeometryThisFrame;
    uint32_t z = 0;
    bool overrideZ = false;
    uint64_t outputLayerHash = 0;
    for (auto* layer : getOutputLayersOrderedByZ()) {
        if (layer == peekThroughLayer) {
            // No longer needed, although it should not show up again, so
            // resetting it is not truly needed either.
            peekThroughLayer = nullptr;

            // peekThroughLayer was already drawn ahead of its z order.
            continue;
        }
        bool skipLayer = false;
        const auto& overrideInfo = layer->getState().overrideInfo;
        if (overrideInfo.buffer != nullptr) {
            if (previousOverride && overrideInfo.buffer->getBuffer() == previousOverride) {
                ALOGV("Skipping redundant buffer");
                skipLayer = true;
            } else {
                // First layer with the override buffer.
                if (overrideInfo.peekThroughLayer) {
                    peekThroughLayer = overrideInfo.peekThroughLayer;

                    // Draw peekThroughLayer first.
                    overrideZ = true;
                    includeGeometry = true;
                    constexpr bool isPeekingThrough = true;
                    peekThroughLayer->writeStateToHWC(includeGeometry, false, z++, overrideZ,
                                                      isPeekingThrough);
                    outputLayerHash ^= android::hashCombine(
                            reinterpret_cast<uint64_t>(&peekThroughLayer->getLayerFE()),
                            z, includeGeometry, overrideZ, isPeekingThrough,
                            peekThroughLayer->requiresClientComposition());
                }

                previousOverride = overrideInfo.buffer->getBuffer();
            }
        }

        constexpr bool isPeekingThrough = false;
        layer->writeStateToHWC(includeGeometry, skipLayer, z++, overrideZ, isPeekingThrough);
        if (!skipLayer) {
            outputLayerHash ^= android::hashCombine(
                    reinterpret_cast<uint64_t>(&layer->getLayerFE()),
                    z, includeGeometry, overrideZ, isPeekingThrough,
                    layer->requiresClientComposition());
        }
    }
    editState().outputLayerHash = outputLayerHash;
}

compositionengine::OutputLayer* Output::findLayerRequestingBackgroundComposition() const {
    compositionengine::OutputLayer* layerRequestingBgComposition = nullptr;
    for (size_t i = 0; i < getOutputLayerCount(); i++) {
        compositionengine::OutputLayer* layer = getOutputLayerOrderedByZByIndex(i);
        compositionengine::OutputLayer* nextLayer = getOutputLayerOrderedByZByIndex(i + 1);

        const auto* compState = layer->getLayerFE().getCompositionState();

        // If any layer has a sideband stream, we will disable blurs. In that case, we don't
        // want to force client composition because of the blur.
        if (compState->sidebandStream != nullptr) {
            return nullptr;
        }

        // If RenderEngine cannot render protected content, we cannot blur.
        if (compState->hasProtectedContent &&
            !getCompositionEngine().getRenderEngine().supportsProtectedContent()) {
            return nullptr;
        }
        if (compState->isOpaque) {
            continue;
        }
        if (compState->backgroundBlurRadius > 0 || compState->blurRegions.size() > 0) {
            layerRequestingBgComposition = layer;
        }

        // If the next layer is the Udfps touched layer, enable client composition for it
        // because that somehow leads to the Udfps touched layer getting device composition
        // consistently.
        if ((nextLayer != nullptr && layerRequestingBgComposition == nullptr) &&
            (strncmp(nextLayer->getLayerFE().getDebugName(), UDFPS_TOUCHED_LAYER_NAME,
                     strlen(UDFPS_TOUCHED_LAYER_NAME)) == 0)) {
            layerRequestingBgComposition = layer;
            break;
        }
    }
    return layerRequestingBgComposition;
}

void Output::updateColorProfile(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    setColorProfile(pickColorProfile(refreshArgs));
}

// Returns a data space that fits all visible layers.  The returned data space
// can only be one of
//  - Dataspace::SRGB (use legacy dataspace and let HWC saturate when colors are enhanced)
//  - Dataspace::DISPLAY_P3
//  - Dataspace::DISPLAY_BT2020
// The returned HDR data space is one of
//  - Dataspace::UNKNOWN
//  - Dataspace::BT2020_HLG
//  - Dataspace::BT2020_PQ
ui::Dataspace Output::getBestDataspace(ui::Dataspace* outHdrDataSpace,
                                       bool* outIsHdrClientComposition) const {
    ui::Dataspace bestDataSpace = ui::Dataspace::V0_SRGB;
    *outHdrDataSpace = ui::Dataspace::UNKNOWN;

    // An Output's layers may be stale when it is disabled. As a consequence, the layers returned by
    // getOutputLayersOrderedByZ may not be in a valid state and it is not safe to access their
    // properties. Return a default dataspace value in this case.
    if (!getState().isEnabled) {
        return ui::Dataspace::V0_SRGB;
    }

    for (const auto* layer : getOutputLayersOrderedByZ()) {
        switch (layer->getLayerFE().getCompositionState()->dataspace) {
            case ui::Dataspace::V0_SCRGB:
            case ui::Dataspace::V0_SCRGB_LINEAR:
            case ui::Dataspace::BT2020:
            case ui::Dataspace::BT2020_ITU:
            case ui::Dataspace::BT2020_LINEAR:
            case ui::Dataspace::DISPLAY_BT2020:
                bestDataSpace = ui::Dataspace::DISPLAY_BT2020;
                break;
            case ui::Dataspace::DISPLAY_P3:
                bestDataSpace = ui::Dataspace::DISPLAY_P3;
                break;
            case ui::Dataspace::BT2020_PQ:
            case ui::Dataspace::BT2020_ITU_PQ:
                bestDataSpace = ui::Dataspace::DISPLAY_P3;
                *outHdrDataSpace = ui::Dataspace::BT2020_PQ;
                *outIsHdrClientComposition =
                        layer->getLayerFE().getCompositionState()->forceClientComposition;
                break;
            case ui::Dataspace::BT2020_HLG:
            case ui::Dataspace::BT2020_ITU_HLG:
                bestDataSpace = ui::Dataspace::DISPLAY_P3;
                // When there's mixed PQ content and HLG content, we set the HDR
                // data space to be BT2020_HLG and convert PQ to HLG.
                if (*outHdrDataSpace == ui::Dataspace::UNKNOWN) {
                    *outHdrDataSpace = ui::Dataspace::BT2020_HLG;
                }
                break;
            default:
                break;
        }
    }

    return bestDataSpace;
}

compositionengine::Output::ColorProfile Output::pickColorProfile(
        const compositionengine::CompositionRefreshArgs& refreshArgs) const {
    if (refreshArgs.outputColorSetting == OutputColorSetting::kUnmanaged) {
        return ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                            ui::RenderIntent::COLORIMETRIC};
    }

    ui::Dataspace hdrDataSpace;
    bool isHdrClientComposition = false;
    ui::Dataspace bestDataSpace = getBestDataspace(&hdrDataSpace, &isHdrClientComposition);

    switch (refreshArgs.forceOutputColorMode) {
        case ui::ColorMode::SRGB:
            bestDataSpace = ui::Dataspace::V0_SRGB;
            break;
        case ui::ColorMode::DISPLAY_P3:
            bestDataSpace = ui::Dataspace::DISPLAY_P3;
            break;
        default:
            break;
    }

    // respect hdrDataSpace only when there is no legacy HDR support
    const bool isHdr = hdrDataSpace != ui::Dataspace::UNKNOWN &&
            !mDisplayColorProfile->hasLegacyHdrSupport(hdrDataSpace) && !isHdrClientComposition;
    if (isHdr) {
        bestDataSpace = hdrDataSpace;
    }

    ui::RenderIntent intent;
    switch (refreshArgs.outputColorSetting) {
        case OutputColorSetting::kManaged:
        case OutputColorSetting::kUnmanaged:
            intent = isHdr ? ui::RenderIntent::TONE_MAP_COLORIMETRIC
                           : ui::RenderIntent::COLORIMETRIC;
            break;
        case OutputColorSetting::kEnhanced:
            intent = isHdr ? ui::RenderIntent::TONE_MAP_ENHANCE : ui::RenderIntent::ENHANCE;
            break;
        default: // vendor display color setting
            intent = static_cast<ui::RenderIntent>(refreshArgs.outputColorSetting);
            break;
    }

    ui::ColorMode outMode;
    ui::Dataspace outDataSpace;
    ui::RenderIntent outRenderIntent;
    mDisplayColorProfile->getBestColorMode(bestDataSpace, intent, &outDataSpace, &outMode,
                                           &outRenderIntent);

    return ColorProfile{outMode, outDataSpace, outRenderIntent};
}

void Output::beginFrame() {
    auto& outputState = editState();
    const bool dirty = !getDirtyRegion().isEmpty();
    const bool empty = getOutputLayerCount() == 0;
    const bool wasEmpty = !outputState.lastCompositionHadVisibleLayers;

    // If nothing has changed (!dirty), don't recompose.
    // If something changed, but we don't currently have any visible layers,
    //   and didn't when we last did a composition, then skip it this time.
    // The second rule does two things:
    // - When all layers are removed from a display, we'll emit one black
    //   frame, then nothing more until we get new layers.
    // - When a display is created with a private layer stack, we won't
    //   emit any black frames until a layer is added to the layer stack.
    mMustRecompose = dirty && !(empty && wasEmpty);

    const char flagPrefix[] = {'-', '+'};
    static_cast<void>(flagPrefix);
    ALOGV("%s: %s composition for %s (%cdirty %cempty %cwasEmpty)", __func__,
          mMustRecompose ? "doing" : "skipping", getName().c_str(), flagPrefix[dirty],
          flagPrefix[empty], flagPrefix[wasEmpty]);

    mRenderSurface->beginFrame(mMustRecompose);

    if (mMustRecompose) {
        outputState.lastCompositionHadVisibleLayers = !empty;
    }
}

void Output::prepareFrame() {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    auto& outputState = editState();
    if (!outputState.isEnabled) {
        return;
    }

    std::optional<android::HWComposer::DeviceRequestedChanges> changes;
    bool success = chooseCompositionStrategy(&changes);
    resetCompositionStrategy();
    outputState.strategyPrediction = CompositionStrategyPredictionState::DISABLED;
    outputState.previousDeviceRequestedChanges = changes;
    outputState.previousDeviceRequestedSuccess = success;
    if (success) {
        applyCompositionStrategy(changes);
    }
    finishPrepareFrame();
}

ftl::Future<std::monostate> Output::presentFrameAndReleaseLayersAsync() {
    return ftl::Future<bool>(std::move(mHwComposerAsyncWorker->send([&]() {
               presentFrameAndReleaseLayers();
               return true;
           })))
            .then([](bool) { return std::monostate{}; });
}

std::future<bool> Output::chooseCompositionStrategyAsync(
        std::optional<android::HWComposer::DeviceRequestedChanges>* changes) {
    return mHwComposerAsyncWorker->send(
            [&, changes]() { return chooseCompositionStrategy(changes); });
}

GpuCompositionResult Output::prepareFrameAsync() {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);
    auto& state = editState();
    const auto& previousChanges = state.previousDeviceRequestedChanges;
    std::optional<android::HWComposer::DeviceRequestedChanges> changes;
    resetCompositionStrategy();
    auto hwcResult = chooseCompositionStrategyAsync(&changes);
    if (state.previousDeviceRequestedSuccess) {
        applyCompositionStrategy(previousChanges);
    }
    finishPrepareFrame();

    base::unique_fd bufferFence;
    std::shared_ptr<renderengine::ExternalTexture> buffer;
    updateProtectedContentState();
    const bool dequeueSucceeded = dequeueRenderBuffer(&bufferFence, &buffer);
    GpuCompositionResult compositionResult;
    if (dequeueSucceeded) {
        std::optional<base::unique_fd> optFd =
                composeSurfaces(Region::INVALID_REGION, buffer, bufferFence);
        if (optFd) {
            compositionResult.fence = std::move(*optFd);
        }
    }

    auto chooseCompositionSuccess = hwcResult.get();
    const bool predictionSucceeded = dequeueSucceeded && changes == previousChanges;
    state.strategyPrediction = predictionSucceeded ? CompositionStrategyPredictionState::SUCCESS
                                                   : CompositionStrategyPredictionState::FAIL;
    if (!predictionSucceeded) {
        ATRACE_NAME("CompositionStrategyPredictionMiss");
        resetCompositionStrategy();
        if (chooseCompositionSuccess) {
            applyCompositionStrategy(changes);
        }
        finishPrepareFrame();
        // Track the dequeued buffer to reuse so we don't need to dequeue another one.
        compositionResult.buffer = buffer;
    } else {
        ATRACE_NAME("CompositionStrategyPredictionHit");
    }
    state.previousDeviceRequestedChanges = std::move(changes);
    state.previousDeviceRequestedSuccess = chooseCompositionSuccess;
    return compositionResult;
}

void Output::devOptRepaintFlash(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    if (CC_LIKELY(!refreshArgs.devOptFlashDirtyRegionsDelay)) {
        return;
    }

    if (getState().isEnabled) {
        if (const auto dirtyRegion = getDirtyRegion(); !dirtyRegion.isEmpty()) {
            base::unique_fd bufferFence;
            std::shared_ptr<renderengine::ExternalTexture> buffer;
            updateProtectedContentState();
            dequeueRenderBuffer(&bufferFence, &buffer);
            static_cast<void>(composeSurfaces(dirtyRegion, buffer, bufferFence));
            mRenderSurface->queueBuffer(base::unique_fd(), getHdrSdrRatio(buffer));
        }
    }

    presentFrameAndReleaseLayers();

    std::this_thread::sleep_for(*refreshArgs.devOptFlashDirtyRegionsDelay);

    prepareFrame();
}

void Output::finishFrame(GpuCompositionResult&& result) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);
    const auto& outputState = getState();
    if (!outputState.isEnabled) {
        return;
    }

    std::optional<base::unique_fd> optReadyFence;
    std::shared_ptr<renderengine::ExternalTexture> buffer;
    base::unique_fd bufferFence;
    if (outputState.strategyPrediction == CompositionStrategyPredictionState::SUCCESS) {
        optReadyFence = std::move(result.fence);
    } else {
        if (result.bufferAvailable()) {
            buffer = std::move(result.buffer);
            bufferFence = std::move(result.fence);
        } else {
            updateProtectedContentState();
            if (!dequeueRenderBuffer(&bufferFence, &buffer)) {
                return;
            }
        }
        // Repaint the framebuffer (if needed), getting the optional fence for when
        // the composition completes.
        optReadyFence = composeSurfaces(Region::INVALID_REGION, buffer, bufferFence);
    }
    if (!optReadyFence) {
        return;
    }

    if (isPowerHintSessionEnabled()) {
        // get fence end time to know when gpu is complete in display
        setHintSessionGpuFence(
                std::make_unique<FenceTime>(sp<Fence>::make(dup(optReadyFence->get()))));
    }
    // swap buffers (presentation)
    mRenderSurface->queueBuffer(std::move(*optReadyFence), getHdrSdrRatio(buffer));
}

void Output::updateProtectedContentState() {
    const auto& outputState = getState();
    auto& renderEngine = getCompositionEngine().getRenderEngine();
    const bool supportsProtectedContent = renderEngine.supportsProtectedContent();

    bool isProtected;
    if (FlagManager::getInstance().display_protected()) {
        isProtected = outputState.isProtected;
    } else {
        isProtected = outputState.isSecure;
    }

    // We need to set the render surface as protected (DRM) if all the following conditions are met:
    // 1. The display is protected (in legacy, check if the display is secure)
    // 2. Protected content is supported
    // 3. At least one layer has protected content.
    if (isProtected && supportsProtectedContent) {
        auto layers = getOutputLayersOrderedByZ();
        bool needsProtected = std::any_of(layers.begin(), layers.end(), [](auto* layer) {
            return layer->getLayerFE().getCompositionState()->hasProtectedContent;
        });
        if (needsProtected != mRenderSurface->isProtected()) {
            mRenderSurface->setProtected(needsProtected);
        }
    }
}

bool Output::dequeueRenderBuffer(base::unique_fd* bufferFence,
                                 std::shared_ptr<renderengine::ExternalTexture>* tex) {
    const auto& outputState = getState();

    // If we aren't doing client composition on this output, but do have a
    // flipClientTarget request for this frame on this output, we still need to
    // dequeue a buffer.
    if (outputState.usesClientComposition || outputState.flipClientTarget) {
        *tex = mRenderSurface->dequeueBuffer(bufferFence);
        if (*tex == nullptr) {
            ALOGW("Dequeuing buffer for display [%s] failed, bailing out of "
                  "client composition for this frame",
                  mName.c_str());
            return false;
        }
    }
    return true;
}

std::optional<base::unique_fd> Output::composeSurfaces(
        const Region& debugRegion, std::shared_ptr<renderengine::ExternalTexture> tex,
        base::unique_fd& fd) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    const auto& outputState = getState();
    const TracedOrdinal<bool> hasClientComposition = {
        base::StringPrintf("hasClientComposition %s", mNamePlusId.c_str()),
        outputState.usesClientComposition};
    if (!hasClientComposition) {
        setExpensiveRenderingExpected(false);
        return base::unique_fd();
    }

    if (tex == nullptr) {
        ALOGW("Buffer not valid for display [%s], bailing out of "
              "client composition for this frame",
              mName.c_str());
        return {};
    }

    ALOGV("hasClientComposition");

    renderengine::DisplaySettings clientCompositionDisplay =
            generateClientCompositionDisplaySettings(tex);

    // Generate the client composition requests for the layers on this output.
    auto& renderEngine = getCompositionEngine().getRenderEngine();
    const bool supportsProtectedContent = renderEngine.supportsProtectedContent();
    std::vector<LayerFE*> clientCompositionLayersFE;
    std::vector<LayerFE::LayerSettings> clientCompositionLayers =
            generateClientCompositionRequests(supportsProtectedContent,
                                              clientCompositionDisplay.outputDataspace,
                                              clientCompositionLayersFE);
    appendRegionFlashRequests(debugRegion, clientCompositionLayers);

    OutputCompositionState& outputCompositionState = editState();
    // Check if the client composition requests were rendered into the provided graphic buffer. If
    // so, we can reuse the buffer and avoid client composition.
    if (mClientCompositionRequestCache) {
        if (mClientCompositionRequestCache->exists(tex->getBuffer()->getId(),
                                                   clientCompositionDisplay,
                                                   clientCompositionLayers)) {
            ATRACE_NAME("ClientCompositionCacheHit");
            outputCompositionState.reusedClientComposition = true;
            setExpensiveRenderingExpected(false);
            // b/239944175 pass the fence associated with the buffer.
            return base::unique_fd(std::move(fd));
        }
        ATRACE_NAME("ClientCompositionCacheMiss");
        mClientCompositionRequestCache->add(tex->getBuffer()->getId(), clientCompositionDisplay,
                                            clientCompositionLayers);
    }

    // We boost GPU frequency here because there will be color spaces conversion
    // or complex GPU shaders and it's expensive. We boost the GPU frequency so that
    // GPU composition can finish in time. We must reset GPU frequency afterwards,
    // because high frequency consumes extra battery.
    const bool expensiveRenderingExpected =
            std::any_of(clientCompositionLayers.begin(), clientCompositionLayers.end(),
                        [outputDataspace =
                                 clientCompositionDisplay.outputDataspace](const auto& layer) {
                            return layer.sourceDataspace != outputDataspace;
                        });
    if (expensiveRenderingExpected) {
        setExpensiveRenderingExpected(true);
    }

    std::vector<renderengine::LayerSettings> clientRenderEngineLayers;
    clientRenderEngineLayers.reserve(clientCompositionLayers.size());
    std::transform(clientCompositionLayers.begin(), clientCompositionLayers.end(),
                   std::back_inserter(clientRenderEngineLayers),
                   [](LayerFE::LayerSettings& settings) -> renderengine::LayerSettings {
                       return settings;
                   });

    const nsecs_t renderEngineStart = systemTime();
    auto fenceResult = renderEngine
                               .drawLayers(clientCompositionDisplay, clientRenderEngineLayers, tex,
                                           std::move(fd))
                               .get();

    if (mClientCompositionRequestCache && fenceStatus(fenceResult) != NO_ERROR) {
        // If rendering was not successful, remove the request from the cache.
        mClientCompositionRequestCache->remove(tex->getBuffer()->getId());
    }

    const auto fence = std::move(fenceResult).value_or(Fence::NO_FENCE);

    if (auto timeStats = getCompositionEngine().getTimeStats()) {
        if (fence->isValid()) {
            timeStats->recordRenderEngineDuration(renderEngineStart,
                                                  std::make_shared<FenceTime>(fence));
        } else {
            timeStats->recordRenderEngineDuration(renderEngineStart, systemTime());
        }
    }

    for (auto* clientComposedLayer : clientCompositionLayersFE) {
        clientComposedLayer->setWasClientComposed(fence);
    }

    return base::unique_fd(fence->dup());
}

renderengine::DisplaySettings Output::generateClientCompositionDisplaySettings(
        const std::shared_ptr<renderengine::ExternalTexture>& buffer) const {
    const auto& outputState = getState();

    renderengine::DisplaySettings clientCompositionDisplay;
    clientCompositionDisplay.namePlusId = mNamePlusId;
    clientCompositionDisplay.physicalDisplay = outputState.framebufferSpace.getContent();
    clientCompositionDisplay.clip = outputState.layerStackSpace.getContent();
    clientCompositionDisplay.orientation =
            ui::Transform::toRotationFlags(outputState.displaySpace.getOrientation());
    clientCompositionDisplay.outputDataspace = mDisplayColorProfile->hasWideColorGamut()
            ? outputState.dataspace
            : ui::Dataspace::UNKNOWN;

    // If we have a valid current display brightness use that, otherwise fall back to the
    // display's max desired
    clientCompositionDisplay.currentLuminanceNits = outputState.displayBrightnessNits > 0.f
            ? outputState.displayBrightnessNits
            : mDisplayColorProfile->getHdrCapabilities().getDesiredMaxLuminance();
    clientCompositionDisplay.maxLuminance =
            mDisplayColorProfile->getHdrCapabilities().getDesiredMaxLuminance();

    float hdrSdrRatioMultiplier = 1.0f / getHdrSdrRatio(buffer);
    clientCompositionDisplay.targetLuminanceNits = outputState.clientTargetBrightness *
            outputState.displayBrightnessNits * hdrSdrRatioMultiplier;
    clientCompositionDisplay.dimmingStage = outputState.clientTargetDimmingStage;
    clientCompositionDisplay.renderIntent =
            static_cast<aidl::android::hardware::graphics::composer3::RenderIntent>(
                    outputState.renderIntent);

    // Compute the global color transform matrix.
    clientCompositionDisplay.colorTransform = outputState.colorTransformMatrix;
    for (auto& info : outputState.borderInfoList) {
        renderengine::BorderRenderInfo borderInfo;
        borderInfo.width = info.width;
        borderInfo.color = info.color;
        borderInfo.combinedRegion = info.combinedRegion;
        clientCompositionDisplay.borderInfoList.emplace_back(std::move(borderInfo));
    }
    clientCompositionDisplay.deviceHandlesColorTransform =
            outputState.usesDeviceComposition || getSkipColorTransform();
    return clientCompositionDisplay;
}

std::vector<LayerFE::LayerSettings> Output::generateClientCompositionRequests(
      bool supportsProtectedContent, ui::Dataspace outputDataspace, std::vector<LayerFE*>& outLayerFEs) {
    std::vector<LayerFE::LayerSettings> clientCompositionLayers;
    ALOGV("Rendering client layers");

    const auto& outputState = getState();
    const Region viewportRegion(outputState.layerStackSpace.getContent());
    bool firstLayer = true;

    bool disableBlurs = false;
    uint64_t previousOverrideBufferId = 0;

    for (auto* layer : getOutputLayersOrderedByZ()) {
        const auto& layerState = layer->getState();
        const auto* layerFEState = layer->getLayerFE().getCompositionState();
        auto& layerFE = layer->getLayerFE();
        layerFE.setWasClientComposed(nullptr);

        const Region clip(viewportRegion.intersect(layerState.visibleRegion));
        ALOGV("Layer: %s", layerFE.getDebugName());
        if (clip.isEmpty()) {
            ALOGV("  Skipping for empty clip");
            firstLayer = false;
            continue;
        }

        disableBlurs |= layerFEState->sidebandStream != nullptr;

        const bool clientComposition = layer->requiresClientComposition();

        // We clear the client target for non-client composed layers if
        // requested by the HWC. We skip this if the layer is not an opaque
        // rectangle, as by definition the layer must blend with whatever is
        // underneath. We also skip the first layer as the buffer target is
        // guaranteed to start out cleared.
        const bool clearClientComposition =
                layerState.clearClientTarget && layerFEState->isOpaque && !firstLayer;

        ALOGV("  Composition type: client %d clear %d", clientComposition, clearClientComposition);

        // If the layer casts a shadow but the content casting the shadow is occluded, skip
        // composing the non-shadow content and only draw the shadows.
        const bool realContentIsVisible = clientComposition &&
                !layerState.visibleRegion.subtract(layerState.shadowRegion).isEmpty();

        if (clientComposition || clearClientComposition) {
            if (auto overrideSettings = layer->getOverrideCompositionSettings()) {
                if (overrideSettings->bufferId != previousOverrideBufferId) {
                    previousOverrideBufferId = overrideSettings->bufferId;
                    clientCompositionLayers.push_back(std::move(*overrideSettings));
                    ALOGV("Replacing [%s] with override in RE", layer->getLayerFE().getDebugName());
                } else {
                    ALOGV("Skipping redundant override buffer for [%s] in RE",
                          layer->getLayerFE().getDebugName());
                }
            } else {
                LayerFE::ClientCompositionTargetSettings::BlurSetting blurSetting = disableBlurs
                        ? LayerFE::ClientCompositionTargetSettings::BlurSetting::Disabled
                        : (layer->getState().overrideInfo.disableBackgroundBlur
                                   ? LayerFE::ClientCompositionTargetSettings::BlurSetting::
                                             BlurRegionsOnly
                                   : LayerFE::ClientCompositionTargetSettings::BlurSetting::
                                             Enabled);
                bool isProtected = supportsProtectedContent;
                if (FlagManager::getInstance().display_protected()) {
                    isProtected = outputState.isProtected && supportsProtectedContent;
                }
                compositionengine::LayerFE::ClientCompositionTargetSettings
                        targetSettings{.clip = clip,
                                       .needsFiltering = layer->needsFiltering() ||
                                               outputState.needsFiltering,
                                       .isSecure = outputState.isSecure,
                                       .isProtected = isProtected,
                                       .viewport = outputState.layerStackSpace.getContent(),
                                       .dataspace = outputDataspace,
                                       .realContentIsVisible = realContentIsVisible,
                                       .clearContent = !clientComposition,
                                       .blurSetting = blurSetting,
                                       .whitePointNits = layerState.whitePointNits,
                                       .treat170mAsSrgb = outputState.treat170mAsSrgb};
                if (auto clientCompositionSettings =
                            layerFE.prepareClientComposition(targetSettings)) {
                    clientCompositionLayers.push_back(std::move(*clientCompositionSettings));
                    if (realContentIsVisible) {
                        layer->editState().clientCompositionTimestamp = systemTime();
                    }
                }
            }

            if (clientComposition) {
                outLayerFEs.push_back(&layerFE);
            }
        }

        firstLayer = false;
    }

    return clientCompositionLayers;
}

void Output::appendRegionFlashRequests(
        const Region& flashRegion, std::vector<LayerFE::LayerSettings>& clientCompositionLayers) {
    if (flashRegion.isEmpty()) {
        return;
    }

    LayerFE::LayerSettings layerSettings;
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

void Output::setHintSessionGpuFence(std::unique_ptr<FenceTime>&&) {
    // The base class does nothing with this call.
}

bool Output::isPowerHintSessionEnabled() {
    return false;
}

void Output::presentFrameAndReleaseLayers() {
    ATRACE_FORMAT("%s for %s", __func__, mNamePlusId.c_str());
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    auto& outputState = editState();
    outputState.dirtyRegion.clear();

    auto frame = presentFrame();

    mRenderSurface->onPresentDisplayCompleted();

    for (auto* layer : getOutputLayersOrderedByZ()) {
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
        if (outputState.usesClientComposition) {
            releaseFence =
                    Fence::merge("LayerRelease", releaseFence, frame.clientTargetAcquireFence);
        }
        layer->getLayerFE()
                .onLayerDisplayed(ftl::yield<FenceResult>(std::move(releaseFence)).share(),
                                  outputState.layerFilter.layerStack);
    }

    // We've got a list of layers needing fences, that are disjoint with
    // OutputLayersOrderedByZ.  The best we can do is to
    // supply them with the present fence.
    for (auto& weakLayer : mReleasedLayers) {
        if (const auto layer = weakLayer.promote()) {
            layer->onLayerDisplayed(ftl::yield<FenceResult>(frame.presentFence).share(),
                                    outputState.layerFilter.layerStack);
        }
    }

    // Clear out the released layers now that we're done with them.
    mReleasedLayers.clear();
}

void Output::renderCachedSets(const CompositionRefreshArgs& refreshArgs) {
    const auto& outputState = getState();
    if (mPlanner && outputState.isEnabled) {
        mPlanner->renderCachedSets(outputState, refreshArgs.scheduledFrameTime,
                                   outputState.usesDeviceComposition || getSkipColorTransform());
    }
}

void Output::dirtyEntireOutput() {
    auto& outputState = editState();
    outputState.dirtyRegion.set(outputState.displaySpace.getBoundsAsRect());
}

void Output::resetCompositionStrategy() {
    // The base output implementation can only do client composition
    auto& outputState = editState();
    outputState.usesClientComposition = true;
    outputState.usesDeviceComposition = false;
    outputState.reusedClientComposition = false;
}

bool Output::getSkipColorTransform() const {
    return true;
}

compositionengine::Output::FrameFences Output::presentFrame() {
    compositionengine::Output::FrameFences result;
    if (getState().usesClientComposition) {
        result.clientTargetAcquireFence = mRenderSurface->getClientTargetAcquireFence();
    }
    return result;
}

void Output::setPredictCompositionStrategy(bool predict) {
    mPredictCompositionStrategy = predict;
    updateHwcAsyncWorker();
}

void Output::updateHwcAsyncWorker() {
    if (mPredictCompositionStrategy || mOffloadPresent) {
        if (!mHwComposerAsyncWorker) {
            mHwComposerAsyncWorker = std::make_unique<HwcAsyncWorker>();
        }
    } else {
        mHwComposerAsyncWorker.reset(nullptr);
    }
}

void Output::setTreat170mAsSrgb(bool enable) {
    editState().treat170mAsSrgb = enable;
}

bool Output::canPredictCompositionStrategy(const CompositionRefreshArgs& refreshArgs) {
    uint64_t lastOutputLayerHash = getState().lastOutputLayerHash;
    uint64_t outputLayerHash = getState().outputLayerHash;
    editState().lastOutputLayerHash = outputLayerHash;

    if (!getState().isEnabled || !mPredictCompositionStrategy) {
        ALOGV("canPredictCompositionStrategy disabled");
        return false;
    }

    if (!getState().previousDeviceRequestedChanges) {
        ALOGV("canPredictCompositionStrategy previous changes not available");
        return false;
    }

    if (!mRenderSurface->supportsCompositionStrategyPrediction()) {
        ALOGV("canPredictCompositionStrategy surface does not support");
        return false;
    }

    if (refreshArgs.devOptFlashDirtyRegionsDelay) {
        ALOGV("canPredictCompositionStrategy devOptFlashDirtyRegionsDelay");
        return false;
    }

    if (lastOutputLayerHash != outputLayerHash) {
        ALOGV("canPredictCompositionStrategy output layers changed");
        return false;
    }

    // If no layer uses clientComposition, then don't predict composition strategy
    // because we have less work to do in parallel.
    if (!anyLayersRequireClientComposition()) {
        ALOGV("canPredictCompositionStrategy no layer uses clientComposition");
        return false;
    }

    return true;
}

bool Output::anyLayersRequireClientComposition() const {
    const auto layers = getOutputLayersOrderedByZ();
    return std::any_of(layers.begin(), layers.end(),
                       [](const auto& layer) { return layer->requiresClientComposition(); });
}

void Output::finishPrepareFrame() {
    const auto& state = getState();
    if (mPlanner) {
        mPlanner->reportFinalPlan(getOutputLayersOrderedByZ());
    }
    mRenderSurface->prepareFrame(state.usesClientComposition, state.usesDeviceComposition);
}

bool Output::mustRecompose() const {
    return mMustRecompose;
}

float Output::getHdrSdrRatio(const std::shared_ptr<renderengine::ExternalTexture>& buffer) const {
    if (buffer == nullptr) {
        return 1.0f;
    }

    if (!FlagManager::getInstance().fp16_client_target()) {
        return 1.0f;
    }

    if (getState().displayBrightnessNits < 0.0f || getState().sdrWhitePointNits <= 0.0f ||
        buffer->getPixelFormat() != PIXEL_FORMAT_RGBA_FP16 ||
        (static_cast<int32_t>(getState().dataspace) &
         static_cast<int32_t>(ui::Dataspace::RANGE_MASK)) !=
                static_cast<int32_t>(ui::Dataspace::RANGE_EXTENDED)) {
        return 1.0f;
    }

    return getState().displayBrightnessNits / getState().sdrWhitePointNits;
}

} // namespace impl
} // namespace android::compositionengine
