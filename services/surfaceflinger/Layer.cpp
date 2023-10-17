/*
 * Copyright (C) 2007 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "Layer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "Layer.h"

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android/native_window.h>
#include <binder/IPCThreadState.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/Display.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <cutils/compiler.h>
#include <cutils/native_handle.h>
#include <cutils/properties.h>
#include <ftl/enum.h>
#include <ftl/fake_guard.h>
#include <gui/BufferItem.h>
#include <gui/LayerDebugInfo.h>
#include <gui/Surface.h>
#include <gui/TraceUtils.h>
#include <math.h>
#include <private/android_filesystem_config.h>
#include <renderengine/RenderEngine.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <system/graphics-base-v1.0.h>
#include <ui/DebugUtils.h>
#include <ui/FloatRect.h>
#include <ui/GraphicBuffer.h>
#include <ui/HdrRenderTypeUtils.h>
#include <ui/PixelFormat.h>
#include <ui/Rect.h>
#include <ui/Transform.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/NativeHandle.h>
#include <utils/StopWatch.h>
#include <utils/Trace.h>

#include <algorithm>
#include <mutex>
#include <optional>
#include <sstream>

#include "DisplayDevice.h"
#include "DisplayHardware/HWComposer.h"
#include "FrameTimeline.h"
#include "FrameTracer/FrameTracer.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/LayerHandle.h"
#include "LayerProtoHelper.h"
#include "MutexUtils.h"
#include "SurfaceFlinger.h"
#include "TimeStats/TimeStats.h"
#include "TunnelModeEnabledReporter.h"

#define DEBUG_RESIZE 0
#define EARLY_RELEASE_ENABLED false

namespace android {
namespace {
constexpr int kDumpTableRowLength = 159;

const ui::Transform kIdentityTransform;

bool assignTransform(ui::Transform* dst, ui::Transform& from) {
    if (*dst == from) {
        return false;
    }
    *dst = from;
    return true;
}

TimeStats::SetFrameRateVote frameRateToSetFrameRateVotePayload(Layer::FrameRate frameRate) {
    using FrameRateCompatibility = TimeStats::SetFrameRateVote::FrameRateCompatibility;
    using Seamlessness = TimeStats::SetFrameRateVote::Seamlessness;
    const auto frameRateCompatibility = [frameRate] {
        switch (frameRate.type) {
            case Layer::FrameRateCompatibility::Default:
                return FrameRateCompatibility::Default;
            case Layer::FrameRateCompatibility::ExactOrMultiple:
                return FrameRateCompatibility::ExactOrMultiple;
            default:
                return FrameRateCompatibility::Undefined;
        }
    }();

    const auto seamlessness = [frameRate] {
        switch (frameRate.seamlessness) {
            case scheduler::Seamlessness::OnlySeamless:
                return Seamlessness::ShouldBeSeamless;
            case scheduler::Seamlessness::SeamedAndSeamless:
                return Seamlessness::NotRequired;
            default:
                return Seamlessness::Undefined;
        }
    }();

    return TimeStats::SetFrameRateVote{.frameRate = frameRate.rate.getValue(),
                                       .frameRateCompatibility = frameRateCompatibility,
                                       .seamlessness = seamlessness};
}

} // namespace

using namespace ftl::flag_operators;

using base::StringAppendF;
using frontend::LayerSnapshot;
using frontend::RoundedCornerState;
using gui::GameMode;
using gui::LayerMetadata;
using gui::WindowInfo;

using PresentState = frametimeline::SurfaceFrame::PresentState;

Layer::Layer(const LayerCreationArgs& args)
      : sequence(args.sequence),
        mFlinger(sp<SurfaceFlinger>::fromExisting(args.flinger)),
        mName(base::StringPrintf("%s#%d", args.name.c_str(), sequence)),
        mClientRef(args.client),
        mWindowType(static_cast<WindowInfo::Type>(
                args.metadata.getInt32(gui::METADATA_WINDOW_TYPE, 0))),
        mLayerCreationFlags(args.flags),
        mBorderEnabled(false),
        mTextureName(args.textureName),
        mLegacyLayerFE(args.flinger->getFactory().createLayerFE(mName)) {
    ALOGV("Creating Layer %s", getDebugName());

    uint32_t layerFlags = 0;
    if (args.flags & ISurfaceComposerClient::eHidden) layerFlags |= layer_state_t::eLayerHidden;
    if (args.flags & ISurfaceComposerClient::eOpaque) layerFlags |= layer_state_t::eLayerOpaque;
    if (args.flags & ISurfaceComposerClient::eSecure) layerFlags |= layer_state_t::eLayerSecure;
    if (args.flags & ISurfaceComposerClient::eSkipScreenshot)
        layerFlags |= layer_state_t::eLayerSkipScreenshot;
    mDrawingState.flags = layerFlags;
    mDrawingState.crop.makeInvalid();
    mDrawingState.z = 0;
    mDrawingState.color.a = 1.0f;
    mDrawingState.layerStack = ui::DEFAULT_LAYER_STACK;
    mDrawingState.sequence = 0;
    mDrawingState.transform.set(0, 0);
    mDrawingState.frameNumber = 0;
    mDrawingState.barrierFrameNumber = 0;
    mDrawingState.producerId = 0;
    mDrawingState.barrierProducerId = 0;
    mDrawingState.bufferTransform = 0;
    mDrawingState.transformToDisplayInverse = false;
    mDrawingState.acquireFence = sp<Fence>::make(-1);
    mDrawingState.acquireFenceTime = std::make_shared<FenceTime>(mDrawingState.acquireFence);
    mDrawingState.dataspace = ui::Dataspace::V0_SRGB;
    mDrawingState.hdrMetadata.validTypes = 0;
    mDrawingState.surfaceDamageRegion = Region::INVALID_REGION;
    mDrawingState.cornerRadius = 0.0f;
    mDrawingState.backgroundBlurRadius = 0;
    mDrawingState.api = -1;
    mDrawingState.hasColorTransform = false;
    mDrawingState.colorSpaceAgnostic = false;
    mDrawingState.frameRateSelectionPriority = PRIORITY_UNSET;
    mDrawingState.metadata = args.metadata;
    mDrawingState.shadowRadius = 0.f;
    mDrawingState.fixedTransformHint = ui::Transform::ROT_INVALID;
    mDrawingState.frameTimelineInfo = {};
    mDrawingState.postTime = -1;
    mDrawingState.destinationFrame.makeInvalid();
    mDrawingState.isTrustedOverlay = false;
    mDrawingState.dropInputMode = gui::DropInputMode::NONE;
    mDrawingState.dimmingEnabled = true;
    mDrawingState.defaultFrameRateCompatibility = FrameRateCompatibility::Default;

    if (args.flags & ISurfaceComposerClient::eNoColorFill) {
        // Set an invalid color so there is no color fill.
        mDrawingState.color.r = -1.0_hf;
        mDrawingState.color.g = -1.0_hf;
        mDrawingState.color.b = -1.0_hf;
    }

    mFrameTracker.setDisplayRefreshPeriod(
            args.flinger->mScheduler->getPacesetterVsyncPeriod().ns());

    mOwnerUid = args.ownerUid;
    mOwnerPid = args.ownerPid;

    mPremultipliedAlpha = !(args.flags & ISurfaceComposerClient::eNonPremultiplied);
    mPotentialCursor = args.flags & ISurfaceComposerClient::eCursorWindow;
    mProtectedByApp = args.flags & ISurfaceComposerClient::eProtectedByApp;

    mSnapshot->sequence = sequence;
    mSnapshot->name = getDebugName();
    mSnapshot->textureName = mTextureName;
    mSnapshot->premultipliedAlpha = mPremultipliedAlpha;
    mSnapshot->parentTransform = {};
}

void Layer::onFirstRef() {
    mFlinger->onLayerFirstRef(this);
}

Layer::~Layer() {
    LOG_ALWAYS_FATAL_IF(std::this_thread::get_id() != mFlinger->mMainThreadId,
                        "Layer destructor called off the main thread.");

    // The original layer and the clone layer share the same texture and buffer. Therefore, only
    // one of the layers, in this case the original layer, needs to handle the deletion. The
    // original layer and the clone should be removed at the same time so there shouldn't be any
    // issue with the clone layer trying to use the texture.
    if (mBufferInfo.mBuffer != nullptr) {
        callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                  mBufferInfo.mBuffer->getBuffer(), mBufferInfo.mFrameNumber,
                                  mBufferInfo.mFence);
    }
    if (!isClone()) {
        // The original layer and the clone layer share the same texture. Therefore, only one of
        // the layers, in this case the original layer, needs to handle the deletion. The original
        // layer and the clone should be removed at the same time so there shouldn't be any issue
        // with the clone layer trying to use the deleted texture.
        mFlinger->deleteTextureAsync(mTextureName);
    }
    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->onDestroy(layerId);
    mFlinger->mFrameTracer->onDestroy(layerId);

    mFrameTracker.logAndResetStats(mName);
    mFlinger->onLayerDestroyed(this);

    if (mDrawingState.sidebandStream != nullptr) {
        mFlinger->mTunnelModeEnabledReporter->decrementTunnelModeCount();
    }
    if (mHadClonedChild) {
        auto& roots = mFlinger->mLayerMirrorRoots;
        roots.erase(std::remove(roots.begin(), roots.end(), this), roots.end());
    }
    if (hasTrustedPresentationListener()) {
        mFlinger->mNumTrustedPresentationListeners--;
        updateTrustedPresentationState(nullptr, nullptr, -1 /* time_in_ms */, true /* leaveState*/);
    }
}

// ---------------------------------------------------------------------------
// callbacks
// ---------------------------------------------------------------------------

void Layer::removeRelativeZ(const std::vector<Layer*>& layersInTree) {
    if (mDrawingState.zOrderRelativeOf == nullptr) {
        return;
    }

    sp<Layer> strongRelative = mDrawingState.zOrderRelativeOf.promote();
    if (strongRelative == nullptr) {
        setZOrderRelativeOf(nullptr);
        return;
    }

    if (!std::binary_search(layersInTree.begin(), layersInTree.end(), strongRelative.get())) {
        strongRelative->removeZOrderRelative(wp<Layer>::fromExisting(this));
        mFlinger->setTransactionFlags(eTraversalNeeded);
        setZOrderRelativeOf(nullptr);
    }
}

void Layer::removeFromCurrentState() {
    if (!mRemovedFromDrawingState) {
        mRemovedFromDrawingState = true;
        mFlinger->mScheduler->deregisterLayer(this);
    }
    updateTrustedPresentationState(nullptr, nullptr, -1 /* time_in_ms */, true /* leaveState*/);

    mFlinger->markLayerPendingRemovalLocked(sp<Layer>::fromExisting(this));
}

sp<Layer> Layer::getRootLayer() {
    sp<Layer> parent = getParent();
    if (parent == nullptr) {
        return sp<Layer>::fromExisting(this);
    }
    return parent->getRootLayer();
}

void Layer::onRemovedFromCurrentState() {
    // Use the root layer since we want to maintain the hierarchy for the entire subtree.
    auto layersInTree = getRootLayer()->getLayersInTree(LayerVector::StateSet::Current);
    std::sort(layersInTree.begin(), layersInTree.end());

    REQUIRE_MUTEX(mFlinger->mStateLock);
    traverse(LayerVector::StateSet::Current,
             [&](Layer* layer) REQUIRES(layer->mFlinger->mStateLock) {
                 layer->removeFromCurrentState();
                 layer->removeRelativeZ(layersInTree);
             });
}

void Layer::addToCurrentState() {
    if (mRemovedFromDrawingState) {
        mRemovedFromDrawingState = false;
        mFlinger->mScheduler->registerLayer(this);
        mFlinger->removeFromOffscreenLayers(this);
    }

    for (const auto& child : mCurrentChildren) {
        child->addToCurrentState();
    }
}

// ---------------------------------------------------------------------------
// set-up
// ---------------------------------------------------------------------------

bool Layer::getPremultipledAlpha() const {
    return mPremultipliedAlpha;
}

sp<IBinder> Layer::getHandle() {
    Mutex::Autolock _l(mLock);
    if (mGetHandleCalled) {
        ALOGE("Get handle called twice" );
        return nullptr;
    }
    mGetHandleCalled = true;
    mHandleAlive = true;
    return sp<LayerHandle>::make(mFlinger, sp<Layer>::fromExisting(this));
}

// ---------------------------------------------------------------------------
// h/w composer set-up
// ---------------------------------------------------------------------------

static Rect reduce(const Rect& win, const Region& exclude) {
    if (CC_LIKELY(exclude.isEmpty())) {
        return win;
    }
    if (exclude.isRect()) {
        return win.reduce(exclude.getBounds());
    }
    return Region(win).subtract(exclude).getBounds();
}

static FloatRect reduce(const FloatRect& win, const Region& exclude) {
    if (CC_LIKELY(exclude.isEmpty())) {
        return win;
    }
    // Convert through Rect (by rounding) for lack of FloatRegion
    return Region(Rect{win}).subtract(exclude).getBounds().toFloatRect();
}

Rect Layer::getScreenBounds(bool reduceTransparentRegion) const {
    if (!reduceTransparentRegion) {
        return Rect{mScreenBounds};
    }

    FloatRect bounds = getBounds();
    ui::Transform t = getTransform();
    // Transform to screen space.
    bounds = t.transform(bounds);
    return Rect{bounds};
}

FloatRect Layer::getBounds() const {
    const State& s(getDrawingState());
    return getBounds(getActiveTransparentRegion(s));
}

FloatRect Layer::getBounds(const Region& activeTransparentRegion) const {
    // Subtract the transparent region and snap to the bounds.
    return reduce(mBounds, activeTransparentRegion);
}

// No early returns.
void Layer::updateTrustedPresentationState(const DisplayDevice* display,
                                           const frontend::LayerSnapshot* snapshot,
                                           int64_t time_in_ms, bool leaveState) {
    if (!hasTrustedPresentationListener()) {
        return;
    }
    const bool lastState = mLastComputedTrustedPresentationState;
    mLastComputedTrustedPresentationState = false;

    if (!leaveState) {
        const auto outputLayer = findOutputLayerForDisplay(display);
        if (outputLayer != nullptr) {
            if (outputLayer->getState().coveredRegionExcludingDisplayOverlays) {
                Region coveredRegion =
                        *outputLayer->getState().coveredRegionExcludingDisplayOverlays;
                mLastComputedTrustedPresentationState =
                        computeTrustedPresentationState(snapshot->geomLayerBounds,
                                                        snapshot->sourceBounds(), coveredRegion,
                                                        snapshot->transformedBounds,
                                                        snapshot->alpha,
                                                        snapshot->geomLayerTransform,
                                                        mTrustedPresentationThresholds);
            } else {
                ALOGE("CoveredRegionExcludingDisplayOverlays was not set for %s. Don't compute "
                      "TrustedPresentationState",
                      getDebugName());
            }
        }
    }
    const bool newState = mLastComputedTrustedPresentationState;
    if (lastState && !newState) {
        // We were in the trusted presentation state, but now we left it,
        // emit the callback if needed
        if (mLastReportedTrustedPresentationState) {
            mLastReportedTrustedPresentationState = false;
            mTrustedPresentationListener.invoke(false);
        }
        // Reset the timer
        mEnteredTrustedPresentationStateTime = -1;
    } else if (!lastState && newState) {
        // We were not in the trusted presentation state, but we entered it, begin the timer
        // and make sure this gets called at least once more!
        mEnteredTrustedPresentationStateTime = time_in_ms;
        mFlinger->forceFutureUpdate(mTrustedPresentationThresholds.stabilityRequirementMs * 1.5);
    }

    // Has the timer elapsed, but we are still in the state? Emit a callback if needed
    if (!mLastReportedTrustedPresentationState && newState &&
        (time_in_ms - mEnteredTrustedPresentationStateTime >
         mTrustedPresentationThresholds.stabilityRequirementMs)) {
        mLastReportedTrustedPresentationState = true;
        mTrustedPresentationListener.invoke(true);
    }
}

/**
 * See SurfaceComposerClient.h: setTrustedPresentationCallback for discussion
 * of how the parameters and thresholds are interpreted. The general spirit is
 * to produce an upper bound on the amount of the buffer which was presented.
 */
bool Layer::computeTrustedPresentationState(const FloatRect& bounds, const FloatRect& sourceBounds,
                                            const Region& coveredRegion,
                                            const FloatRect& screenBounds, float alpha,
                                            const ui::Transform& effectiveTransform,
                                            const TrustedPresentationThresholds& thresholds) {
    if (alpha < thresholds.minAlpha) {
        return false;
    }
    if (sourceBounds.getWidth() == 0 || sourceBounds.getHeight() == 0) {
        return false;
    }
    if (screenBounds.getWidth() == 0 || screenBounds.getHeight() == 0) {
        return false;
    }

    const float sx = effectiveTransform.dsdx();
    const float sy = effectiveTransform.dsdy();
    float fractionRendered = std::min(sx * sy, 1.0f);

    float boundsOverSourceW = bounds.getWidth() / (float)sourceBounds.getWidth();
    float boundsOverSourceH = bounds.getHeight() / (float)sourceBounds.getHeight();
    fractionRendered *= boundsOverSourceW * boundsOverSourceH;

    Region tJunctionFreeRegion = Region::createTJunctionFreeRegion(coveredRegion);
    // Compute the size of all the rects since they may be disconnected.
    float coveredSize = 0;
    for (auto rect = tJunctionFreeRegion.begin(); rect < tJunctionFreeRegion.end(); rect++) {
        float size = rect->width() * rect->height();
        coveredSize += size;
    }

    fractionRendered *= (1 - (coveredSize / (screenBounds.getWidth() * screenBounds.getHeight())));

    if (fractionRendered < thresholds.minFractionRendered) {
        return false;
    }

    return true;
}

void Layer::computeBounds(FloatRect parentBounds, ui::Transform parentTransform,
                          float parentShadowRadius) {
    const State& s(getDrawingState());

    // Calculate effective layer transform
    mEffectiveTransform = parentTransform * getActiveTransform(s);

    if (CC_UNLIKELY(!isTransformValid())) {
        ALOGW("Stop computing bounds for %s because it has invalid transformation.",
              getDebugName());
        return;
    }

    // Transform parent bounds to layer space
    parentBounds = getActiveTransform(s).inverse().transform(parentBounds);

    // Calculate source bounds
    mSourceBounds = computeSourceBounds(parentBounds);

    // Calculate bounds by croping diplay frame with layer crop and parent bounds
    FloatRect bounds = mSourceBounds;
    const Rect layerCrop = getCrop(s);
    if (!layerCrop.isEmpty()) {
        bounds = mSourceBounds.intersect(layerCrop.toFloatRect());
    }
    bounds = bounds.intersect(parentBounds);

    mBounds = bounds;
    mScreenBounds = mEffectiveTransform.transform(mBounds);

    // Use the layer's own shadow radius if set. Otherwise get the radius from
    // parent.
    if (s.shadowRadius > 0.f) {
        mEffectiveShadowRadius = s.shadowRadius;
    } else {
        mEffectiveShadowRadius = parentShadowRadius;
    }

    // Shadow radius is passed down to only one layer so if the layer can draw shadows,
    // don't pass it to its children.
    const float childShadowRadius = canDrawShadows() ? 0.f : mEffectiveShadowRadius;

    for (const sp<Layer>& child : mDrawingChildren) {
        child->computeBounds(mBounds, mEffectiveTransform, childShadowRadius);
    }

    if (mPotentialCursor) {
        prepareCursorCompositionState();
    }
}

Rect Layer::getCroppedBufferSize(const State& s) const {
    Rect size = getBufferSize(s);
    Rect crop = getCrop(s);
    if (!crop.isEmpty() && size.isValid()) {
        size.intersect(crop, &size);
    } else if (!crop.isEmpty()) {
        size = crop;
    }
    return size;
}

void Layer::setupRoundedCornersCropCoordinates(Rect win,
                                               const FloatRect& roundedCornersCrop) const {
    // Translate win by the rounded corners rect coordinates, to have all values in
    // layer coordinate space.
    win.left -= roundedCornersCrop.left;
    win.right -= roundedCornersCrop.left;
    win.top -= roundedCornersCrop.top;
    win.bottom -= roundedCornersCrop.top;
}

void Layer::prepareBasicGeometryCompositionState() {
    const auto& drawingState{getDrawingState()};
    const auto alpha = static_cast<float>(getAlpha());
    const bool opaque = isOpaque(drawingState);
    const bool usesRoundedCorners = hasRoundedCorners();

    auto blendMode = Hwc2::IComposerClient::BlendMode::NONE;
    if (!opaque || alpha != 1.0f) {
        blendMode = mPremultipliedAlpha ? Hwc2::IComposerClient::BlendMode::PREMULTIPLIED
                                        : Hwc2::IComposerClient::BlendMode::COVERAGE;
    }

    // Please keep in sync with LayerSnapshotBuilder
    auto* snapshot = editLayerSnapshot();
    snapshot->outputFilter = getOutputFilter();
    snapshot->isVisible = isVisible();
    snapshot->isOpaque = opaque && !usesRoundedCorners && alpha == 1.f;
    snapshot->shadowRadius = mEffectiveShadowRadius;

    snapshot->contentDirty = contentDirty;
    contentDirty = false;

    snapshot->geomLayerBounds = mBounds;
    snapshot->geomLayerTransform = getTransform();
    snapshot->geomInverseLayerTransform = snapshot->geomLayerTransform.inverse();
    snapshot->transparentRegionHint = getActiveTransparentRegion(drawingState);
    snapshot->localTransform = getActiveTransform(drawingState);
    snapshot->localTransformInverse = snapshot->localTransform.inverse();
    snapshot->blendMode = static_cast<Hwc2::IComposerClient::BlendMode>(blendMode);
    snapshot->alpha = alpha;
    snapshot->backgroundBlurRadius = drawingState.backgroundBlurRadius;
    snapshot->blurRegions = drawingState.blurRegions;
    snapshot->stretchEffect = getStretchEffect();
}

void Layer::prepareGeometryCompositionState() {
    const auto& drawingState{getDrawingState()};
    auto* snapshot = editLayerSnapshot();

    // Please keep in sync with LayerSnapshotBuilder
    snapshot->geomBufferSize = getBufferSize(drawingState);
    snapshot->geomContentCrop = getBufferCrop();
    snapshot->geomCrop = getCrop(drawingState);
    snapshot->geomBufferTransform = getBufferTransform();
    snapshot->geomBufferUsesDisplayInverseTransform = getTransformToDisplayInverse();
    snapshot->geomUsesSourceCrop = usesSourceCrop();
    snapshot->isSecure = isSecure();

    snapshot->metadata.clear();
    const auto& supportedMetadata = mFlinger->getHwComposer().getSupportedLayerGenericMetadata();
    for (const auto& [key, mandatory] : supportedMetadata) {
        const auto& genericLayerMetadataCompatibilityMap =
                mFlinger->getGenericLayerMetadataKeyMap();
        auto compatIter = genericLayerMetadataCompatibilityMap.find(key);
        if (compatIter == std::end(genericLayerMetadataCompatibilityMap)) {
            continue;
        }
        const uint32_t id = compatIter->second;

        auto it = drawingState.metadata.mMap.find(id);
        if (it == std::end(drawingState.metadata.mMap)) {
            continue;
        }

        snapshot->metadata.emplace(key,
                                   compositionengine::GenericLayerMetadataEntry{mandatory,
                                                                                it->second});
    }
}

void Layer::preparePerFrameCompositionState() {
    const auto& drawingState{getDrawingState()};
    // Please keep in sync with LayerSnapshotBuilder
    auto* snapshot = editLayerSnapshot();

    snapshot->forceClientComposition = false;

    snapshot->isColorspaceAgnostic = isColorSpaceAgnostic();
    snapshot->dataspace = getDataSpace();
    snapshot->colorTransform = getColorTransform();
    snapshot->colorTransformIsIdentity = !hasColorTransform();
    snapshot->surfaceDamage = surfaceDamageRegion;
    snapshot->hasProtectedContent = isProtected();
    snapshot->dimmingEnabled = isDimmingEnabled();
    snapshot->currentHdrSdrRatio = getCurrentHdrSdrRatio();
    snapshot->desiredHdrSdrRatio = getDesiredHdrSdrRatio();
    snapshot->cachingHint = getCachingHint();

    const bool usesRoundedCorners = hasRoundedCorners();

    snapshot->isOpaque = isOpaque(drawingState) && !usesRoundedCorners && getAlpha() == 1.0_hf;

    // Force client composition for special cases known only to the front-end.
    // Rounded corners no longer force client composition, since we may use a
    // hole punch so that the layer will appear to have rounded corners.
    if (isHdrY410() || drawShadows() || drawingState.blurRegions.size() > 0 ||
        snapshot->stretchEffect.hasEffect()) {
        snapshot->forceClientComposition = true;
    }
    // If there are no visible region changes, we still need to update blur parameters.
    snapshot->blurRegions = drawingState.blurRegions;
    snapshot->backgroundBlurRadius = drawingState.backgroundBlurRadius;

    // Layer framerate is used in caching decisions.
    // Retrieve it from the scheduler which maintains an instance of LayerHistory, and store it in
    // LayerFECompositionState where it would be visible to Flattener.
    snapshot->fps = mFlinger->getLayerFramerate(systemTime(), getSequence());

    if (hasBufferOrSidebandStream()) {
        preparePerFrameBufferCompositionState();
    } else {
        preparePerFrameEffectsCompositionState();
    }
}

void Layer::preparePerFrameBufferCompositionState() {
    // Please keep in sync with LayerSnapshotBuilder
    auto* snapshot = editLayerSnapshot();
    // Sideband layers
    if (snapshot->sidebandStream.get() && !snapshot->sidebandStreamHasFrame) {
        snapshot->compositionType =
                aidl::android::hardware::graphics::composer3::Composition::SIDEBAND;
        return;
    } else if ((mDrawingState.flags & layer_state_t::eLayerIsDisplayDecoration) != 0) {
        snapshot->compositionType =
                aidl::android::hardware::graphics::composer3::Composition::DISPLAY_DECORATION;
    } else if ((mDrawingState.flags & layer_state_t::eLayerIsRefreshRateIndicator) != 0) {
        snapshot->compositionType =
                aidl::android::hardware::graphics::composer3::Composition::REFRESH_RATE_INDICATOR;
    } else {
        // Normal buffer layers
        snapshot->hdrMetadata = mBufferInfo.mHdrMetadata;
        snapshot->compositionType = mPotentialCursor
                ? aidl::android::hardware::graphics::composer3::Composition::CURSOR
                : aidl::android::hardware::graphics::composer3::Composition::DEVICE;
    }

    snapshot->buffer = getBuffer();
    snapshot->acquireFence = mBufferInfo.mFence;
    snapshot->frameNumber = mBufferInfo.mFrameNumber;
    snapshot->sidebandStreamHasFrame = false;
}

void Layer::preparePerFrameEffectsCompositionState() {
    // Please keep in sync with LayerSnapshotBuilder
    auto* snapshot = editLayerSnapshot();
    snapshot->color = getColor();
    snapshot->compositionType =
            aidl::android::hardware::graphics::composer3::Composition::SOLID_COLOR;
}

void Layer::prepareCursorCompositionState() {
    const State& drawingState{getDrawingState()};
    // Please keep in sync with LayerSnapshotBuilder
    auto* snapshot = editLayerSnapshot();

    // Apply the layer's transform, followed by the display's global transform
    // Here we're guaranteed that the layer's transform preserves rects
    Rect win = getCroppedBufferSize(drawingState);
    // Subtract the transparent region and snap to the bounds
    Rect bounds = reduce(win, getActiveTransparentRegion(drawingState));
    Rect frame(getTransform().transform(bounds));

    snapshot->cursorFrame = frame;
}

const char* Layer::getDebugName() const {
    return mName.c_str();
}

// ---------------------------------------------------------------------------
// drawing...
// ---------------------------------------------------------------------------

aidl::android::hardware::graphics::composer3::Composition Layer::getCompositionType(
        const DisplayDevice& display) const {
    const auto outputLayer = findOutputLayerForDisplay(&display);
    if (outputLayer == nullptr) {
        return aidl::android::hardware::graphics::composer3::Composition::INVALID;
    }
    if (outputLayer->getState().hwc) {
        return (*outputLayer->getState().hwc).hwcCompositionType;
    } else {
        return aidl::android::hardware::graphics::composer3::Composition::CLIENT;
    }
}

// ----------------------------------------------------------------------------
// local state
// ----------------------------------------------------------------------------

bool Layer::isSecure() const {
    const State& s(mDrawingState);
    if (s.flags & layer_state_t::eLayerSecure) {
        return true;
    }

    const auto p = mDrawingParent.promote();
    return (p != nullptr) ? p->isSecure() : false;
}

void Layer::transferAvailableJankData(const std::deque<sp<CallbackHandle>>& handles,
                                      std::vector<JankData>& jankData) {
    if (mPendingJankClassifications.empty() ||
        !mPendingJankClassifications.front()->getJankType()) {
        return;
    }

    bool includeJankData = false;
    for (const auto& handle : handles) {
        for (const auto& cb : handle->callbackIds) {
            if (cb.includeJankData) {
                includeJankData = true;
                break;
            }
        }

        if (includeJankData) {
            jankData.reserve(mPendingJankClassifications.size());
            break;
        }
    }

    while (!mPendingJankClassifications.empty() &&
           mPendingJankClassifications.front()->getJankType()) {
        if (includeJankData) {
            std::shared_ptr<frametimeline::SurfaceFrame> surfaceFrame =
                    mPendingJankClassifications.front();
            jankData.emplace_back(
                    JankData(surfaceFrame->getToken(), surfaceFrame->getJankType().value()));
        }
        mPendingJankClassifications.pop_front();
    }
}

// ----------------------------------------------------------------------------
// transaction
// ----------------------------------------------------------------------------

uint32_t Layer::doTransaction(uint32_t flags) {
    ATRACE_CALL();

    // TODO: This is unfortunate.
    mDrawingStateModified = mDrawingState.modified;
    mDrawingState.modified = false;

    const State& s(getDrawingState());

    if (updateGeometry()) {
        // invalidate and recompute the visible regions if needed
        flags |= Layer::eVisibleRegion;
    }

    if (s.sequence != mLastCommittedTxSequence) {
        // invalidate and recompute the visible regions if needed
        mLastCommittedTxSequence = s.sequence;
        flags |= eVisibleRegion;
        this->contentDirty = true;

        // we may use linear filtering, if the matrix scales us
        mNeedsFiltering = getActiveTransform(s).needsBilinearFiltering();
    }

    if (!mPotentialCursor && (flags & Layer::eVisibleRegion)) {
        mFlinger->mUpdateInputInfo = true;
    }

    commitTransaction(mDrawingState);

    return flags;
}

void Layer::commitTransaction(State&) {
    // Set the present state for all bufferlessSurfaceFramesTX to Presented. The
    // bufferSurfaceFrameTX will be presented in latchBuffer.
    for (auto& [token, surfaceFrame] : mDrawingState.bufferlessSurfaceFramesTX) {
        if (surfaceFrame->getPresentState() != PresentState::Presented) {
            // With applyPendingStates, we could end up having presented surfaceframes from previous
            // states
            surfaceFrame->setPresentState(PresentState::Presented, mLastLatchTime);
            mFlinger->mFrameTimeline->addSurfaceFrame(surfaceFrame);
        }
    }
    mDrawingState.bufferlessSurfaceFramesTX.clear();
}

uint32_t Layer::clearTransactionFlags(uint32_t mask) {
    const auto flags = mTransactionFlags & mask;
    mTransactionFlags &= ~mask;
    return flags;
}

void Layer::setTransactionFlags(uint32_t mask) {
    mTransactionFlags |= mask;
}

bool Layer::setChildLayer(const sp<Layer>& childLayer, int32_t z) {
    ssize_t idx = mCurrentChildren.indexOf(childLayer);
    if (idx < 0) {
        return false;
    }
    if (childLayer->setLayer(z)) {
        mCurrentChildren.removeAt(idx);
        mCurrentChildren.add(childLayer);
        return true;
    }
    return false;
}

bool Layer::setChildRelativeLayer(const sp<Layer>& childLayer,
        const sp<IBinder>& relativeToHandle, int32_t relativeZ) {
    ssize_t idx = mCurrentChildren.indexOf(childLayer);
    if (idx < 0) {
        return false;
    }
    if (childLayer->setRelativeLayer(relativeToHandle, relativeZ)) {
        mCurrentChildren.removeAt(idx);
        mCurrentChildren.add(childLayer);
        return true;
    }
    return false;
}

bool Layer::setLayer(int32_t z) {
    if (mDrawingState.z == z && !usingRelativeZ(LayerVector::StateSet::Current)) return false;
    mDrawingState.sequence++;
    mDrawingState.z = z;
    mDrawingState.modified = true;

    mFlinger->mSomeChildrenChanged = true;

    // Discard all relative layering.
    if (mDrawingState.zOrderRelativeOf != nullptr) {
        sp<Layer> strongRelative = mDrawingState.zOrderRelativeOf.promote();
        if (strongRelative != nullptr) {
            strongRelative->removeZOrderRelative(wp<Layer>::fromExisting(this));
        }
        setZOrderRelativeOf(nullptr);
    }
    setTransactionFlags(eTransactionNeeded);
    return true;
}

void Layer::removeZOrderRelative(const wp<Layer>& relative) {
    mDrawingState.zOrderRelatives.remove(relative);
    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
}

void Layer::addZOrderRelative(const wp<Layer>& relative) {
    mDrawingState.zOrderRelatives.add(relative);
    mDrawingState.modified = true;
    mDrawingState.sequence++;
    setTransactionFlags(eTransactionNeeded);
}

void Layer::setZOrderRelativeOf(const wp<Layer>& relativeOf) {
    mDrawingState.zOrderRelativeOf = relativeOf;
    mDrawingState.sequence++;
    mDrawingState.modified = true;
    mDrawingState.isRelativeOf = relativeOf != nullptr;

    setTransactionFlags(eTransactionNeeded);
}

bool Layer::setRelativeLayer(const sp<IBinder>& relativeToHandle, int32_t relativeZ) {
    sp<Layer> relative = LayerHandle::getLayer(relativeToHandle);
    if (relative == nullptr) {
        return false;
    }

    if (mDrawingState.z == relativeZ && usingRelativeZ(LayerVector::StateSet::Current) &&
        mDrawingState.zOrderRelativeOf == relative) {
        return false;
    }

    if (CC_UNLIKELY(relative->usingRelativeZ(LayerVector::StateSet::Drawing)) &&
        (relative->mDrawingState.zOrderRelativeOf == this)) {
        ALOGE("Detected relative layer loop between %s and %s",
              mName.c_str(), relative->mName.c_str());
        ALOGE("Ignoring new call to set relative layer");
        return false;
    }

    mFlinger->mSomeChildrenChanged = true;

    mDrawingState.sequence++;
    mDrawingState.modified = true;
    mDrawingState.z = relativeZ;

    auto oldZOrderRelativeOf = mDrawingState.zOrderRelativeOf.promote();
    if (oldZOrderRelativeOf != nullptr) {
        oldZOrderRelativeOf->removeZOrderRelative(wp<Layer>::fromExisting(this));
    }
    setZOrderRelativeOf(relative);
    relative->addZOrderRelative(wp<Layer>::fromExisting(this));

    setTransactionFlags(eTransactionNeeded);

    return true;
}

bool Layer::setTrustedOverlay(bool isTrustedOverlay) {
    if (mDrawingState.isTrustedOverlay == isTrustedOverlay) return false;
    mDrawingState.isTrustedOverlay = isTrustedOverlay;
    mDrawingState.modified = true;
    mFlinger->mUpdateInputInfo = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::isTrustedOverlay() const {
    if (getDrawingState().isTrustedOverlay) {
        return true;
    }
    const auto& p = mDrawingParent.promote();
    return (p != nullptr) && p->isTrustedOverlay();
}

bool Layer::setAlpha(float alpha) {
    if (mDrawingState.color.a == alpha) return false;
    mDrawingState.sequence++;
    mDrawingState.color.a = alpha;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setBackgroundColor(const half3& color, float alpha, ui::Dataspace dataspace) {
    if (!mDrawingState.bgColorLayer && alpha == 0) {
        return false;
    }
    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    if (!mDrawingState.bgColorLayer && alpha != 0) {
        // create background color layer if one does not yet exist
        uint32_t flags = ISurfaceComposerClient::eFXSurfaceEffect;
        std::string name = mName + "BackgroundColorLayer";
        mDrawingState.bgColorLayer = mFlinger->getFactory().createEffectLayer(
                LayerCreationArgs(mFlinger.get(), nullptr, std::move(name), flags,
                                  LayerMetadata()));

        // add to child list
        addChild(mDrawingState.bgColorLayer);
        mFlinger->mLayersAdded = true;
        // set up SF to handle added color layer
        if (isRemovedFromCurrentState()) {
            MUTEX_ALIAS(mFlinger->mStateLock, mDrawingState.bgColorLayer->mFlinger->mStateLock);
            mDrawingState.bgColorLayer->onRemovedFromCurrentState();
        }
        mFlinger->setTransactionFlags(eTransactionNeeded);
    } else if (mDrawingState.bgColorLayer && alpha == 0) {
        MUTEX_ALIAS(mFlinger->mStateLock, mDrawingState.bgColorLayer->mFlinger->mStateLock);
        mDrawingState.bgColorLayer->reparent(nullptr);
        mDrawingState.bgColorLayer = nullptr;
        return true;
    }

    mDrawingState.bgColorLayer->setColor(color);
    mDrawingState.bgColorLayer->setLayer(std::numeric_limits<int32_t>::min());
    mDrawingState.bgColorLayer->setAlpha(alpha);
    mDrawingState.bgColorLayer->setDataspace(dataspace);

    return true;
}

bool Layer::setCornerRadius(float cornerRadius) {
    if (mDrawingState.cornerRadius == cornerRadius) return false;

    mDrawingState.sequence++;
    mDrawingState.cornerRadius = cornerRadius;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setBackgroundBlurRadius(int backgroundBlurRadius) {
    if (mDrawingState.backgroundBlurRadius == backgroundBlurRadius) return false;
    // If we start or stop drawing blur then the layer's visibility state may change so increment
    // the magic sequence number.
    if (mDrawingState.backgroundBlurRadius == 0 || backgroundBlurRadius == 0) {
        mDrawingState.sequence++;
    }
    mDrawingState.backgroundBlurRadius = backgroundBlurRadius;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setTransparentRegionHint(const Region& transparent) {
    mDrawingState.sequence++;
    mDrawingState.transparentRegionHint = transparent;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setBlurRegions(const std::vector<BlurRegion>& blurRegions) {
    // If we start or stop drawing blur then the layer's visibility state may change so increment
    // the magic sequence number.
    if (mDrawingState.blurRegions.size() == 0 || blurRegions.size() == 0) {
        mDrawingState.sequence++;
    }
    mDrawingState.blurRegions = blurRegions;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setFlags(uint32_t flags, uint32_t mask) {
    const uint32_t newFlags = (mDrawingState.flags & ~mask) | (flags & mask);
    if (mDrawingState.flags == newFlags) return false;
    mDrawingState.sequence++;
    mDrawingState.flags = newFlags;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setCrop(const Rect& crop) {
    if (mDrawingState.crop == crop) return false;
    mDrawingState.sequence++;
    mDrawingState.crop = crop;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setMetadata(const LayerMetadata& data) {
    if (!mDrawingState.metadata.merge(data, true /* eraseEmpty */)) return false;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setLayerStack(ui::LayerStack layerStack) {
    if (mDrawingState.layerStack == layerStack) return false;
    mDrawingState.sequence++;
    mDrawingState.layerStack = layerStack;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setColorSpaceAgnostic(const bool agnostic) {
    if (mDrawingState.colorSpaceAgnostic == agnostic) {
        return false;
    }
    mDrawingState.sequence++;
    mDrawingState.colorSpaceAgnostic = agnostic;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setDimmingEnabled(const bool dimmingEnabled) {
    if (mDrawingState.dimmingEnabled == dimmingEnabled) return false;

    mDrawingState.sequence++;
    mDrawingState.dimmingEnabled = dimmingEnabled;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setFrameRateSelectionPriority(int32_t priority) {
    if (mDrawingState.frameRateSelectionPriority == priority) return false;
    mDrawingState.frameRateSelectionPriority = priority;
    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

int32_t Layer::getFrameRateSelectionPriority() const {
    // Check if layer has priority set.
    if (mDrawingState.frameRateSelectionPriority != PRIORITY_UNSET) {
        return mDrawingState.frameRateSelectionPriority;
    }
    // If not, search whether its parents have it set.
    sp<Layer> parent = getParent();
    if (parent != nullptr) {
        return parent->getFrameRateSelectionPriority();
    }

    return Layer::PRIORITY_UNSET;
}

bool Layer::setDefaultFrameRateCompatibility(FrameRateCompatibility compatibility) {
    if (mDrawingState.defaultFrameRateCompatibility == compatibility) return false;
    mDrawingState.defaultFrameRateCompatibility = compatibility;
    mDrawingState.modified = true;
    mFlinger->mScheduler->setDefaultFrameRateCompatibility(this);
    setTransactionFlags(eTransactionNeeded);
    return true;
}

scheduler::LayerInfo::FrameRateCompatibility Layer::getDefaultFrameRateCompatibility() const {
    return mDrawingState.defaultFrameRateCompatibility;
}

bool Layer::isLayerFocusedBasedOnPriority(int32_t priority) {
    return priority == PRIORITY_FOCUSED_WITH_MODE || priority == PRIORITY_FOCUSED_WITHOUT_MODE;
};

ui::LayerStack Layer::getLayerStack(LayerVector::StateSet state) const {
    bool useDrawing = state == LayerVector::StateSet::Drawing;
    const auto parent = useDrawing ? mDrawingParent.promote() : mCurrentParent.promote();
    if (parent) {
        return parent->getLayerStack();
    }
    return getDrawingState().layerStack;
}

bool Layer::setShadowRadius(float shadowRadius) {
    if (mDrawingState.shadowRadius == shadowRadius) {
        return false;
    }

    mDrawingState.sequence++;
    mDrawingState.shadowRadius = shadowRadius;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setFixedTransformHint(ui::Transform::RotationFlags fixedTransformHint) {
    if (mDrawingState.fixedTransformHint == fixedTransformHint) {
        return false;
    }

    mDrawingState.sequence++;
    mDrawingState.fixedTransformHint = fixedTransformHint;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setStretchEffect(const StretchEffect& effect) {
    StretchEffect temp = effect;
    temp.sanitize();
    if (mDrawingState.stretchEffect == temp) {
        return false;
    }
    mDrawingState.sequence++;
    mDrawingState.stretchEffect = temp;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

StretchEffect Layer::getStretchEffect() const {
    if (mDrawingState.stretchEffect.hasEffect()) {
        return mDrawingState.stretchEffect;
    }

    sp<Layer> parent = getParent();
    if (parent != nullptr) {
        auto effect = parent->getStretchEffect();
        if (effect.hasEffect()) {
            // TODO(b/179047472): Map it? Or do we make the effect be in global space?
            return effect;
        }
    }
    return StretchEffect{};
}

bool Layer::enableBorder(bool shouldEnable, float width, const half4& color) {
    if (mBorderEnabled == shouldEnable && mBorderWidth == width && mBorderColor == color) {
        return false;
    }
    mBorderEnabled = shouldEnable;
    mBorderWidth = width;
    mBorderColor = color;
    return true;
}

bool Layer::isBorderEnabled() {
    return mBorderEnabled;
}

float Layer::getBorderWidth() {
    return mBorderWidth;
}

const half4& Layer::getBorderColor() {
    return mBorderColor;
}

bool Layer::propagateFrameRateForLayerTree(FrameRate parentFrameRate, bool* transactionNeeded) {
    // The frame rate for layer tree is this layer's frame rate if present, or the parent frame rate
    const auto frameRate = [&] {
        if (mDrawingState.frameRate.rate.isValid() ||
            mDrawingState.frameRate.type == FrameRateCompatibility::NoVote) {
            return mDrawingState.frameRate;
        }

        return parentFrameRate;
    }();

    *transactionNeeded |= setFrameRateForLayerTreeLegacy(frameRate);

    // The frame rate is propagated to the children
    bool childrenHaveFrameRate = false;
    for (const sp<Layer>& child : mCurrentChildren) {
        childrenHaveFrameRate |=
                child->propagateFrameRateForLayerTree(frameRate, transactionNeeded);
    }

    // If we don't have a valid frame rate, but the children do, we set this
    // layer as NoVote to allow the children to control the refresh rate
    if (!frameRate.rate.isValid() && frameRate.type != FrameRateCompatibility::NoVote &&
        childrenHaveFrameRate) {
        *transactionNeeded |=
                setFrameRateForLayerTreeLegacy(FrameRate(Fps(), FrameRateCompatibility::NoVote));
    }

    // We return whether this layer ot its children has a vote. We ignore ExactOrMultiple votes for
    // the same reason we are allowing touch boost for those layers. See
    // RefreshRateSelector::rankFrameRates for details.
    const auto layerVotedWithDefaultCompatibility =
            frameRate.rate.isValid() && frameRate.type == FrameRateCompatibility::Default;
    const auto layerVotedWithNoVote = frameRate.type == FrameRateCompatibility::NoVote;
    const auto layerVotedWithExactCompatibility =
            frameRate.rate.isValid() && frameRate.type == FrameRateCompatibility::Exact;
    return layerVotedWithDefaultCompatibility || layerVotedWithNoVote ||
            layerVotedWithExactCompatibility || childrenHaveFrameRate;
}

void Layer::updateTreeHasFrameRateVote() {
    const auto root = [&]() -> sp<Layer> {
        sp<Layer> layer = sp<Layer>::fromExisting(this);
        while (auto parent = layer->getParent()) {
            layer = parent;
        }
        return layer;
    }();

    bool transactionNeeded = false;
    root->propagateFrameRateForLayerTree({}, &transactionNeeded);

    // TODO(b/195668952): we probably don't need eTraversalNeeded here
    if (transactionNeeded) {
        mFlinger->setTransactionFlags(eTraversalNeeded);
    }
}

bool Layer::setFrameRate(FrameRate frameRate) {
    if (mDrawingState.frameRate == frameRate) {
        return false;
    }

    mDrawingState.sequence++;
    mDrawingState.frameRate = frameRate;
    mDrawingState.modified = true;

    updateTreeHasFrameRateVote();

    setTransactionFlags(eTransactionNeeded);
    return true;
}

void Layer::setFrameTimelineVsyncForBufferTransaction(const FrameTimelineInfo& info,
                                                      nsecs_t postTime) {
    mDrawingState.postTime = postTime;

    // Check if one of the bufferlessSurfaceFramesTX contains the same vsyncId. This can happen if
    // there are two transactions with the same token, the first one without a buffer and the
    // second one with a buffer. We promote the bufferlessSurfaceFrame to a bufferSurfaceFrameTX
    // in that case.
    auto it = mDrawingState.bufferlessSurfaceFramesTX.find(info.vsyncId);
    if (it != mDrawingState.bufferlessSurfaceFramesTX.end()) {
        // Promote the bufferlessSurfaceFrame to a bufferSurfaceFrameTX
        mDrawingState.bufferSurfaceFrameTX = it->second;
        mDrawingState.bufferlessSurfaceFramesTX.erase(it);
        mDrawingState.bufferSurfaceFrameTX->promoteToBuffer();
        mDrawingState.bufferSurfaceFrameTX->setActualQueueTime(postTime);
    } else {
        mDrawingState.bufferSurfaceFrameTX =
                createSurfaceFrameForBuffer(info, postTime, mTransactionName);
    }

    setFrameTimelineVsyncForSkippedFrames(info, postTime, mTransactionName);
}

void Layer::setFrameTimelineVsyncForBufferlessTransaction(const FrameTimelineInfo& info,
                                                          nsecs_t postTime) {
    mDrawingState.frameTimelineInfo = info;
    mDrawingState.postTime = postTime;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    if (const auto& bufferSurfaceFrameTX = mDrawingState.bufferSurfaceFrameTX;
        bufferSurfaceFrameTX != nullptr) {
        if (bufferSurfaceFrameTX->getToken() == info.vsyncId) {
            // BufferSurfaceFrame takes precedence over BufferlessSurfaceFrame. If the same token is
            // being used for BufferSurfaceFrame, don't create a new one.
            return;
        }
    }
    // For Transactions without a buffer, we create only one SurfaceFrame per vsyncId. If multiple
    // transactions use the same vsyncId, we just treat them as one SurfaceFrame (unless they are
    // targeting different vsyncs).
    auto it = mDrawingState.bufferlessSurfaceFramesTX.find(info.vsyncId);
    if (it == mDrawingState.bufferlessSurfaceFramesTX.end()) {
        auto surfaceFrame = createSurfaceFrameForTransaction(info, postTime);
        mDrawingState.bufferlessSurfaceFramesTX[info.vsyncId] = surfaceFrame;
    } else {
        if (it->second->getPresentState() == PresentState::Presented) {
            // If the SurfaceFrame was already presented, its safe to overwrite it since it must
            // have been from previous vsync.
            it->second = createSurfaceFrameForTransaction(info, postTime);
        }
    }

    setFrameTimelineVsyncForSkippedFrames(info, postTime, mTransactionName);
}

void Layer::addSurfaceFrameDroppedForBuffer(
        std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame, nsecs_t dropTime) {
    surfaceFrame->setDropTime(dropTime);
    surfaceFrame->setPresentState(PresentState::Dropped);
    mFlinger->mFrameTimeline->addSurfaceFrame(surfaceFrame);
}

void Layer::addSurfaceFramePresentedForBuffer(
        std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame, nsecs_t acquireFenceTime,
        nsecs_t currentLatchTime) {
    surfaceFrame->setAcquireFenceTime(acquireFenceTime);
    surfaceFrame->setPresentState(PresentState::Presented, mLastLatchTime);
    mFlinger->mFrameTimeline->addSurfaceFrame(surfaceFrame);
    updateLastLatchTime(currentLatchTime);
}

std::shared_ptr<frametimeline::SurfaceFrame> Layer::createSurfaceFrameForTransaction(
        const FrameTimelineInfo& info, nsecs_t postTime) {
    auto surfaceFrame =
            mFlinger->mFrameTimeline->createSurfaceFrameForToken(info, mOwnerPid, mOwnerUid,
                                                                 getSequence(), mName,
                                                                 mTransactionName,
                                                                 /*isBuffer*/ false, getGameMode());
    surfaceFrame->setActualStartTime(info.startTimeNanos);
    // For Transactions, the post time is considered to be both queue and acquire fence time.
    surfaceFrame->setActualQueueTime(postTime);
    surfaceFrame->setAcquireFenceTime(postTime);
    const auto fps = mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());
    if (fps) {
        surfaceFrame->setRenderRate(*fps);
    }
    onSurfaceFrameCreated(surfaceFrame);
    return surfaceFrame;
}

std::shared_ptr<frametimeline::SurfaceFrame> Layer::createSurfaceFrameForBuffer(
        const FrameTimelineInfo& info, nsecs_t queueTime, std::string debugName) {
    auto surfaceFrame =
            mFlinger->mFrameTimeline->createSurfaceFrameForToken(info, mOwnerPid, mOwnerUid,
                                                                 getSequence(), mName, debugName,
                                                                 /*isBuffer*/ true, getGameMode());
    surfaceFrame->setActualStartTime(info.startTimeNanos);
    // For buffers, acquire fence time will set during latch.
    surfaceFrame->setActualQueueTime(queueTime);
    const auto fps = mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());
    if (fps) {
        surfaceFrame->setRenderRate(*fps);
    }
    onSurfaceFrameCreated(surfaceFrame);
    return surfaceFrame;
}

void Layer::setFrameTimelineVsyncForSkippedFrames(const FrameTimelineInfo& info, nsecs_t postTime,
                                                  std::string debugName) {
    if (info.skippedFrameVsyncId == FrameTimelineInfo::INVALID_VSYNC_ID) {
        return;
    }

    FrameTimelineInfo skippedFrameTimelineInfo = info;
    skippedFrameTimelineInfo.vsyncId = info.skippedFrameVsyncId;

    auto surfaceFrame =
            mFlinger->mFrameTimeline->createSurfaceFrameForToken(skippedFrameTimelineInfo,
                                                                 mOwnerPid, mOwnerUid,
                                                                 getSequence(), mName, debugName,
                                                                 /*isBuffer*/ false, getGameMode());
    surfaceFrame->setActualStartTime(skippedFrameTimelineInfo.skippedFrameStartTimeNanos);
    // For Transactions, the post time is considered to be both queue and acquire fence time.
    surfaceFrame->setActualQueueTime(postTime);
    surfaceFrame->setAcquireFenceTime(postTime);
    const auto fps = mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());
    if (fps) {
        surfaceFrame->setRenderRate(*fps);
    }
    onSurfaceFrameCreated(surfaceFrame);
    addSurfaceFrameDroppedForBuffer(surfaceFrame, postTime);
}

bool Layer::setFrameRateForLayerTreeLegacy(FrameRate frameRate) {
    if (mDrawingState.frameRateForLayerTree == frameRate) {
        return false;
    }

    mDrawingState.frameRateForLayerTree = frameRate;

    // TODO(b/195668952): we probably don't need to dirty visible regions here
    // or even store frameRateForLayerTree in mDrawingState
    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    mFlinger->mScheduler
            ->recordLayerHistory(sequence, getLayerProps(), systemTime(),
                                 scheduler::LayerHistory::LayerUpdateType::SetFrameRate);
    return true;
}

bool Layer::setFrameRateForLayerTree(FrameRate frameRate, const scheduler::LayerProps& layerProps) {
    if (mDrawingState.frameRateForLayerTree == frameRate) {
        return false;
    }

    mDrawingState.frameRateForLayerTree = frameRate;
    mFlinger->mScheduler
            ->recordLayerHistory(sequence, layerProps, systemTime(),
                                 scheduler::LayerHistory::LayerUpdateType::SetFrameRate);
    return true;
}

Layer::FrameRate Layer::getFrameRateForLayerTree() const {
    return getDrawingState().frameRateForLayerTree;
}

bool Layer::isHiddenByPolicy() const {
    const State& s(mDrawingState);
    const auto& parent = mDrawingParent.promote();
    if (parent != nullptr && parent->isHiddenByPolicy()) {
        return true;
    }
    if (usingRelativeZ(LayerVector::StateSet::Drawing)) {
        auto zOrderRelativeOf = mDrawingState.zOrderRelativeOf.promote();
        if (zOrderRelativeOf != nullptr) {
            if (zOrderRelativeOf->isHiddenByPolicy()) {
                return true;
            }
        }
    }
    if (CC_UNLIKELY(!isTransformValid())) {
        ALOGW("Hide layer %s because it has invalid transformation.", getDebugName());
        return true;
    }
    return s.flags & layer_state_t::eLayerHidden;
}

uint32_t Layer::getEffectiveUsage(uint32_t usage) const {
    // TODO: should we do something special if mSecure is set?
    if (mProtectedByApp) {
        // need a hardware-protected path to external video sink
        usage |= GraphicBuffer::USAGE_PROTECTED;
    }
    if (mPotentialCursor) {
        usage |= GraphicBuffer::USAGE_CURSOR;
    }
    usage |= GraphicBuffer::USAGE_HW_COMPOSER;
    return usage;
}

void Layer::skipReportingTransformHint() {
    mSkipReportingTransformHint = true;
}

void Layer::updateTransformHint(ui::Transform::RotationFlags transformHint) {
    if (mFlinger->mDebugDisableTransformHint || transformHint & ui::Transform::ROT_INVALID) {
        transformHint = ui::Transform::ROT_0;
    }

    setTransformHintLegacy(transformHint);
}

// ----------------------------------------------------------------------------
// debugging
// ----------------------------------------------------------------------------

// TODO(marissaw): add new layer state info to layer debugging
gui::LayerDebugInfo Layer::getLayerDebugInfo(const DisplayDevice* display) const {
    using namespace std::string_literals;

    gui::LayerDebugInfo info;
    const State& ds = getDrawingState();
    info.mName = getName();
    sp<Layer> parent = mDrawingParent.promote();
    info.mParentName = parent ? parent->getName() : "none"s;
    info.mType = getType();

    info.mVisibleRegion = getVisibleRegion(display);
    info.mSurfaceDamageRegion = surfaceDamageRegion;
    info.mLayerStack = getLayerStack().id;
    info.mX = ds.transform.tx();
    info.mY = ds.transform.ty();
    info.mZ = ds.z;
    info.mCrop = ds.crop;
    info.mColor = ds.color;
    info.mFlags = ds.flags;
    info.mPixelFormat = getPixelFormat();
    info.mDataSpace = static_cast<android_dataspace>(getDataSpace());
    info.mMatrix[0][0] = ds.transform[0][0];
    info.mMatrix[0][1] = ds.transform[0][1];
    info.mMatrix[1][0] = ds.transform[1][0];
    info.mMatrix[1][1] = ds.transform[1][1];
    {
        sp<const GraphicBuffer> buffer = getBuffer();
        if (buffer != 0) {
            info.mActiveBufferWidth = buffer->getWidth();
            info.mActiveBufferHeight = buffer->getHeight();
            info.mActiveBufferStride = buffer->getStride();
            info.mActiveBufferFormat = buffer->format;
        } else {
            info.mActiveBufferWidth = 0;
            info.mActiveBufferHeight = 0;
            info.mActiveBufferStride = 0;
            info.mActiveBufferFormat = 0;
        }
    }
    info.mNumQueuedFrames = getQueuedFrameCount();
    info.mIsOpaque = isOpaque(ds);
    info.mContentDirty = contentDirty;
    info.mStretchEffect = getStretchEffect();
    return info;
}

void Layer::miniDumpHeader(std::string& result) {
    result.append(kDumpTableRowLength, '-');
    result.append("\n");
    result.append(" Layer name\n");
    result.append("           Z | ");
    result.append(" Window Type | ");
    result.append(" Comp Type | ");
    result.append(" Transform | ");
    result.append("  Disp Frame (LTRB) | ");
    result.append("         Source Crop (LTRB) | ");
    result.append("    Frame Rate (Explicit) (Seamlessness) [Focused]\n");
    result.append(kDumpTableRowLength, '-');
    result.append("\n");
}

void Layer::miniDump(std::string& result, const DisplayDevice& display) const {
    const auto outputLayer = findOutputLayerForDisplay(&display);
    if (!outputLayer) {
        return;
    }

    std::string name;
    if (mName.length() > 77) {
        std::string shortened;
        shortened.append(mName, 0, 36);
        shortened.append("[...]");
        shortened.append(mName, mName.length() - 36);
        name = std::move(shortened);
    } else {
        name = mName;
    }

    StringAppendF(&result, " %s\n", name.c_str());

    const State& layerState(getDrawingState());
    const auto& outputLayerState = outputLayer->getState();

    if (layerState.zOrderRelativeOf != nullptr || mDrawingParent != nullptr) {
        StringAppendF(&result, "  rel %6d | ", layerState.z);
    } else {
        StringAppendF(&result, "  %10d | ", layerState.z);
    }
    StringAppendF(&result, "  %10d | ", mWindowType);
    StringAppendF(&result, "%10s | ", toString(getCompositionType(display)).c_str());
    StringAppendF(&result, "%10s | ", toString(outputLayerState.bufferTransform).c_str());
    const Rect& frame = outputLayerState.displayFrame;
    StringAppendF(&result, "%4d %4d %4d %4d | ", frame.left, frame.top, frame.right, frame.bottom);
    const FloatRect& crop = outputLayerState.sourceCrop;
    StringAppendF(&result, "%6.1f %6.1f %6.1f %6.1f | ", crop.left, crop.top, crop.right,
                  crop.bottom);
    const auto frameRate = getFrameRateForLayerTree();
    if (frameRate.rate.isValid() || frameRate.type != FrameRateCompatibility::Default) {
        StringAppendF(&result, "%s %15s %17s", to_string(frameRate.rate).c_str(),
                      ftl::enum_string(frameRate.type).c_str(),
                      ftl::enum_string(frameRate.seamlessness).c_str());
    } else {
        result.append(41, ' ');
    }

    const auto focused = isLayerFocusedBasedOnPriority(getFrameRateSelectionPriority());
    StringAppendF(&result, "    [%s]\n", focused ? "*" : " ");

    result.append(kDumpTableRowLength, '-');
    result.append("\n");
}

void Layer::dumpFrameStats(std::string& result) const {
    mFrameTracker.dumpStats(result);
}

void Layer::clearFrameStats() {
    mFrameTracker.clearStats();
}

void Layer::logFrameStats() {
    mFrameTracker.logAndResetStats(mName);
}

void Layer::getFrameStats(FrameStats* outStats) const {
    mFrameTracker.getStats(outStats);
}

void Layer::dumpOffscreenDebugInfo(std::string& result) const {
    std::string hasBuffer = hasBufferOrSidebandStream() ? " (contains buffer)" : "";
    StringAppendF(&result, "Layer %s%s pid:%d uid:%d%s\n", getName().c_str(), hasBuffer.c_str(),
                  mOwnerPid, mOwnerUid, isHandleAlive() ? " handleAlive" : "");
}

void Layer::onDisconnect() {
    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->onDestroy(layerId);
    mFlinger->mFrameTracer->onDestroy(layerId);
}

size_t Layer::getDescendantCount() const {
    size_t count = 0;
    for (const sp<Layer>& child : mDrawingChildren) {
        count += 1 + child->getChildrenCount();
    }
    return count;
}

void Layer::setGameModeForTree(GameMode gameMode) {
    const auto& currentState = getDrawingState();
    if (currentState.metadata.has(gui::METADATA_GAME_MODE)) {
        gameMode =
                static_cast<GameMode>(currentState.metadata.getInt32(gui::METADATA_GAME_MODE, 0));
    }
    setGameMode(gameMode);
    for (const sp<Layer>& child : mCurrentChildren) {
        child->setGameModeForTree(gameMode);
    }
}

void Layer::addChild(const sp<Layer>& layer) {
    mFlinger->mSomeChildrenChanged = true;
    setTransactionFlags(eTransactionNeeded);

    mCurrentChildren.add(layer);
    layer->setParent(sp<Layer>::fromExisting(this));
    layer->setGameModeForTree(mGameMode);
    updateTreeHasFrameRateVote();
}

ssize_t Layer::removeChild(const sp<Layer>& layer) {
    mFlinger->mSomeChildrenChanged = true;
    setTransactionFlags(eTransactionNeeded);

    layer->setParent(nullptr);
    const auto removeResult = mCurrentChildren.remove(layer);

    updateTreeHasFrameRateVote();
    layer->setGameModeForTree(GameMode::Unsupported);
    layer->updateTreeHasFrameRateVote();

    return removeResult;
}

void Layer::setChildrenDrawingParent(const sp<Layer>& newParent) {
    for (const sp<Layer>& child : mDrawingChildren) {
        child->mDrawingParent = newParent;
        const float parentShadowRadius =
                newParent->canDrawShadows() ? 0.f : newParent->mEffectiveShadowRadius;
        child->computeBounds(newParent->mBounds, newParent->mEffectiveTransform,
                             parentShadowRadius);
    }
}

bool Layer::reparent(const sp<IBinder>& newParentHandle) {
    sp<Layer> newParent;
    if (newParentHandle != nullptr) {
        newParent = LayerHandle::getLayer(newParentHandle);
        if (newParent == nullptr) {
            ALOGE("Unable to promote Layer handle");
            return false;
        }
        if (newParent == this) {
            ALOGE("Invalid attempt to reparent Layer (%s) to itself", getName().c_str());
            return false;
        }
    }

    sp<Layer> parent = getParent();
    if (parent != nullptr) {
        parent->removeChild(sp<Layer>::fromExisting(this));
    }

    if (newParentHandle != nullptr) {
        newParent->addChild(sp<Layer>::fromExisting(this));
        if (!newParent->isRemovedFromCurrentState()) {
            addToCurrentState();
        } else {
            onRemovedFromCurrentState();
        }
    } else {
        onRemovedFromCurrentState();
    }

    return true;
}

bool Layer::setColorTransform(const mat4& matrix) {
    static const mat4 identityMatrix = mat4();

    if (mDrawingState.colorTransform == matrix) {
        return false;
    }
    ++mDrawingState.sequence;
    mDrawingState.colorTransform = matrix;
    mDrawingState.hasColorTransform = matrix != identityMatrix;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

mat4 Layer::getColorTransform() const {
    mat4 colorTransform = mat4(getDrawingState().colorTransform);
    if (sp<Layer> parent = mDrawingParent.promote(); parent != nullptr) {
        colorTransform = parent->getColorTransform() * colorTransform;
    }
    return colorTransform;
}

bool Layer::hasColorTransform() const {
    bool hasColorTransform = getDrawingState().hasColorTransform;
    if (sp<Layer> parent = mDrawingParent.promote(); parent != nullptr) {
        hasColorTransform = hasColorTransform || parent->hasColorTransform();
    }
    return hasColorTransform;
}

bool Layer::isLegacyDataSpace() const {
    // return true when no higher bits are set
    return !(getDataSpace() &
             (ui::Dataspace::STANDARD_MASK | ui::Dataspace::TRANSFER_MASK |
              ui::Dataspace::RANGE_MASK));
}

void Layer::setParent(const sp<Layer>& layer) {
    mCurrentParent = layer;
}

int32_t Layer::getZ(LayerVector::StateSet) const {
    return mDrawingState.z;
}

bool Layer::usingRelativeZ(LayerVector::StateSet stateSet) const {
    const bool useDrawing = stateSet == LayerVector::StateSet::Drawing;
    const State& state = useDrawing ? mDrawingState : mDrawingState;
    return state.isRelativeOf;
}

__attribute__((no_sanitize("unsigned-integer-overflow"))) LayerVector Layer::makeTraversalList(
        LayerVector::StateSet stateSet, bool* outSkipRelativeZUsers) {
    LOG_ALWAYS_FATAL_IF(stateSet == LayerVector::StateSet::Invalid,
                        "makeTraversalList received invalid stateSet");
    const bool useDrawing = stateSet == LayerVector::StateSet::Drawing;
    const LayerVector& children = useDrawing ? mDrawingChildren : mCurrentChildren;
    const State& state = useDrawing ? mDrawingState : mDrawingState;

    if (state.zOrderRelatives.size() == 0) {
        *outSkipRelativeZUsers = true;
        return children;
    }

    LayerVector traverse(stateSet);
    for (const wp<Layer>& weakRelative : state.zOrderRelatives) {
        sp<Layer> strongRelative = weakRelative.promote();
        if (strongRelative != nullptr) {
            traverse.add(strongRelative);
        }
    }

    for (const sp<Layer>& child : children) {
        if (child->usingRelativeZ(stateSet)) {
            continue;
        }
        traverse.add(child);
    }

    return traverse;
}

/**
 * Negatively signed relatives are before 'this' in Z-order.
 */
void Layer::traverseInZOrder(LayerVector::StateSet stateSet, const LayerVector::Visitor& visitor) {
    // In the case we have other layers who are using a relative Z to us, makeTraversalList will
    // produce a new list for traversing, including our relatives, and not including our children
    // who are relatives of another surface. In the case that there are no relative Z,
    // makeTraversalList returns our children directly to avoid significant overhead.
    // However in this case we need to take the responsibility for filtering children which
    // are relatives of another surface here.
    bool skipRelativeZUsers = false;
    const LayerVector list = makeTraversalList(stateSet, &skipRelativeZUsers);

    size_t i = 0;
    for (; i < list.size(); i++) {
        const auto& relative = list[i];
        if (skipRelativeZUsers && relative->usingRelativeZ(stateSet)) {
            continue;
        }

        if (relative->getZ(stateSet) >= 0) {
            break;
        }
        relative->traverseInZOrder(stateSet, visitor);
    }

    visitor(this);
    for (; i < list.size(); i++) {
        const auto& relative = list[i];

        if (skipRelativeZUsers && relative->usingRelativeZ(stateSet)) {
            continue;
        }
        relative->traverseInZOrder(stateSet, visitor);
    }
}

/**
 * Positively signed relatives are before 'this' in reverse Z-order.
 */
void Layer::traverseInReverseZOrder(LayerVector::StateSet stateSet,
                                    const LayerVector::Visitor& visitor) {
    // See traverseInZOrder for documentation.
    bool skipRelativeZUsers = false;
    LayerVector list = makeTraversalList(stateSet, &skipRelativeZUsers);

    int32_t i = 0;
    for (i = int32_t(list.size()) - 1; i >= 0; i--) {
        const auto& relative = list[i];

        if (skipRelativeZUsers && relative->usingRelativeZ(stateSet)) {
            continue;
        }

        if (relative->getZ(stateSet) < 0) {
            break;
        }
        relative->traverseInReverseZOrder(stateSet, visitor);
    }
    visitor(this);
    for (; i >= 0; i--) {
        const auto& relative = list[i];

        if (skipRelativeZUsers && relative->usingRelativeZ(stateSet)) {
            continue;
        }

        relative->traverseInReverseZOrder(stateSet, visitor);
    }
}

void Layer::traverse(LayerVector::StateSet state, const LayerVector::Visitor& visitor) {
    visitor(this);
    const LayerVector& children =
          state == LayerVector::StateSet::Drawing ? mDrawingChildren : mCurrentChildren;
    for (const sp<Layer>& child : children) {
        child->traverse(state, visitor);
    }
}

void Layer::traverseChildren(const LayerVector::Visitor& visitor) {
    for (const sp<Layer>& child : mDrawingChildren) {
        visitor(child.get());
    }
}

LayerVector Layer::makeChildrenTraversalList(LayerVector::StateSet stateSet,
                                             const std::vector<Layer*>& layersInTree) {
    LOG_ALWAYS_FATAL_IF(stateSet == LayerVector::StateSet::Invalid,
                        "makeTraversalList received invalid stateSet");
    const bool useDrawing = stateSet == LayerVector::StateSet::Drawing;
    const LayerVector& children = useDrawing ? mDrawingChildren : mCurrentChildren;
    const State& state = useDrawing ? mDrawingState : mDrawingState;

    LayerVector traverse(stateSet);
    for (const wp<Layer>& weakRelative : state.zOrderRelatives) {
        sp<Layer> strongRelative = weakRelative.promote();
        // Only add relative layers that are also descendents of the top most parent of the tree.
        // If a relative layer is not a descendent, then it should be ignored.
        if (std::binary_search(layersInTree.begin(), layersInTree.end(), strongRelative.get())) {
            traverse.add(strongRelative);
        }
    }

    for (const sp<Layer>& child : children) {
        const State& childState = useDrawing ? child->mDrawingState : child->mDrawingState;
        // If a layer has a relativeOf layer, only ignore if the layer it's relative to is a
        // descendent of the top most parent of the tree. If it's not a descendent, then just add
        // the child here since it won't be added later as a relative.
        if (std::binary_search(layersInTree.begin(), layersInTree.end(),
                               childState.zOrderRelativeOf.promote().get())) {
            continue;
        }
        traverse.add(child);
    }

    return traverse;
}

void Layer::traverseChildrenInZOrderInner(const std::vector<Layer*>& layersInTree,
                                          LayerVector::StateSet stateSet,
                                          const LayerVector::Visitor& visitor) {
    const LayerVector list = makeChildrenTraversalList(stateSet, layersInTree);

    size_t i = 0;
    for (; i < list.size(); i++) {
        const auto& relative = list[i];
        if (relative->getZ(stateSet) >= 0) {
            break;
        }
        relative->traverseChildrenInZOrderInner(layersInTree, stateSet, visitor);
    }

    visitor(this);
    for (; i < list.size(); i++) {
        const auto& relative = list[i];
        relative->traverseChildrenInZOrderInner(layersInTree, stateSet, visitor);
    }
}

std::vector<Layer*> Layer::getLayersInTree(LayerVector::StateSet stateSet) {
    const bool useDrawing = stateSet == LayerVector::StateSet::Drawing;
    const LayerVector& children = useDrawing ? mDrawingChildren : mCurrentChildren;

    std::vector<Layer*> layersInTree = {this};
    for (size_t i = 0; i < children.size(); i++) {
        const auto& child = children[i];
        std::vector<Layer*> childLayers = child->getLayersInTree(stateSet);
        layersInTree.insert(layersInTree.end(), childLayers.cbegin(), childLayers.cend());
    }

    return layersInTree;
}

void Layer::traverseChildrenInZOrder(LayerVector::StateSet stateSet,
                                     const LayerVector::Visitor& visitor) {
    std::vector<Layer*> layersInTree = getLayersInTree(stateSet);
    std::sort(layersInTree.begin(), layersInTree.end());
    traverseChildrenInZOrderInner(layersInTree, stateSet, visitor);
}

ui::Transform Layer::getTransform() const {
    return mEffectiveTransform;
}

bool Layer::isTransformValid() const {
    float transformDet = getTransform().det();
    return transformDet != 0 && !isinf(transformDet) && !isnan(transformDet);
}

half Layer::getAlpha() const {
    const auto& p = mDrawingParent.promote();

    half parentAlpha = (p != nullptr) ? p->getAlpha() : 1.0_hf;
    return parentAlpha * getDrawingState().color.a;
}

ui::Transform::RotationFlags Layer::getFixedTransformHint() const {
    ui::Transform::RotationFlags fixedTransformHint = mDrawingState.fixedTransformHint;
    if (fixedTransformHint != ui::Transform::ROT_INVALID) {
        return fixedTransformHint;
    }
    const auto& p = mCurrentParent.promote();
    if (!p) return fixedTransformHint;
    return p->getFixedTransformHint();
}

half4 Layer::getColor() const {
    const half4 color(getDrawingState().color);
    return half4(color.r, color.g, color.b, getAlpha());
}

int32_t Layer::getBackgroundBlurRadius() const {
    if (getDrawingState().backgroundBlurRadius == 0) {
        return 0;
    }

    const auto& p = mDrawingParent.promote();
    half parentAlpha = (p != nullptr) ? p->getAlpha() : 1.0_hf;
    return parentAlpha * getDrawingState().backgroundBlurRadius;
}

const std::vector<BlurRegion> Layer::getBlurRegions() const {
    auto regionsCopy(getDrawingState().blurRegions);
    float layerAlpha = getAlpha();
    for (auto& region : regionsCopy) {
        region.alpha = region.alpha * layerAlpha;
    }
    return regionsCopy;
}

RoundedCornerState Layer::getRoundedCornerState() const {
    // Get parent settings
    RoundedCornerState parentSettings;
    const auto& parent = mDrawingParent.promote();
    if (parent != nullptr) {
        parentSettings = parent->getRoundedCornerState();
        if (parentSettings.hasRoundedCorners()) {
            ui::Transform t = getActiveTransform(getDrawingState());
            t = t.inverse();
            parentSettings.cropRect = t.transform(parentSettings.cropRect);
            parentSettings.radius.x *= t.getScaleX();
            parentSettings.radius.y *= t.getScaleY();
        }
    }

    // Get layer settings
    Rect layerCropRect = getCroppedBufferSize(getDrawingState());
    const vec2 radius(getDrawingState().cornerRadius, getDrawingState().cornerRadius);
    RoundedCornerState layerSettings(layerCropRect.toFloatRect(), radius);
    const bool layerSettingsValid = layerSettings.hasRoundedCorners() && layerCropRect.isValid();

    if (layerSettingsValid && parentSettings.hasRoundedCorners()) {
        // If the parent and the layer have rounded corner settings, use the parent settings if the
        // parent crop is entirely inside the layer crop.
        // This has limitations and cause rendering artifacts. See b/200300845 for correct fix.
        if (parentSettings.cropRect.left > layerCropRect.left &&
            parentSettings.cropRect.top > layerCropRect.top &&
            parentSettings.cropRect.right < layerCropRect.right &&
            parentSettings.cropRect.bottom < layerCropRect.bottom) {
            return parentSettings;
        } else {
            return layerSettings;
        }
    } else if (layerSettingsValid) {
        return layerSettings;
    } else if (parentSettings.hasRoundedCorners()) {
        return parentSettings;
    }
    return {};
}

bool Layer::findInHierarchy(const sp<Layer>& l) {
    if (l == this) {
        return true;
    }
    for (auto& child : mDrawingChildren) {
      if (child->findInHierarchy(l)) {
          return true;
      }
    }
    return false;
}

void Layer::commitChildList() {
    for (size_t i = 0; i < mCurrentChildren.size(); i++) {
        const auto& child = mCurrentChildren[i];
        child->commitChildList();
    }
    mDrawingChildren = mCurrentChildren;
    mDrawingParent = mCurrentParent;
    if (CC_UNLIKELY(usingRelativeZ(LayerVector::StateSet::Drawing))) {
        auto zOrderRelativeOf = mDrawingState.zOrderRelativeOf.promote();
        if (zOrderRelativeOf == nullptr) return;
        if (findInHierarchy(zOrderRelativeOf)) {
            ALOGE("Detected Z ordering loop between %s and %s", mName.c_str(),
                  zOrderRelativeOf->mName.c_str());
            ALOGE("Severing rel Z loop, potentially dangerous");
            mDrawingState.isRelativeOf = false;
            zOrderRelativeOf->removeZOrderRelative(wp<Layer>::fromExisting(this));
        }
    }
}


void Layer::setInputInfo(const WindowInfo& info) {
    mDrawingState.inputInfo = info;
    mDrawingState.touchableRegionCrop =
            LayerHandle::getLayer(info.touchableRegionCropHandle.promote());
    mDrawingState.modified = true;
    mFlinger->mUpdateInputInfo = true;
    setTransactionFlags(eTransactionNeeded);
}

LayerProto* Layer::writeToProto(LayersProto& layersProto, uint32_t traceFlags) {
    LayerProto* layerProto = layersProto.add_layers();
    writeToProtoDrawingState(layerProto);
    writeToProtoCommonState(layerProto, LayerVector::StateSet::Drawing, traceFlags);

    if (traceFlags & LayerTracing::TRACE_COMPOSITION) {
        ui::LayerStack layerStack =
                (mSnapshot) ? mSnapshot->outputFilter.layerStack : ui::INVALID_LAYER_STACK;
        writeCompositionStateToProto(layerProto, layerStack);
    }

    for (const sp<Layer>& layer : mDrawingChildren) {
        layer->writeToProto(layersProto, traceFlags);
    }

    return layerProto;
}

void Layer::writeCompositionStateToProto(LayerProto* layerProto, ui::LayerStack layerStack) {
    ftl::FakeGuard guard(mFlinger->mStateLock); // Called from the main thread.
    ftl::FakeGuard mainThreadGuard(kMainThreadContext);

    // Only populate for the primary display.
    if (const auto display = mFlinger->getDisplayFromLayerStack(layerStack)) {
        const auto compositionType = getCompositionType(*display);
        layerProto->set_hwc_composition_type(static_cast<HwcCompositionType>(compositionType));
        LayerProtoHelper::writeToProto(getVisibleRegion(display),
                                       [&]() { return layerProto->mutable_visible_region(); });
    }
}

void Layer::writeToProtoDrawingState(LayerProto* layerInfo) {
    const ui::Transform transform = getTransform();
    auto buffer = getExternalTexture();
    if (buffer != nullptr) {
        LayerProtoHelper::writeToProto(*buffer,
                                       [&]() { return layerInfo->mutable_active_buffer(); });
        LayerProtoHelper::writeToProtoDeprecated(ui::Transform(getBufferTransform()),
                                                 layerInfo->mutable_buffer_transform());
    }
    layerInfo->set_invalidate(contentDirty);
    layerInfo->set_is_protected(isProtected());
    layerInfo->set_dataspace(dataspaceDetails(static_cast<android_dataspace>(getDataSpace())));
    layerInfo->set_queued_frames(getQueuedFrameCount());
    layerInfo->set_curr_frame(mCurrentFrameNumber);
    layerInfo->set_requested_corner_radius(getDrawingState().cornerRadius);
    layerInfo->set_corner_radius(
            (getRoundedCornerState().radius.x + getRoundedCornerState().radius.y) / 2.0);
    layerInfo->set_background_blur_radius(getBackgroundBlurRadius());
    layerInfo->set_is_trusted_overlay(isTrustedOverlay());
    LayerProtoHelper::writeToProtoDeprecated(transform, layerInfo->mutable_transform());
    LayerProtoHelper::writePositionToProto(transform.tx(), transform.ty(),
                                           [&]() { return layerInfo->mutable_position(); });
    LayerProtoHelper::writeToProto(mBounds, [&]() { return layerInfo->mutable_bounds(); });
    LayerProtoHelper::writeToProto(surfaceDamageRegion,
                                   [&]() { return layerInfo->mutable_damage_region(); });

    if (hasColorTransform()) {
        LayerProtoHelper::writeToProto(getColorTransform(), layerInfo->mutable_color_transform());
    }

    LayerProtoHelper::writeToProto(mSourceBounds,
                                   [&]() { return layerInfo->mutable_source_bounds(); });
    LayerProtoHelper::writeToProto(mScreenBounds,
                                   [&]() { return layerInfo->mutable_screen_bounds(); });
    LayerProtoHelper::writeToProto(getRoundedCornerState().cropRect,
                                   [&]() { return layerInfo->mutable_corner_radius_crop(); });
    layerInfo->set_shadow_radius(mEffectiveShadowRadius);
}

void Layer::writeToProtoCommonState(LayerProto* layerInfo, LayerVector::StateSet stateSet,
                                    uint32_t traceFlags) {
    const bool useDrawing = stateSet == LayerVector::StateSet::Drawing;
    const LayerVector& children = useDrawing ? mDrawingChildren : mCurrentChildren;
    const State& state = useDrawing ? mDrawingState : mDrawingState;

    ui::Transform requestedTransform = state.transform;

    layerInfo->set_id(sequence);
    layerInfo->set_name(getName().c_str());
    layerInfo->set_type(getType());

    for (const auto& child : children) {
        layerInfo->add_children(child->sequence);
    }

    for (const wp<Layer>& weakRelative : state.zOrderRelatives) {
        sp<Layer> strongRelative = weakRelative.promote();
        if (strongRelative != nullptr) {
            layerInfo->add_relatives(strongRelative->sequence);
        }
    }

    LayerProtoHelper::writeToProto(state.transparentRegionHint,
                                   [&]() { return layerInfo->mutable_transparent_region(); });

    layerInfo->set_layer_stack(getLayerStack().id);
    layerInfo->set_z(state.z);

    LayerProtoHelper::writePositionToProto(requestedTransform.tx(), requestedTransform.ty(), [&]() {
        return layerInfo->mutable_requested_position();
    });

    LayerProtoHelper::writeToProto(state.crop, [&]() { return layerInfo->mutable_crop(); });

    layerInfo->set_is_opaque(isOpaque(state));

    layerInfo->set_pixel_format(decodePixelFormat(getPixelFormat()));
    LayerProtoHelper::writeToProto(getColor(), [&]() { return layerInfo->mutable_color(); });
    LayerProtoHelper::writeToProto(state.color,
                                   [&]() { return layerInfo->mutable_requested_color(); });
    layerInfo->set_flags(state.flags);

    LayerProtoHelper::writeToProtoDeprecated(requestedTransform,
                                             layerInfo->mutable_requested_transform());

    auto parent = useDrawing ? mDrawingParent.promote() : mCurrentParent.promote();
    if (parent != nullptr) {
        layerInfo->set_parent(parent->sequence);
    } else {
        layerInfo->set_parent(-1);
    }

    auto zOrderRelativeOf = state.zOrderRelativeOf.promote();
    if (zOrderRelativeOf != nullptr) {
        layerInfo->set_z_order_relative_of(zOrderRelativeOf->sequence);
    } else {
        layerInfo->set_z_order_relative_of(-1);
    }

    layerInfo->set_is_relative_of(state.isRelativeOf);

    layerInfo->set_owner_uid(mOwnerUid);

    if ((traceFlags & LayerTracing::TRACE_INPUT) && needsInputInfo()) {
        WindowInfo info;
        if (useDrawing) {
            info = fillInputInfo(
                    InputDisplayArgs{.transform = &kIdentityTransform, .isSecure = true});
        } else {
            info = state.inputInfo;
        }

        LayerProtoHelper::writeToProto(info, state.touchableRegionCrop,
                                       [&]() { return layerInfo->mutable_input_window_info(); });
    }

    if (traceFlags & LayerTracing::TRACE_EXTRA) {
        auto protoMap = layerInfo->mutable_metadata();
        for (const auto& entry : state.metadata.mMap) {
            (*protoMap)[entry.first] = std::string(entry.second.cbegin(), entry.second.cend());
        }
    }

    LayerProtoHelper::writeToProto(state.destinationFrame,
                                   [&]() { return layerInfo->mutable_destination_frame(); });
}

bool Layer::isRemovedFromCurrentState() const  {
    return mRemovedFromDrawingState;
}

// Applies the given transform to the region, while protecting against overflows caused by any
// offsets. If applying the offset in the transform to any of the Rects in the region would result
// in an overflow, they are not added to the output Region.
static Region transformTouchableRegionSafely(const ui::Transform& t, const Region& r,
                                             const std::string& debugWindowName) {
    // Round the translation using the same rounding strategy used by ui::Transform.
    const auto tx = static_cast<int32_t>(t.tx() + 0.5);
    const auto ty = static_cast<int32_t>(t.ty() + 0.5);

    ui::Transform transformWithoutOffset = t;
    transformWithoutOffset.set(0.f, 0.f);

    const Region transformed = transformWithoutOffset.transform(r);

    // Apply the translation to each of the Rects in the region while discarding any that overflow.
    Region ret;
    for (const auto& rect : transformed) {
        Rect newRect;
        if (__builtin_add_overflow(rect.left, tx, &newRect.left) ||
            __builtin_add_overflow(rect.top, ty, &newRect.top) ||
            __builtin_add_overflow(rect.right, tx, &newRect.right) ||
            __builtin_add_overflow(rect.bottom, ty, &newRect.bottom)) {
            ALOGE("Applying transform to touchable region of window '%s' resulted in an overflow.",
                  debugWindowName.c_str());
            continue;
        }
        ret.orSelf(newRect);
    }
    return ret;
}

void Layer::fillInputFrameInfo(WindowInfo& info, const ui::Transform& screenToDisplay) {
    auto [inputBounds, inputBoundsValid] = getInputBounds(/*fillParentBounds=*/false);
    if (!inputBoundsValid) {
        info.touchableRegion.clear();
    }

    const Rect roundedFrameInDisplay = getInputBoundsInDisplaySpace(inputBounds, screenToDisplay);
    info.frameLeft = roundedFrameInDisplay.left;
    info.frameTop = roundedFrameInDisplay.top;
    info.frameRight = roundedFrameInDisplay.right;
    info.frameBottom = roundedFrameInDisplay.bottom;

    ui::Transform inputToLayer;
    inputToLayer.set(inputBounds.left, inputBounds.top);
    const ui::Transform layerToScreen = getInputTransform();
    const ui::Transform inputToDisplay = screenToDisplay * layerToScreen * inputToLayer;

    // InputDispatcher expects a display-to-input transform.
    info.transform = inputToDisplay.inverse();

    // The touchable region is specified in the input coordinate space. Change it to display space.
    info.touchableRegion =
            transformTouchableRegionSafely(inputToDisplay, info.touchableRegion, mName);
}

void Layer::fillTouchOcclusionMode(WindowInfo& info) {
    sp<Layer> p = sp<Layer>::fromExisting(this);
    while (p != nullptr && !p->hasInputInfo()) {
        p = p->mDrawingParent.promote();
    }
    if (p != nullptr) {
        info.touchOcclusionMode = p->mDrawingState.inputInfo.touchOcclusionMode;
    }
}

gui::DropInputMode Layer::getDropInputMode() const {
    gui::DropInputMode mode = mDrawingState.dropInputMode;
    if (mode == gui::DropInputMode::ALL) {
        return mode;
    }
    sp<Layer> parent = mDrawingParent.promote();
    if (parent) {
        gui::DropInputMode parentMode = parent->getDropInputMode();
        if (parentMode != gui::DropInputMode::NONE) {
            return parentMode;
        }
    }
    return mode;
}

void Layer::handleDropInputMode(gui::WindowInfo& info) const {
    if (mDrawingState.inputInfo.inputConfig.test(WindowInfo::InputConfig::NO_INPUT_CHANNEL)) {
        return;
    }

    // Check if we need to drop input unconditionally
    gui::DropInputMode dropInputMode = getDropInputMode();
    if (dropInputMode == gui::DropInputMode::ALL) {
        info.inputConfig |= WindowInfo::InputConfig::DROP_INPUT;
        ALOGV("Dropping input for %s as requested by policy.", getDebugName());
        return;
    }

    // Check if we need to check if the window is obscured by parent
    if (dropInputMode != gui::DropInputMode::OBSCURED) {
        return;
    }

    // Check if the parent has set an alpha on the layer
    sp<Layer> parent = mDrawingParent.promote();
    if (parent && parent->getAlpha() != 1.0_hf) {
        info.inputConfig |= WindowInfo::InputConfig::DROP_INPUT;
        ALOGV("Dropping input for %s as requested by policy because alpha=%f", getDebugName(),
              static_cast<float>(getAlpha()));
    }

    // Check if the parent has cropped the buffer
    Rect bufferSize = getCroppedBufferSize(getDrawingState());
    if (!bufferSize.isValid()) {
        info.inputConfig |= WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED;
        return;
    }

    // Screenbounds are the layer bounds cropped by parents, transformed to screenspace.
    // To check if the layer has been cropped, we take the buffer bounds, apply the local
    // layer crop and apply the same set of transforms to move to screenspace. If the bounds
    // match then the layer has not been cropped by its parents.
    Rect bufferInScreenSpace(getTransform().transform(bufferSize));
    bool croppedByParent = bufferInScreenSpace != Rect{mScreenBounds};

    if (croppedByParent) {
        info.inputConfig |= WindowInfo::InputConfig::DROP_INPUT;
        ALOGV("Dropping input for %s as requested by policy because buffer is cropped by parent",
              getDebugName());
    } else {
        // If the layer is not obscured by its parents (by setting an alpha or crop), then only drop
        // input if the window is obscured. This check should be done in surfaceflinger but the
        // logic currently resides in inputflinger. So pass the if_obscured check to input to only
        // drop input events if the window is obscured.
        info.inputConfig |= WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED;
    }
}

WindowInfo Layer::fillInputInfo(const InputDisplayArgs& displayArgs) {
    if (!hasInputInfo()) {
        mDrawingState.inputInfo.name = getName();
        mDrawingState.inputInfo.ownerUid = gui::Uid{mOwnerUid};
        mDrawingState.inputInfo.ownerPid = gui::Pid{mOwnerPid};
        mDrawingState.inputInfo.inputConfig |= WindowInfo::InputConfig::NO_INPUT_CHANNEL;
        mDrawingState.inputInfo.displayId = getLayerStack().id;
    }

    const ui::Transform& displayTransform =
            displayArgs.transform != nullptr ? *displayArgs.transform : kIdentityTransform;

    WindowInfo info = mDrawingState.inputInfo;
    info.id = sequence;
    info.displayId = getLayerStack().id;

    fillInputFrameInfo(info, displayTransform);

    if (displayArgs.transform == nullptr) {
        // Do not let the window receive touches if it is not associated with a valid display
        // transform. We still allow the window to receive keys and prevent ANRs.
        info.inputConfig |= WindowInfo::InputConfig::NOT_TOUCHABLE;
    }

    info.setInputConfig(WindowInfo::InputConfig::NOT_VISIBLE, !isVisibleForInput());

    info.alpha = getAlpha();
    fillTouchOcclusionMode(info);
    handleDropInputMode(info);

    // If the window will be blacked out on a display because the display does not have the secure
    // flag and the layer has the secure flag set, then drop input.
    if (!displayArgs.isSecure && isSecure()) {
        info.inputConfig |= WindowInfo::InputConfig::DROP_INPUT;
    }

    sp<Layer> cropLayer = mDrawingState.touchableRegionCrop.promote();
    if (info.replaceTouchableRegionWithCrop) {
        Rect inputBoundsInDisplaySpace;
        if (!cropLayer) {
            FloatRect inputBounds = getInputBounds(/*fillParentBounds=*/true).first;
            inputBoundsInDisplaySpace = getInputBoundsInDisplaySpace(inputBounds, displayTransform);
        } else {
            FloatRect inputBounds = cropLayer->getInputBounds(/*fillParentBounds=*/true).first;
            inputBoundsInDisplaySpace =
                    cropLayer->getInputBoundsInDisplaySpace(inputBounds, displayTransform);
        }
        info.touchableRegion = Region(inputBoundsInDisplaySpace);
    } else if (cropLayer != nullptr) {
        FloatRect inputBounds = cropLayer->getInputBounds(/*fillParentBounds=*/true).first;
        Rect inputBoundsInDisplaySpace =
                cropLayer->getInputBoundsInDisplaySpace(inputBounds, displayTransform);
        info.touchableRegion = info.touchableRegion.intersect(inputBoundsInDisplaySpace);
    }

    // Inherit the trusted state from the parent hierarchy, but don't clobber the trusted state
    // if it was set by WM for a known system overlay
    if (isTrustedOverlay()) {
        info.inputConfig |= WindowInfo::InputConfig::TRUSTED_OVERLAY;
    }

    // If the layer is a clone, we need to crop the input region to cloned root to prevent
    // touches from going outside the cloned area.
    if (isClone()) {
        info.inputConfig |= WindowInfo::InputConfig::CLONE;
        if (const sp<Layer> clonedRoot = getClonedRoot()) {
            const Rect rect = displayTransform.transform(Rect{clonedRoot->mScreenBounds});
            info.touchableRegion = info.touchableRegion.intersect(rect);
        }
    }

    return info;
}

Rect Layer::getInputBoundsInDisplaySpace(const FloatRect& inputBounds,
                                         const ui::Transform& screenToDisplay) {
    // InputDispatcher works in the display device's coordinate space. Here, we calculate the
    // frame and transform used for the layer, which determines the bounds and the coordinate space
    // within which the layer will receive input.

    // Coordinate space definitions:
    //   - display: The display device's coordinate space. Correlates to pixels on the display.
    //   - screen: The post-rotation coordinate space for the display, a.k.a. logical display space.
    //   - layer: The coordinate space of this layer.
    //   - input: The coordinate space in which this layer will receive input events. This could be
    //            different than layer space if a surfaceInset is used, which changes the origin
    //            of the input space.

    // Crop the input bounds to ensure it is within the parent's bounds.
    const FloatRect croppedInputBounds = mBounds.intersect(inputBounds);
    const ui::Transform layerToScreen = getInputTransform();
    const ui::Transform layerToDisplay = screenToDisplay * layerToScreen;
    return Rect{layerToDisplay.transform(croppedInputBounds)};
}

sp<Layer> Layer::getClonedRoot() {
    if (mClonedChild != nullptr) {
        return sp<Layer>::fromExisting(this);
    }
    if (mDrawingParent == nullptr || mDrawingParent.promote() == nullptr) {
        return nullptr;
    }
    return mDrawingParent.promote()->getClonedRoot();
}

bool Layer::hasInputInfo() const {
    return mDrawingState.inputInfo.token != nullptr ||
            mDrawingState.inputInfo.inputConfig.test(WindowInfo::InputConfig::NO_INPUT_CHANNEL);
}

compositionengine::OutputLayer* Layer::findOutputLayerForDisplay(
        const DisplayDevice* display) const {
    if (!display) return nullptr;
    if (!mFlinger->mLayerLifecycleManagerEnabled) {
        return display->getCompositionDisplay()->getOutputLayerForLayer(
                getCompositionEngineLayerFE());
    }
    sp<LayerFE> layerFE;
    frontend::LayerHierarchy::TraversalPath path{.id = static_cast<uint32_t>(sequence)};
    for (auto& [p, layer] : mLayerFEs) {
        if (p == path) {
            layerFE = layer;
        }
    }

    if (!layerFE) return nullptr;
    return display->getCompositionDisplay()->getOutputLayerForLayer(layerFE);
}

Region Layer::getVisibleRegion(const DisplayDevice* display) const {
    const auto outputLayer = findOutputLayerForDisplay(display);
    return outputLayer ? outputLayer->getState().visibleRegion : Region();
}

void Layer::setInitialValuesForClone(const sp<Layer>& clonedFrom, uint32_t mirrorRootId) {
    mSnapshot->path.id = clonedFrom->getSequence();
    mSnapshot->path.mirrorRootId = mirrorRootId;

    cloneDrawingState(clonedFrom.get());
    mClonedFrom = clonedFrom;
    mPremultipliedAlpha = clonedFrom->mPremultipliedAlpha;
    mPotentialCursor = clonedFrom->mPotentialCursor;
    mProtectedByApp = clonedFrom->mProtectedByApp;
    updateCloneBufferInfo();
}

void Layer::updateCloneBufferInfo() {
    if (!isClone() || !isClonedFromAlive()) {
        return;
    }

    sp<Layer> clonedFrom = getClonedFrom();
    mBufferInfo = clonedFrom->mBufferInfo;
    mSidebandStream = clonedFrom->mSidebandStream;
    surfaceDamageRegion = clonedFrom->surfaceDamageRegion;
    mCurrentFrameNumber = clonedFrom->mCurrentFrameNumber.load();
    mPreviousFrameNumber = clonedFrom->mPreviousFrameNumber;

    // After buffer info is updated, the drawingState from the real layer needs to be copied into
    // the cloned. This is because some properties of drawingState can change when latchBuffer is
    // called. However, copying the drawingState would also overwrite the cloned layer's relatives
    // and touchableRegionCrop. Therefore, temporarily store the relatives so they can be set in
    // the cloned drawingState again.
    wp<Layer> tmpZOrderRelativeOf = mDrawingState.zOrderRelativeOf;
    SortedVector<wp<Layer>> tmpZOrderRelatives = mDrawingState.zOrderRelatives;
    wp<Layer> tmpTouchableRegionCrop = mDrawingState.touchableRegionCrop;
    WindowInfo tmpInputInfo = mDrawingState.inputInfo;

    cloneDrawingState(clonedFrom.get());

    mDrawingState.touchableRegionCrop = tmpTouchableRegionCrop;
    mDrawingState.zOrderRelativeOf = tmpZOrderRelativeOf;
    mDrawingState.zOrderRelatives = tmpZOrderRelatives;
    mDrawingState.inputInfo = tmpInputInfo;
}

bool Layer::updateMirrorInfo(const std::deque<Layer*>& cloneRootsPendingUpdates) {
    if (mClonedChild == nullptr || !mClonedChild->isClonedFromAlive()) {
        // If mClonedChild is null, there is nothing to mirror. If isClonedFromAlive returns false,
        // it means that there is a clone, but the layer it was cloned from has been destroyed. In
        // that case, we want to delete the reference to the clone since we want it to get
        // destroyed. The root, this layer, will still be around since the client can continue
        // to hold a reference, but no cloned layers will be displayed.
        mClonedChild = nullptr;
        return true;
    }

    std::map<sp<Layer>, sp<Layer>> clonedLayersMap;
    // If the real layer exists and is in current state, add the clone as a child of the root.
    // There's no need to remove from drawingState when the layer is offscreen since currentState is
    // copied to drawingState for the root layer. So the clonedChild is always removed from
    // drawingState and then needs to be added back each traversal.
    if (!mClonedChild->getClonedFrom()->isRemovedFromCurrentState()) {
        addChildToDrawing(mClonedChild);
    }

    mClonedChild->updateClonedDrawingState(clonedLayersMap);
    mClonedChild->updateClonedChildren(sp<Layer>::fromExisting(this), clonedLayersMap);
    mClonedChild->updateClonedRelatives(clonedLayersMap);

    for (Layer* root : cloneRootsPendingUpdates) {
        if (clonedLayersMap.find(sp<Layer>::fromExisting(root)) != clonedLayersMap.end()) {
            return false;
        }
    }
    return true;
}

void Layer::updateClonedDrawingState(std::map<sp<Layer>, sp<Layer>>& clonedLayersMap) {
    // If the layer the clone was cloned from is alive, copy the content of the drawingState
    // to the clone. If the real layer is no longer alive, continue traversing the children
    // since we may be able to pull out other children that are still alive.
    if (isClonedFromAlive()) {
        sp<Layer> clonedFrom = getClonedFrom();
        cloneDrawingState(clonedFrom.get());
        clonedLayersMap.emplace(clonedFrom, sp<Layer>::fromExisting(this));
    }

    // The clone layer may have children in drawingState since they may have been created and
    // added from a previous request to updateMirorInfo. This is to ensure we don't recreate clones
    // that already exist, since we can just re-use them.
    // The drawingChildren will not get overwritten by the currentChildren since the clones are
    // not updated in the regular traversal. They are skipped since the root will lose the
    // reference to them when it copies its currentChildren to drawing.
    for (sp<Layer>& child : mDrawingChildren) {
        child->updateClonedDrawingState(clonedLayersMap);
    }
}

void Layer::updateClonedChildren(const sp<Layer>& mirrorRoot,
                                 std::map<sp<Layer>, sp<Layer>>& clonedLayersMap) {
    mDrawingChildren.clear();

    if (!isClonedFromAlive()) {
        return;
    }

    sp<Layer> clonedFrom = getClonedFrom();
    for (sp<Layer>& child : clonedFrom->mDrawingChildren) {
        if (child == mirrorRoot) {
            // This is to avoid cyclical mirroring.
            continue;
        }
        sp<Layer> clonedChild = clonedLayersMap[child];
        if (clonedChild == nullptr) {
            clonedChild = child->createClone(mirrorRoot->getSequence());
            clonedLayersMap[child] = clonedChild;
        }
        addChildToDrawing(clonedChild);
        clonedChild->updateClonedChildren(mirrorRoot, clonedLayersMap);
    }
}

void Layer::updateClonedInputInfo(const std::map<sp<Layer>, sp<Layer>>& clonedLayersMap) {
    auto cropLayer = mDrawingState.touchableRegionCrop.promote();
    if (cropLayer != nullptr) {
        if (clonedLayersMap.count(cropLayer) == 0) {
            // Real layer had a crop layer but it's not in the cloned hierarchy. Just set to
            // self as crop layer to avoid going outside bounds.
            mDrawingState.touchableRegionCrop = wp<Layer>::fromExisting(this);
        } else {
            const sp<Layer>& clonedCropLayer = clonedLayersMap.at(cropLayer);
            mDrawingState.touchableRegionCrop = clonedCropLayer;
        }
    }
    // Cloned layers shouldn't handle watch outside since their z order is not determined by
    // WM or the client.
    mDrawingState.inputInfo.setInputConfig(WindowInfo::InputConfig::WATCH_OUTSIDE_TOUCH, false);
}

void Layer::updateClonedRelatives(const std::map<sp<Layer>, sp<Layer>>& clonedLayersMap) {
    mDrawingState.zOrderRelativeOf = wp<Layer>();
    mDrawingState.zOrderRelatives.clear();

    if (!isClonedFromAlive()) {
        return;
    }

    const sp<Layer>& clonedFrom = getClonedFrom();
    for (wp<Layer>& relativeWeak : clonedFrom->mDrawingState.zOrderRelatives) {
        const sp<Layer>& relative = relativeWeak.promote();
        if (clonedLayersMap.count(relative) > 0) {
            auto& clonedRelative = clonedLayersMap.at(relative);
            mDrawingState.zOrderRelatives.add(clonedRelative);
        }
    }

    // Check if the relativeLayer for the real layer is part of the cloned hierarchy.
    // It's possible that the layer it's relative to is outside the requested cloned hierarchy.
    // In that case, we treat the layer as if the relativeOf has been removed. This way, it will
    // still traverse the children, but the layer with the missing relativeOf will not be shown
    // on screen.
    const sp<Layer>& relativeOf = clonedFrom->mDrawingState.zOrderRelativeOf.promote();
    if (clonedLayersMap.count(relativeOf) > 0) {
        const sp<Layer>& clonedRelativeOf = clonedLayersMap.at(relativeOf);
        mDrawingState.zOrderRelativeOf = clonedRelativeOf;
    }

    updateClonedInputInfo(clonedLayersMap);

    for (sp<Layer>& child : mDrawingChildren) {
        child->updateClonedRelatives(clonedLayersMap);
    }
}

void Layer::addChildToDrawing(const sp<Layer>& layer) {
    mDrawingChildren.add(layer);
    layer->mDrawingParent = sp<Layer>::fromExisting(this);
}

Layer::FrameRateCompatibility Layer::FrameRate::convertCompatibility(int8_t compatibility) {
    switch (compatibility) {
        case ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT:
            return FrameRateCompatibility::Default;
        case ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE:
            return FrameRateCompatibility::ExactOrMultiple;
        case ANATIVEWINDOW_FRAME_RATE_EXACT:
            return FrameRateCompatibility::Exact;
        case ANATIVEWINDOW_FRAME_RATE_MIN:
            return FrameRateCompatibility::Min;
        case ANATIVEWINDOW_FRAME_RATE_NO_VOTE:
            return FrameRateCompatibility::NoVote;
        default:
            LOG_ALWAYS_FATAL("Invalid frame rate compatibility value %d", compatibility);
            return FrameRateCompatibility::Default;
    }
}

scheduler::Seamlessness Layer::FrameRate::convertChangeFrameRateStrategy(int8_t strategy) {
    switch (strategy) {
        case ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS:
            return Seamlessness::OnlySeamless;
        case ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS:
            return Seamlessness::SeamedAndSeamless;
        default:
            LOG_ALWAYS_FATAL("Invalid change frame sate strategy value %d", strategy);
            return Seamlessness::Default;
    }
}

bool Layer::isInternalDisplayOverlay() const {
    const State& s(mDrawingState);
    if (s.flags & layer_state_t::eLayerSkipScreenshot) {
        return true;
    }

    sp<Layer> parent = mDrawingParent.promote();
    return parent && parent->isInternalDisplayOverlay();
}

void Layer::setClonedChild(const sp<Layer>& clonedChild) {
    mClonedChild = clonedChild;
    mHadClonedChild = true;
    mFlinger->mLayerMirrorRoots.push_back(this);
}

bool Layer::setDropInputMode(gui::DropInputMode mode) {
    if (mDrawingState.dropInputMode == mode) {
        return false;
    }
    mDrawingState.dropInputMode = mode;
    return true;
}

void Layer::cloneDrawingState(const Layer* from) {
    mDrawingState = from->mDrawingState;
    // Skip callback info since they are not applicable for cloned layers.
    mDrawingState.releaseBufferListener = nullptr;
    // TODO (b/238781169) currently broken for mirror layers because we do not
    // track release fences for mirror layers composed on other displays
    mDrawingState.callbackHandles = {};
}

void Layer::callReleaseBufferCallback(const sp<ITransactionCompletedListener>& listener,
                                      const sp<GraphicBuffer>& buffer, uint64_t framenumber,
                                      const sp<Fence>& releaseFence) {
    if (!listener) {
        return;
    }
    ATRACE_FORMAT_INSTANT("callReleaseBufferCallback %s - %" PRIu64, getDebugName(), framenumber);
    uint32_t currentMaxAcquiredBufferCount =
            mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mOwnerUid);
    listener->onReleaseBuffer({buffer->getId(), framenumber},
                              releaseFence ? releaseFence : Fence::NO_FENCE,
                              currentMaxAcquiredBufferCount);
}

void Layer::onLayerDisplayed(ftl::SharedFuture<FenceResult> futureFenceResult,
                             ui::LayerStack layerStack) {
    // If we are displayed on multiple displays in a single composition cycle then we would
    // need to do careful tracking to enable the use of the mLastClientCompositionFence.
    //  For example we can only use it if all the displays are client comp, and we need
    //  to merge all the client comp fences. We could do this, but for now we just
    // disable the optimization when a layer is composed on multiple displays.
    if (mClearClientCompositionFenceOnLayerDisplayed) {
        mLastClientCompositionFence = nullptr;
    } else {
        mClearClientCompositionFenceOnLayerDisplayed = true;
    }

    // The previous release fence notifies the client that SurfaceFlinger is done with the previous
    // buffer that was presented on this layer. The first transaction that came in this frame that
    // replaced the previous buffer on this layer needs this release fence, because the fence will
    // let the client know when that previous buffer is removed from the screen.
    //
    // Every other transaction on this layer does not need a release fence because no other
    // Transactions that were set on this layer this frame are going to have their preceding buffer
    // removed from the display this frame.
    //
    // For example, if we have 3 transactions this frame. The first transaction doesn't contain a
    // buffer so it doesn't need a previous release fence because the layer still needs the previous
    // buffer. The second transaction contains a buffer so it needs a previous release fence because
    // the previous buffer will be released this frame. The third transaction also contains a
    // buffer. It replaces the buffer in the second transaction. The buffer in the second
    // transaction will now no longer be presented so it is released immediately and the third
    // transaction doesn't need a previous release fence.
    sp<CallbackHandle> ch;
    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->releasePreviousBuffer && mPreviousReleaseBufferEndpoint == handle->listener) {
            ch = handle;
            break;
        }
    }

    // Prevent tracing the same release multiple times.
    if (mPreviousFrameNumber != mPreviousReleasedFrameNumber) {
        mPreviousReleasedFrameNumber = mPreviousFrameNumber;
    }

    if (ch != nullptr) {
        ch->previousReleaseCallbackId = mPreviousReleaseCallbackId;
        ch->previousReleaseFences.emplace_back(std::move(futureFenceResult));
        ch->name = mName;
    }
    mPreviouslyPresentedLayerStacks.push_back(layerStack);
}

void Layer::onSurfaceFrameCreated(
        const std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame) {
    while (mPendingJankClassifications.size() >= kPendingClassificationMaxSurfaceFrames) {
        // Too many SurfaceFrames pending classification. The front of the deque is probably not
        // tracked by FrameTimeline and will never be presented. This will only result in a memory
        // leak.
        if (hasBufferOrSidebandStreamInDrawing()) {
            // Only log for layers with a buffer, since we expect the jank data to be drained for
            // these, while there may be no jank listeners for bufferless layers.
            ALOGW("Removing the front of pending jank deque from layer - %s to prevent memory leak",
                  mName.c_str());
            std::string miniDump = mPendingJankClassifications.front()->miniDump();
            ALOGD("Head SurfaceFrame mini dump\n%s", miniDump.c_str());
        }
        mPendingJankClassifications.pop_front();
    }
    mPendingJankClassifications.emplace_back(surfaceFrame);
}

void Layer::releasePendingBuffer(nsecs_t dequeueReadyTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        if (mFlinger->mLayerLifecycleManagerEnabled) {
            handle->transformHint = mTransformHint;
        } else {
            handle->transformHint = mSkipReportingTransformHint
                    ? std::nullopt
                    : std::make_optional<uint32_t>(mTransformHintLegacy);
        }
        handle->dequeueReadyTime = dequeueReadyTime;
        handle->currentMaxAcquiredBufferCount =
                mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mOwnerUid);
        ATRACE_FORMAT_INSTANT("releasePendingBuffer %s - %" PRIu64, getDebugName(),
                              handle->previousReleaseCallbackId.framenumber);
    }

    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->releasePreviousBuffer && mPreviousReleaseBufferEndpoint == handle->listener) {
            handle->previousReleaseCallbackId = mPreviousReleaseCallbackId;
            break;
        }
    }

    std::vector<JankData> jankData;
    transferAvailableJankData(mDrawingState.callbackHandles, jankData);
    mFlinger->getTransactionCallbackInvoker().addCallbackHandles(mDrawingState.callbackHandles,
                                                                 jankData);
    mDrawingState.callbackHandles = {};
}

bool Layer::willPresentCurrentTransaction() const {
    // Returns true if the most recent Transaction applied to CurrentState will be presented.
    return (getSidebandStreamChanged() || getAutoRefresh() ||
            (mDrawingState.modified &&
             (mDrawingState.buffer != nullptr || mDrawingState.bgColorLayer != nullptr)));
}

bool Layer::setTransform(uint32_t transform) {
    if (mDrawingState.bufferTransform == transform) return false;
    mDrawingState.bufferTransform = transform;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setTransformToDisplayInverse(bool transformToDisplayInverse) {
    if (mDrawingState.transformToDisplayInverse == transformToDisplayInverse) return false;
    mDrawingState.sequence++;
    mDrawingState.transformToDisplayInverse = transformToDisplayInverse;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setBufferCrop(const Rect& bufferCrop) {
    if (mDrawingState.bufferCrop == bufferCrop) return false;

    mDrawingState.sequence++;
    mDrawingState.bufferCrop = bufferCrop;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setDestinationFrame(const Rect& destinationFrame) {
    if (mDrawingState.destinationFrame == destinationFrame) return false;

    mDrawingState.sequence++;
    mDrawingState.destinationFrame = destinationFrame;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

// Translate destination frame into scale and position. If a destination frame is not set, use the
// provided scale and position
bool Layer::updateGeometry() {
    if ((mDrawingState.flags & layer_state_t::eIgnoreDestinationFrame) ||
        mDrawingState.destinationFrame.isEmpty()) {
        // If destination frame is not set, use the requested transform set via
        // Layer::setPosition and Layer::setMatrix.
        return assignTransform(&mDrawingState.transform, mRequestedTransform);
    }

    Rect destRect = mDrawingState.destinationFrame;
    int32_t destW = destRect.width();
    int32_t destH = destRect.height();
    if (destRect.left < 0) {
        destRect.left = 0;
        destRect.right = destW;
    }
    if (destRect.top < 0) {
        destRect.top = 0;
        destRect.bottom = destH;
    }

    if (!mDrawingState.buffer) {
        ui::Transform t;
        t.set(destRect.left, destRect.top);
        return assignTransform(&mDrawingState.transform, t);
    }

    uint32_t bufferWidth = mDrawingState.buffer->getWidth();
    uint32_t bufferHeight = mDrawingState.buffer->getHeight();
    // Undo any transformations on the buffer.
    if (mDrawingState.bufferTransform & ui::Transform::ROT_90) {
        std::swap(bufferWidth, bufferHeight);
    }
    uint32_t invTransform = SurfaceFlinger::getActiveDisplayRotationFlags();
    if (mDrawingState.transformToDisplayInverse) {
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufferWidth, bufferHeight);
        }
    }

    float sx = destW / static_cast<float>(bufferWidth);
    float sy = destH / static_cast<float>(bufferHeight);
    ui::Transform t;
    t.set(sx, 0, 0, sy);
    t.set(destRect.left, destRect.top);
    return assignTransform(&mDrawingState.transform, t);
}

bool Layer::setMatrix(const layer_state_t::matrix22_t& matrix) {
    if (mRequestedTransform.dsdx() == matrix.dsdx && mRequestedTransform.dtdy() == matrix.dtdy &&
        mRequestedTransform.dtdx() == matrix.dtdx && mRequestedTransform.dsdy() == matrix.dsdy) {
        return false;
    }

    mRequestedTransform.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);

    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    return true;
}

bool Layer::setPosition(float x, float y) {
    if (mRequestedTransform.tx() == x && mRequestedTransform.ty() == y) {
        return false;
    }

    mRequestedTransform.set(x, y);

    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    return true;
}

void Layer::resetDrawingStateBufferInfo() {
    mDrawingState.producerId = 0;
    mDrawingState.frameNumber = 0;
    mDrawingState.releaseBufferListener = nullptr;
    mDrawingState.buffer = nullptr;
    mDrawingState.acquireFence = sp<Fence>::make(-1);
    mDrawingState.acquireFenceTime = std::make_unique<FenceTime>(mDrawingState.acquireFence);
    mCallbackHandleAcquireTimeOrFence = mDrawingState.acquireFenceTime->getSignalTime();
    mDrawingState.releaseBufferEndpoint = nullptr;
}

bool Layer::setBuffer(std::shared_ptr<renderengine::ExternalTexture>& buffer,
                      const BufferData& bufferData, nsecs_t postTime, nsecs_t desiredPresentTime,
                      bool isAutoTimestamp, std::optional<nsecs_t> dequeueTime,
                      const FrameTimelineInfo& info) {
    ATRACE_FORMAT("setBuffer %s - hasBuffer=%s", getDebugName(), (buffer ? "true" : "false"));

    const bool frameNumberChanged =
            bufferData.flags.test(BufferData::BufferDataChange::frameNumberChanged);
    const uint64_t frameNumber =
            frameNumberChanged ? bufferData.frameNumber : mDrawingState.frameNumber + 1;
    ATRACE_FORMAT_INSTANT("setBuffer %s - %" PRIu64, getDebugName(), frameNumber);

    if (mDrawingState.buffer) {
        mReleasePreviousBuffer = true;
        if (!mBufferInfo.mBuffer ||
            (!mDrawingState.buffer->hasSameBuffer(*mBufferInfo.mBuffer) ||
             mDrawingState.frameNumber != mBufferInfo.mFrameNumber)) {
            // If mDrawingState has a buffer, and we are about to update again
            // before swapping to drawing state, then the first buffer will be
            // dropped and we should decrement the pending buffer count and
            // call any release buffer callbacks if set.
            callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                      mDrawingState.buffer->getBuffer(), mDrawingState.frameNumber,
                                      mDrawingState.acquireFence);
            decrementPendingBufferCount();
            if (mDrawingState.bufferSurfaceFrameTX != nullptr &&
                mDrawingState.bufferSurfaceFrameTX->getPresentState() != PresentState::Presented) {
                addSurfaceFrameDroppedForBuffer(mDrawingState.bufferSurfaceFrameTX, systemTime());
                mDrawingState.bufferSurfaceFrameTX.reset();
            }
        } else if (EARLY_RELEASE_ENABLED && mLastClientCompositionFence != nullptr) {
            callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                      mDrawingState.buffer->getBuffer(), mDrawingState.frameNumber,
                                      mLastClientCompositionFence);
            mLastClientCompositionFence = nullptr;
        }
    } else if (buffer) {
        // if we are latching a buffer for the first time then clear the mLastLatchTime since
        // we don't want to incorrectly classify a frame if we miss the desired present time.
        updateLastLatchTime(0);
    }

    mDrawingState.desiredPresentTime = desiredPresentTime;
    mDrawingState.isAutoTimestamp = isAutoTimestamp;
    mDrawingState.latchedVsyncId = info.vsyncId;
    mDrawingState.useVsyncIdForRefreshRateSelection = info.useForRefreshRateSelection;
    mDrawingState.modified = true;
    if (!buffer) {
        resetDrawingStateBufferInfo();
        setTransactionFlags(eTransactionNeeded);
        mDrawingState.bufferSurfaceFrameTX = nullptr;
        setFrameTimelineVsyncForBufferlessTransaction(info, postTime);
        return true;
    }

    if ((mDrawingState.producerId > bufferData.producerId) ||
        ((mDrawingState.producerId == bufferData.producerId) &&
         (mDrawingState.frameNumber > frameNumber))) {
        ALOGE("Out of order buffers detected for %s producedId=%d frameNumber=%" PRIu64
              " -> producedId=%d frameNumber=%" PRIu64,
              getDebugName(), mDrawingState.producerId, mDrawingState.frameNumber,
              bufferData.producerId, frameNumber);
        TransactionTraceWriter::getInstance().invoke("out_of_order_buffers_", /*overwrite=*/false);
    }

    mDrawingState.producerId = bufferData.producerId;
    mDrawingState.barrierProducerId =
            std::max(mDrawingState.producerId, mDrawingState.barrierProducerId);
    mDrawingState.frameNumber = frameNumber;
    mDrawingState.barrierFrameNumber =
            std::max(mDrawingState.frameNumber, mDrawingState.barrierFrameNumber);

    mDrawingState.releaseBufferListener = bufferData.releaseBufferListener;
    mDrawingState.buffer = std::move(buffer);
    mDrawingState.acquireFence = bufferData.flags.test(BufferData::BufferDataChange::fenceChanged)
            ? bufferData.acquireFence
            : Fence::NO_FENCE;
    mDrawingState.acquireFenceTime = std::make_unique<FenceTime>(mDrawingState.acquireFence);
    if (mDrawingState.acquireFenceTime->getSignalTime() == Fence::SIGNAL_TIME_PENDING) {
        // We latched this buffer unsiganled, so we need to pass the acquire fence
        // on the callback instead of just the acquire time, since it's unknown at
        // this point.
        mCallbackHandleAcquireTimeOrFence = mDrawingState.acquireFence;
    } else {
        mCallbackHandleAcquireTimeOrFence = mDrawingState.acquireFenceTime->getSignalTime();
    }
    setTransactionFlags(eTransactionNeeded);

    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->setPostTime(layerId, mDrawingState.frameNumber, getName().c_str(),
                                      mOwnerUid, postTime, getGameMode());

    if (mFlinger->mLegacyFrontEndEnabled) {
        recordLayerHistoryBufferUpdate(getLayerProps());
    }

    setFrameTimelineVsyncForBufferTransaction(info, postTime);

    if (dequeueTime && *dequeueTime != 0) {
        const uint64_t bufferId = mDrawingState.buffer->getId();
        mFlinger->mFrameTracer->traceNewLayer(layerId, getName().c_str());
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, *dequeueTime,
                                               FrameTracer::FrameEvent::DEQUEUE);
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, postTime,
                                               FrameTracer::FrameEvent::QUEUE);
    }

    mDrawingState.releaseBufferEndpoint = bufferData.releaseBufferEndpoint;

    // If the layer had been updated a TextureView, this would make sure the present time could be
    // same to TextureView update when it's a small dirty, and get the correct heuristic rate.
    if (mFlinger->mScheduler->supportSmallDirtyDetection()) {
        if (mDrawingState.useVsyncIdForRefreshRateSelection) {
            mUsedVsyncIdForRefreshRateSelection = true;
        }
    }
    return true;
}

void Layer::setDesiredPresentTime(nsecs_t desiredPresentTime, bool isAutoTimestamp) {
    mDrawingState.desiredPresentTime = desiredPresentTime;
    mDrawingState.isAutoTimestamp = isAutoTimestamp;
}

void Layer::recordLayerHistoryBufferUpdate(const scheduler::LayerProps& layerProps) {
    ATRACE_CALL();
    const nsecs_t presentTime = [&] {
        if (!mDrawingState.isAutoTimestamp) {
            ATRACE_FORMAT_INSTANT("desiredPresentTime");
            return mDrawingState.desiredPresentTime;
        }

        if (mDrawingState.useVsyncIdForRefreshRateSelection) {
            const auto prediction =
                    mFlinger->mFrameTimeline->getTokenManager()->getPredictionsForToken(
                            mDrawingState.latchedVsyncId);
            if (prediction.has_value()) {
                ATRACE_FORMAT_INSTANT("predictedPresentTime");
                mMaxTimeForUseVsyncId = prediction->presentTime +
                        scheduler::LayerHistory::kMaxPeriodForHistory.count();
                return prediction->presentTime;
            }
        }

        if (!mFlinger->mScheduler->supportSmallDirtyDetection()) {
            return static_cast<nsecs_t>(0);
        }

        // If the layer is not an application and didn't set an explicit rate or desiredPresentTime,
        // return "0" to tell the layer history that it will use the max refresh rate without
        // calculating the adaptive rate.
        if (mWindowType != WindowInfo::Type::APPLICATION &&
            mWindowType != WindowInfo::Type::BASE_APPLICATION) {
            return static_cast<nsecs_t>(0);
        }

        // Return the valid present time only when the layer potentially updated a TextureView so
        // LayerHistory could heuristically calculate the rate if the UI is continually updating.
        if (mUsedVsyncIdForRefreshRateSelection) {
            const auto prediction =
                    mFlinger->mFrameTimeline->getTokenManager()->getPredictionsForToken(
                            mDrawingState.latchedVsyncId);
            if (prediction.has_value()) {
                if (mMaxTimeForUseVsyncId >= prediction->presentTime) {
                    return prediction->presentTime;
                }
                mUsedVsyncIdForRefreshRateSelection = false;
            }
        }

        return static_cast<nsecs_t>(0);
    }();

    if (ATRACE_ENABLED() && presentTime > 0) {
        const auto presentIn = TimePoint::fromNs(presentTime) - TimePoint::now();
        ATRACE_FORMAT_INSTANT("presentIn %s", to_string(presentIn).c_str());
    }

    mFlinger->mScheduler->recordLayerHistory(sequence, layerProps, presentTime,
                                             scheduler::LayerHistory::LayerUpdateType::Buffer);
}

void Layer::recordLayerHistoryAnimationTx(const scheduler::LayerProps& layerProps) {
    const nsecs_t presentTime =
            mDrawingState.isAutoTimestamp ? 0 : mDrawingState.desiredPresentTime;
    mFlinger->mScheduler->recordLayerHistory(sequence, layerProps, presentTime,
                                             scheduler::LayerHistory::LayerUpdateType::AnimationTX);
}

bool Layer::setDataspace(ui::Dataspace dataspace) {
    if (mDrawingState.dataspace == dataspace) return false;
    mDrawingState.dataspace = dataspace;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setExtendedRangeBrightness(float currentBufferRatio, float desiredRatio) {
    if (mDrawingState.currentHdrSdrRatio == currentBufferRatio &&
        mDrawingState.desiredHdrSdrRatio == desiredRatio)
        return false;
    mDrawingState.currentHdrSdrRatio = currentBufferRatio;
    mDrawingState.desiredHdrSdrRatio = desiredRatio;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setCachingHint(gui::CachingHint cachingHint) {
    if (mDrawingState.cachingHint == cachingHint) return false;
    mDrawingState.cachingHint = cachingHint;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setHdrMetadata(const HdrMetadata& hdrMetadata) {
    if (mDrawingState.hdrMetadata == hdrMetadata) return false;
    mDrawingState.hdrMetadata = hdrMetadata;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setSurfaceDamageRegion(const Region& surfaceDamage) {
    if (mDrawingState.surfaceDamageRegion.hasSameRects(surfaceDamage)) return false;
    mDrawingState.surfaceDamageRegion = surfaceDamage;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    setIsSmallDirty();
    return true;
}

bool Layer::setApi(int32_t api) {
    if (mDrawingState.api == api) return false;
    mDrawingState.api = api;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setSidebandStream(const sp<NativeHandle>& sidebandStream) {
    if (mDrawingState.sidebandStream == sidebandStream) return false;

    if (mDrawingState.sidebandStream != nullptr && sidebandStream == nullptr) {
        mFlinger->mTunnelModeEnabledReporter->decrementTunnelModeCount();
    } else if (sidebandStream != nullptr) {
        mFlinger->mTunnelModeEnabledReporter->incrementTunnelModeCount();
    }

    mDrawingState.sidebandStream = sidebandStream;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    if (!mSidebandStreamChanged.exchange(true)) {
        // mSidebandStreamChanged was false
        mFlinger->onLayerUpdate();
    }
    return true;
}

bool Layer::setTransactionCompletedListeners(const std::vector<sp<CallbackHandle>>& handles,
                                             bool willPresent) {
    // If there is no handle, we will not send a callback so reset mReleasePreviousBuffer and return
    if (handles.empty()) {
        mReleasePreviousBuffer = false;
        return false;
    }

    std::deque<sp<CallbackHandle>> remainingHandles;
    for (const auto& handle : handles) {
        // If this transaction set a buffer on this layer, release its previous buffer
        handle->releasePreviousBuffer = mReleasePreviousBuffer;

        // If this layer will be presented in this frame
        if (willPresent) {
            // If this transaction set an acquire fence on this layer, set its acquire time
            handle->acquireTimeOrFence = mCallbackHandleAcquireTimeOrFence;
            handle->frameNumber = mDrawingState.frameNumber;

            // Store so latched time and release fence can be set
            mDrawingState.callbackHandles.push_back(handle);

        } else { // If this layer will NOT need to be relatched and presented this frame
            // Queue this handle to be notified below.
            remainingHandles.push_back(handle);
        }
    }

    if (!remainingHandles.empty()) {
        // Notify the transaction completed threads these handles are done. These are only the
        // handles that were not added to the mDrawingState, which will be notified later.
        std::vector<JankData> jankData;
        transferAvailableJankData(remainingHandles, jankData);
        mFlinger->getTransactionCallbackInvoker().addCallbackHandles(remainingHandles, jankData);
    }

    mReleasePreviousBuffer = false;
    mCallbackHandleAcquireTimeOrFence = -1;

    return willPresent;
}

Rect Layer::getBufferSize(const State& /*s*/) const {
    // for buffer state layers we use the display frame size as the buffer size.

    if (mBufferInfo.mBuffer == nullptr) {
        return Rect::INVALID_RECT;
    }

    uint32_t bufWidth = mBufferInfo.mBuffer->getWidth();
    uint32_t bufHeight = mBufferInfo.mBuffer->getHeight();

    // Undo any transformations on the buffer and return the result.
    if (mBufferInfo.mTransform & ui::Transform::ROT_90) {
        std::swap(bufWidth, bufHeight);
    }

    if (getTransformToDisplayInverse()) {
        uint32_t invTransform = SurfaceFlinger::getActiveDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufWidth, bufHeight);
        }
    }

    return Rect(0, 0, static_cast<int32_t>(bufWidth), static_cast<int32_t>(bufHeight));
}

FloatRect Layer::computeSourceBounds(const FloatRect& parentBounds) const {
    if (mBufferInfo.mBuffer == nullptr) {
        return parentBounds;
    }

    return getBufferSize(getDrawingState()).toFloatRect();
}

bool Layer::fenceHasSignaled() const {
    if (SurfaceFlinger::enableLatchUnsignaledConfig != LatchUnsignaledConfig::Disabled) {
        return true;
    }

    const bool fenceSignaled =
            getDrawingState().acquireFence->getStatus() == Fence::Status::Signaled;
    if (!fenceSignaled) {
        mFlinger->mTimeStats->incrementLatchSkipped(getSequence(),
                                                    TimeStats::LatchSkipReason::LateAcquire);
    }

    return fenceSignaled;
}

void Layer::onPreComposition(nsecs_t refreshStartTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->refreshStartTime = refreshStartTime;
    }
}

void Layer::setAutoRefresh(bool autoRefresh) {
    mDrawingState.autoRefresh = autoRefresh;
}

bool Layer::latchSidebandStream(bool& recomputeVisibleRegions) {
    // We need to update the sideband stream if the layer has both a buffer and a sideband stream.
    auto* snapshot = editLayerSnapshot();
    snapshot->sidebandStreamHasFrame = hasFrameUpdate() && mSidebandStream.get();

    if (mSidebandStreamChanged.exchange(false)) {
        const State& s(getDrawingState());
        // mSidebandStreamChanged was true
        mSidebandStream = s.sidebandStream;
        snapshot->sidebandStream = mSidebandStream;
        if (mSidebandStream != nullptr) {
            setTransactionFlags(eTransactionNeeded);
            mFlinger->setTransactionFlags(eTraversalNeeded);
        }
        recomputeVisibleRegions = true;

        return true;
    }
    return false;
}

bool Layer::hasFrameUpdate() const {
    const State& c(getDrawingState());
    return (mDrawingStateModified || mDrawingState.modified) &&
            (c.buffer != nullptr || c.bgColorLayer != nullptr);
}

void Layer::updateTexImage(nsecs_t latchTime, bool bgColorOnly) {
    const State& s(getDrawingState());

    if (!s.buffer) {
        if (bgColorOnly || mBufferInfo.mBuffer) {
            for (auto& handle : mDrawingState.callbackHandles) {
                handle->latchTime = latchTime;
            }
        }
        return;
    }

    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->frameNumber == mDrawingState.frameNumber) {
            handle->latchTime = latchTime;
        }
    }

    const int32_t layerId = getSequence();
    const uint64_t bufferId = mDrawingState.buffer->getId();
    const uint64_t frameNumber = mDrawingState.frameNumber;
    const auto acquireFence = std::make_shared<FenceTime>(mDrawingState.acquireFence);
    mFlinger->mTimeStats->setAcquireFence(layerId, frameNumber, acquireFence);
    mFlinger->mTimeStats->setLatchTime(layerId, frameNumber, latchTime);

    mFlinger->mFrameTracer->traceFence(layerId, bufferId, frameNumber, acquireFence,
                                       FrameTracer::FrameEvent::ACQUIRE_FENCE);
    mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, latchTime,
                                           FrameTracer::FrameEvent::LATCH);

    auto& bufferSurfaceFrame = mDrawingState.bufferSurfaceFrameTX;
    if (bufferSurfaceFrame != nullptr &&
        bufferSurfaceFrame->getPresentState() != PresentState::Presented) {
        // Update only if the bufferSurfaceFrame wasn't already presented. A Presented
        // bufferSurfaceFrame could be seen here if a pending state was applied successfully and we
        // are processing the next state.
        addSurfaceFramePresentedForBuffer(bufferSurfaceFrame,
                                          mDrawingState.acquireFenceTime->getSignalTime(),
                                          latchTime);
        mDrawingState.bufferSurfaceFrameTX.reset();
    }

    std::deque<sp<CallbackHandle>> remainingHandles;
    mFlinger->getTransactionCallbackInvoker()
            .addOnCommitCallbackHandles(mDrawingState.callbackHandles, remainingHandles);
    mDrawingState.callbackHandles = remainingHandles;

    mDrawingStateModified = false;
}

void Layer::gatherBufferInfo() {
    mPreviousReleaseCallbackId = {getCurrentBufferId(), mBufferInfo.mFrameNumber};
    mPreviousReleaseBufferEndpoint = mBufferInfo.mReleaseBufferEndpoint;
    if (!mDrawingState.buffer) {
        mBufferInfo = {};
        return;
    }

    if ((!mBufferInfo.mBuffer || !mDrawingState.buffer->hasSameBuffer(*mBufferInfo.mBuffer))) {
        decrementPendingBufferCount();
    }

    mBufferInfo.mBuffer = mDrawingState.buffer;
    mBufferInfo.mReleaseBufferEndpoint = mDrawingState.releaseBufferEndpoint;
    mBufferInfo.mFence = mDrawingState.acquireFence;
    mBufferInfo.mFrameNumber = mDrawingState.frameNumber;
    mBufferInfo.mPixelFormat =
            !mBufferInfo.mBuffer ? PIXEL_FORMAT_NONE : mBufferInfo.mBuffer->getPixelFormat();
    mBufferInfo.mFrameLatencyNeeded = true;
    mBufferInfo.mDesiredPresentTime = mDrawingState.desiredPresentTime;
    mBufferInfo.mFenceTime = std::make_shared<FenceTime>(mDrawingState.acquireFence);
    mBufferInfo.mFence = mDrawingState.acquireFence;
    mBufferInfo.mTransform = mDrawingState.bufferTransform;
    auto lastDataspace = mBufferInfo.mDataspace;
    mBufferInfo.mDataspace = translateDataspace(mDrawingState.dataspace);
    if (mBufferInfo.mBuffer != nullptr) {
        auto& mapper = GraphicBufferMapper::get();
        // TODO: We should measure if it's faster to do a blind write if we're on newer api levels
        // and don't need to possibly remaps buffers.
        ui::Dataspace dataspace = ui::Dataspace::UNKNOWN;
        status_t err = OK;
        {
            ATRACE_NAME("getDataspace");
            err = mapper.getDataspace(mBufferInfo.mBuffer->getBuffer()->handle, &dataspace);
        }
        if (err != OK || dataspace != mBufferInfo.mDataspace) {
            {
                ATRACE_NAME("setDataspace");
                err = mapper.setDataspace(mBufferInfo.mBuffer->getBuffer()->handle,
                                          static_cast<ui::Dataspace>(mBufferInfo.mDataspace));
            }

            // Some GPU drivers may cache gralloc metadata which means before we composite we need
            // to upsert RenderEngine's caches. Put in a special workaround to be backwards
            // compatible with old vendors, with a ticking clock.
            static const int32_t kVendorVersion =
                    base::GetIntProperty("ro.vndk.version", __ANDROID_API_FUTURE__);
            if (const auto format =
                        static_cast<aidl::android::hardware::graphics::common::PixelFormat>(
                                mBufferInfo.mBuffer->getPixelFormat());
                err == OK && kVendorVersion < __ANDROID_API_U__ &&
                (format ==
                         aidl::android::hardware::graphics::common::PixelFormat::
                                 IMPLEMENTATION_DEFINED ||
                 format == aidl::android::hardware::graphics::common::PixelFormat::YCBCR_420_888 ||
                 format == aidl::android::hardware::graphics::common::PixelFormat::YV12 ||
                 format == aidl::android::hardware::graphics::common::PixelFormat::YCBCR_P010)) {
                mBufferInfo.mBuffer->remapBuffer();
            }
        }
    }
    if (lastDataspace != mBufferInfo.mDataspace) {
        mFlinger->mHdrLayerInfoChanged = true;
    }
    if (mBufferInfo.mDesiredHdrSdrRatio != mDrawingState.desiredHdrSdrRatio) {
        mBufferInfo.mDesiredHdrSdrRatio = mDrawingState.desiredHdrSdrRatio;
        mFlinger->mHdrLayerInfoChanged = true;
    }
    mBufferInfo.mCrop = computeBufferCrop(mDrawingState);
    mBufferInfo.mScaleMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
    mBufferInfo.mSurfaceDamage = mDrawingState.surfaceDamageRegion;
    mBufferInfo.mHdrMetadata = mDrawingState.hdrMetadata;
    mBufferInfo.mApi = mDrawingState.api;
    mBufferInfo.mTransformToDisplayInverse = mDrawingState.transformToDisplayInverse;
}

Rect Layer::computeBufferCrop(const State& s) {
    if (s.buffer && !s.bufferCrop.isEmpty()) {
        Rect bufferCrop;
        s.buffer->getBounds().intersect(s.bufferCrop, &bufferCrop);
        return bufferCrop;
    } else if (s.buffer) {
        return s.buffer->getBounds();
    } else {
        return s.bufferCrop;
    }
}

sp<Layer> Layer::createClone(uint32_t mirrorRootId) {
    LayerCreationArgs args(mFlinger.get(), nullptr, mName + " (Mirror)", 0, LayerMetadata());
    args.textureName = mTextureName;
    sp<Layer> layer = mFlinger->getFactory().createBufferStateLayer(args);
    layer->setInitialValuesForClone(sp<Layer>::fromExisting(this), mirrorRootId);
    return layer;
}

void Layer::decrementPendingBufferCount() {
    int32_t pendingBuffers = --mPendingBufferTransactions;
    tracePendingBufferCount(pendingBuffers);
}

void Layer::tracePendingBufferCount(int32_t pendingBuffers) {
    ATRACE_INT(mBlastTransactionName.c_str(), pendingBuffers);
}

/*
 * We don't want to send the layer's transform to input, but rather the
 * parent's transform. This is because Layer's transform is
 * information about how the buffer is placed on screen. The parent's
 * transform makes more sense to send since it's information about how the
 * layer is placed on screen. This transform is used by input to determine
 * how to go from screen space back to window space.
 */
ui::Transform Layer::getInputTransform() const {
    if (!hasBufferOrSidebandStream()) {
        return getTransform();
    }
    sp<Layer> parent = mDrawingParent.promote();
    if (parent == nullptr) {
        return ui::Transform();
    }

    return parent->getTransform();
}

/**
 * Returns the bounds used to fill the input frame and the touchable region.
 *
 * Similar to getInputTransform, we need to update the bounds to include the transform.
 * This is because bounds don't include the buffer transform, where the input assumes
 * that's already included.
 */
std::pair<FloatRect, bool> Layer::getInputBounds(bool fillParentBounds) const {
    Rect croppedBufferSize = getCroppedBufferSize(getDrawingState());
    FloatRect inputBounds = croppedBufferSize.toFloatRect();
    if (hasBufferOrSidebandStream() && croppedBufferSize.isValid() &&
        mDrawingState.transform.getType() != ui::Transform::IDENTITY) {
        inputBounds = mDrawingState.transform.transform(inputBounds);
    }

    bool inputBoundsValid = croppedBufferSize.isValid();
    if (!inputBoundsValid) {
        /**
         * Input bounds are based on the layer crop or buffer size. But if we are using
         * the layer bounds as the input bounds (replaceTouchableRegionWithCrop flag) then
         * we can use the parent bounds as the input bounds if the layer does not have buffer
         * or a crop. We want to unify this logic but because of compat reasons we cannot always
         * use the parent bounds. A layer without a buffer can get input. So when a window is
         * initially added, its touchable region can fill its parent layer bounds and that can
         * have negative consequences.
         */
        inputBounds = fillParentBounds ? mBounds : FloatRect{};
    }

    // Clamp surface inset to the input bounds.
    const float inset = static_cast<float>(mDrawingState.inputInfo.surfaceInset);
    const float xSurfaceInset = std::clamp(inset, 0.f, inputBounds.getWidth() / 2.f);
    const float ySurfaceInset = std::clamp(inset, 0.f, inputBounds.getHeight() / 2.f);

    // Apply the insets to the input bounds.
    inputBounds.left += xSurfaceInset;
    inputBounds.top += ySurfaceInset;
    inputBounds.right -= xSurfaceInset;
    inputBounds.bottom -= ySurfaceInset;

    return {inputBounds, inputBoundsValid};
}

bool Layer::isSimpleBufferUpdate(const layer_state_t& s) const {
    const uint64_t requiredFlags = layer_state_t::eBufferChanged;

    const uint64_t deniedFlags = layer_state_t::eProducerDisconnect | layer_state_t::eLayerChanged |
            layer_state_t::eRelativeLayerChanged | layer_state_t::eTransparentRegionChanged |
            layer_state_t::eFlagsChanged | layer_state_t::eBlurRegionsChanged |
            layer_state_t::eLayerStackChanged | layer_state_t::eAutoRefreshChanged |
            layer_state_t::eReparent;

    if ((s.what & requiredFlags) != requiredFlags) {
        ATRACE_FORMAT_INSTANT("%s: false [missing required flags 0x%" PRIx64 "]", __func__,
                              (s.what | requiredFlags) & ~s.what);
        return false;
    }

    if (s.what & deniedFlags) {
        ATRACE_FORMAT_INSTANT("%s: false [has denied flags 0x%" PRIx64 "]", __func__,
                              s.what & deniedFlags);
        return false;
    }

    if (s.what & layer_state_t::ePositionChanged) {
        if (mRequestedTransform.tx() != s.x || mRequestedTransform.ty() != s.y) {
            ATRACE_FORMAT_INSTANT("%s: false [ePositionChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eAlphaChanged) {
        if (mDrawingState.color.a != s.color.a) {
            ATRACE_FORMAT_INSTANT("%s: false [eAlphaChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eColorTransformChanged) {
        if (mDrawingState.colorTransform != s.colorTransform) {
            ATRACE_FORMAT_INSTANT("%s: false [eColorTransformChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eBackgroundColorChanged) {
        if (mDrawingState.bgColorLayer || s.bgColor.a != 0) {
            ATRACE_FORMAT_INSTANT("%s: false [eBackgroundColorChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eMatrixChanged) {
        if (mRequestedTransform.dsdx() != s.matrix.dsdx ||
            mRequestedTransform.dtdy() != s.matrix.dtdy ||
            mRequestedTransform.dtdx() != s.matrix.dtdx ||
            mRequestedTransform.dsdy() != s.matrix.dsdy) {
            ATRACE_FORMAT_INSTANT("%s: false [eMatrixChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eCornerRadiusChanged) {
        if (mDrawingState.cornerRadius != s.cornerRadius) {
            ATRACE_FORMAT_INSTANT("%s: false [eCornerRadiusChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eBackgroundBlurRadiusChanged) {
        if (mDrawingState.backgroundBlurRadius != static_cast<int>(s.backgroundBlurRadius)) {
            ATRACE_FORMAT_INSTANT("%s: false [eBackgroundBlurRadiusChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eBufferTransformChanged) {
        if (mDrawingState.bufferTransform != s.bufferTransform) {
            ATRACE_FORMAT_INSTANT("%s: false [eBufferTransformChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eTransformToDisplayInverseChanged) {
        if (mDrawingState.transformToDisplayInverse != s.transformToDisplayInverse) {
            ATRACE_FORMAT_INSTANT("%s: false [eTransformToDisplayInverseChanged changed]",
                                  __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eCropChanged) {
        if (mDrawingState.crop != s.crop) {
            ATRACE_FORMAT_INSTANT("%s: false [eCropChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eDataspaceChanged) {
        if (mDrawingState.dataspace != s.dataspace) {
            ATRACE_FORMAT_INSTANT("%s: false [eDataspaceChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eHdrMetadataChanged) {
        if (mDrawingState.hdrMetadata != s.hdrMetadata) {
            ATRACE_FORMAT_INSTANT("%s: false [eHdrMetadataChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eSidebandStreamChanged) {
        if (mDrawingState.sidebandStream != s.sidebandStream) {
            ATRACE_FORMAT_INSTANT("%s: false [eSidebandStreamChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eColorSpaceAgnosticChanged) {
        if (mDrawingState.colorSpaceAgnostic != s.colorSpaceAgnostic) {
            ATRACE_FORMAT_INSTANT("%s: false [eColorSpaceAgnosticChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eShadowRadiusChanged) {
        if (mDrawingState.shadowRadius != s.shadowRadius) {
            ATRACE_FORMAT_INSTANT("%s: false [eShadowRadiusChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eFixedTransformHintChanged) {
        if (mDrawingState.fixedTransformHint != s.fixedTransformHint) {
            ATRACE_FORMAT_INSTANT("%s: false [eFixedTransformHintChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eTrustedOverlayChanged) {
        if (mDrawingState.isTrustedOverlay != s.isTrustedOverlay) {
            ATRACE_FORMAT_INSTANT("%s: false [eTrustedOverlayChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eStretchChanged) {
        StretchEffect temp = s.stretchEffect;
        temp.sanitize();
        if (mDrawingState.stretchEffect != temp) {
            ATRACE_FORMAT_INSTANT("%s: false [eStretchChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eBufferCropChanged) {
        if (mDrawingState.bufferCrop != s.bufferCrop) {
            ATRACE_FORMAT_INSTANT("%s: false [eBufferCropChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eDestinationFrameChanged) {
        if (mDrawingState.destinationFrame != s.destinationFrame) {
            ATRACE_FORMAT_INSTANT("%s: false [eDestinationFrameChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eDimmingEnabledChanged) {
        if (mDrawingState.dimmingEnabled != s.dimmingEnabled) {
            ATRACE_FORMAT_INSTANT("%s: false [eDimmingEnabledChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eExtendedRangeBrightnessChanged) {
        if (mDrawingState.currentHdrSdrRatio != s.currentHdrSdrRatio ||
            mDrawingState.desiredHdrSdrRatio != s.desiredHdrSdrRatio) {
            ATRACE_FORMAT_INSTANT("%s: false [eExtendedRangeBrightnessChanged changed]", __func__);
            return false;
        }
    }

    return true;
}

bool Layer::isHdrY410() const {
    // pixel format is HDR Y410 masquerading as RGBA_1010102
    return (mBufferInfo.mDataspace == ui::Dataspace::BT2020_ITU_PQ &&
            mBufferInfo.mApi == NATIVE_WINDOW_API_MEDIA &&
            mBufferInfo.mPixelFormat == HAL_PIXEL_FORMAT_RGBA_1010102);
}

sp<LayerFE> Layer::getCompositionEngineLayerFE() const {
    // There's no need to get a CE Layer if the layer isn't going to draw anything.
    return hasSomethingToDraw() ? mLegacyLayerFE : nullptr;
}

const LayerSnapshot* Layer::getLayerSnapshot() const {
    return mSnapshot.get();
}

LayerSnapshot* Layer::editLayerSnapshot() {
    return mSnapshot.get();
}

std::unique_ptr<frontend::LayerSnapshot> Layer::stealLayerSnapshot() {
    return std::move(mSnapshot);
}

void Layer::updateLayerSnapshot(std::unique_ptr<frontend::LayerSnapshot> snapshot) {
    mSnapshot = std::move(snapshot);
}

const compositionengine::LayerFECompositionState* Layer::getCompositionState() const {
    return mSnapshot.get();
}

sp<LayerFE> Layer::copyCompositionEngineLayerFE() const {
    auto result = mFlinger->getFactory().createLayerFE(mName);
    result->mSnapshot = std::make_unique<LayerSnapshot>(*mSnapshot);
    return result;
}

sp<LayerFE> Layer::getCompositionEngineLayerFE(
        const frontend::LayerHierarchy::TraversalPath& path) {
    for (auto& [p, layerFE] : mLayerFEs) {
        if (p == path) {
            return layerFE;
        }
    }
    auto layerFE = mFlinger->getFactory().createLayerFE(mName);
    mLayerFEs.emplace_back(path, layerFE);
    return layerFE;
}

void Layer::useSurfaceDamage() {
    if (mFlinger->mForceFullDamage) {
        surfaceDamageRegion = Region::INVALID_REGION;
    } else {
        surfaceDamageRegion = mBufferInfo.mSurfaceDamage;
    }
}

void Layer::useEmptyDamage() {
    surfaceDamageRegion.clear();
}

bool Layer::isOpaque(const Layer::State& s) const {
    // if we don't have a buffer or sidebandStream yet, we're translucent regardless of the
    // layer's opaque flag.
    if (!hasSomethingToDraw()) {
        return false;
    }

    // if the layer has the opaque flag, then we're always opaque
    if ((s.flags & layer_state_t::eLayerOpaque) == layer_state_t::eLayerOpaque) {
        return true;
    }

    // If the buffer has no alpha channel, then we are opaque
    if (hasBufferOrSidebandStream() && LayerSnapshot::isOpaqueFormat(getPixelFormat())) {
        return true;
    }

    // Lastly consider the layer opaque if drawing a color with alpha == 1.0
    return fillsColor() && getAlpha() == 1.0_hf;
}

bool Layer::canReceiveInput() const {
    return !isHiddenByPolicy() && (mBufferInfo.mBuffer == nullptr || getAlpha() > 0.0f);
}

bool Layer::isVisible() const {
    if (!hasSomethingToDraw()) {
        return false;
    }

    if (isHiddenByPolicy()) {
        return false;
    }

    return getAlpha() > 0.0f || hasBlur();
}

void Layer::onPostComposition(const DisplayDevice* display,
                              const std::shared_ptr<FenceTime>& glDoneFence,
                              const std::shared_ptr<FenceTime>& presentFence,
                              const CompositorTiming& compositorTiming) {
    // mFrameLatencyNeeded is true when a new frame was latched for the
    // composition.
    if (!mBufferInfo.mFrameLatencyNeeded) return;

    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->gpuCompositionDoneFence = glDoneFence;
        handle->compositorTiming = compositorTiming;
    }

    // Update mFrameTracker.
    nsecs_t desiredPresentTime = mBufferInfo.mDesiredPresentTime;
    mFrameTracker.setDesiredPresentTime(desiredPresentTime);

    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->setDesiredTime(layerId, mCurrentFrameNumber, desiredPresentTime);

    const auto outputLayer = findOutputLayerForDisplay(display);
    if (outputLayer && outputLayer->requiresClientComposition()) {
        nsecs_t clientCompositionTimestamp = outputLayer->getState().clientCompositionTimestamp;
        mFlinger->mFrameTracer->traceTimestamp(layerId, getCurrentBufferId(), mCurrentFrameNumber,
                                               clientCompositionTimestamp,
                                               FrameTracer::FrameEvent::FALLBACK_COMPOSITION);
        // Update the SurfaceFrames in the drawing state
        if (mDrawingState.bufferSurfaceFrameTX) {
            mDrawingState.bufferSurfaceFrameTX->setGpuComposition();
        }
        for (auto& [token, surfaceFrame] : mDrawingState.bufferlessSurfaceFramesTX) {
            surfaceFrame->setGpuComposition();
        }
    }

    std::shared_ptr<FenceTime> frameReadyFence = mBufferInfo.mFenceTime;
    if (frameReadyFence->isValid()) {
        mFrameTracker.setFrameReadyFence(std::move(frameReadyFence));
    } else {
        // There was no fence for this frame, so assume that it was ready
        // to be presented at the desired present time.
        mFrameTracker.setFrameReadyTime(desiredPresentTime);
    }

    if (display) {
        const Fps refreshRate = display->refreshRateSelector().getActiveMode().fps;
        const std::optional<Fps> renderRate =
                mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());

        const auto vote = frameRateToSetFrameRateVotePayload(mDrawingState.frameRate);
        const auto gameMode = getGameMode();

        if (presentFence->isValid()) {
            mFlinger->mTimeStats->setPresentFence(layerId, mCurrentFrameNumber, presentFence,
                                                  refreshRate, renderRate, vote, gameMode);
            mFlinger->mFrameTracer->traceFence(layerId, getCurrentBufferId(), mCurrentFrameNumber,
                                               presentFence,
                                               FrameTracer::FrameEvent::PRESENT_FENCE);
            mFrameTracker.setActualPresentFence(std::shared_ptr<FenceTime>(presentFence));
        } else if (const auto displayId = PhysicalDisplayId::tryCast(display->getId());
                   displayId && mFlinger->getHwComposer().isConnected(*displayId)) {
            // The HWC doesn't support present fences, so use the present timestamp instead.
            const nsecs_t presentTimestamp =
                    mFlinger->getHwComposer().getPresentTimestamp(*displayId);

            const nsecs_t now = systemTime(CLOCK_MONOTONIC);
            const nsecs_t vsyncPeriod = display->getVsyncPeriodFromHWC();
            const nsecs_t actualPresentTime = now - ((now - presentTimestamp) % vsyncPeriod);

            mFlinger->mTimeStats->setPresentTime(layerId, mCurrentFrameNumber, actualPresentTime,
                                                 refreshRate, renderRate, vote, gameMode);
            mFlinger->mFrameTracer->traceTimestamp(layerId, getCurrentBufferId(),
                                                   mCurrentFrameNumber, actualPresentTime,
                                                   FrameTracer::FrameEvent::PRESENT_FENCE);
            mFrameTracker.setActualPresentTime(actualPresentTime);
        }
    }

    mFrameTracker.advanceFrame();
    mBufferInfo.mFrameLatencyNeeded = false;
}

bool Layer::willReleaseBufferOnLatch() const {
    return !mDrawingState.buffer && mBufferInfo.mBuffer;
}

bool Layer::latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime) {
    const bool bgColorOnly = mDrawingState.bgColorLayer != nullptr;
    return latchBufferImpl(recomputeVisibleRegions, latchTime, bgColorOnly);
}

bool Layer::latchBufferImpl(bool& recomputeVisibleRegions, nsecs_t latchTime, bool bgColorOnly) {
    ATRACE_FORMAT_INSTANT("latchBuffer %s - %" PRIu64, getDebugName(),
                          getDrawingState().frameNumber);

    bool refreshRequired = latchSidebandStream(recomputeVisibleRegions);

    if (refreshRequired) {
        return refreshRequired;
    }

    // If the head buffer's acquire fence hasn't signaled yet, return and
    // try again later
    if (!fenceHasSignaled()) {
        ATRACE_NAME("!fenceHasSignaled()");
        mFlinger->onLayerUpdate();
        return false;
    }
    updateTexImage(latchTime, bgColorOnly);

    // Capture the old state of the layer for comparisons later
    BufferInfo oldBufferInfo = mBufferInfo;
    const bool oldOpacity = isOpaque(mDrawingState);
    mPreviousFrameNumber = mCurrentFrameNumber;
    mCurrentFrameNumber = mDrawingState.frameNumber;
    gatherBufferInfo();

    if (mBufferInfo.mBuffer) {
        // We latched a buffer that will be presented soon. Clear the previously presented layer
        // stack list.
        mPreviouslyPresentedLayerStacks.clear();
    }

    if (mDrawingState.buffer == nullptr) {
        const bool bufferReleased = oldBufferInfo.mBuffer != nullptr;
        recomputeVisibleRegions = bufferReleased;
        return bufferReleased;
    }

    if (oldBufferInfo.mBuffer == nullptr) {
        // the first time we receive a buffer, we need to trigger a
        // geometry invalidation.
        recomputeVisibleRegions = true;
    }

    if ((mBufferInfo.mCrop != oldBufferInfo.mCrop) ||
        (mBufferInfo.mTransform != oldBufferInfo.mTransform) ||
        (mBufferInfo.mScaleMode != oldBufferInfo.mScaleMode) ||
        (mBufferInfo.mTransformToDisplayInverse != oldBufferInfo.mTransformToDisplayInverse)) {
        recomputeVisibleRegions = true;
    }

    if (oldBufferInfo.mBuffer != nullptr) {
        uint32_t bufWidth = mBufferInfo.mBuffer->getWidth();
        uint32_t bufHeight = mBufferInfo.mBuffer->getHeight();
        if (bufWidth != oldBufferInfo.mBuffer->getWidth() ||
            bufHeight != oldBufferInfo.mBuffer->getHeight()) {
            recomputeVisibleRegions = true;
        }
    }

    if (oldOpacity != isOpaque(mDrawingState)) {
        recomputeVisibleRegions = true;
    }

    return true;
}

bool Layer::hasReadyFrame() const {
    return hasFrameUpdate() || getSidebandStreamChanged() || getAutoRefresh();
}

bool Layer::isProtected() const {
    return (mBufferInfo.mBuffer != nullptr) &&
            (mBufferInfo.mBuffer->getUsage() & GRALLOC_USAGE_PROTECTED);
}

void Layer::latchAndReleaseBuffer() {
    if (hasReadyFrame()) {
        bool ignored = false;
        latchBuffer(ignored, systemTime());
    }
    releasePendingBuffer(systemTime());
}

PixelFormat Layer::getPixelFormat() const {
    return mBufferInfo.mPixelFormat;
}

bool Layer::getTransformToDisplayInverse() const {
    return mBufferInfo.mTransformToDisplayInverse;
}

Rect Layer::getBufferCrop() const {
    // this is the crop rectangle that applies to the buffer
    // itself (as opposed to the window)
    if (!mBufferInfo.mCrop.isEmpty()) {
        // if the buffer crop is defined, we use that
        return mBufferInfo.mCrop;
    } else if (mBufferInfo.mBuffer != nullptr) {
        // otherwise we use the whole buffer
        return mBufferInfo.mBuffer->getBounds();
    } else {
        // if we don't have a buffer yet, we use an empty/invalid crop
        return Rect();
    }
}

uint32_t Layer::getBufferTransform() const {
    return mBufferInfo.mTransform;
}

ui::Dataspace Layer::getDataSpace() const {
    return hasBufferOrSidebandStream() ? mBufferInfo.mDataspace : mDrawingState.dataspace;
}

ui::Dataspace Layer::translateDataspace(ui::Dataspace dataspace) {
    ui::Dataspace updatedDataspace = dataspace;
    // translate legacy dataspaces to modern dataspaces
    switch (dataspace) {
        // Treat unknown dataspaces as V0_sRGB
        case ui::Dataspace::UNKNOWN:
        case ui::Dataspace::SRGB:
            updatedDataspace = ui::Dataspace::V0_SRGB;
            break;
        case ui::Dataspace::SRGB_LINEAR:
            updatedDataspace = ui::Dataspace::V0_SRGB_LINEAR;
            break;
        case ui::Dataspace::JFIF:
            updatedDataspace = ui::Dataspace::V0_JFIF;
            break;
        case ui::Dataspace::BT601_625:
            updatedDataspace = ui::Dataspace::V0_BT601_625;
            break;
        case ui::Dataspace::BT601_525:
            updatedDataspace = ui::Dataspace::V0_BT601_525;
            break;
        case ui::Dataspace::BT709:
            updatedDataspace = ui::Dataspace::V0_BT709;
            break;
        default:
            break;
    }

    return updatedDataspace;
}

sp<GraphicBuffer> Layer::getBuffer() const {
    return mBufferInfo.mBuffer ? mBufferInfo.mBuffer->getBuffer() : nullptr;
}

void Layer::setTransformHintLegacy(ui::Transform::RotationFlags displayTransformHint) {
    mTransformHintLegacy = getFixedTransformHint();
    if (mTransformHintLegacy == ui::Transform::ROT_INVALID) {
        mTransformHintLegacy = displayTransformHint;
    }
    mSkipReportingTransformHint = false;
}

const std::shared_ptr<renderengine::ExternalTexture>& Layer::getExternalTexture() const {
    return mBufferInfo.mBuffer;
}

bool Layer::setColor(const half3& color) {
    if (mDrawingState.color.rgb == color) {
        return false;
    }

    mDrawingState.sequence++;
    mDrawingState.color.rgb = color;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::fillsColor() const {
    return !hasBufferOrSidebandStream() && mDrawingState.color.r >= 0.0_hf &&
            mDrawingState.color.g >= 0.0_hf && mDrawingState.color.b >= 0.0_hf;
}

bool Layer::hasBlur() const {
    return getBackgroundBlurRadius() > 0 || getDrawingState().blurRegions.size() > 0;
}

void Layer::updateSnapshot(bool updateGeometry) {
    if (!getCompositionEngineLayerFE()) {
        return;
    }

    auto* snapshot = editLayerSnapshot();
    if (updateGeometry) {
        prepareBasicGeometryCompositionState();
        prepareGeometryCompositionState();
        snapshot->roundedCorner = getRoundedCornerState();
        snapshot->stretchEffect = getStretchEffect();
        snapshot->transformedBounds = mScreenBounds;
        if (mEffectiveShadowRadius > 0.f) {
            snapshot->shadowSettings = mFlinger->mDrawingState.globalShadowSettings;

            // Note: this preserves existing behavior of shadowing the entire layer and not cropping
            // it if transparent regions are present. This may not be necessary since shadows are
            // typically cast by layers without transparent regions.
            snapshot->shadowSettings.boundaries = mBounds;

            const float casterAlpha = snapshot->alpha;
            const bool casterIsOpaque =
                    ((mBufferInfo.mBuffer != nullptr) && isOpaque(mDrawingState));

            // If the casting layer is translucent, we need to fill in the shadow underneath the
            // layer. Otherwise the generated shadow will only be shown around the casting layer.
            snapshot->shadowSettings.casterIsTranslucent = !casterIsOpaque || (casterAlpha < 1.0f);
            snapshot->shadowSettings.ambientColor *= casterAlpha;
            snapshot->shadowSettings.spotColor *= casterAlpha;
        }
        snapshot->shadowSettings.length = mEffectiveShadowRadius;
    }
    snapshot->contentOpaque = isOpaque(mDrawingState);
    snapshot->layerOpaqueFlagSet =
            (mDrawingState.flags & layer_state_t::eLayerOpaque) == layer_state_t::eLayerOpaque;
    snapshot->isHdrY410 = isHdrY410();
    sp<Layer> p = mDrawingParent.promote();
    if (p != nullptr) {
        snapshot->parentTransform = p->getTransform();
    } else {
        snapshot->parentTransform.reset();
    }
    snapshot->bufferSize = getBufferSize(mDrawingState);
    snapshot->externalTexture = mBufferInfo.mBuffer;
    snapshot->hasReadyFrame = hasReadyFrame();
    preparePerFrameCompositionState();
}

void Layer::updateChildrenSnapshots(bool updateGeometry) {
    for (const sp<Layer>& child : mDrawingChildren) {
        child->updateSnapshot(updateGeometry);
        child->updateChildrenSnapshots(updateGeometry);
    }
}

void Layer::updateMetadataSnapshot(const LayerMetadata& parentMetadata) {
    mSnapshot->layerMetadata = parentMetadata;
    mSnapshot->layerMetadata.merge(mDrawingState.metadata);
    for (const sp<Layer>& child : mDrawingChildren) {
        child->updateMetadataSnapshot(mSnapshot->layerMetadata);
    }
}

void Layer::updateRelativeMetadataSnapshot(const LayerMetadata& relativeLayerMetadata,
                                           std::unordered_set<Layer*>& visited) {
    if (visited.find(this) != visited.end()) {
        ALOGW("Cycle containing layer %s detected in z-order relatives", getDebugName());
        return;
    }
    visited.insert(this);

    mSnapshot->relativeLayerMetadata = relativeLayerMetadata;

    if (mDrawingState.zOrderRelatives.empty()) {
        return;
    }
    LayerMetadata childRelativeLayerMetadata = mSnapshot->relativeLayerMetadata;
    childRelativeLayerMetadata.merge(mSnapshot->layerMetadata);
    for (wp<Layer> weakRelative : mDrawingState.zOrderRelatives) {
        sp<Layer> relative = weakRelative.promote();
        if (!relative) {
            continue;
        }
        relative->updateRelativeMetadataSnapshot(childRelativeLayerMetadata, visited);
    }
}

bool Layer::setTrustedPresentationInfo(TrustedPresentationThresholds const& thresholds,
                                       TrustedPresentationListener const& listener) {
    bool hadTrustedPresentationListener = hasTrustedPresentationListener();
    mTrustedPresentationListener = listener;
    mTrustedPresentationThresholds = thresholds;
    bool haveTrustedPresentationListener = hasTrustedPresentationListener();
    if (!hadTrustedPresentationListener && haveTrustedPresentationListener) {
        mFlinger->mNumTrustedPresentationListeners++;
    } else if (hadTrustedPresentationListener && !haveTrustedPresentationListener) {
        mFlinger->mNumTrustedPresentationListeners--;
    }

    // Reset trusted presentation states to ensure we start the time again.
    mEnteredTrustedPresentationStateTime = -1;
    mLastReportedTrustedPresentationState = false;
    mLastComputedTrustedPresentationState = false;

    // If there's a new trusted presentation listener, the code needs to go through the composite
    // path to ensure it recomutes the current state and invokes the TrustedPresentationListener if
    // we're already in the requested state.
    return haveTrustedPresentationListener;
}

void Layer::updateLastLatchTime(nsecs_t latchTime) {
    mLastLatchTime = latchTime;
}

void Layer::setIsSmallDirty() {
    if (!mFlinger->mScheduler->supportSmallDirtyDetection()) {
        return;
    }

    if (mWindowType != WindowInfo::Type::APPLICATION &&
        mWindowType != WindowInfo::Type::BASE_APPLICATION) {
        return;
    }
    Rect bounds = mDrawingState.surfaceDamageRegion.getBounds();
    if (!bounds.isValid()) {
        return;
    }

    // If the damage region is a small dirty, this could give the hint for the layer history that
    // it could suppress the heuristic rate when calculating.
    mSmallDirty = mFlinger->mScheduler->isSmallDirtyArea(mOwnerUid,
                                                         bounds.getWidth() * bounds.getHeight());
}

// ---------------------------------------------------------------------------

std::ostream& operator<<(std::ostream& stream, const Layer::FrameRate& rate) {
    return stream << "{rate=" << rate.rate << " type=" << ftl::enum_string(rate.type)
                  << " seamlessness=" << ftl::enum_string(rate.seamlessness) << '}';
}

} // namespace android

#if defined(__gl_h_)
#error "don't include gl/gl.h in this file"
#endif

#if defined(__gl2_h_)
#error "don't include gl2/gl2.h in this file"
#endif

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
