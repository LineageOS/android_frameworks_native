/*
 * Copyright (C) 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "BufferLayer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "BufferLayer.h"
#include "Colorizer.h"
#include "DisplayDevice.h"
#include "LayerRejecter.h"

#include <renderengine/RenderEngine.h>

#include <gui/BufferItem.h>
#include <gui/BufferQueue.h>
#include <gui/LayerDebugInfo.h>
#include <gui/Surface.h>

#include <ui/DebugUtils.h>

#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/NativeHandle.h>
#include <utils/StopWatch.h>
#include <utils/Trace.h>

#include <cutils/compiler.h>
#include <cutils/native_handle.h>
#include <cutils/properties.h>

#include <math.h>
#include <stdlib.h>
#include <mutex>

namespace android {

BufferLayer::BufferLayer(SurfaceFlinger* flinger, const sp<Client>& client, const String8& name,
                         uint32_t w, uint32_t h, uint32_t flags)
      : Layer(flinger, client, name, w, h, flags),
        mTextureName(mFlinger->getNewTexture()),
        mCurrentScalingMode(NATIVE_WINDOW_SCALING_MODE_FREEZE),
        mBufferLatched(false),
        mRefreshPending(false) {
    ALOGV("Creating Layer %s", name.string());

    mTexture.init(renderengine::Texture::TEXTURE_EXTERNAL, mTextureName);

    mPremultipliedAlpha = !(flags & ISurfaceComposerClient::eNonPremultiplied);

    mPotentialCursor = flags & ISurfaceComposerClient::eCursorWindow;
    mProtectedByApp = flags & ISurfaceComposerClient::eProtectedByApp;

    // drawing state & current state are identical
    mDrawingState = mCurrentState;
}

BufferLayer::~BufferLayer() {
    mFlinger->deleteTextureAsync(mTextureName);

    if (!getBE().mHwcLayers.empty()) {
        ALOGE("Found stale hardware composer layers when destroying "
              "surface flinger layer %s",
              mName.string());
        destroyAllHwcLayers();
    }
}

void BufferLayer::useSurfaceDamage() {
    if (mFlinger->mForceFullDamage) {
        surfaceDamageRegion = Region::INVALID_REGION;
    } else {
        surfaceDamageRegion = getDrawingSurfaceDamage();
    }
}

void BufferLayer::useEmptyDamage() {
    surfaceDamageRegion.clear();
}

bool BufferLayer::isOpaque(const Layer::State& s) const {
    // if we don't have a buffer or sidebandStream yet, we're translucent regardless of the
    // layer's opaque flag.
    if ((getBE().compositionInfo.hwc.sidebandStream == nullptr) && (mActiveBuffer == nullptr)) {
        return false;
    }

    // if the layer has the opaque flag, then we're always opaque,
    // otherwise we use the current buffer's format.
    return ((s.flags & layer_state_t::eLayerOpaque) != 0) || getOpacityForFormat(getPixelFormat());
}

bool BufferLayer::isVisible() const {
    return !(isHiddenByPolicy()) && getAlpha() > 0.0f &&
            (mActiveBuffer != nullptr || getBE().compositionInfo.hwc.sidebandStream != nullptr);
}

bool BufferLayer::isFixedSize() const {
    return getEffectiveScalingMode() != NATIVE_WINDOW_SCALING_MODE_FREEZE;
}

static constexpr mat4 inverseOrientation(uint32_t transform) {
    const mat4 flipH(-1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1);
    const mat4 flipV(1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1);
    const mat4 rot90(0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1);
    mat4 tr;

    if (transform & NATIVE_WINDOW_TRANSFORM_ROT_90) {
        tr = tr * rot90;
    }
    if (transform & NATIVE_WINDOW_TRANSFORM_FLIP_H) {
        tr = tr * flipH;
    }
    if (transform & NATIVE_WINDOW_TRANSFORM_FLIP_V) {
        tr = tr * flipV;
    }
    return inverse(tr);
}

/*
 * onDraw will draw the current layer onto the presentable buffer
 */
void BufferLayer::onDraw(const RenderArea& renderArea, const Region& clip,
                         bool useIdentityTransform) {
    ATRACE_CALL();

    if (CC_UNLIKELY(mActiveBuffer == 0)) {
        // the texture has not been created yet, this Layer has
        // in fact never been drawn into. This happens frequently with
        // SurfaceView because the WindowManager can't know when the client
        // has drawn the first time.

        // If there is nothing under us, we paint the screen in black, otherwise
        // we just skip this update.

        // figure out if there is something below us
        Region under;
        bool finished = false;
        mFlinger->mDrawingState.traverseInZOrder([&](Layer* layer) {
            if (finished || layer == static_cast<BufferLayer const*>(this)) {
                finished = true;
                return;
            }
            under.orSelf(renderArea.getTransform().transform(layer->visibleRegion));
        });
        // if not everything below us is covered, we plug the holes!
        Region holes(clip.subtract(under));
        if (!holes.isEmpty()) {
            clearWithOpenGL(renderArea, 0, 0, 0, 1);
        }
        return;
    }

    // Bind the current buffer to the GL texture, and wait for it to be
    // ready for us to draw into.
    status_t err = bindTextureImage();
    if (err != NO_ERROR) {
        ALOGW("onDraw: bindTextureImage failed (err=%d)", err);
        // Go ahead and draw the buffer anyway; no matter what we do the screen
        // is probably going to have something visibly wrong.
    }

    bool blackOutLayer = isProtected() || (isSecure() && !renderArea.isSecure());

    auto& engine(mFlinger->getRenderEngine());

    if (!blackOutLayer) {
        // TODO: we could be more subtle with isFixedSize()
        const bool useFiltering = needsFiltering(renderArea) || isFixedSize();

        // Query the texture matrix given our current filtering mode.
        float textureMatrix[16];
        setFilteringEnabled(useFiltering);
        getDrawingTransformMatrix(textureMatrix);

        if (getTransformToDisplayInverse()) {
            /*
             * the code below applies the primary display's inverse transform to
             * the texture transform
             */
            uint32_t transform = DisplayDevice::getPrimaryDisplayOrientationTransform();
            mat4 tr = inverseOrientation(transform);

            /**
             * TODO(b/36727915): This is basically a hack.
             *
             * Ensure that regardless of the parent transformation,
             * this buffer is always transformed from native display
             * orientation to display orientation. For example, in the case
             * of a camera where the buffer remains in native orientation,
             * we want the pixels to always be upright.
             */
            sp<Layer> p = mDrawingParent.promote();
            if (p != nullptr) {
                const auto parentTransform = p->getTransform();
                tr = tr * inverseOrientation(parentTransform.getOrientation());
            }

            // and finally apply it to the original texture matrix
            const mat4 texTransform(mat4(static_cast<const float*>(textureMatrix)) * tr);
            memcpy(textureMatrix, texTransform.asArray(), sizeof(textureMatrix));
        }

        // Set things up for texturing.
        mTexture.setDimensions(mActiveBuffer->getWidth(), mActiveBuffer->getHeight());
        mTexture.setFiltering(useFiltering);
        mTexture.setMatrix(textureMatrix);

        engine.setupLayerTexturing(mTexture);
    } else {
        engine.setupLayerBlackedOut();
    }
    drawWithOpenGL(renderArea, useIdentityTransform);
    engine.disableTexturing();
}

bool BufferLayer::isHdrY410() const {
    // pixel format is HDR Y410 masquerading as RGBA_1010102
    return (mCurrentDataSpace == ui::Dataspace::BT2020_ITU_PQ &&
            getDrawingApi() == NATIVE_WINDOW_API_MEDIA &&
            getBE().compositionInfo.mBuffer->getPixelFormat() == HAL_PIXEL_FORMAT_RGBA_1010102);
}

void BufferLayer::setPerFrameData(const sp<const DisplayDevice>& display) {
    // Apply this display's projection's viewport to the visible region
    // before giving it to the HWC HAL.
    const ui::Transform& tr = display->getTransform();
    const auto& viewport = display->getViewport();
    Region visible = tr.transform(visibleRegion.intersect(viewport));
    const auto displayId = display->getId();
    getBE().compositionInfo.hwc.visibleRegion = visible;
    getBE().compositionInfo.hwc.surfaceDamage = surfaceDamageRegion;

    // Sideband layers
    if (getBE().compositionInfo.hwc.sidebandStream.get()) {
        setCompositionType(displayId, HWC2::Composition::Sideband);
        getBE().compositionInfo.compositionType = HWC2::Composition::Sideband;
        return;
    }

    if (getBE().compositionInfo.hwc.skipGeometry) {
        // Device or Cursor layers
        if (mPotentialCursor) {
            ALOGV("[%s] Requesting Cursor composition", mName.string());
            setCompositionType(displayId, HWC2::Composition::Cursor);
        } else {
            ALOGV("[%s] Requesting Device composition", mName.string());
            setCompositionType(displayId, HWC2::Composition::Device);
        }
    }

    getBE().compositionInfo.hwc.dataspace = mCurrentDataSpace;
    getBE().compositionInfo.hwc.hdrMetadata = getDrawingHdrMetadata();
    getBE().compositionInfo.hwc.supportedPerFrameMetadata = display->getSupportedPerFrameMetadata();

    setHwcLayerBuffer(display);
}

bool BufferLayer::onPreComposition(nsecs_t refreshStartTime) {
    if (mBufferLatched) {
        Mutex::Autolock lock(mFrameEventHistoryMutex);
        mFrameEventHistory.addPreComposition(mCurrentFrameNumber, refreshStartTime);
    }
    mRefreshPending = false;
    return hasReadyFrame();
}

bool BufferLayer::onPostComposition(const std::shared_ptr<FenceTime>& glDoneFence,
                                    const std::shared_ptr<FenceTime>& presentFence,
                                    const CompositorTiming& compositorTiming) {

    // mFrameLatencyNeeded is true when a new frame was latched for the
    // composition.
    if (!mFrameLatencyNeeded) return false;

    // Update mFrameEventHistory.
    {
        Mutex::Autolock lock(mFrameEventHistoryMutex);
        mFrameEventHistory.addPostComposition(mCurrentFrameNumber, glDoneFence, presentFence,
                                              compositorTiming);
    }

    // Update mFrameTracker.
    nsecs_t desiredPresentTime = getDesiredPresentTime();
    mFrameTracker.setDesiredPresentTime(desiredPresentTime);

    const std::string layerName(getName().c_str());
    mTimeStats.setDesiredTime(layerName, mCurrentFrameNumber, desiredPresentTime);

    std::shared_ptr<FenceTime> frameReadyFence = getCurrentFenceTime();
    if (frameReadyFence->isValid()) {
        mFrameTracker.setFrameReadyFence(std::move(frameReadyFence));
    } else {
        // There was no fence for this frame, so assume that it was ready
        // to be presented at the desired present time.
        mFrameTracker.setFrameReadyTime(desiredPresentTime);
    }

    if (presentFence->isValid()) {
        mTimeStats.setPresentFence(layerName, mCurrentFrameNumber, presentFence);
        mFrameTracker.setActualPresentFence(std::shared_ptr<FenceTime>(presentFence));
    } else if (mFlinger->getHwComposer().isConnected(HWC_DISPLAY_PRIMARY)) {
        // The HWC doesn't support present fences, so use the refresh
        // timestamp instead.
        const nsecs_t actualPresentTime =
                mFlinger->getHwComposer().getRefreshTimestamp(HWC_DISPLAY_PRIMARY);
        mTimeStats.setPresentTime(layerName, mCurrentFrameNumber, actualPresentTime);
        mFrameTracker.setActualPresentTime(actualPresentTime);
    }

    mFrameTracker.advanceFrame();
    mFrameLatencyNeeded = false;
    return true;
}

Region BufferLayer::latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime) {
    ATRACE_CALL();

    std::optional<Region> sidebandStreamDirtyRegion = latchSidebandStream(recomputeVisibleRegions);

    if (sidebandStreamDirtyRegion) {
        return *sidebandStreamDirtyRegion;
    }

    Region dirtyRegion;

    if (!hasReadyFrame()) {
        return dirtyRegion;
    }

    // if we've already called updateTexImage() without going through
    // a composition step, we have to skip this layer at this point
    // because we cannot call updateTeximage() without a corresponding
    // compositionComplete() call.
    // we'll trigger an update in onPreComposition().
    if (mRefreshPending) {
        return dirtyRegion;
    }

    // If the head buffer's acquire fence hasn't signaled yet, return and
    // try again later
    if (!fenceHasSignaled()) {
        mFlinger->signalLayerUpdate();
        return dirtyRegion;
    }

    // Capture the old state of the layer for comparisons later
    const State& s(getDrawingState());
    const bool oldOpacity = isOpaque(s);
    sp<GraphicBuffer> oldBuffer = mActiveBuffer;

    if (!allTransactionsSignaled()) {
        mFlinger->signalLayerUpdate();
        return dirtyRegion;
    }

    status_t err = updateTexImage(recomputeVisibleRegions, latchTime);
    if (err != NO_ERROR) {
        return dirtyRegion;
    }

    err = updateActiveBuffer();
    if (err != NO_ERROR) {
        return dirtyRegion;
    }

    mBufferLatched = true;

    err = updateFrameNumber(latchTime);
    if (err != NO_ERROR) {
        return dirtyRegion;
    }

    mRefreshPending = true;
    mFrameLatencyNeeded = true;
    if (oldBuffer == nullptr) {
        // the first time we receive a buffer, we need to trigger a
        // geometry invalidation.
        recomputeVisibleRegions = true;
    }

    ui::Dataspace dataSpace = getDrawingDataSpace();
    // treat modern dataspaces as legacy dataspaces whenever possible, until
    // we can trust the buffer producers
    switch (dataSpace) {
        case ui::Dataspace::V0_SRGB:
            dataSpace = ui::Dataspace::SRGB;
            break;
        case ui::Dataspace::V0_SRGB_LINEAR:
            dataSpace = ui::Dataspace::SRGB_LINEAR;
            break;
        case ui::Dataspace::V0_JFIF:
            dataSpace = ui::Dataspace::JFIF;
            break;
        case ui::Dataspace::V0_BT601_625:
            dataSpace = ui::Dataspace::BT601_625;
            break;
        case ui::Dataspace::V0_BT601_525:
            dataSpace = ui::Dataspace::BT601_525;
            break;
        case ui::Dataspace::V0_BT709:
            dataSpace = ui::Dataspace::BT709;
            break;
        default:
            break;
    }
    mCurrentDataSpace = dataSpace;

    Rect crop(getDrawingCrop());
    const uint32_t transform(getDrawingTransform());
    const uint32_t scalingMode(getDrawingScalingMode());
    if ((crop != mCurrentCrop) || (transform != mCurrentTransform) ||
        (scalingMode != mCurrentScalingMode)) {
        mCurrentCrop = crop;
        mCurrentTransform = transform;
        mCurrentScalingMode = scalingMode;
        recomputeVisibleRegions = true;
    }

    if (oldBuffer != nullptr) {
        uint32_t bufWidth = mActiveBuffer->getWidth();
        uint32_t bufHeight = mActiveBuffer->getHeight();
        if (bufWidth != uint32_t(oldBuffer->width) || bufHeight != uint32_t(oldBuffer->height)) {
            recomputeVisibleRegions = true;
        }
    }

    if (oldOpacity != isOpaque(s)) {
        recomputeVisibleRegions = true;
    }

    // Remove any sync points corresponding to the buffer which was just
    // latched
    {
        Mutex::Autolock lock(mLocalSyncPointMutex);
        auto point = mLocalSyncPoints.begin();
        while (point != mLocalSyncPoints.end()) {
            if (!(*point)->frameIsAvailable() || !(*point)->transactionIsApplied()) {
                // This sync point must have been added since we started
                // latching. Don't drop it yet.
                ++point;
                continue;
            }

            if ((*point)->getFrameNumber() <= mCurrentFrameNumber) {
                point = mLocalSyncPoints.erase(point);
            } else {
                ++point;
            }
        }
    }

    // FIXME: postedRegion should be dirty & bounds
    // transform the dirty region to window-manager space
    return getTransform().transform(Region(Rect(getActiveWidth(s), getActiveHeight(s))));
}

// transaction
void BufferLayer::notifyAvailableFrames() {
    auto headFrameNumber = getHeadFrameNumber();
    bool headFenceSignaled = fenceHasSignaled();
    Mutex::Autolock lock(mLocalSyncPointMutex);
    for (auto& point : mLocalSyncPoints) {
        if (headFrameNumber >= point->getFrameNumber() && headFenceSignaled) {
            point->setFrameAvailable();
        }
    }
}

bool BufferLayer::hasReadyFrame() const {
    return hasDrawingBuffer() || getSidebandStreamChanged() || getAutoRefresh();
}

uint32_t BufferLayer::getEffectiveScalingMode() const {
    if (mOverrideScalingMode >= 0) {
        return mOverrideScalingMode;
    }

    return mCurrentScalingMode;
}

bool BufferLayer::isProtected() const {
    const sp<GraphicBuffer>& buffer(mActiveBuffer);
    return (buffer != 0) && (buffer->getUsage() & GRALLOC_USAGE_PROTECTED);
}

bool BufferLayer::latchUnsignaledBuffers() {
    static bool propertyLoaded = false;
    static bool latch = false;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    if (!propertyLoaded) {
        char value[PROPERTY_VALUE_MAX] = {};
        property_get("debug.sf.latch_unsignaled", value, "0");
        latch = atoi(value);
        propertyLoaded = true;
    }
    return latch;
}

// h/w composer set-up
bool BufferLayer::allTransactionsSignaled() {
    auto headFrameNumber = getHeadFrameNumber();
    bool matchingFramesFound = false;
    bool allTransactionsApplied = true;
    Mutex::Autolock lock(mLocalSyncPointMutex);

    for (auto& point : mLocalSyncPoints) {
        if (point->getFrameNumber() > headFrameNumber) {
            break;
        }
        matchingFramesFound = true;

        if (!point->frameIsAvailable()) {
            // We haven't notified the remote layer that the frame for
            // this point is available yet. Notify it now, and then
            // abort this attempt to latch.
            point->setFrameAvailable();
            allTransactionsApplied = false;
            break;
        }

        allTransactionsApplied = allTransactionsApplied && point->transactionIsApplied();
    }
    return !matchingFramesFound || allTransactionsApplied;
}

// As documented in libhardware header, formats in the range
// 0x100 - 0x1FF are specific to the HAL implementation, and
// are known to have no alpha channel
// TODO: move definition for device-specific range into
// hardware.h, instead of using hard-coded values here.
#define HARDWARE_IS_DEVICE_FORMAT(f) ((f) >= 0x100 && (f) <= 0x1FF)

bool BufferLayer::getOpacityForFormat(uint32_t format) {
    if (HARDWARE_IS_DEVICE_FORMAT(format)) {
        return true;
    }
    switch (format) {
        case HAL_PIXEL_FORMAT_RGBA_8888:
        case HAL_PIXEL_FORMAT_BGRA_8888:
        case HAL_PIXEL_FORMAT_RGBA_FP16:
        case HAL_PIXEL_FORMAT_RGBA_1010102:
            return false;
    }
    // in all other case, we have no blending (also for unknown formats)
    return true;
}

bool BufferLayer::needsFiltering(const RenderArea& renderArea) const {
    return mNeedsFiltering || renderArea.needsFiltering();
}

void BufferLayer::drawWithOpenGL(const RenderArea& renderArea, bool useIdentityTransform) const {
    ATRACE_CALL();
    const State& s(getDrawingState());

    computeGeometry(renderArea, getBE().mMesh, useIdentityTransform);

    /*
     * NOTE: the way we compute the texture coordinates here produces
     * different results than when we take the HWC path -- in the later case
     * the "source crop" is rounded to texel boundaries.
     * This can produce significantly different results when the texture
     * is scaled by a large amount.
     *
     * The GL code below is more logical (imho), and the difference with
     * HWC is due to a limitation of the HWC API to integers -- a question
     * is suspend is whether we should ignore this problem or revert to
     * GL composition when a buffer scaling is applied (maybe with some
     * minimal value)? Or, we could make GL behave like HWC -- but this feel
     * like more of a hack.
     */
    const Rect bounds{computeBounds()}; // Rounds from FloatRect

    ui::Transform t = getTransform();
    Rect win = bounds;

    float left = float(win.left) / float(getActiveWidth(s));
    float top = float(win.top) / float(getActiveHeight(s));
    float right = float(win.right) / float(getActiveWidth(s));
    float bottom = float(win.bottom) / float(getActiveHeight(s));

    // TODO: we probably want to generate the texture coords with the mesh
    // here we assume that we only have 4 vertices
    renderengine::Mesh::VertexArray<vec2> texCoords(getBE().mMesh.getTexCoordArray<vec2>());
    // flip texcoords vertically because BufferLayerConsumer expects them to be in GL convention
    texCoords[0] = vec2(left, 1.0f - top);
    texCoords[1] = vec2(left, 1.0f - bottom);
    texCoords[2] = vec2(right, 1.0f - bottom);
    texCoords[3] = vec2(right, 1.0f - top);

    auto& engine(mFlinger->getRenderEngine());
    engine.setupLayerBlending(mPremultipliedAlpha, isOpaque(s), false /* disableTexture */,
                              getColor());
    engine.setSourceDataSpace(mCurrentDataSpace);

    if (isHdrY410()) {
        engine.setSourceY410BT2020(true);
    }

    engine.drawMesh(getBE().mMesh);
    engine.disableBlending();

    engine.setSourceY410BT2020(false);
}

uint64_t BufferLayer::getHeadFrameNumber() const {
    if (hasDrawingBuffer()) {
        return getFrameNumber();
    } else {
        return mCurrentFrameNumber;
    }
}

} // namespace android

#if defined(__gl_h_)
#error "don't include gl/gl.h in this file"
#endif

#if defined(__gl2_h_)
#error "don't include gl2/gl2.h in this file"
#endif
