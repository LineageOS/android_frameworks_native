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
#define LOG_TAG "BufferStateLayer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "BufferStateLayer.h"

#include <private/gui/SyncFeatures.h>
#include <renderengine/Image.h>

namespace android {

// clang-format off
const std::array<float, 16> BufferStateLayer::IDENTITY_MATRIX{
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1
};
// clang-format on

BufferStateLayer::BufferStateLayer(const LayerCreationArgs& args) : BufferLayer(args) {
    mOverrideScalingMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
}
BufferStateLayer::~BufferStateLayer() = default;

// -----------------------------------------------------------------------
// Interface implementation for Layer
// -----------------------------------------------------------------------
void BufferStateLayer::onLayerDisplayed(const sp<Fence>& releaseFence) {
    // The transaction completed callback can only be sent if the release fence from the PREVIOUS
    // frame has fired. In practice, we should never actually wait on the previous release fence
    // but we should store it just in case.
    mPreviousReleaseFence = releaseFence;
}

void BufferStateLayer::setTransformHint(uint32_t /*orientation*/) const {
    // TODO(marissaw): send the transform hint to buffer owner
    return;
}

void BufferStateLayer::releasePendingBuffer(nsecs_t /*dequeueReadyTime*/) {
    return;
}

bool BufferStateLayer::shouldPresentNow(nsecs_t /*expectedPresentTime*/) const {
    if (getSidebandStreamChanged() || getAutoRefresh()) {
        return true;
    }

    return hasFrameUpdate();
}

bool BufferStateLayer::willPresentCurrentTransaction() const {
    // Returns true if the most recent Transaction applied to CurrentState will be presented.
    return getSidebandStreamChanged() || getAutoRefresh() ||
            (mCurrentState.modified && mCurrentState.buffer != nullptr);
}

bool BufferStateLayer::getTransformToDisplayInverse() const {
    return mCurrentState.transformToDisplayInverse;
}

void BufferStateLayer::pushPendingState() {
    if (!mCurrentState.modified) {
        return;
    }
    mPendingStates.push_back(mCurrentState);
    ATRACE_INT(mTransactionName.string(), mPendingStates.size());
}

bool BufferStateLayer::applyPendingStates(Layer::State* stateToCommit) {
    const bool stateUpdateAvailable = !mPendingStates.empty();
    while (!mPendingStates.empty()) {
        popPendingState(stateToCommit);
    }
    mCurrentStateModified = stateUpdateAvailable && mCurrentState.modified;
    mCurrentState.modified = false;
    return stateUpdateAvailable;
}

Rect BufferStateLayer::getCrop(const Layer::State& s) const {
    return (getEffectiveScalingMode() == NATIVE_WINDOW_SCALING_MODE_SCALE_CROP)
            ? GLConsumer::scaleDownCrop(s.crop, s.active.w, s.active.h)
            : s.crop;
}

bool BufferStateLayer::setTransform(uint32_t transform) {
    if (mCurrentState.transform == transform) return false;
    mCurrentState.sequence++;
    mCurrentState.transform = transform;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setTransformToDisplayInverse(bool transformToDisplayInverse) {
    if (mCurrentState.transformToDisplayInverse == transformToDisplayInverse) return false;
    mCurrentState.sequence++;
    mCurrentState.transformToDisplayInverse = transformToDisplayInverse;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setCrop(const Rect& crop) {
    if (mCurrentState.crop == crop) return false;
    mCurrentState.sequence++;
    mCurrentState.crop = crop;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setBuffer(const sp<GraphicBuffer>& buffer) {
    if (mCurrentState.buffer) {
        mReleasePreviousBuffer = true;
    }

    mCurrentState.sequence++;
    mCurrentState.buffer = buffer;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setAcquireFence(const sp<Fence>& fence) {
    // The acquire fences of BufferStateLayers have already signaled before they are set
    mCallbackHandleAcquireTime = fence->getSignalTime();

    mCurrentState.acquireFence = fence;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setDataspace(ui::Dataspace dataspace) {
    if (mCurrentState.dataspace == dataspace) return false;
    mCurrentState.sequence++;
    mCurrentState.dataspace = dataspace;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setHdrMetadata(const HdrMetadata& hdrMetadata) {
    if (mCurrentState.hdrMetadata == hdrMetadata) return false;
    mCurrentState.sequence++;
    mCurrentState.hdrMetadata = hdrMetadata;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSurfaceDamageRegion(const Region& surfaceDamage) {
    mCurrentState.sequence++;
    mCurrentState.surfaceDamageRegion = surfaceDamage;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setApi(int32_t api) {
    if (mCurrentState.api == api) return false;
    mCurrentState.sequence++;
    mCurrentState.api = api;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSidebandStream(const sp<NativeHandle>& sidebandStream) {
    if (mCurrentState.sidebandStream == sidebandStream) return false;
    mCurrentState.sequence++;
    mCurrentState.sidebandStream = sidebandStream;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    if (!mSidebandStreamChanged.exchange(true)) {
        // mSidebandStreamChanged was false
        mFlinger->signalLayerUpdate();
    }
    return true;
}

bool BufferStateLayer::setTransactionCompletedListeners(
        const std::vector<sp<CallbackHandle>>& handles) {
    // If there is no handle, we will not send a callback so reset mReleasePreviousBuffer and return
    if (handles.empty()) {
        mReleasePreviousBuffer = false;
        return false;
    }

    const bool willPresent = willPresentCurrentTransaction();

    for (const auto& handle : handles) {
        // If this transaction set a buffer on this layer, release its previous buffer
        handle->releasePreviousBuffer = mReleasePreviousBuffer;

        // If this layer will be presented in this frame
        if (willPresent) {
            // If this transaction set an acquire fence on this layer, set its acquire time
            handle->acquireTime = mCallbackHandleAcquireTime;

            // Notify the transaction completed thread that there is a pending latched callback
            // handle
            mFlinger->getTransactionCompletedThread().registerPendingLatchedCallbackHandle(handle);

            // Store so latched time and release fence can be set
            mCurrentState.callbackHandles.push_back(handle);

        } else { // If this layer will NOT need to be relatched and presented this frame
            // Notify the transaction completed thread this handle is done
            mFlinger->getTransactionCompletedThread().addUnlatchedCallbackHandle(handle);
        }
    }

    mReleasePreviousBuffer = false;
    mCallbackHandleAcquireTime = -1;

    return willPresent;
}

bool BufferStateLayer::setSize(uint32_t w, uint32_t h) {
    if (mCurrentState.active.w == w && mCurrentState.active.h == h) return false;
    mCurrentState.active.w = w;
    mCurrentState.active.h = h;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setPosition(float x, float y, bool /*immediate*/) {
    if (mCurrentState.active.transform.tx() == x && mCurrentState.active.transform.ty() == y)
        return false;

    mCurrentState.active.transform.set(x, y);

    mCurrentState.sequence++;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setTransparentRegionHint(const Region& transparent) {
    mCurrentState.transparentRegionHint = transparent;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setMatrix(const layer_state_t::matrix22_t& matrix,
                                 bool allowNonRectPreservingTransforms) {
    ui::Transform t;
    t.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);

    if (!allowNonRectPreservingTransforms && !t.preserveRects()) {
        ALOGW("Attempt to set rotation matrix without permission ACCESS_SURFACE_FLINGER ignored");
        return false;
    }

    mCurrentState.sequence++;
    mCurrentState.active.transform.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Interface implementation for BufferLayer
// -----------------------------------------------------------------------
bool BufferStateLayer::fenceHasSignaled() const {
    if (latchUnsignaledBuffers()) {
        return true;
    }

    return getDrawingState().acquireFence->getStatus() == Fence::Status::Signaled;
}

nsecs_t BufferStateLayer::getDesiredPresentTime() {
    // TODO(marissaw): support an equivalent to desiredPresentTime for timestats metrics
    return 0;
}

std::shared_ptr<FenceTime> BufferStateLayer::getCurrentFenceTime() const {
    return std::make_shared<FenceTime>(getDrawingState().acquireFence);
}

void BufferStateLayer::getDrawingTransformMatrix(float *matrix) {
    std::copy(std::begin(mTransformMatrix), std::end(mTransformMatrix), matrix);
}

uint32_t BufferStateLayer::getDrawingTransform() const {
    return getDrawingState().transform;
}

ui::Dataspace BufferStateLayer::getDrawingDataSpace() const {
    return getDrawingState().dataspace;
}

Rect BufferStateLayer::getDrawingCrop() const {
    return Rect::INVALID_RECT;
}

uint32_t BufferStateLayer::getDrawingScalingMode() const {
    return NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
}

Region BufferStateLayer::getDrawingSurfaceDamage() const {
    return getDrawingState().surfaceDamageRegion;
}

const HdrMetadata& BufferStateLayer::getDrawingHdrMetadata() const {
    return getDrawingState().hdrMetadata;
}

int BufferStateLayer::getDrawingApi() const {
    return getDrawingState().api;
}

PixelFormat BufferStateLayer::getPixelFormat() const {
    return mActiveBuffer->format;
}

uint64_t BufferStateLayer::getFrameNumber() const {
    return mFrameNumber;
}

bool BufferStateLayer::getAutoRefresh() const {
    // TODO(marissaw): support shared buffer mode
    return false;
}

bool BufferStateLayer::getSidebandStreamChanged() const {
    return mSidebandStreamChanged.load();
}

std::optional<Region> BufferStateLayer::latchSidebandStream(bool& recomputeVisibleRegions) {
    if (mSidebandStreamChanged.exchange(false)) {
        const State& s(getDrawingState());
        // mSidebandStreamChanged was true
        // replicated in LayerBE until FE/BE is ready to be synchronized
        getBE().compositionInfo.hwc.sidebandStream = s.sidebandStream;
        if (getBE().compositionInfo.hwc.sidebandStream != nullptr) {
            setTransactionFlags(eTransactionNeeded);
            mFlinger->setTransactionFlags(eTraversalNeeded);
        }
        recomputeVisibleRegions = true;

        return getTransform().transform(Region(Rect(s.active.w, s.active.h)));
    }
    return {};
}

bool BufferStateLayer::hasFrameUpdate() const {
    return mCurrentStateModified && getCurrentState().buffer != nullptr;
}

void BufferStateLayer::setFilteringEnabled(bool enabled) {
    GLConsumer::computeTransformMatrix(mTransformMatrix.data(), mActiveBuffer, mCurrentCrop,
                                       mCurrentTransform, enabled);
}

status_t BufferStateLayer::bindTextureImage() {
    const State& s(getDrawingState());
    auto& engine(mFlinger->getRenderEngine());

    engine.checkErrors();

    // TODO(marissaw): once buffers are cached, don't create a new image everytime
    mTextureImage = engine.createImage();

    bool created =
            mTextureImage->setNativeWindowBuffer(s.buffer->getNativeBuffer(),
                                                 s.buffer->getUsage() & GRALLOC_USAGE_PROTECTED);
    if (!created) {
        ALOGE("Failed to create image. size=%ux%u st=%u usage=%#" PRIx64 " fmt=%d",
              s.buffer->getWidth(), s.buffer->getHeight(), s.buffer->getStride(),
              s.buffer->getUsage(), s.buffer->getPixelFormat());
        engine.bindExternalTextureImage(mTextureName, *engine.createImage());
        return NO_INIT;
    }

    engine.bindExternalTextureImage(mTextureName, *mTextureImage);

    // Wait for the new buffer to be ready.
    if (s.acquireFence->isValid()) {
        if (SyncFeatures::getInstance().useWaitSync()) {
            base::unique_fd fenceFd(s.acquireFence->dup());
            if (fenceFd == -1) {
                ALOGE("error dup'ing fence fd: %d", errno);
                return -errno;
            }
            if (!engine.waitFence(std::move(fenceFd))) {
                ALOGE("failed to wait on fence fd");
                return UNKNOWN_ERROR;
            }
        } else {
            status_t err = s.acquireFence->waitForever("BufferStateLayer::bindTextureImage");
            if (err != NO_ERROR) {
                ALOGE("error waiting for fence: %d", err);
                return err;
            }
        }
    }

    return NO_ERROR;
}

status_t BufferStateLayer::updateTexImage(bool& /*recomputeVisibleRegions*/, nsecs_t latchTime,
                                          const sp<Fence>& releaseFence) {
    const State& s(getDrawingState());

    if (!s.buffer) {
        return NO_ERROR;
    }

    const int32_t layerID = getSequence();

    // Reject if the layer is invalid
    uint32_t bufferWidth = s.buffer->width;
    uint32_t bufferHeight = s.buffer->height;

    if (s.transform & ui::Transform::ROT_90) {
        std::swap(bufferWidth, bufferHeight);
    }

    if (s.transformToDisplayInverse) {
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayOrientationTransform();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufferWidth, bufferHeight);
        }
    }

    if (getEffectiveScalingMode() == NATIVE_WINDOW_SCALING_MODE_FREEZE &&
        (s.active.w != bufferWidth || s.active.h != bufferHeight)) {
        ALOGE("[%s] rejecting buffer: "
              "bufferWidth=%d, bufferHeight=%d, front.active.{w=%d, h=%d}",
              mName.string(), bufferWidth, bufferHeight, s.active.w, s.active.h);
        mTimeStats.removeTimeRecord(layerID, getFrameNumber());
        return BAD_VALUE;
    }

    mFlinger->getTransactionCompletedThread()
            .addLatchedCallbackHandles(getDrawingState().callbackHandles, latchTime,
                                       mPreviousReleaseFence);

    // Handle sync fences
    if (SyncFeatures::getInstance().useNativeFenceSync() && releaseFence != Fence::NO_FENCE) {
        // TODO(alecmouri): Fail somewhere upstream if the fence is invalid.
        if (!releaseFence->isValid()) {
            mTimeStats.clearLayerRecord(layerID);
            return UNKNOWN_ERROR;
        }

        // Check status of fences first because merging is expensive.
        // Merging an invalid fence with any other fence results in an
        // invalid fence.
        auto currentStatus = s.acquireFence->getStatus();
        if (currentStatus == Fence::Status::Invalid) {
            ALOGE("Existing fence has invalid state");
            mTimeStats.clearLayerRecord(layerID);
            return BAD_VALUE;
        }

        auto incomingStatus = releaseFence->getStatus();
        if (incomingStatus == Fence::Status::Invalid) {
            ALOGE("New fence has invalid state");
            mDrawingState.acquireFence = releaseFence;
            mTimeStats.clearLayerRecord(layerID);
            return BAD_VALUE;
        }

        // If both fences are signaled or both are unsignaled, we need to merge
        // them to get an accurate timestamp.
        if (currentStatus == incomingStatus) {
            char fenceName[32] = {};
            snprintf(fenceName, 32, "%.28s:%d", mName.string(), mFrameNumber);
            sp<Fence> mergedFence =
                    Fence::merge(fenceName, mDrawingState.acquireFence, releaseFence);
            if (!mergedFence.get()) {
                ALOGE("failed to merge release fences");
                // synchronization is broken, the best we can do is hope fences
                // signal in order so the new fence will act like a union
                mDrawingState.acquireFence = releaseFence;
                mTimeStats.clearLayerRecord(layerID);
                return BAD_VALUE;
            }
            mDrawingState.acquireFence = mergedFence;
        } else if (incomingStatus == Fence::Status::Unsignaled) {
            // If one fence has signaled and the other hasn't, the unsignaled
            // fence will approximately correspond with the correct timestamp.
            // There's a small race if both fences signal at about the same time
            // and their statuses are retrieved with unfortunate timing. However,
            // by this point, they will have both signaled and only the timestamp
            // will be slightly off; any dependencies after this point will
            // already have been met.
            mDrawingState.acquireFence = releaseFence;
        }
    } else {
        // Bind the new buffer to the GL texture.
        //
        // Older devices require the "implicit" synchronization provided
        // by glEGLImageTargetTexture2DOES, which this method calls.  Newer
        // devices will either call this in Layer::onDraw, or (if it's not
        // a GL-composited layer) not at all.
        status_t err = bindTextureImage();
        if (err != NO_ERROR) {
            mTimeStats.clearLayerRecord(layerID);
            return BAD_VALUE;
        }
    }

    // TODO(marissaw): properly support mTimeStats
    mTimeStats.setPostTime(layerID, getFrameNumber(), getName().c_str(), latchTime);
    mTimeStats.setAcquireFence(layerID, getFrameNumber(), getCurrentFenceTime());
    mTimeStats.setLatchTime(layerID, getFrameNumber(), latchTime);

    return NO_ERROR;
}

status_t BufferStateLayer::updateActiveBuffer() {
    const State& s(getDrawingState());

    if (s.buffer == nullptr) {
        return BAD_VALUE;
    }

    mActiveBuffer = s.buffer;
    getBE().compositionInfo.mBuffer = mActiveBuffer;
    getBE().compositionInfo.mBufferSlot = 0;

    return NO_ERROR;
}

status_t BufferStateLayer::updateFrameNumber(nsecs_t /*latchTime*/) {
    // TODO(marissaw): support frame history events
    mCurrentFrameNumber = mFrameNumber;
    return NO_ERROR;
}

void BufferStateLayer::setHwcLayerBuffer(DisplayId displayId) {
    auto& hwcInfo = getBE().mHwcLayers[displayId];
    auto& hwcLayer = hwcInfo.layer;

    const State& s(getDrawingState());

    // TODO(marissaw): support more than one slot
    uint32_t hwcSlot = 0;

    auto error = hwcLayer->setBuffer(hwcSlot, s.buffer, s.acquireFence);
    if (error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set buffer %p: %s (%d)", mName.string(),
              s.buffer->handle, to_string(error).c_str(), static_cast<int32_t>(error));
    }

    mCurrentStateModified = false;
    mFrameNumber++;
}

void BufferStateLayer::onFirstRef() {
    BufferLayer::onFirstRef();

    if (const auto display = mFlinger->getDefaultDisplayDevice()) {
        updateTransformHint(display);
    }
}

} // namespace android
