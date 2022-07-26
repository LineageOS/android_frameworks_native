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

#include <limits>

#include <FrameTimeline/FrameTimeline.h>
#include <compositionengine/CompositionEngine.h>
#include <gui/BufferQueue.h>
#include <private/gui/SyncFeatures.h>
#include <renderengine/Image.h>
#include "TunnelModeEnabledReporter.h"

#include <gui/TraceUtils.h>
#include "EffectLayer.h"
#include "FrameTracer/FrameTracer.h"
#include "TimeStats/TimeStats.h"

#define EARLY_RELEASE_ENABLED false

#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <cutils/compiler.h>
#include <cutils/native_handle.h>
#include <cutils/properties.h>
#include <gui/BufferItem.h>
#include <gui/BufferQueue.h>
#include <gui/GLConsumer.h>
#include <gui/LayerDebugInfo.h>
#include <gui/Surface.h>
#include <renderengine/RenderEngine.h>
#include <ui/DebugUtils.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/NativeHandle.h>
#include <utils/StopWatch.h>
#include <utils/Trace.h>

#include <cmath>
#include <cstdlib>
#include <mutex>
#include <sstream>

#include "Colorizer.h"
#include "DisplayDevice.h"
#include "FrameTracer/FrameTracer.h"
#include "TimeStats/TimeStats.h"

namespace android {

using PresentState = frametimeline::SurfaceFrame::PresentState;
using gui::WindowInfo;
namespace {
static constexpr float defaultMaxLuminance = 1000.0;

constexpr mat4 inverseOrientation(uint32_t transform) {
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

BufferStateLayer::BufferStateLayer(const LayerCreationArgs& args)
      : Layer(args),
        mTextureName(args.textureName),
        mCompositionState{mFlinger->getCompositionEngine().createLayerFECompositionState()},
        mHwcSlotGenerator(new HwcSlotGenerator()) {
    ALOGV("Creating Layer %s", getDebugName());

    mPremultipliedAlpha = !(args.flags & ISurfaceComposerClient::eNonPremultiplied);
    mPotentialCursor = args.flags & ISurfaceComposerClient::eCursorWindow;
    mProtectedByApp = args.flags & ISurfaceComposerClient::eProtectedByApp;
    mDrawingState.dataspace = ui::Dataspace::V0_SRGB;
}

BufferStateLayer::~BufferStateLayer() {
    // The original layer and the clone layer share the same texture and buffer. Therefore, only
    // one of the layers, in this case the original layer, needs to handle the deletion. The
    // original layer and the clone should be removed at the same time so there shouldn't be any
    // issue with the clone layer trying to use the texture.
    if (mBufferInfo.mBuffer != nullptr) {
        callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                  mBufferInfo.mBuffer->getBuffer(), mBufferInfo.mFrameNumber,
                                  mBufferInfo.mFence,
                                  mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(
                                          mOwnerUid));
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
}

void BufferStateLayer::callReleaseBufferCallback(const sp<ITransactionCompletedListener>& listener,
                                                 const sp<GraphicBuffer>& buffer,
                                                 uint64_t framenumber,
                                                 const sp<Fence>& releaseFence,
                                                 uint32_t currentMaxAcquiredBufferCount) {
    if (!listener) {
        return;
    }
    ATRACE_FORMAT_INSTANT("callReleaseBufferCallback %s - %" PRIu64, getDebugName(), framenumber);
    listener->onReleaseBuffer({buffer->getId(), framenumber},
                              releaseFence ? releaseFence : Fence::NO_FENCE,
                              currentMaxAcquiredBufferCount);
}

// -----------------------------------------------------------------------
// Interface implementation for Layer
// -----------------------------------------------------------------------
void BufferStateLayer::onLayerDisplayed(ftl::SharedFuture<FenceResult> futureFenceResult) {
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
    // Transactions that were set on this layer this frame are going to have their preceeding buffer
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
        if (handle->releasePreviousBuffer &&
            mDrawingState.releaseBufferEndpoint == handle->listener) {
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
}

void BufferStateLayer::onSurfaceFrameCreated(
        const std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame) {
    while (mPendingJankClassifications.size() >= kPendingClassificationMaxSurfaceFrames) {
        // Too many SurfaceFrames pending classification. The front of the deque is probably not
        // tracked by FrameTimeline and will never be presented. This will only result in a memory
        // leak.
        ALOGW("Removing the front of pending jank deque from layer - %s to prevent memory leak",
              mName.c_str());
        std::string miniDump = mPendingJankClassifications.front()->miniDump();
        ALOGD("Head SurfaceFrame mini dump\n%s", miniDump.c_str());
        mPendingJankClassifications.pop_front();
    }
    mPendingJankClassifications.emplace_back(surfaceFrame);
}

void BufferStateLayer::releasePendingBuffer(nsecs_t dequeueReadyTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->transformHint = mTransformHint;
        handle->dequeueReadyTime = dequeueReadyTime;
        handle->currentMaxAcquiredBufferCount =
                mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mOwnerUid);
        ATRACE_FORMAT_INSTANT("releasePendingBuffer %s - %" PRIu64, getDebugName(),
                              handle->previousReleaseCallbackId.framenumber);
    }

    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->releasePreviousBuffer &&
            mDrawingState.releaseBufferEndpoint == handle->listener) {
            handle->previousReleaseCallbackId = mPreviousReleaseCallbackId;
            break;
        }
    }

    std::vector<JankData> jankData;
    jankData.reserve(mPendingJankClassifications.size());
    while (!mPendingJankClassifications.empty()
            && mPendingJankClassifications.front()->getJankType()) {
        std::shared_ptr<frametimeline::SurfaceFrame> surfaceFrame =
                mPendingJankClassifications.front();
        mPendingJankClassifications.pop_front();
        jankData.emplace_back(
                JankData(surfaceFrame->getToken(), surfaceFrame->getJankType().value()));
    }

    mFlinger->getTransactionCallbackInvoker().addCallbackHandles(
            mDrawingState.callbackHandles, jankData);

    sp<Fence> releaseFence = Fence::NO_FENCE;
    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->releasePreviousBuffer &&
            mDrawingState.releaseBufferEndpoint == handle->listener) {
            releaseFence =
                    handle->previousReleaseFence ? handle->previousReleaseFence : Fence::NO_FENCE;
            break;
        }
    }

    mDrawingState.callbackHandles = {};
}

bool BufferStateLayer::willPresentCurrentTransaction() const {
    // Returns true if the most recent Transaction applied to CurrentState will be presented.
    return (getSidebandStreamChanged() || getAutoRefresh() ||
            (mDrawingState.modified &&
             (mDrawingState.buffer != nullptr || mDrawingState.bgColorLayer != nullptr)));
}

Rect BufferStateLayer::getCrop(const Layer::State& s) const {
    return s.crop;
}

bool BufferStateLayer::setTransform(uint32_t transform) {
    if (mDrawingState.bufferTransform == transform) return false;
    mDrawingState.bufferTransform = transform;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setTransformToDisplayInverse(bool transformToDisplayInverse) {
    if (mDrawingState.transformToDisplayInverse == transformToDisplayInverse) return false;
    mDrawingState.sequence++;
    mDrawingState.transformToDisplayInverse = transformToDisplayInverse;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setCrop(const Rect& crop) {
    if (mDrawingState.crop == crop) return false;
    mDrawingState.sequence++;
    mDrawingState.crop = crop;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setBufferCrop(const Rect& bufferCrop) {
    if (mDrawingState.bufferCrop == bufferCrop) return false;

    mDrawingState.sequence++;
    mDrawingState.bufferCrop = bufferCrop;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setDestinationFrame(const Rect& destinationFrame) {
    if (mDrawingState.destinationFrame == destinationFrame) return false;

    mDrawingState.sequence++;
    mDrawingState.destinationFrame = destinationFrame;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

// Translate destination frame into scale and position. If a destination frame is not set, use the
// provided scale and position
bool BufferStateLayer::updateGeometry() {
    if ((mDrawingState.flags & layer_state_t::eIgnoreDestinationFrame) ||
        mDrawingState.destinationFrame.isEmpty()) {
        // If destination frame is not set, use the requested transform set via
        // BufferStateLayer::setPosition and BufferStateLayer::setMatrix.
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
    uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
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

bool BufferStateLayer::setMatrix(const layer_state_t::matrix22_t& matrix) {
    if (mRequestedTransform.dsdx() == matrix.dsdx && mRequestedTransform.dtdy() == matrix.dtdy &&
        mRequestedTransform.dtdx() == matrix.dtdx && mRequestedTransform.dsdy() == matrix.dsdy) {
        return false;
    }

    ui::Transform t;
    t.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);

    mRequestedTransform.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);

    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    return true;
}

bool BufferStateLayer::setPosition(float x, float y) {
    if (mRequestedTransform.tx() == x && mRequestedTransform.ty() == y) {
        return false;
    }

    mRequestedTransform.set(x, y);

    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    return true;
}

bool BufferStateLayer::setBuffer(std::shared_ptr<renderengine::ExternalTexture>& buffer,
                                 const BufferData& bufferData, nsecs_t postTime,
                                 nsecs_t desiredPresentTime, bool isAutoTimestamp,
                                 std::optional<nsecs_t> dequeueTime,
                                 const FrameTimelineInfo& info) {
    ATRACE_CALL();

    if (!buffer) {
        return false;
    }

    const bool frameNumberChanged =
            bufferData.flags.test(BufferData::BufferDataChange::frameNumberChanged);
    const uint64_t frameNumber =
            frameNumberChanged ? bufferData.frameNumber : mDrawingState.frameNumber + 1;

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
                                      mDrawingState.acquireFence,
                                      mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(
                                              mOwnerUid));
            decrementPendingBufferCount();
            if (mDrawingState.bufferSurfaceFrameTX != nullptr &&
                mDrawingState.bufferSurfaceFrameTX->getPresentState() != PresentState::Presented) {
              addSurfaceFrameDroppedForBuffer(mDrawingState.bufferSurfaceFrameTX);
              mDrawingState.bufferSurfaceFrameTX.reset();
            }
        } else if (EARLY_RELEASE_ENABLED && mLastClientCompositionFence != nullptr) {
            callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                      mDrawingState.buffer->getBuffer(), mDrawingState.frameNumber,
                                      mLastClientCompositionFence,
                                      mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(
                                              mOwnerUid));
            mLastClientCompositionFence = nullptr;
        }
    }

    mDrawingState.frameNumber = frameNumber;
    mDrawingState.releaseBufferListener = bufferData.releaseBufferListener;
    mDrawingState.buffer = std::move(buffer);
    mDrawingState.clientCacheId = bufferData.cachedBuffer;

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

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->setPostTime(layerId, mDrawingState.frameNumber, getName().c_str(),
                                      mOwnerUid, postTime, getGameMode());
    mDrawingState.desiredPresentTime = desiredPresentTime;
    mDrawingState.isAutoTimestamp = isAutoTimestamp;

    const nsecs_t presentTime = [&] {
        if (!isAutoTimestamp) return desiredPresentTime;

        const auto prediction =
                mFlinger->mFrameTimeline->getTokenManager()->getPredictionsForToken(info.vsyncId);
        if (prediction.has_value()) return prediction->presentTime;

        return static_cast<nsecs_t>(0);
    }();

    using LayerUpdateType = scheduler::LayerHistory::LayerUpdateType;
    mFlinger->mScheduler->recordLayerHistory(this, presentTime, LayerUpdateType::Buffer);

    setFrameTimelineVsyncForBufferTransaction(info, postTime);

    if (dequeueTime && *dequeueTime != 0) {
        const uint64_t bufferId = mDrawingState.buffer->getId();
        mFlinger->mFrameTracer->traceNewLayer(layerId, getName().c_str());
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, *dequeueTime,
                                               FrameTracer::FrameEvent::DEQUEUE);
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, postTime,
                                               FrameTracer::FrameEvent::QUEUE);
    }

    mDrawingState.width = mDrawingState.buffer->getWidth();
    mDrawingState.height = mDrawingState.buffer->getHeight();
    mDrawingState.releaseBufferEndpoint = bufferData.releaseBufferEndpoint;
    return true;
}

bool BufferStateLayer::setDataspace(ui::Dataspace dataspace) {
    if (mDrawingState.dataspace == dataspace) return false;
    mDrawingState.dataspace = dataspace;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setHdrMetadata(const HdrMetadata& hdrMetadata) {
    if (mDrawingState.hdrMetadata == hdrMetadata) return false;
    mDrawingState.hdrMetadata = hdrMetadata;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSurfaceDamageRegion(const Region& surfaceDamage) {
    mDrawingState.surfaceDamageRegion = surfaceDamage;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setApi(int32_t api) {
    if (mDrawingState.api == api) return false;
    mDrawingState.api = api;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSidebandStream(const sp<NativeHandle>& sidebandStream) {
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
            handle->acquireTimeOrFence = mCallbackHandleAcquireTimeOrFence;
            handle->frameNumber = mDrawingState.frameNumber;

            // Store so latched time and release fence can be set
            mDrawingState.callbackHandles.push_back(handle);

        } else { // If this layer will NOT need to be relatched and presented this frame
            // Notify the transaction completed thread this handle is done
            mFlinger->getTransactionCallbackInvoker().registerUnpresentedCallbackHandle(handle);
        }
    }

    mReleasePreviousBuffer = false;
    mCallbackHandleAcquireTimeOrFence = -1;

    return willPresent;
}

bool BufferStateLayer::setTransparentRegionHint(const Region& transparent) {
    mDrawingState.sequence++;
    mDrawingState.transparentRegionHint = transparent;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

Rect BufferStateLayer::getBufferSize(const State& /*s*/) const {
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
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufWidth, bufHeight);
        }
    }

    return Rect(0, 0, static_cast<int32_t>(bufWidth), static_cast<int32_t>(bufHeight));
}

FloatRect BufferStateLayer::computeSourceBounds(const FloatRect& parentBounds) const {
    if (mBufferInfo.mBuffer == nullptr) {
        return parentBounds;
    }

    return getBufferSize(getDrawingState()).toFloatRect();
}

// -----------------------------------------------------------------------
bool BufferStateLayer::fenceHasSignaled() const {
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

bool BufferStateLayer::onPreComposition(nsecs_t refreshStartTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->refreshStartTime = refreshStartTime;
    }
    return hasReadyFrame();
}

void BufferStateLayer::setAutoRefresh(bool autoRefresh) {
    mDrawingState.autoRefresh = autoRefresh;
}

bool BufferStateLayer::latchSidebandStream(bool& recomputeVisibleRegions) {
    // We need to update the sideband stream if the layer has both a buffer and a sideband stream.
    editCompositionState()->sidebandStreamHasFrame = hasFrameUpdate() && mSidebandStream.get();

    if (mSidebandStreamChanged.exchange(false)) {
        const State& s(getDrawingState());
        // mSidebandStreamChanged was true
        mSidebandStream = s.sidebandStream;
        editCompositionState()->sidebandStream = mSidebandStream;
        if (mSidebandStream != nullptr) {
            setTransactionFlags(eTransactionNeeded);
            mFlinger->setTransactionFlags(eTraversalNeeded);
        }
        recomputeVisibleRegions = true;

        return true;
    }
    return false;
}

bool BufferStateLayer::hasFrameUpdate() const {
    const State& c(getDrawingState());
    return (mDrawingStateModified || mDrawingState.modified) && (c.buffer != nullptr || c.bgColorLayer != nullptr);
}

void BufferStateLayer::updateTexImage(nsecs_t latchTime) {
    const State& s(getDrawingState());

    if (!s.buffer) {
        if (s.bgColorLayer) {
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

void BufferStateLayer::gatherBufferInfo() {
    if (!mBufferInfo.mBuffer || !mDrawingState.buffer->hasSameBuffer(*mBufferInfo.mBuffer)) {
        decrementPendingBufferCount();
    }

    mPreviousReleaseCallbackId = {getCurrentBufferId(), mBufferInfo.mFrameNumber};
    mBufferInfo.mBuffer = mDrawingState.buffer;
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
    if (lastDataspace != mBufferInfo.mDataspace) {
        mFlinger->mSomeDataspaceChanged = true;
    }
    mBufferInfo.mCrop = computeBufferCrop(mDrawingState);
    mBufferInfo.mScaleMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
    mBufferInfo.mSurfaceDamage = mDrawingState.surfaceDamageRegion;
    mBufferInfo.mHdrMetadata = mDrawingState.hdrMetadata;
    mBufferInfo.mApi = mDrawingState.api;
    mBufferInfo.mTransformToDisplayInverse = mDrawingState.transformToDisplayInverse;
    mBufferInfo.mBufferSlot = mHwcSlotGenerator->getHwcCacheSlot(mDrawingState.clientCacheId);
}

Rect BufferStateLayer::computeBufferCrop(const State& s) {
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

sp<Layer> BufferStateLayer::createClone() {
    LayerCreationArgs args(mFlinger.get(), nullptr, mName + " (Mirror)", 0, LayerMetadata());
    args.textureName = mTextureName;
    sp<BufferStateLayer> layer = mFlinger->getFactory().createBufferStateLayer(args);
    layer->mHwcSlotGenerator = mHwcSlotGenerator;
    layer->setInitialValuesForClone(this);
    return layer;
}

bool BufferStateLayer::bufferNeedsFiltering() const {
    const State& s(getDrawingState());
    if (!s.buffer) {
        return false;
    }

    int32_t bufferWidth = static_cast<int32_t>(s.buffer->getWidth());
    int32_t bufferHeight = static_cast<int32_t>(s.buffer->getHeight());

    // Undo any transformations on the buffer and return the result.
    if (s.bufferTransform & ui::Transform::ROT_90) {
        std::swap(bufferWidth, bufferHeight);
    }

    if (s.transformToDisplayInverse) {
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufferWidth, bufferHeight);
        }
    }

    const Rect layerSize{getBounds()};
    int32_t layerWidth = layerSize.getWidth();
    int32_t layerHeight = layerSize.getHeight();

    // Align the layer orientation with the buffer before comparism
    if (mTransformHint & ui::Transform::ROT_90) {
        std::swap(layerWidth, layerHeight);
    }

    return layerWidth != bufferWidth || layerHeight != bufferHeight;
}

void BufferStateLayer::decrementPendingBufferCount() {
    int32_t pendingBuffers = --mPendingBufferTransactions;
    tracePendingBufferCount(pendingBuffers);
}

void BufferStateLayer::tracePendingBufferCount(int32_t pendingBuffers) {
    ATRACE_INT(mBlastTransactionName.c_str(), pendingBuffers);
}


/*
 * We don't want to send the layer's transform to input, but rather the
 * parent's transform. This is because BufferStateLayer's transform is
 * information about how the buffer is placed on screen. The parent's
 * transform makes more sense to send since it's information about how the
 * layer is placed on screen. This transform is used by input to determine
 * how to go from screen space back to window space.
 */
ui::Transform BufferStateLayer::getInputTransform() const {
    sp<Layer> parent = mDrawingParent.promote();
    if (parent == nullptr) {
        return ui::Transform();
    }

    return parent->getTransform();
}

/**
 * Similar to getInputTransform, we need to update the bounds to include the transform.
 * This is because bounds for BSL doesn't include buffer transform, where the input assumes
 * that's already included.
 */
Rect BufferStateLayer::getInputBounds() const {
    Rect bufferBounds = getCroppedBufferSize(getDrawingState());
    if (mDrawingState.transform.getType() == ui::Transform::IDENTITY || !bufferBounds.isValid()) {
        return bufferBounds;
    }
    return mDrawingState.transform.transform(bufferBounds);
}

bool BufferStateLayer::simpleBufferUpdate(const layer_state_t& s) const {
    const uint64_t requiredFlags = layer_state_t::eBufferChanged;

    const uint64_t deniedFlags = layer_state_t::eProducerDisconnect | layer_state_t::eLayerChanged |
            layer_state_t::eRelativeLayerChanged | layer_state_t::eTransparentRegionChanged |
            layer_state_t::eFlagsChanged | layer_state_t::eBlurRegionsChanged |
            layer_state_t::eLayerStackChanged | layer_state_t::eAutoRefreshChanged |
            layer_state_t::eReparent;

    const uint64_t allowedFlags = layer_state_t::eHasListenerCallbacksChanged |
            layer_state_t::eFrameRateSelectionPriority | layer_state_t::eFrameRateChanged |
            layer_state_t::eSurfaceDamageRegionChanged | layer_state_t::eApiChanged |
            layer_state_t::eMetadataChanged | layer_state_t::eDropInputModeChanged |
            layer_state_t::eInputInfoChanged;

    if ((s.what & requiredFlags) != requiredFlags) {
        ALOGV("%s: false [missing required flags 0x%" PRIx64 "]", __func__,
              (s.what | requiredFlags) & ~s.what);
        return false;
    }

    if (s.what & deniedFlags) {
        ALOGV("%s: false [has denied flags 0x%" PRIx64 "]", __func__, s.what & deniedFlags);
        return false;
    }

    if (s.what & allowedFlags) {
        ALOGV("%s: [has allowed flags 0x%" PRIx64 "]", __func__, s.what & allowedFlags);
    }

    if (s.what & layer_state_t::ePositionChanged) {
        if (mRequestedTransform.tx() != s.x || mRequestedTransform.ty() != s.y) {
            ALOGV("%s: false [ePositionChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eAlphaChanged) {
        if (mDrawingState.color.a != s.alpha) {
            ALOGV("%s: false [eAlphaChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eColorTransformChanged) {
        if (mDrawingState.colorTransform != s.colorTransform) {
            ALOGV("%s: false [eColorTransformChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eBackgroundColorChanged) {
        if (mDrawingState.bgColorLayer || s.bgColorAlpha != 0) {
            ALOGV("%s: false [eBackgroundColorChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eMatrixChanged) {
        if (mRequestedTransform.dsdx() != s.matrix.dsdx ||
            mRequestedTransform.dtdy() != s.matrix.dtdy ||
            mRequestedTransform.dtdx() != s.matrix.dtdx ||
            mRequestedTransform.dsdy() != s.matrix.dsdy) {
            ALOGV("%s: false [eMatrixChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eCornerRadiusChanged) {
        if (mDrawingState.cornerRadius != s.cornerRadius) {
            ALOGV("%s: false [eCornerRadiusChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eBackgroundBlurRadiusChanged) {
        if (mDrawingState.backgroundBlurRadius != static_cast<int>(s.backgroundBlurRadius)) {
            ALOGV("%s: false [eBackgroundBlurRadiusChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eTransformChanged) {
        if (mDrawingState.bufferTransform != s.transform) {
            ALOGV("%s: false [eTransformChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eTransformToDisplayInverseChanged) {
        if (mDrawingState.transformToDisplayInverse != s.transformToDisplayInverse) {
            ALOGV("%s: false [eTransformToDisplayInverseChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eCropChanged) {
        if (mDrawingState.crop != s.crop) {
            ALOGV("%s: false [eCropChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eDataspaceChanged) {
        if (mDrawingState.dataspace != s.dataspace) {
            ALOGV("%s: false [eDataspaceChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eHdrMetadataChanged) {
        if (mDrawingState.hdrMetadata != s.hdrMetadata) {
            ALOGV("%s: false [eHdrMetadataChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eSidebandStreamChanged) {
        if (mDrawingState.sidebandStream != s.sidebandStream) {
            ALOGV("%s: false [eSidebandStreamChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eColorSpaceAgnosticChanged) {
        if (mDrawingState.colorSpaceAgnostic != s.colorSpaceAgnostic) {
            ALOGV("%s: false [eColorSpaceAgnosticChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eShadowRadiusChanged) {
        if (mDrawingState.shadowRadius != s.shadowRadius) {
            ALOGV("%s: false [eShadowRadiusChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eFixedTransformHintChanged) {
        if (mDrawingState.fixedTransformHint != s.fixedTransformHint) {
            ALOGV("%s: false [eFixedTransformHintChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eTrustedOverlayChanged) {
        if (mDrawingState.isTrustedOverlay != s.isTrustedOverlay) {
            ALOGV("%s: false [eTrustedOverlayChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eStretchChanged) {
        StretchEffect temp = s.stretchEffect;
        temp.sanitize();
        if (mDrawingState.stretchEffect != temp) {
            ALOGV("%s: false [eStretchChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eBufferCropChanged) {
        if (mDrawingState.bufferCrop != s.bufferCrop) {
            ALOGV("%s: false [eBufferCropChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eDestinationFrameChanged) {
        if (mDrawingState.destinationFrame != s.destinationFrame) {
            ALOGV("%s: false [eDestinationFrameChanged changed]", __func__);
            return false;
        }
    }

    if (s.what & layer_state_t::eDimmingEnabledChanged) {
        if (mDrawingState.dimmingEnabled != s.dimmingEnabled) {
            ALOGV("%s: false [eDimmingEnabledChanged changed]", __func__);
            return false;
        }
    }

    ALOGV("%s: true", __func__);
    return true;
}

void BufferStateLayer::useSurfaceDamage() {
    if (mFlinger->mForceFullDamage) {
        surfaceDamageRegion = Region::INVALID_REGION;
    } else {
        surfaceDamageRegion = mBufferInfo.mSurfaceDamage;
    }
}

void BufferStateLayer::useEmptyDamage() {
    surfaceDamageRegion.clear();
}

bool BufferStateLayer::isOpaque(const Layer::State& s) const {
    // if we don't have a buffer or sidebandStream yet, we're translucent regardless of the
    // layer's opaque flag.
    if ((mSidebandStream == nullptr) && (mBufferInfo.mBuffer == nullptr)) {
        return false;
    }

    // if the layer has the opaque flag, then we're always opaque,
    // otherwise we use the current buffer's format.
    return ((s.flags & layer_state_t::eLayerOpaque) != 0) || getOpacityForFormat(getPixelFormat());
}

bool BufferStateLayer::canReceiveInput() const {
    return !isHiddenByPolicy() && (mBufferInfo.mBuffer == nullptr || getAlpha() > 0.0f);
}

bool BufferStateLayer::isVisible() const {
    return !isHiddenByPolicy() && getAlpha() > 0.0f &&
            (mBufferInfo.mBuffer != nullptr || mSidebandStream != nullptr);
}

std::optional<compositionengine::LayerFE::LayerSettings> BufferStateLayer::prepareClientComposition(
        compositionengine::LayerFE::ClientCompositionTargetSettings& targetSettings) {
    ATRACE_CALL();

    std::optional<compositionengine::LayerFE::LayerSettings> result =
            Layer::prepareClientComposition(targetSettings);
    if (!result) {
        return result;
    }

    if (CC_UNLIKELY(mBufferInfo.mBuffer == 0) && mSidebandStream != nullptr) {
        // For surfaceview of tv sideband, there is no activeBuffer
        // in bufferqueue, we need return LayerSettings.
        return result;
    }
    const bool blackOutLayer = (isProtected() && !targetSettings.supportsProtectedContent) ||
            ((isSecure() || isProtected()) && !targetSettings.isSecure);
    const bool bufferCanBeUsedAsHwTexture =
            mBufferInfo.mBuffer->getUsage() & GraphicBuffer::USAGE_HW_TEXTURE;
    compositionengine::LayerFE::LayerSettings& layer = *result;
    if (blackOutLayer || !bufferCanBeUsedAsHwTexture) {
        ALOGE_IF(!bufferCanBeUsedAsHwTexture, "%s is blacked out as buffer is not gpu readable",
                 mName.c_str());
        prepareClearClientComposition(layer, true /* blackout */);
        return layer;
    }

    const State& s(getDrawingState());
    layer.source.buffer.buffer = mBufferInfo.mBuffer;
    layer.source.buffer.isOpaque = isOpaque(s);
    layer.source.buffer.fence = mBufferInfo.mFence;
    layer.source.buffer.textureName = mTextureName;
    layer.source.buffer.usePremultipliedAlpha = getPremultipledAlpha();
    layer.source.buffer.isY410BT2020 = isHdrY410();
    bool hasSmpte2086 = mBufferInfo.mHdrMetadata.validTypes & HdrMetadata::SMPTE2086;
    bool hasCta861_3 = mBufferInfo.mHdrMetadata.validTypes & HdrMetadata::CTA861_3;
    float maxLuminance = 0.f;
    if (hasSmpte2086 && hasCta861_3) {
        maxLuminance = std::min(mBufferInfo.mHdrMetadata.smpte2086.maxLuminance,
                                mBufferInfo.mHdrMetadata.cta8613.maxContentLightLevel);
    } else if (hasSmpte2086) {
        maxLuminance = mBufferInfo.mHdrMetadata.smpte2086.maxLuminance;
    } else if (hasCta861_3) {
        maxLuminance = mBufferInfo.mHdrMetadata.cta8613.maxContentLightLevel;
    } else {
        switch (layer.sourceDataspace & HAL_DATASPACE_TRANSFER_MASK) {
            case HAL_DATASPACE_TRANSFER_ST2084:
            case HAL_DATASPACE_TRANSFER_HLG:
                // Behavior-match previous releases for HDR content
                maxLuminance = defaultMaxLuminance;
                break;
        }
    }
    layer.source.buffer.maxLuminanceNits = maxLuminance;
    layer.frameNumber = mCurrentFrameNumber;
    layer.bufferId = mBufferInfo.mBuffer ? mBufferInfo.mBuffer->getId() : 0;

    const bool useFiltering =
            targetSettings.needsFiltering || mNeedsFiltering || bufferNeedsFiltering();

    // Query the texture matrix given our current filtering mode.
    float textureMatrix[16];
    getDrawingTransformMatrix(useFiltering, textureMatrix);

    if (getTransformToDisplayInverse()) {
        /*
         * the code below applies the primary display's inverse transform to
         * the texture transform
         */
        uint32_t transform = DisplayDevice::getPrimaryDisplayRotationFlags();
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

    const Rect win{getBounds()};
    float bufferWidth = getBufferSize(s).getWidth();
    float bufferHeight = getBufferSize(s).getHeight();

    // BufferStateLayers can have a "buffer size" of [0, 0, -1, -1] when no display frame has
    // been set and there is no parent layer bounds. In that case, the scale is meaningless so
    // ignore them.
    if (!getBufferSize(s).isValid()) {
        bufferWidth = float(win.right) - float(win.left);
        bufferHeight = float(win.bottom) - float(win.top);
    }

    const float scaleHeight = (float(win.bottom) - float(win.top)) / bufferHeight;
    const float scaleWidth = (float(win.right) - float(win.left)) / bufferWidth;
    const float translateY = float(win.top) / bufferHeight;
    const float translateX = float(win.left) / bufferWidth;

    // Flip y-coordinates because GLConsumer expects OpenGL convention.
    mat4 tr = mat4::translate(vec4(.5f, .5f, 0.f, 1.f)) * mat4::scale(vec4(1.f, -1.f, 1.f, 1.f)) *
            mat4::translate(vec4(-.5f, -.5f, 0.f, 1.f)) *
            mat4::translate(vec4(translateX, translateY, 0.f, 1.f)) *
            mat4::scale(vec4(scaleWidth, scaleHeight, 1.0f, 1.0f));

    layer.source.buffer.useTextureFiltering = useFiltering;
    layer.source.buffer.textureTransform = mat4(static_cast<const float*>(textureMatrix)) * tr;

    return layer;
}

bool BufferStateLayer::isHdrY410() const {
    // pixel format is HDR Y410 masquerading as RGBA_1010102
    return (mBufferInfo.mDataspace == ui::Dataspace::BT2020_ITU_PQ &&
            mBufferInfo.mApi == NATIVE_WINDOW_API_MEDIA &&
            mBufferInfo.mPixelFormat == HAL_PIXEL_FORMAT_RGBA_1010102);
}

sp<compositionengine::LayerFE> BufferStateLayer::getCompositionEngineLayerFE() const {
    return asLayerFE();
}

compositionengine::LayerFECompositionState* BufferStateLayer::editCompositionState() {
    return mCompositionState.get();
}

const compositionengine::LayerFECompositionState* BufferStateLayer::getCompositionState() const {
    return mCompositionState.get();
}

void BufferStateLayer::preparePerFrameCompositionState() {
    Layer::preparePerFrameCompositionState();

    // Sideband layers
    auto* compositionState = editCompositionState();
    if (compositionState->sidebandStream.get() && !compositionState->sidebandStreamHasFrame) {
        compositionState->compositionType =
                aidl::android::hardware::graphics::composer3::Composition::SIDEBAND;
        return;
    } else if ((mDrawingState.flags & layer_state_t::eLayerIsDisplayDecoration) != 0) {
        compositionState->compositionType =
                aidl::android::hardware::graphics::composer3::Composition::DISPLAY_DECORATION;
    } else {
        // Normal buffer layers
        compositionState->hdrMetadata = mBufferInfo.mHdrMetadata;
        compositionState->compositionType = mPotentialCursor
                ? aidl::android::hardware::graphics::composer3::Composition::CURSOR
                : aidl::android::hardware::graphics::composer3::Composition::DEVICE;
    }

    compositionState->buffer = getBuffer();
    compositionState->bufferSlot = (mBufferInfo.mBufferSlot == BufferQueue::INVALID_BUFFER_SLOT)
            ? 0
            : mBufferInfo.mBufferSlot;
    compositionState->acquireFence = mBufferInfo.mFence;
    compositionState->frameNumber = mBufferInfo.mFrameNumber;
    compositionState->sidebandStreamHasFrame = false;
}

void BufferStateLayer::onPostComposition(const DisplayDevice* display,
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
        const Fps refreshRate = display->refreshRateConfigs().getActiveMode()->getFps();
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
            // The HWC doesn't support present fences, so use the refresh
            // timestamp instead.
            const nsecs_t actualPresentTime = display->getRefreshTimestamp();
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

bool BufferStateLayer::latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime) {
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

    updateTexImage(latchTime);
    if (mDrawingState.buffer == nullptr) {
        return false;
    }

    // Capture the old state of the layer for comparisons later
    BufferInfo oldBufferInfo = mBufferInfo;
    const bool oldOpacity = isOpaque(mDrawingState);
    mPreviousFrameNumber = mCurrentFrameNumber;
    mCurrentFrameNumber = mDrawingState.frameNumber;
    gatherBufferInfo();

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

bool BufferStateLayer::hasReadyFrame() const {
    return hasFrameUpdate() || getSidebandStreamChanged() || getAutoRefresh();
}

bool BufferStateLayer::isProtected() const {
    return (mBufferInfo.mBuffer != nullptr) &&
            (mBufferInfo.mBuffer->getUsage() & GRALLOC_USAGE_PROTECTED);
}

// As documented in libhardware header, formats in the range
// 0x100 - 0x1FF are specific to the HAL implementation, and
// are known to have no alpha channel
// TODO: move definition for device-specific range into
// hardware.h, instead of using hard-coded values here.
#define HARDWARE_IS_DEVICE_FORMAT(f) ((f) >= 0x100 && (f) <= 0x1FF)

bool BufferStateLayer::getOpacityForFormat(PixelFormat format) {
    if (HARDWARE_IS_DEVICE_FORMAT(format)) {
        return true;
    }
    switch (format) {
        case PIXEL_FORMAT_RGBA_8888:
        case PIXEL_FORMAT_BGRA_8888:
        case PIXEL_FORMAT_RGBA_FP16:
        case PIXEL_FORMAT_RGBA_1010102:
        case PIXEL_FORMAT_R_8:
            return false;
    }
    // in all other case, we have no blending (also for unknown formats)
    return true;
}

bool BufferStateLayer::needsFiltering(const DisplayDevice* display) const {
    const auto outputLayer = findOutputLayerForDisplay(display);
    if (outputLayer == nullptr) {
        return false;
    }

    // We need filtering if the sourceCrop rectangle size does not match the
    // displayframe rectangle size (not a 1:1 render)
    const auto& compositionState = outputLayer->getState();
    const auto displayFrame = compositionState.displayFrame;
    const auto sourceCrop = compositionState.sourceCrop;
    return sourceCrop.getHeight() != displayFrame.getHeight() ||
            sourceCrop.getWidth() != displayFrame.getWidth();
}

bool BufferStateLayer::needsFilteringForScreenshots(
        const DisplayDevice* display, const ui::Transform& inverseParentTransform) const {
    const auto outputLayer = findOutputLayerForDisplay(display);
    if (outputLayer == nullptr) {
        return false;
    }

    // We need filtering if the sourceCrop rectangle size does not match the
    // viewport rectangle size (not a 1:1 render)
    const auto& compositionState = outputLayer->getState();
    const ui::Transform& displayTransform = display->getTransform();
    const ui::Transform inverseTransform = inverseParentTransform * displayTransform.inverse();
    // Undo the transformation of the displayFrame so that we're back into
    // layer-stack space.
    const Rect frame = inverseTransform.transform(compositionState.displayFrame);
    const FloatRect sourceCrop = compositionState.sourceCrop;

    int32_t frameHeight = frame.getHeight();
    int32_t frameWidth = frame.getWidth();
    // If the display transform had a rotational component then undo the
    // rotation so that the orientation matches the source crop.
    if (displayTransform.getOrientation() & ui::Transform::ROT_90) {
        std::swap(frameHeight, frameWidth);
    }
    return sourceCrop.getHeight() != frameHeight || sourceCrop.getWidth() != frameWidth;
}

void BufferStateLayer::latchAndReleaseBuffer() {
    if (hasReadyFrame()) {
        bool ignored = false;
        latchBuffer(ignored, systemTime());
    }
    releasePendingBuffer(systemTime());
}

PixelFormat BufferStateLayer::getPixelFormat() const {
    return mBufferInfo.mPixelFormat;
}

bool BufferStateLayer::getTransformToDisplayInverse() const {
    return mBufferInfo.mTransformToDisplayInverse;
}

Rect BufferStateLayer::getBufferCrop() const {
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

uint32_t BufferStateLayer::getBufferTransform() const {
    return mBufferInfo.mTransform;
}

ui::Dataspace BufferStateLayer::getDataSpace() const {
    return mBufferInfo.mDataspace;
}

ui::Dataspace BufferStateLayer::translateDataspace(ui::Dataspace dataspace) {
    ui::Dataspace updatedDataspace = dataspace;
    // translate legacy dataspaces to modern dataspaces
    switch (dataspace) {
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

sp<GraphicBuffer> BufferStateLayer::getBuffer() const {
    return mBufferInfo.mBuffer ? mBufferInfo.mBuffer->getBuffer() : nullptr;
}

void BufferStateLayer::getDrawingTransformMatrix(bool filteringEnabled, float outMatrix[16]) {
    sp<GraphicBuffer> buffer = getBuffer();
    if (!buffer) {
        ALOGE("Buffer should not be null!");
        return;
    }
    GLConsumer::computeTransformMatrix(outMatrix, buffer->getWidth(), buffer->getHeight(),
                                       buffer->getPixelFormat(), mBufferInfo.mCrop,
                                       mBufferInfo.mTransform, filteringEnabled);
}

void BufferStateLayer::setInitialValuesForClone(const sp<Layer>& clonedFrom) {
    Layer::setInitialValuesForClone(clonedFrom);

    sp<BufferStateLayer> bufferClonedFrom = static_cast<BufferStateLayer*>(clonedFrom.get());
    mPremultipliedAlpha = bufferClonedFrom->mPremultipliedAlpha;
    mPotentialCursor = bufferClonedFrom->mPotentialCursor;
    mProtectedByApp = bufferClonedFrom->mProtectedByApp;

    updateCloneBufferInfo();
}

void BufferStateLayer::updateCloneBufferInfo() {
    if (!isClone() || !isClonedFromAlive()) {
        return;
    }

    sp<BufferStateLayer> clonedFrom = static_cast<BufferStateLayer*>(getClonedFrom().get());
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

void BufferStateLayer::setTransformHint(ui::Transform::RotationFlags displayTransformHint) {
    mTransformHint = getFixedTransformHint();
    if (mTransformHint == ui::Transform::ROT_INVALID) {
        mTransformHint = displayTransformHint;
    }
}

const std::shared_ptr<renderengine::ExternalTexture>& BufferStateLayer::getExternalTexture() const {
    return mBufferInfo.mBuffer;
}

} // namespace android
