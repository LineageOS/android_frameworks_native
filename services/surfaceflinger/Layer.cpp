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

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <binder/IPCThreadState.h>
#include <common/trace.h>
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
#include <gui/Surface.h>
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

#include <algorithm>
#include <optional>

#include "DisplayDevice.h"
#include "DisplayHardware/HWComposer.h"
#include "FrameTimeline.h"
#include "FrameTracer/FrameTracer.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/LayerHandle.h"
#include "Layer.h"
#include "LayerProtoHelper.h"
#include "SurfaceFlinger.h"
#include "TimeStats/TimeStats.h"
#include "TransactionCallbackInvoker.h"
#include "TunnelModeEnabledReporter.h"
#include "Utils/FenceUtils.h"

#define DEBUG_RESIZE 0
#define EARLY_RELEASE_ENABLED false

namespace android {
using namespace std::chrono_literals;
namespace {
constexpr int kDumpTableRowLength = 159;

const ui::Transform kIdentityTransform;

TimeStats::SetFrameRateVote frameRateToSetFrameRateVotePayload(Layer::FrameRate frameRate) {
    using FrameRateCompatibility = TimeStats::SetFrameRateVote::FrameRateCompatibility;
    using Seamlessness = TimeStats::SetFrameRateVote::Seamlessness;
    const auto frameRateCompatibility = [frameRate] {
        switch (frameRate.vote.type) {
            case Layer::FrameRateCompatibility::Default:
                return FrameRateCompatibility::Default;
            case Layer::FrameRateCompatibility::ExactOrMultiple:
                return FrameRateCompatibility::ExactOrMultiple;
            default:
                return FrameRateCompatibility::Undefined;
        }
    }();

    const auto seamlessness = [frameRate] {
        switch (frameRate.vote.seamlessness) {
            case scheduler::Seamlessness::OnlySeamless:
                return Seamlessness::ShouldBeSeamless;
            case scheduler::Seamlessness::SeamedAndSeamless:
                return Seamlessness::NotRequired;
            default:
                return Seamlessness::Undefined;
        }
    }();

    return TimeStats::SetFrameRateVote{.frameRate = frameRate.vote.rate.getValue(),
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
using ui::Size;

using PresentState = frametimeline::SurfaceFrame::PresentState;

Layer::Layer(const surfaceflinger::LayerCreationArgs& args)
      : sequence(args.sequence),
        mFlinger(sp<SurfaceFlinger>::fromExisting(args.flinger)),
        mName(base::StringPrintf("%s#%d", args.name.c_str(), sequence)),
        mWindowType(static_cast<WindowInfo::Type>(
                args.metadata.getInt32(gui::METADATA_WINDOW_TYPE, 0))) {
    ALOGV("Creating Layer %s", getDebugName());

    mDrawingState.crop = {0, 0, -1, -1};
    mDrawingState.sequence = 0;
    mDrawingState.transform.set(0, 0);
    mDrawingState.frameNumber = 0;
    mDrawingState.previousFrameNumber = 0;
    mDrawingState.barrierFrameNumber = 0;
    mDrawingState.producerId = 0;
    mDrawingState.barrierProducerId = 0;
    mDrawingState.bufferTransform = 0;
    mDrawingState.transformToDisplayInverse = false;
    mDrawingState.acquireFence = sp<Fence>::make(-1);
    mDrawingState.acquireFenceTime = std::make_shared<FenceTime>(mDrawingState.acquireFence);
    mDrawingState.dataspace = ui::Dataspace::V0_SRGB;
    mDrawingState.metadata = args.metadata;
    mDrawingState.frameTimelineInfo = {};
    mDrawingState.postTime = -1;
    mDeprecatedFrameTracker.setDisplayRefreshPeriod(
            args.flinger->mScheduler->getPacesetterVsyncPeriod().ns());

    mOwnerUid = args.ownerUid;
    mOwnerPid = args.ownerPid;
    mOwnerAppId = mOwnerUid % PER_USER_RANGE;

    mPotentialCursor = args.flags & ISurfaceComposerClient::eCursorWindow;
    mLayerFEs.emplace_back(frontend::LayerHierarchy::TraversalPath{static_cast<uint32_t>(sequence)},
                           args.flinger->getFactory().createLayerFE(mName, this));
}

void Layer::onFirstRef() {
    mFlinger->onLayerFirstRef(this);
}

Layer::~Layer() {
    LOG_ALWAYS_FATAL_IF(std::this_thread::get_id() != mFlinger->mMainThreadId,
                        "Layer destructor called off the main thread.");

    if (mBufferInfo.mBuffer != nullptr) {
        callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                  mBufferInfo.mBuffer->getBuffer(), mBufferInfo.mFrameNumber,
                                  mBufferInfo.mFence);
    }
    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->onDestroy(layerId);
    mFlinger->mFrameTracer->onDestroy(layerId);

    mFlinger->onLayerDestroyed(this);

    const auto currentTime = std::chrono::steady_clock::now();
    if (mBufferInfo.mTimeSinceDataspaceUpdate > std::chrono::steady_clock::time_point::min()) {
        mFlinger->mLayerEvents.emplace_back(mOwnerUid, getSequence(), mBufferInfo.mDataspace,
                                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                                    currentTime -
                                                    mBufferInfo.mTimeSinceDataspaceUpdate));
    }

    if (mDrawingState.sidebandStream != nullptr) {
        mFlinger->mTunnelModeEnabledReporter->decrementTunnelModeCount();
    }
    if (hasTrustedPresentationListener()) {
        mFlinger->mNumTrustedPresentationListeners--;
        updateTrustedPresentationState(nullptr, nullptr, -1 /* time_in_ms */, true /* leaveState*/);
    }
}

// ---------------------------------------------------------------------------
// set-up
// ---------------------------------------------------------------------------
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
        const auto outputLayer = findOutputLayerForDisplay(display, snapshot->path);
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

Rect Layer::getCroppedBufferSize(const State& s) const {
    Rect size = getBufferSize(s);
    Rect crop = Rect(getCrop(s));
    if (!crop.isEmpty() && size.isValid()) {
        size.intersect(crop, &size);
    } else if (!crop.isEmpty()) {
        size = crop;
    }
    return size;
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
    return getCompositionType(outputLayer);
}

aidl::android::hardware::graphics::composer3::Composition Layer::getCompositionType(
        const compositionengine::OutputLayer* outputLayer) const {
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
// transaction
// ----------------------------------------------------------------------------

void Layer::commitTransaction() {
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

void Layer::setTransactionFlags(uint32_t mask) {
    mTransactionFlags |= mask;
}

bool Layer::setCrop(const FloatRect& crop) {
    if (mDrawingState.crop == crop) return false;
    mDrawingState.sequence++;
    mDrawingState.crop = crop;

    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::isLayerFocusedBasedOnPriority(int32_t priority) {
    return priority == PRIORITY_FOCUSED_WITH_MODE || priority == PRIORITY_FOCUSED_WITHOUT_MODE;
};

void Layer::setFrameTimelineVsyncForBufferTransaction(const FrameTimelineInfo& info,
                                                      nsecs_t postTime, gui::GameMode gameMode) {
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
                createSurfaceFrameForBuffer(info, postTime, mTransactionName, gameMode);
    }

    setFrameTimelineVsyncForSkippedFrames(info, postTime, mTransactionName, gameMode);
}

void Layer::setFrameTimelineVsyncForBufferlessTransaction(const FrameTimelineInfo& info,
                                                          nsecs_t postTime,
                                                          gui::GameMode gameMode) {
    mDrawingState.frameTimelineInfo = info;
    mDrawingState.postTime = postTime;
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
        auto surfaceFrame = createSurfaceFrameForTransaction(info, postTime, gameMode);
        mDrawingState.bufferlessSurfaceFramesTX[info.vsyncId] = surfaceFrame;
    } else {
        if (it->second->getPresentState() == PresentState::Presented) {
            // If the SurfaceFrame was already presented, its safe to overwrite it since it must
            // have been from previous vsync.
            it->second = createSurfaceFrameForTransaction(info, postTime, gameMode);
        }
    }

    setFrameTimelineVsyncForSkippedFrames(info, postTime, mTransactionName, gameMode);
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
        const FrameTimelineInfo& info, nsecs_t postTime, gui::GameMode gameMode) {
    auto surfaceFrame =
            mFlinger->mFrameTimeline->createSurfaceFrameForToken(info, mOwnerPid, mOwnerUid,
                                                                 getSequence(), mName,
                                                                 mTransactionName,
                                                                 /*isBuffer*/ false, gameMode);
    // Buffer hasn't yet been latched, so use mDrawingState
    surfaceFrame->setDesiredPresentTime(mDrawingState.desiredPresentTime);

    surfaceFrame->setActualStartTime(info.startTimeNanos);
    // For Transactions, the post time is considered to be both queue and acquire fence time.
    surfaceFrame->setActualQueueTime(postTime);
    surfaceFrame->setAcquireFenceTime(postTime);
    const auto fps = mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());
    if (fps) {
        surfaceFrame->setRenderRate(*fps);
    }
    return surfaceFrame;
}

std::shared_ptr<frametimeline::SurfaceFrame> Layer::createSurfaceFrameForBuffer(
        const FrameTimelineInfo& info, nsecs_t queueTime, std::string debugName,
        gui::GameMode gameMode) {
    auto surfaceFrame =
            mFlinger->mFrameTimeline->createSurfaceFrameForToken(info, mOwnerPid, mOwnerUid,
                                                                 getSequence(), mName, debugName,
                                                                 /*isBuffer*/ true, gameMode);
    // Buffer hasn't yet been latched, so use mDrawingState
    surfaceFrame->setDesiredPresentTime(mDrawingState.desiredPresentTime);
    surfaceFrame->setActualStartTime(info.startTimeNanos);
    // For buffers, acquire fence time will set during latch.
    surfaceFrame->setActualQueueTime(queueTime);
    const auto fps = mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());
    if (fps) {
        surfaceFrame->setRenderRate(*fps);
    }
    return surfaceFrame;
}

void Layer::setFrameTimelineVsyncForSkippedFrames(const FrameTimelineInfo& info, nsecs_t postTime,
                                                  std::string debugName, gui::GameMode gameMode) {
    if (info.skippedFrameVsyncId == FrameTimelineInfo::INVALID_VSYNC_ID) {
        return;
    }

    FrameTimelineInfo skippedFrameTimelineInfo = info;
    skippedFrameTimelineInfo.vsyncId = info.skippedFrameVsyncId;

    auto surfaceFrame =
            mFlinger->mFrameTimeline->createSurfaceFrameForToken(skippedFrameTimelineInfo,
                                                                 mOwnerPid, mOwnerUid,
                                                                 getSequence(), mName, debugName,
                                                                 /*isBuffer*/ false, gameMode);
    // Buffer hasn't yet been latched, so use mDrawingState
    surfaceFrame->setDesiredPresentTime(mDrawingState.desiredPresentTime);
    surfaceFrame->setActualStartTime(skippedFrameTimelineInfo.skippedFrameStartTimeNanos);
    // For Transactions, the post time is considered to be both queue and acquire fence time.
    surfaceFrame->setActualQueueTime(postTime);
    surfaceFrame->setAcquireFenceTime(postTime);
    const auto fps = mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());
    if (fps) {
        surfaceFrame->setRenderRate(*fps);
    }
    addSurfaceFrameDroppedForBuffer(surfaceFrame, postTime);
}

bool Layer::setFrameRateForLayerTree(FrameRate frameRate, const scheduler::LayerProps& layerProps,
                                     nsecs_t now) {
    if (mDrawingState.frameRateForLayerTree == frameRate) {
        return false;
    }

    mDrawingState.frameRateForLayerTree = frameRate;
    mFlinger->mScheduler
            ->recordLayerHistory(sequence, layerProps, now, now,
                                 scheduler::LayerHistory::LayerUpdateType::SetFrameRate);
    return true;
}

Layer::FrameRate Layer::getFrameRateForLayerTree() const {
    return getDrawingState().frameRateForLayerTree;
}

// ----------------------------------------------------------------------------
// debugging
// ----------------------------------------------------------------------------

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

void Layer::miniDump(std::string& result, const frontend::LayerSnapshot& snapshot,
                     const DisplayDevice& display) const {
    const auto outputLayer = findOutputLayerForDisplay(&display, snapshot.path);
    if (!outputLayer) {
        return;
    }

    StringAppendF(&result, " %s\n", snapshot.debugName.c_str());
    StringAppendF(&result, "  %10zu | ", snapshot.globalZ);
    StringAppendF(&result, "  %10d | ",
                  snapshot.layerMetadata.getInt32(gui::METADATA_WINDOW_TYPE, 0));
    StringAppendF(&result, "%10s | ", toString(getCompositionType(outputLayer)).c_str());
    const auto& outputLayerState = outputLayer->getState();
    StringAppendF(&result, "%10s | ", toString(outputLayerState.bufferTransform).c_str());
    const Rect& frame = outputLayerState.displayFrame;
    StringAppendF(&result, "%4d %4d %4d %4d | ", frame.left, frame.top, frame.right, frame.bottom);
    const FloatRect& crop = outputLayerState.sourceCrop;
    StringAppendF(&result, "%6.1f %6.1f %6.1f %6.1f | ", crop.left, crop.top, crop.right,
                  crop.bottom);
    const auto frameRate = snapshot.frameRate;
    std::string frameRateStr;
    if (frameRate.vote.rate.isValid()) {
        StringAppendF(&frameRateStr, "%.2f", frameRate.vote.rate.getValue());
    }
    if (frameRate.vote.rate.isValid() || frameRate.vote.type != FrameRateCompatibility::Default) {
        StringAppendF(&result, "%6s %15s %17s", frameRateStr.c_str(),
                      ftl::enum_string(frameRate.vote.type).c_str(),
                      ftl::enum_string(frameRate.vote.seamlessness).c_str());
    } else if (frameRate.category != FrameRateCategory::Default) {
        StringAppendF(&result, "%6s %15s %17s", frameRateStr.c_str(),
                      (std::string("Cat::") + ftl::enum_string(frameRate.category)).c_str(),
                      ftl::enum_string(frameRate.vote.seamlessness).c_str());
    } else {
        result.append(41, ' ');
    }

    const auto focused = isLayerFocusedBasedOnPriority(snapshot.frameRateSelectionPriority);
    StringAppendF(&result, "    [%s]\n", focused ? "*" : " ");

    result.append(kDumpTableRowLength, '-');
    result.append("\n");
}

void Layer::dumpFrameStats(std::string& result) const {
    if (FlagManager::getInstance().deprecate_frame_tracker()) {
        FrameStats fs = FrameStats();
        getFrameStats(&fs);
        for (auto desired = fs.desiredPresentTimesNano.begin(),
                  actual = fs.actualPresentTimesNano.begin(),
                  ready = fs.frameReadyTimesNano.begin();
             desired != fs.desiredPresentTimesNano.end() &&
             actual != fs.actualPresentTimesNano.end() && ready != fs.frameReadyTimesNano.end();
             ++desired, ++actual, ++ready) {
            result.append(std::format("{}\t{}\t{}\n", *desired, *actual, *ready));
        }

        result.push_back('\n');
    } else {
        mDeprecatedFrameTracker.dumpStats(result);
    }
}

void Layer::clearFrameStats() {
    if (FlagManager::getInstance().deprecate_frame_tracker()) {
        mFrameStatsHistorySize = 0;
    } else {
        mDeprecatedFrameTracker.clearStats();
    }
}

void Layer::getFrameStats(FrameStats* outStats) const {
    if (FlagManager::getInstance().deprecate_frame_tracker()) {
        if (auto ftl = getTimeline()) {
            float fps = ftl->get().computeFps({getSequence()});
            ftl->get().generateFrameStats(getSequence(), mFrameStatsHistorySize, outStats);
            outStats->refreshPeriodNano = Fps::fromValue(fps).getPeriodNsecs();
        }
    } else {
        mDeprecatedFrameTracker.getStats(outStats);
    }
}

void Layer::onDisconnect() {
    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->onDestroy(layerId);
    mFlinger->mFrameTracer->onDestroy(layerId);
}

void Layer::writeCompositionStateToProto(perfetto::protos::LayerProto* layerProto,
                                         ui::LayerStack layerStack) {
    ftl::FakeGuard guard(mFlinger->mStateLock); // Called from the main thread.
    ftl::FakeGuard mainThreadGuard(kMainThreadContext);

    // Only populate for the primary display.
    if (const auto display = mFlinger->getDisplayFromLayerStack(layerStack)) {
        const auto compositionType = getCompositionType(*display);
        layerProto->set_hwc_composition_type(
                static_cast<perfetto::protos::HwcCompositionType>(compositionType));
        LayerProtoHelper::writeToProto(getVisibleRegion(display),
                                       [&]() { return layerProto->mutable_visible_region(); });
    }
}

compositionengine::OutputLayer* Layer::findOutputLayerForDisplay(
        const DisplayDevice* display) const {
    if (!display) return nullptr;
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

compositionengine::OutputLayer* Layer::findOutputLayerForDisplay(
        const DisplayDevice* display, const frontend::LayerHierarchy::TraversalPath& path) const {
    if (!display) return nullptr;
    sp<LayerFE> layerFE;
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

void Layer::callReleaseBufferCallback(const sp<ITransactionCompletedListener>& listener,
                                      const sp<GraphicBuffer>& buffer, uint64_t framenumber,
                                      const sp<Fence>& releaseFence) {
    if (!listener && !mBufferReleaseChannel) {
        return;
    }

    SFTRACE_FORMAT_INSTANT("callReleaseBufferCallback %s - %" PRIu64, getDebugName(), framenumber);

    ReleaseCallbackId callbackId{buffer->getId(), framenumber};
    const sp<Fence>& fence = releaseFence ? releaseFence : Fence::NO_FENCE;
    uint32_t currentMaxAcquiredBufferCount =
            mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mOwnerUid);

    if (listener) {
        listener->onReleaseBuffer(callbackId, fence, currentMaxAcquiredBufferCount);
    }

    if (!mBufferReleaseChannel) {
        return;
    }

    status_t status = mBufferReleaseChannel->writeReleaseFence(callbackId, fence,
                                                               currentMaxAcquiredBufferCount);
    if (status != OK) {
        int error = -status;
        // callReleaseBufferCallback is called during Layer's destructor. In this case, it's
        // expected to receive connection errors.
        if (error != EPIPE && error != ECONNRESET) {
            ALOGD("[%s] writeReleaseFence failed. error %d (%s)", getDebugName(), error,
                  strerror(error));
        }
    }
}

sp<CallbackHandle> Layer::findCallbackHandle() {
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
    return ch;
}

void Layer::prepareReleaseCallbacks(ftl::Future<FenceResult> futureFenceResult,
                                    ui::LayerStack layerStack) {
    sp<CallbackHandle> ch = findCallbackHandle();

    if (ch != nullptr) {
        ch->previousReleaseCallbackId = mPreviousReleaseCallbackId;
        ch->previousReleaseFences.emplace_back(std::move(futureFenceResult));
        ch->name = mName;
    } else {
        // If we didn't get a release callback yet (e.g. some scenarios when capturing
        // screenshots asynchronously) then make sure we don't drop the fence.
        // Older fences for the same layer stack can be dropped when a new fence arrives.
        // An assumption here is that RenderEngine performs work sequentially, so an
        // incoming fence will not fire before an existing fence.
        mAdditionalPreviousReleaseFences.emplace_or_replace(layerStack,
                                                            std::move(futureFenceResult));
    }

    if (mBufferInfo.mBuffer) {
        mPreviouslyPresentedLayerStacks.push_back(layerStack);
    }

    if (mDrawingState.frameNumber > 0) {
        mDrawingState.previousFrameNumber = mDrawingState.frameNumber;
    }
}

void Layer::releasePendingBuffer(nsecs_t dequeueReadyTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->bufferReleaseChannel = mBufferReleaseChannel;
        handle->transformHint = mTransformHint;
        handle->dequeueReadyTime = dequeueReadyTime;
        handle->currentMaxAcquiredBufferCount =
                mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mOwnerUid);
        SFTRACE_FORMAT_INSTANT("releasePendingBuffer %s - %" PRIu64, getDebugName(),
                               handle->previousReleaseCallbackId.framenumber);
    }

    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->releasePreviousBuffer && mPreviousReleaseBufferEndpoint == handle->listener) {
            handle->previousReleaseCallbackId = mPreviousReleaseCallbackId;
            break;
        }
    }

    mFlinger->getTransactionCallbackInvoker().addCallbackHandles(mDrawingState.callbackHandles);
    mDrawingState.callbackHandles = {};
}

bool Layer::setTransform(uint32_t transform) {
    if (mDrawingState.bufferTransform == transform) return false;
    mDrawingState.bufferTransform = transform;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setTransformToDisplayInverse(bool transformToDisplayInverse) {
    if (mDrawingState.transformToDisplayInverse == transformToDisplayInverse) return false;
    mDrawingState.sequence++;
    mDrawingState.transformToDisplayInverse = transformToDisplayInverse;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

void Layer::releasePreviousBuffer() {
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
        const int32_t layerId = getSequence();
        mFlinger->mTimeStats->removeTimeRecord(layerId, mDrawingState.frameNumber);
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
}

void Layer::resetDrawingStateBufferInfo() {
    mDrawingState.producerId = 0;
    mDrawingState.frameNumber = 0;
    mDrawingState.previousFrameNumber = 0;
    mDrawingState.releaseBufferListener = nullptr;
    mDrawingState.buffer = nullptr;
    mDrawingState.acquireFence = sp<Fence>::make(-1);
    mDrawingState.acquireFenceTime = std::make_unique<FenceTime>(mDrawingState.acquireFence);
    mCallbackHandleAcquireTimeOrFence = mDrawingState.acquireFenceTime->getSignalTime();
    mDrawingState.releaseBufferEndpoint = nullptr;
}

bool Layer::setBuffer(std::shared_ptr<renderengine::ExternalTexture>& buffer,
                      const BufferData& bufferData, nsecs_t postTime, nsecs_t desiredPresentTime,
                      bool isAutoTimestamp, const FrameTimelineInfo& info, gui::GameMode gameMode) {
    SFTRACE_FORMAT("setBuffer %s - hasBuffer=%s", getDebugName(), (buffer ? "true" : "false"));

    const bool frameNumberChanged =
            bufferData.flags.test(BufferData::BufferDataChange::frameNumberChanged);
    const uint64_t frameNumber =
            frameNumberChanged ? bufferData.frameNumber : mDrawingState.frameNumber + 1;
    SFTRACE_FORMAT_INSTANT("setBuffer %s - %" PRIu64, getDebugName(), frameNumber);

    if (mDrawingState.buffer) {
        releasePreviousBuffer();
    } else if (buffer) {
        // if we are latching a buffer for the first time then clear the mLastLatchTime since
        // we don't want to incorrectly classify a frame if we miss the desired present time.
        updateLastLatchTime(0);
    }

    mDrawingState.desiredPresentTime = desiredPresentTime;
    mDrawingState.isAutoTimestamp = isAutoTimestamp;
    mDrawingState.latchedVsyncId = info.vsyncId;
    mDrawingState.useVsyncIdForRefreshRateSelection = info.useForRefreshRateSelection;
    if (!buffer) {
        resetDrawingStateBufferInfo();
        setTransactionFlags(eTransactionNeeded);
        mDrawingState.bufferSurfaceFrameTX = nullptr;
        setFrameTimelineVsyncForBufferlessTransaction(info, postTime, gameMode);
        return true;
    } else {
        // release sideband stream if it exists and a non null buffer is being set
        if (mDrawingState.sidebandStream != nullptr) {
            setSidebandStream(nullptr, info, postTime, gameMode);
        }
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
                                      mOwnerUid, postTime, gameMode);

    setFrameTimelineVsyncForBufferTransaction(info, postTime, gameMode);

    if (bufferData.dequeueTime > 0) {
        const uint64_t bufferId = mDrawingState.buffer->getId();
        mFlinger->mFrameTracer->traceNewLayer(layerId, getName().c_str());
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber,
                                               bufferData.dequeueTime,
                                               FrameTracer::FrameEvent::DEQUEUE);
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, postTime,
                                               FrameTracer::FrameEvent::QUEUE);
    }

    mDrawingState.releaseBufferEndpoint = bufferData.releaseBufferEndpoint;

    // If the layer had been updated a TextureView, this would make sure the present time could be
    // same to TextureView update when it's a small dirty, and get the correct heuristic rate.
    if (mFlinger->mScheduler->supportSmallDirtyDetection(mOwnerAppId)) {
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

void Layer::recordLayerHistoryBufferUpdate(const scheduler::LayerProps& layerProps, nsecs_t now) {
    SFTRACE_CALL();
    const nsecs_t presentTime = [&] {
        if (!mDrawingState.isAutoTimestamp) {
            SFTRACE_FORMAT_INSTANT("desiredPresentTime");
            return mDrawingState.desiredPresentTime;
        }

        if (mDrawingState.useVsyncIdForRefreshRateSelection) {
            const auto prediction =
                    mFlinger->mFrameTimeline->getTokenManager()->getPredictionsForToken(
                            mDrawingState.latchedVsyncId);
            if (prediction.has_value()) {
                SFTRACE_FORMAT_INSTANT("predictedPresentTime");
                mMaxTimeForUseVsyncId = prediction->presentTime +
                        scheduler::LayerHistory::kMaxPeriodForHistory.count();
                return prediction->presentTime;
            }
        }

        if (!mFlinger->mScheduler->supportSmallDirtyDetection(mOwnerAppId)) {
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

    if (SFTRACE_ENABLED() && presentTime > 0) {
        const auto presentIn = TimePoint::fromNs(presentTime) - TimePoint::now();
        SFTRACE_FORMAT_INSTANT("presentIn %s", to_string(presentIn).c_str());
    }

    mFlinger->mScheduler->recordLayerHistory(sequence, layerProps, presentTime, now,
                                             scheduler::LayerHistory::LayerUpdateType::Buffer);
}

void Layer::recordLayerHistoryAnimationTx(const scheduler::LayerProps& layerProps, nsecs_t now) {
    const nsecs_t presentTime =
            mDrawingState.isAutoTimestamp ? 0 : mDrawingState.desiredPresentTime;
    mFlinger->mScheduler->recordLayerHistory(sequence, layerProps, presentTime, now,
                                             scheduler::LayerHistory::LayerUpdateType::AnimationTX);
}

bool Layer::setDataspace(ui::Dataspace dataspace) {
    if (mDrawingState.dataspace == dataspace) return false;
    mDrawingState.dataspace = dataspace;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setExtendedRangeBrightness(float currentBufferRatio, float desiredRatio) {
    if (mDrawingState.currentHdrSdrRatio == currentBufferRatio &&
        mDrawingState.desiredHdrSdrRatio == desiredRatio)
        return false;
    mDrawingState.currentHdrSdrRatio = currentBufferRatio;
    mDrawingState.desiredHdrSdrRatio = desiredRatio;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setDesiredHdrHeadroom(float desiredRatio) {
    if (mDrawingState.desiredHdrSdrRatio == desiredRatio) return false;
    mDrawingState.desiredHdrSdrRatio = desiredRatio;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool Layer::setSidebandStream(const sp<NativeHandle>& sidebandStream, const FrameTimelineInfo& info,
                              nsecs_t postTime, gui::GameMode gameMode) {
    if (mDrawingState.sidebandStream == sidebandStream) return false;

    if (mDrawingState.sidebandStream != nullptr && sidebandStream == nullptr) {
        mFlinger->mTunnelModeEnabledReporter->decrementTunnelModeCount();
    } else if (sidebandStream != nullptr) {
        mFlinger->mTunnelModeEnabledReporter->incrementTunnelModeCount();
    }

    mDrawingState.sidebandStream = sidebandStream;
    if (sidebandStream != nullptr && mDrawingState.buffer != nullptr) {
        releasePreviousBuffer();
        resetDrawingStateBufferInfo();
        mDrawingState.bufferSurfaceFrameTX = nullptr;
        setFrameTimelineVsyncForBufferlessTransaction(info, postTime, gameMode);
    }
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
            handle->previousFrameNumber = mDrawingState.previousFrameNumber;
            if (mPreviousReleaseBufferEndpoint == handle->listener) {
                // Add fence from previous screenshot now so that it can be dispatched to the
                // client.
                for (auto& [_, future] : mAdditionalPreviousReleaseFences) {
                    handle->previousReleaseFences.emplace_back(std::move(future));
                }
                mAdditionalPreviousReleaseFences.clear();
            }
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
        mFlinger->getTransactionCallbackInvoker().addCallbackHandles(remainingHandles);
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

bool Layer::latchSidebandStream(bool& recomputeVisibleRegions) {
    if (mSidebandStreamChanged.exchange(false)) {
        const State& s(getDrawingState());
        // mSidebandStreamChanged was true
        mSidebandStream = s.sidebandStream;
        if (mSidebandStream != nullptr) {
            setTransactionFlags(eTransactionNeeded);
            mFlinger->setTransactionFlags(eTraversalNeeded);
        }
        recomputeVisibleRegions = true;
        return true;
    }
    return false;
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
            SFTRACE_NAME("getDataspace");
            err = mapper.getDataspace(mBufferInfo.mBuffer->getBuffer()->handle, &dataspace);
        }
        if (err != OK || dataspace != mBufferInfo.mDataspace) {
            {
                SFTRACE_NAME("setDataspace");
                err = mapper.setDataspace(mBufferInfo.mBuffer->getBuffer()->handle,
                                          static_cast<ui::Dataspace>(mBufferInfo.mDataspace));
            }

            // Some GPU drivers may cache gralloc metadata which means before we composite we need
            // to upsert RenderEngine's caches. Put in a special workaround to be backwards
            // compatible with old vendors, with a ticking clock.
            static const int32_t kVendorVersion =
                    base::GetIntProperty("ro.vendor.api_level", 0);
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
    if (lastDataspace != mBufferInfo.mDataspace ||
        mBufferInfo.mTimeSinceDataspaceUpdate == std::chrono::steady_clock::time_point::min()) {
        mFlinger->mHdrLayerInfoChanged = true;
        const auto currentTime = std::chrono::steady_clock::now();
        if (mBufferInfo.mTimeSinceDataspaceUpdate > std::chrono::steady_clock::time_point::min()) {
            mFlinger->mLayerEvents
                    .emplace_back(mOwnerUid, getSequence(), lastDataspace,
                                  std::chrono::duration_cast<std::chrono::milliseconds>(
                                          currentTime - mBufferInfo.mTimeSinceDataspaceUpdate));
        }
        mBufferInfo.mTimeSinceDataspaceUpdate = currentTime;
    }
    if (mBufferInfo.mDesiredHdrSdrRatio != mDrawingState.desiredHdrSdrRatio) {
        mBufferInfo.mDesiredHdrSdrRatio = mDrawingState.desiredHdrSdrRatio;
        mFlinger->mHdrLayerInfoChanged = true;
    }
    mBufferInfo.mCrop = computeBufferCrop(mDrawingState);
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

void Layer::decrementPendingBufferCount() {
    int32_t pendingBuffers = --mPendingBuffers;
    tracePendingBufferCount(pendingBuffers);
}

void Layer::tracePendingBufferCount(int32_t pendingBuffers) {
    SFTRACE_INT(mBlastTransactionName.c_str(), pendingBuffers);
}

sp<LayerFE> Layer::getCompositionEngineLayerFE(
        const frontend::LayerHierarchy::TraversalPath& path) {
    for (auto& [p, layerFE] : mLayerFEs) {
        if (p == path) {
            return layerFE;
        }
    }
    auto layerFE = mFlinger->getFactory().createLayerFE(mName, this);
    mLayerFEs.emplace_back(path, layerFE);
    return layerFE;
}

void Layer::onCompositionPresented(const DisplayDevice* display,
                                   const std::shared_ptr<FenceTime>& glDoneFence,
                                   const std::shared_ptr<FenceTime>& presentFence,
                                   const CompositorTiming& compositorTiming,
                                   gui::GameMode gameMode) {
    // mFrameLatencyNeeded is true when a new frame was latched for the
    // composition.
    if (!mBufferInfo.mFrameLatencyNeeded) return;

    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->gpuCompositionDoneFence = glDoneFence;
        handle->compositorTiming = compositorTiming;
    }

    // Update mDeprecatedFrameTracker.
    nsecs_t desiredPresentTime = mBufferInfo.mDesiredPresentTime;
    mDeprecatedFrameTracker.setDesiredPresentTime(desiredPresentTime);

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

    // The SurfaceFrame's AcquireFence is the same as this.
    std::shared_ptr<FenceTime> frameReadyFence = mBufferInfo.mFenceTime;
    if (frameReadyFence->isValid()) {
        mDeprecatedFrameTracker.setFrameReadyFence(std::move(frameReadyFence));
    } else {
        // There was no fence for this frame, so assume that it was ready
        // to be presented at the desired present time.
        mDeprecatedFrameTracker.setFrameReadyTime(desiredPresentTime);
    }
    if (display) {
        const auto activeMode = display->refreshRateSelector().getActiveMode();
        const Fps refreshRate = activeMode.fps;
        const std::optional<Fps> renderRate =
                mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());

        const auto vote = frameRateToSetFrameRateVotePayload(getFrameRateForLayerTree());

        if (presentFence->isValid()) {
            mFlinger->mTimeStats->setPresentFence(layerId, mCurrentFrameNumber, presentFence,
                                                  refreshRate, renderRate, vote, gameMode);
            mFlinger->mFrameTracer->traceFence(layerId, getCurrentBufferId(), mCurrentFrameNumber,
                                               presentFence,
                                               FrameTracer::FrameEvent::PRESENT_FENCE);
            mDeprecatedFrameTracker.setActualPresentFence(std::shared_ptr<FenceTime>(presentFence));
        } else if (const auto displayId = PhysicalDisplayId::tryCast(display->getId());
                   displayId && mFlinger->getHwComposer().isConnected(*displayId)) {
            // The HWC doesn't support present fences, so use the present timestamp instead.
            const nsecs_t presentTimestamp =
                    mFlinger->getHwComposer().getPresentTimestamp(*displayId);

            const nsecs_t now = systemTime(CLOCK_MONOTONIC);
            const nsecs_t vsyncPeriod =
                    mFlinger->getHwComposer()
                            .getDisplayVsyncPeriod(*displayId)
                            .value_opt()
                            .value_or(activeMode.modePtr->getVsyncRate().getPeriodNsecs());

            const nsecs_t actualPresentTime = now - ((now - presentTimestamp) % vsyncPeriod);

            mFlinger->mTimeStats->setPresentTime(layerId, mCurrentFrameNumber, actualPresentTime,
                                                 refreshRate, renderRate, vote, gameMode);
            mFlinger->mFrameTracer->traceTimestamp(layerId, getCurrentBufferId(),
                                                   mCurrentFrameNumber, actualPresentTime,
                                                   FrameTracer::FrameEvent::PRESENT_FENCE);
            mDeprecatedFrameTracker.setActualPresentTime(actualPresentTime);
        }
    }

    mFrameStatsHistorySize++;
    mDeprecatedFrameTracker.advanceFrame();
    mBufferInfo.mFrameLatencyNeeded = false;
}

bool Layer::latchBufferImpl(bool& recomputeVisibleRegions, nsecs_t latchTime, bool bgColorOnly) {
    SFTRACE_FORMAT_INSTANT("latchBuffer %s - %" PRIu64, getDebugName(),
                           getDrawingState().frameNumber);

    bool refreshRequired = latchSidebandStream(recomputeVisibleRegions);

    if (refreshRequired) {
        return refreshRequired;
    }

    // If the head buffer's acquire fence hasn't signaled yet, return and
    // try again later
    if (!fenceHasSignaled()) {
        SFTRACE_NAME("!fenceHasSignaled()");
        mFlinger->onLayerUpdate();
        return false;
    }
    updateTexImage(latchTime, bgColorOnly);

    // Capture the old state of the layer for comparisons later
    BufferInfo oldBufferInfo = mBufferInfo;
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
    return true;
}

bool Layer::getTransformToDisplayInverse() const {
    return mBufferInfo.mTransformToDisplayInverse;
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

void Layer::setBufferReleaseChannel(
        const std::shared_ptr<gui::BufferReleaseChannel::ProducerEndpoint>& channel) {
    mBufferReleaseChannel = channel;
}

void Layer::updateLastLatchTime(nsecs_t latchTime) {
    mLastLatchTime = latchTime;
}

void Layer::setIsSmallDirty(frontend::LayerSnapshot* snapshot) {
    if (!mFlinger->mScheduler->supportSmallDirtyDetection(mOwnerAppId)) {
        snapshot->isSmallDirty = false;
        return;
    }

    if (mWindowType != WindowInfo::Type::APPLICATION &&
        mWindowType != WindowInfo::Type::BASE_APPLICATION) {
        snapshot->isSmallDirty = false;
        return;
    }

    Rect bounds = snapshot->surfaceDamage.getBounds();
    if (!bounds.isValid()) {
        snapshot->isSmallDirty = false;
        return;
    }

    // Transform to screen space.
    bounds = snapshot->localTransform.transform(bounds);

    // If the damage region is a small dirty, this could give the hint for the layer history that
    // it could suppress the heuristic rate when calculating.
    snapshot->isSmallDirty =
            mFlinger->mScheduler->isSmallDirtyArea(mOwnerAppId,
                                                   bounds.getWidth() * bounds.getHeight());
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
