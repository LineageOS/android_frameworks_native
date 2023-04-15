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

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "DisplayDevice"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <compositionengine/CompositionEngine.h>
#include <compositionengine/Display.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/DisplayColorProfileCreationArgs.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/DisplaySurface.h>
#include <compositionengine/ProjectionSpace.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/RenderSurfaceCreationArgs.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <configstore/Utils.h>
#include <log/log.h>
#include <system/window.h>
#include <ui/GraphicTypes.h>

#include "Display/DisplaySnapshot.h"
#include "DisplayDevice.h"
#include "FrontEnd/DisplayInfo.h"
#include "Layer.h"
#include "RefreshRateOverlay.h"
#include "SurfaceFlinger.h"

namespace android {

namespace hal = hardware::graphics::composer::hal;

ui::Transform::RotationFlags DisplayDevice::sPrimaryDisplayRotationFlags = ui::Transform::ROT_0;

DisplayDeviceCreationArgs::DisplayDeviceCreationArgs(
        const sp<SurfaceFlinger>& flinger, HWComposer& hwComposer, const wp<IBinder>& displayToken,
        std::shared_ptr<compositionengine::Display> compositionDisplay)
      : flinger(flinger),
        hwComposer(hwComposer),
        displayToken(displayToken),
        compositionDisplay(compositionDisplay) {}

DisplayDevice::DisplayDevice(DisplayDeviceCreationArgs& args)
      : mFlinger(args.flinger),
        mHwComposer(args.hwComposer),
        mDisplayToken(args.displayToken),
        mSequenceId(args.sequenceId),
        mCompositionDisplay{args.compositionDisplay},
        mActiveModeFPSTrace("ActiveModeFPS -" + to_string(getId())),
        mActiveModeFPSHwcTrace("ActiveModeFPS_HWC -" + to_string(getId())),
        mRenderFrameRateFPSTrace("RenderRateFPS -" + to_string(getId())),
        mPhysicalOrientation(args.physicalOrientation),
        mIsPrimary(args.isPrimary),
        mRequestedRefreshRate(args.requestedRefreshRate),
        mRefreshRateSelector(std::move(args.refreshRateSelector)) {
    mCompositionDisplay->editState().isSecure = args.isSecure;
    mCompositionDisplay->createRenderSurface(
            compositionengine::RenderSurfaceCreationArgsBuilder()
                    .setDisplayWidth(ANativeWindow_getWidth(args.nativeWindow.get()))
                    .setDisplayHeight(ANativeWindow_getHeight(args.nativeWindow.get()))
                    .setNativeWindow(std::move(args.nativeWindow))
                    .setDisplaySurface(std::move(args.displaySurface))
                    .setMaxTextureCacheSize(
                            static_cast<size_t>(SurfaceFlinger::maxFrameBufferAcquiredBuffers))
                    .build());

    if (!mFlinger->mDisableClientCompositionCache &&
        SurfaceFlinger::maxFrameBufferAcquiredBuffers > 0) {
        mCompositionDisplay->createClientCompositionCache(
                static_cast<uint32_t>(SurfaceFlinger::maxFrameBufferAcquiredBuffers));
    }

    mCompositionDisplay->setPredictCompositionStrategy(mFlinger->mPredictCompositionStrategy);
    mCompositionDisplay->setTreat170mAsSrgb(mFlinger->mTreat170mAsSrgb);
    mCompositionDisplay->createDisplayColorProfile(
            compositionengine::DisplayColorProfileCreationArgsBuilder()
                    .setHasWideColorGamut(args.hasWideColorGamut)
                    .setHdrCapabilities(std::move(args.hdrCapabilities))
                    .setSupportedPerFrameMetadata(args.supportedPerFrameMetadata)
                    .setHwcColorModes(std::move(args.hwcColorModes))
                    .Build());

    if (!mCompositionDisplay->isValid()) {
        ALOGE("Composition Display did not validate!");
    }

    mCompositionDisplay->getRenderSurface()->initialize();

    if (const auto powerModeOpt = args.initialPowerMode) {
        setPowerMode(*powerModeOpt);
    }

    // initialize the display orientation transform.
    setProjection(ui::ROTATION_0, Rect::INVALID_RECT, Rect::INVALID_RECT);
}

DisplayDevice::~DisplayDevice() = default;

void DisplayDevice::disconnect() {
    mCompositionDisplay->disconnect();
}

int DisplayDevice::getWidth() const {
    return mCompositionDisplay->getState().displaySpace.getBounds().width;
}

int DisplayDevice::getHeight() const {
    return mCompositionDisplay->getState().displaySpace.getBounds().height;
}

void DisplayDevice::setDisplayName(const std::string& displayName) {
    if (!displayName.empty()) {
        // never override the name with an empty name
        mDisplayName = displayName;
        mCompositionDisplay->setName(displayName);
    }
}

auto DisplayDevice::getFrontEndInfo() const -> frontend::DisplayInfo {
    gui::DisplayInfo info;
    info.displayId = getLayerStack().id;

    // The physical orientation is set when the orientation of the display panel is
    // different than the default orientation of the device. Other services like
    // InputFlinger do not know about this, so we do not need to expose the physical
    // orientation of the panel outside of SurfaceFlinger.
    const ui::Rotation inversePhysicalOrientation = ui::ROTATION_0 - mPhysicalOrientation;
    auto width = getWidth();
    auto height = getHeight();
    if (inversePhysicalOrientation == ui::ROTATION_90 ||
        inversePhysicalOrientation == ui::ROTATION_270) {
        std::swap(width, height);
    }
    const ui::Transform undoPhysicalOrientation(ui::Transform::toRotationFlags(
                                                        inversePhysicalOrientation),
                                                width, height);
    const auto& displayTransform = undoPhysicalOrientation * getTransform();
    // Send the inverse display transform to input so it can convert display coordinates to
    // logical display.
    info.transform = displayTransform.inverse();

    info.logicalWidth = getLayerStackSpaceRect().width();
    info.logicalHeight = getLayerStackSpaceRect().height();

    return {.info = info,
            .transform = displayTransform,
            .receivesInput = receivesInput(),
            .isSecure = isSecure(),
            .isPrimary = isPrimary(),
            .isVirtual = isVirtual(),
            .rotationFlags = ui::Transform::toRotationFlags(mOrientation),
            .transformHint = getTransformHint()};
}

void DisplayDevice::setPowerMode(hal::PowerMode mode) {
    if (mode == hal::PowerMode::OFF || mode == hal::PowerMode::ON) {
        if (mStagedBrightness && mBrightness != mStagedBrightness) {
            getCompositionDisplay()->setNextBrightness(*mStagedBrightness);
            mBrightness = *mStagedBrightness;
        }
        mStagedBrightness = std::nullopt;
        getCompositionDisplay()->applyDisplayBrightness(true);
    }

    if (mPowerMode) {
        *mPowerMode = mode;
    } else {
        mPowerMode.emplace("PowerMode -" + to_string(getId()), mode);
    }

    getCompositionDisplay()->setCompositionEnabled(isPoweredOn());
}

void DisplayDevice::tracePowerMode() {
    // assign the same value for tracing
    if (mPowerMode) {
        const hal::PowerMode powerMode = *mPowerMode;
        *mPowerMode = powerMode;
    }
}

void DisplayDevice::enableLayerCaching(bool enable) {
    getCompositionDisplay()->setLayerCachingEnabled(enable);
}

std::optional<hal::PowerMode> DisplayDevice::getPowerMode() const {
    return mPowerMode;
}

bool DisplayDevice::isPoweredOn() const {
    return mPowerMode && *mPowerMode != hal::PowerMode::OFF;
}

void DisplayDevice::setActiveMode(DisplayModeId modeId, Fps displayFps, Fps renderFps) {
    ATRACE_INT(mActiveModeFPSTrace.c_str(), displayFps.getIntValue());
    ATRACE_INT(mRenderFrameRateFPSTrace.c_str(), renderFps.getIntValue());

    mRefreshRateSelector->setActiveMode(modeId, renderFps);

    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->changeRefreshRate(displayFps, renderFps);
    }
}

status_t DisplayDevice::initiateModeChange(const ActiveModeInfo& info,
                                           const hal::VsyncPeriodChangeConstraints& constraints,
                                           hal::VsyncPeriodChangeTimeline* outTimeline) {
    if (!info.modeOpt || info.modeOpt->modePtr->getPhysicalDisplayId() != getPhysicalId()) {
        ALOGE("Trying to initiate a mode change to invalid mode %s on display %s",
              info.modeOpt ? std::to_string(info.modeOpt->modePtr->getId().value()).c_str()
                           : "null",
              to_string(getId()).c_str());
        return BAD_VALUE;
    }
    mUpcomingActiveMode = info;
    ATRACE_INT(mActiveModeFPSHwcTrace.c_str(), info.modeOpt->modePtr->getFps().getIntValue());
    return mHwComposer.setActiveModeWithConstraints(getPhysicalId(),
                                                    info.modeOpt->modePtr->getHwcId(), constraints,
                                                    outTimeline);
}

nsecs_t DisplayDevice::getVsyncPeriodFromHWC() const {
    const auto physicalId = getPhysicalId();
    if (!mHwComposer.isConnected(physicalId)) {
        return 0;
    }

    nsecs_t vsyncPeriod;
    const auto status = mHwComposer.getDisplayVsyncPeriod(physicalId, &vsyncPeriod);
    if (status == NO_ERROR) {
        return vsyncPeriod;
    }

    return refreshRateSelector().getActiveMode().modePtr->getVsyncPeriod();
}

ui::Dataspace DisplayDevice::getCompositionDataSpace() const {
    return mCompositionDisplay->getState().dataspace;
}

void DisplayDevice::setLayerFilter(ui::LayerFilter filter) {
    mCompositionDisplay->setLayerFilter(filter);
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->setLayerStack(filter.layerStack);
    }
}

void DisplayDevice::setFlags(uint32_t flags) {
    mFlags = flags;
}

void DisplayDevice::setDisplaySize(int width, int height) {
    LOG_FATAL_IF(!isVirtual(), "Changing the display size is supported only for virtual displays.");
    const auto size = ui::Size(width, height);
    mCompositionDisplay->setDisplaySize(size);
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->setViewport(size);
    }
}

void DisplayDevice::setProjection(ui::Rotation orientation, Rect layerStackSpaceRect,
                                  Rect orientedDisplaySpaceRect) {
    mOrientation = orientation;

    if (isPrimary()) {
        sPrimaryDisplayRotationFlags = ui::Transform::toRotationFlags(orientation);
    }

    // We need to take care of display rotation for globalTransform for case if the panel is not
    // installed aligned with device orientation.
    const auto transformOrientation = orientation + mPhysicalOrientation;

    const auto& state = getCompositionDisplay()->getState();

    // If the layer stack and destination frames have never been set, then configure them to be the
    // same as the physical device, taking into account the total transform.
    if (!orientedDisplaySpaceRect.isValid()) {
        ui::Size bounds = state.displaySpace.getBounds();
        bounds.rotate(transformOrientation);
        orientedDisplaySpaceRect = Rect(bounds);
    }
    if (layerStackSpaceRect.isEmpty()) {
        ui::Size bounds = state.framebufferSpace.getBounds();
        bounds.rotate(transformOrientation);
        layerStackSpaceRect = Rect(bounds);
    }
    getCompositionDisplay()->setProjection(transformOrientation, layerStackSpaceRect,
                                           orientedDisplaySpaceRect);
}

void DisplayDevice::stageBrightness(float brightness) {
    mStagedBrightness = brightness;
}

void DisplayDevice::persistBrightness(bool needsComposite) {
    if (mStagedBrightness && mBrightness != mStagedBrightness) {
        if (needsComposite) {
            getCompositionDisplay()->setNextBrightness(*mStagedBrightness);
        }
        mBrightness = *mStagedBrightness;
    }
    mStagedBrightness = std::nullopt;
}

std::optional<float> DisplayDevice::getStagedBrightness() const {
    return mStagedBrightness;
}

ui::Transform::RotationFlags DisplayDevice::getPrimaryDisplayRotationFlags() {
    return sPrimaryDisplayRotationFlags;
}

void DisplayDevice::dump(utils::Dumper& dumper) const {
    using namespace std::string_view_literals;

    dumper.dump("name"sv, '"' + mDisplayName + '"');
    dumper.dump("powerMode"sv, mPowerMode);

    if (mRefreshRateSelector) {
        mRefreshRateSelector->dump(dumper);
    }
}

bool DisplayDevice::hasRenderIntent(ui::RenderIntent intent) const {
    return mCompositionDisplay->getDisplayColorProfile()->hasRenderIntent(intent);
}

DisplayId DisplayDevice::getId() const {
    return mCompositionDisplay->getId();
}

bool DisplayDevice::isSecure() const {
    return mCompositionDisplay->isSecure();
}

const Rect DisplayDevice::getBounds() const {
    return mCompositionDisplay->getState().displaySpace.getBoundsAsRect();
}

const Region& DisplayDevice::getUndefinedRegion() const {
    return mCompositionDisplay->getState().undefinedRegion;
}

ui::LayerStack DisplayDevice::getLayerStack() const {
    return mCompositionDisplay->getState().layerFilter.layerStack;
}

ui::Transform::RotationFlags DisplayDevice::getTransformHint() const {
    return mCompositionDisplay->getTransformHint();
}

const ui::Transform& DisplayDevice::getTransform() const {
    return mCompositionDisplay->getState().transform;
}

const Rect& DisplayDevice::getLayerStackSpaceRect() const {
    return mCompositionDisplay->getState().layerStackSpace.getContent();
}

const Rect& DisplayDevice::getOrientedDisplaySpaceRect() const {
    return mCompositionDisplay->getState().orientedDisplaySpace.getContent();
}

bool DisplayDevice::hasWideColorGamut() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasWideColorGamut();
}

bool DisplayDevice::hasHDR10PlusSupport() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasHDR10PlusSupport();
}

bool DisplayDevice::hasHDR10Support() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasHDR10Support();
}

bool DisplayDevice::hasHLGSupport() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasHLGSupport();
}

bool DisplayDevice::hasDolbyVisionSupport() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasDolbyVisionSupport();
}

int DisplayDevice::getSupportedPerFrameMetadata() const {
    return mCompositionDisplay->getDisplayColorProfile()->getSupportedPerFrameMetadata();
}

void DisplayDevice::overrideHdrTypes(const std::vector<ui::Hdr>& hdrTypes) {
    mOverrideHdrTypes = hdrTypes;
}

HdrCapabilities DisplayDevice::getHdrCapabilities() const {
    const HdrCapabilities& capabilities =
            mCompositionDisplay->getDisplayColorProfile()->getHdrCapabilities();
    std::vector<ui::Hdr> hdrTypes = capabilities.getSupportedHdrTypes();
    if (!mOverrideHdrTypes.empty()) {
        hdrTypes = mOverrideHdrTypes;
    }
    return HdrCapabilities(hdrTypes, capabilities.getDesiredMaxLuminance(),
                           capabilities.getDesiredMaxAverageLuminance(),
                           capabilities.getDesiredMinLuminance());
}

void DisplayDevice::enableRefreshRateOverlay(bool enable, bool setByHwc, bool showSpinner,
                                             bool showRenderRate, bool showInMiddle) {
    if (!enable) {
        mRefreshRateOverlay.reset();
        return;
    }

    ftl::Flags<RefreshRateOverlay::Features> features;
    if (showSpinner) {
        features |= RefreshRateOverlay::Features::Spinner;
    }

    if (showRenderRate) {
        features |= RefreshRateOverlay::Features::RenderRate;
    }

    if (showInMiddle) {
        features |= RefreshRateOverlay::Features::ShowInMiddle;
    }

    if (setByHwc) {
        features |= RefreshRateOverlay::Features::SetByHwc;
    }

    const auto fpsRange = mRefreshRateSelector->getSupportedRefreshRateRange();
    mRefreshRateOverlay = std::make_unique<RefreshRateOverlay>(fpsRange, features);
    mRefreshRateOverlay->setLayerStack(getLayerStack());
    mRefreshRateOverlay->setViewport(getSize());
    updateRefreshRateOverlayRate(getActiveMode().modePtr->getFps(), getActiveMode().fps);
}

void DisplayDevice::updateRefreshRateOverlayRate(Fps displayFps, Fps renderFps, bool setByHwc) {
    ATRACE_CALL();
    if (mRefreshRateOverlay && (!mRefreshRateOverlay->isSetByHwc() || setByHwc)) {
        mRefreshRateOverlay->changeRefreshRate(displayFps, renderFps);
    }
}

bool DisplayDevice::onKernelTimerChanged(std::optional<DisplayModeId> desiredModeId,
                                         bool timerExpired) {
    if (mRefreshRateSelector && mRefreshRateOverlay) {
        const auto newMode =
                mRefreshRateSelector->onKernelTimerChanged(desiredModeId, timerExpired);
        if (newMode) {
            updateRefreshRateOverlayRate(newMode->modePtr->getFps(), newMode->fps);
            return true;
        }
    }

    return false;
}

void DisplayDevice::animateRefreshRateOverlay() {
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->animate();
    }
}

auto DisplayDevice::setDesiredActiveMode(const ActiveModeInfo& info, bool force)
        -> DesiredActiveModeAction {
    ATRACE_CALL();

    LOG_ALWAYS_FATAL_IF(!info.modeOpt, "desired mode not provided");
    LOG_ALWAYS_FATAL_IF(getPhysicalId() != info.modeOpt->modePtr->getPhysicalDisplayId(),
                        "DisplayId mismatch");

    ALOGV("%s(%s)", __func__, to_string(*info.modeOpt->modePtr).c_str());

    std::scoped_lock lock(mActiveModeLock);
    if (mDesiredActiveModeChanged) {
        // If a mode change is pending, just cache the latest request in mDesiredActiveMode
        const auto prevConfig = mDesiredActiveMode.event;
        mDesiredActiveMode = info;
        mDesiredActiveMode.event = mDesiredActiveMode.event | prevConfig;
        return DesiredActiveModeAction::None;
    }

    const auto& desiredMode = *info.modeOpt->modePtr;

    // Check if we are already at the desired mode
    const auto currentMode = refreshRateSelector().getActiveMode();
    if (!force && currentMode.modePtr->getId() == desiredMode.getId()) {
        if (currentMode == info.modeOpt) {
            return DesiredActiveModeAction::None;
        }

        setActiveMode(desiredMode.getId(), desiredMode.getFps(), info.modeOpt->fps);
        return DesiredActiveModeAction::InitiateRenderRateSwitch;
    }

    // Set the render frame rate to the current physical refresh rate to schedule the next
    // frame as soon as possible.
    setActiveMode(currentMode.modePtr->getId(), currentMode.modePtr->getFps(),
                  currentMode.modePtr->getFps());

    // Initiate a mode change.
    mDesiredActiveModeChanged = true;
    mDesiredActiveMode = info;
    return DesiredActiveModeAction::InitiateDisplayModeSwitch;
}

std::optional<DisplayDevice::ActiveModeInfo> DisplayDevice::getDesiredActiveMode() const {
    std::scoped_lock lock(mActiveModeLock);
    if (mDesiredActiveModeChanged) return mDesiredActiveMode;
    return std::nullopt;
}

void DisplayDevice::clearDesiredActiveModeState() {
    std::scoped_lock lock(mActiveModeLock);
    mDesiredActiveMode.event = scheduler::DisplayModeEvent::None;
    mDesiredActiveModeChanged = false;
}

void DisplayDevice::adjustRefreshRate(Fps pacesetterDisplayRefreshRate) {
    using fps_approx_ops::operator<=;
    if (mRequestedRefreshRate <= 0_Hz) {
        return;
    }

    using fps_approx_ops::operator>;
    if (mRequestedRefreshRate > pacesetterDisplayRefreshRate) {
        mAdjustedRefreshRate = pacesetterDisplayRefreshRate;
        return;
    }

    unsigned divisor = static_cast<unsigned>(
            std::floor(pacesetterDisplayRefreshRate.getValue() / mRequestedRefreshRate.getValue()));
    if (divisor == 0) {
        mAdjustedRefreshRate = 0_Hz;
        return;
    }

    mAdjustedRefreshRate = pacesetterDisplayRefreshRate / divisor;
}

std::atomic<int32_t> DisplayDeviceState::sNextSequenceId(1);

}  // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
