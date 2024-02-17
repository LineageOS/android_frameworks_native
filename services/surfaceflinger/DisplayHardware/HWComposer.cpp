/*
 * Copyright (C) 2010 The Android Open Source Project
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
#include <chrono>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

// #define LOG_NDEBUG 0

#undef LOG_TAG
#define LOG_TAG "HWComposer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "HWComposer.h"

#include <android-base/properties.h>
#include <compositionengine/Output.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <ftl/concat.h>
#include <gui/TraceUtils.h>
#include <log/log.h>
#include <ui/DebugUtils.h>
#include <ui/GraphicBuffer.h>
#include <utils/Errors.h>
#include <utils/Trace.h>

#include "../Layer.h" // needed only for debugging
#include "../SurfaceFlingerProperties.h"
#include "ComposerHal.h"
#include "HWC2.h"

#define LOG_HWC_DISPLAY_ERROR(hwcDisplayId, msg) \
    ALOGE("%s failed for HWC display %" PRIu64 ": %s", __FUNCTION__, hwcDisplayId, msg)

#define LOG_DISPLAY_ERROR(displayId, msg) \
    ALOGE("%s failed for display %s: %s", __FUNCTION__, to_string(displayId).c_str(), msg)

#define LOG_HWC_ERROR(what, error, displayId)                          \
    ALOGE("%s: %s failed for display %s: %s (%d)", __FUNCTION__, what, \
          to_string(displayId).c_str(), to_string(error).c_str(), static_cast<int32_t>(error))

#define RETURN_IF_INVALID_DISPLAY(displayId, ...)            \
    do {                                                     \
        if (mDisplayData.count(displayId) == 0) {            \
            LOG_DISPLAY_ERROR(displayId, "Invalid display"); \
            return __VA_ARGS__;                              \
        }                                                    \
    } while (false)

#define RETURN_IF_HWC_ERROR_FOR(what, error, displayId, ...) \
    do {                                                     \
        if (error != hal::Error::NONE) {                     \
            LOG_HWC_ERROR(what, error, displayId);           \
            return __VA_ARGS__;                              \
        }                                                    \
    } while (false)

#define RETURN_IF_HWC_ERROR(error, displayId, ...) \
    RETURN_IF_HWC_ERROR_FOR(__FUNCTION__, error, displayId, __VA_ARGS__)

using aidl::android::hardware::graphics::common::HdrConversionCapability;
using aidl::android::hardware::graphics::common::HdrConversionStrategy;
using aidl::android::hardware::graphics::composer3::Capability;
using aidl::android::hardware::graphics::composer3::DisplayCapability;
using aidl::android::hardware::graphics::composer3::VrrConfig;
using namespace std::string_literals;
namespace hal = android::hardware::graphics::composer::hal;

namespace android {

HWComposer::~HWComposer() = default;

namespace impl {

HWComposer::HWComposer(std::unique_ptr<Hwc2::Composer> composer)
      : mComposer(std::move(composer)),
        mMaxVirtualDisplayDimension(static_cast<size_t>(sysprop::max_virtual_display_dimension(0))),
        mUpdateDeviceProductInfoOnHotplugReconnect(
                sysprop::update_device_product_info_on_hotplug_reconnect(false)),
        mEnableVrrTimeout(base::GetBoolProperty("debug.sf.vrr_timeout_hint_enabled"s, true)) {}

HWComposer::HWComposer(const std::string& composerServiceName)
      : HWComposer(Hwc2::Composer::create(composerServiceName)) {}

HWComposer::~HWComposer() {
    mDisplayData.clear();
}

void HWComposer::setCallback(HWC2::ComposerCallback& callback) {
    loadCapabilities();
    loadLayerMetadataSupport();
    loadOverlayProperties();
    loadHdrConversionCapabilities();

    if (mRegisteredCallback) {
        ALOGW("Callback already registered. Ignored extra registration attempt.");
        return;
    }
    mRegisteredCallback = true;

    mComposer->registerCallback(callback);
}

bool HWComposer::getDisplayIdentificationData(hal::HWDisplayId hwcDisplayId, uint8_t* outPort,
                                              DisplayIdentificationData* outData) const {
    const auto error = static_cast<hal::Error>(
            mComposer->getDisplayIdentificationData(hwcDisplayId, outPort, outData));
    if (error != hal::Error::NONE) {
        if (error != hal::Error::UNSUPPORTED) {
            LOG_HWC_DISPLAY_ERROR(hwcDisplayId, to_string(error).c_str());
        }
        return false;
    }
    return true;
}

bool HWComposer::hasCapability(Capability capability) const {
    return mCapabilities.count(capability) > 0;
}

bool HWComposer::hasDisplayCapability(HalDisplayId displayId, DisplayCapability capability) const {
    RETURN_IF_INVALID_DISPLAY(displayId, false);
    return mDisplayData.at(displayId).hwcDisplay->hasCapability(capability);
}

std::optional<DisplayIdentificationInfo> HWComposer::onHotplug(hal::HWDisplayId hwcDisplayId,
                                                               hal::Connection connection) {
    switch (connection) {
        case hal::Connection::CONNECTED:
            return onHotplugConnect(hwcDisplayId);
        case hal::Connection::DISCONNECTED:
            return onHotplugDisconnect(hwcDisplayId);
        case hal::Connection::INVALID:
            return {};
    }
}

bool HWComposer::updatesDeviceProductInfoOnHotplugReconnect() const {
    return mUpdateDeviceProductInfoOnHotplugReconnect;
}

std::optional<PhysicalDisplayId> HWComposer::onVsync(hal::HWDisplayId hwcDisplayId,
                                                     nsecs_t timestamp) {
    const auto displayIdOpt = toPhysicalDisplayId(hwcDisplayId);
    if (!displayIdOpt) {
        LOG_HWC_DISPLAY_ERROR(hwcDisplayId, "Invalid HWC display");
        return {};
    }

    RETURN_IF_INVALID_DISPLAY(*displayIdOpt, {});

    auto& displayData = mDisplayData[*displayIdOpt];

    {
        // There have been reports of HWCs that signal several vsync events
        // with the same timestamp when turning the display off and on. This
        // is a bug in the HWC implementation, but filter the extra events
        // out here so they don't cause havoc downstream.
        if (timestamp == displayData.lastPresentTimestamp) {
            ALOGW("Ignoring duplicate VSYNC event from HWC for display %s (t=%" PRId64 ")",
                  to_string(*displayIdOpt).c_str(), timestamp);
            return {};
        }

        displayData.lastPresentTimestamp = timestamp;
    }

    ATRACE_INT(ftl::Concat("HW_VSYNC_", displayIdOpt->value).c_str(),
               displayData.vsyncTraceToggle);
    displayData.vsyncTraceToggle = !displayData.vsyncTraceToggle;

    return displayIdOpt;
}

size_t HWComposer::getMaxVirtualDisplayCount() const {
    return mComposer->getMaxVirtualDisplayCount();
}

size_t HWComposer::getMaxVirtualDisplayDimension() const {
    return mMaxVirtualDisplayDimension;
}

bool HWComposer::allocateVirtualDisplay(HalVirtualDisplayId displayId, ui::Size resolution,
                                        ui::PixelFormat* format) {
    if (!resolution.isValid()) {
        ALOGE("%s: Invalid resolution %dx%d", __func__, resolution.width, resolution.height);
        return false;
    }

    const uint32_t width = static_cast<uint32_t>(resolution.width);
    const uint32_t height = static_cast<uint32_t>(resolution.height);

    if (mMaxVirtualDisplayDimension > 0 &&
        (width > mMaxVirtualDisplayDimension || height > mMaxVirtualDisplayDimension)) {
        ALOGE("%s: Resolution %ux%u exceeds maximum dimension %zu", __func__, width, height,
              mMaxVirtualDisplayDimension);
        return false;
    }

    hal::HWDisplayId hwcDisplayId;
    const auto error = static_cast<hal::Error>(
            mComposer->createVirtualDisplay(width, height, format, &hwcDisplayId));
    RETURN_IF_HWC_ERROR_FOR("createVirtualDisplay", error, displayId, false);

    auto display = std::make_unique<HWC2::impl::Display>(*mComposer.get(), mCapabilities,
                                                         hwcDisplayId, hal::DisplayType::VIRTUAL);
    display->setConnected(true);
    auto& displayData = mDisplayData[displayId];
    displayData.hwcDisplay = std::move(display);
    return true;
}

void HWComposer::allocatePhysicalDisplay(hal::HWDisplayId hwcDisplayId,
                                         PhysicalDisplayId displayId) {
    mPhysicalDisplayIdMap[hwcDisplayId] = displayId;

    if (!mPrimaryHwcDisplayId) {
        mPrimaryHwcDisplayId = hwcDisplayId;
    }

    auto& displayData = mDisplayData[displayId];
    auto newDisplay =
            std::make_unique<HWC2::impl::Display>(*mComposer.get(), mCapabilities, hwcDisplayId,
                                                  hal::DisplayType::PHYSICAL);
    newDisplay->setConnected(true);
    displayData.hwcDisplay = std::move(newDisplay);
}

int32_t HWComposer::getAttribute(hal::HWDisplayId hwcDisplayId, hal::HWConfigId configId,
                                 hal::Attribute attribute) const {
    int32_t value = 0;
    auto error = static_cast<hal::Error>(
            mComposer->getDisplayAttribute(hwcDisplayId, configId, attribute, &value));

    RETURN_IF_HWC_ERROR_FOR("getDisplayAttribute", error, *toPhysicalDisplayId(hwcDisplayId), -1);
    return value;
}

std::shared_ptr<HWC2::Layer> HWComposer::createLayer(HalDisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId, nullptr);

    auto expected = mDisplayData[displayId].hwcDisplay->createLayer();
    if (!expected.has_value()) {
        auto error = std::move(expected).error();
        RETURN_IF_HWC_ERROR(error, displayId, nullptr);
    }
    return std::move(expected).value();
}

bool HWComposer::isConnected(PhysicalDisplayId displayId) const {
    return mDisplayData.count(displayId) && mDisplayData.at(displayId).hwcDisplay->isConnected();
}

std::vector<HWComposer::HWCDisplayMode> HWComposer::getModes(PhysicalDisplayId displayId,
                                                             int32_t maxFrameIntervalNs) const {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    const auto hwcDisplayId = mDisplayData.at(displayId).hwcDisplay->getId();

    if (mComposer->isVrrSupported()) {
        return getModesFromDisplayConfigurations(hwcDisplayId, maxFrameIntervalNs);
    }

    return getModesFromLegacyDisplayConfigs(hwcDisplayId);
}

std::vector<HWComposer::HWCDisplayMode> HWComposer::getModesFromDisplayConfigurations(
        uint64_t hwcDisplayId, int32_t maxFrameIntervalNs) const {
    std::vector<hal::DisplayConfiguration> configs;
    auto error = static_cast<hal::Error>(
            mComposer->getDisplayConfigurations(hwcDisplayId, maxFrameIntervalNs, &configs));
    RETURN_IF_HWC_ERROR_FOR("getDisplayConfigurations", error, *toPhysicalDisplayId(hwcDisplayId),
                            {});

    std::vector<HWCDisplayMode> modes;
    modes.reserve(configs.size());
    for (auto config : configs) {
        auto hwcMode = HWCDisplayMode{.hwcId = static_cast<hal::HWConfigId>(config.configId),
                                      .width = config.width,
                                      .height = config.height,
                                      .vsyncPeriod = config.vsyncPeriod,
                                      .configGroup = config.configGroup,
                                      .vrrConfig = config.vrrConfig};

        if (config.dpi) {
            hwcMode.dpiX = config.dpi->x;
            hwcMode.dpiY = config.dpi->y;
        }

        if (!mEnableVrrTimeout) {
            hwcMode.vrrConfig->notifyExpectedPresentConfig = {};
        }

        modes.push_back(hwcMode);
    }

    return modes;
}

std::vector<HWComposer::HWCDisplayMode> HWComposer::getModesFromLegacyDisplayConfigs(
        uint64_t hwcDisplayId) const {
    std::vector<hal::HWConfigId> configIds;
    auto error = static_cast<hal::Error>(mComposer->getDisplayConfigs(hwcDisplayId, &configIds));
    RETURN_IF_HWC_ERROR_FOR("getDisplayConfigs", error, *toPhysicalDisplayId(hwcDisplayId), {});

    std::vector<HWCDisplayMode> modes;
    modes.reserve(configIds.size());
    for (auto configId : configIds) {
        auto hwcMode = HWCDisplayMode{
                .hwcId = configId,
                .width = getAttribute(hwcDisplayId, configId, hal::Attribute::WIDTH),
                .height = getAttribute(hwcDisplayId, configId, hal::Attribute::HEIGHT),
                .vsyncPeriod = getAttribute(hwcDisplayId, configId, hal::Attribute::VSYNC_PERIOD),
                .configGroup = getAttribute(hwcDisplayId, configId, hal::Attribute::CONFIG_GROUP),
        };

        const int32_t dpiX = getAttribute(hwcDisplayId, configId, hal::Attribute::DPI_X);
        const int32_t dpiY = getAttribute(hwcDisplayId, configId, hal::Attribute::DPI_Y);
        if (dpiX != -1) {
            hwcMode.dpiX = static_cast<float>(dpiX) / 1000.f;
        }
        if (dpiY != -1) {
            hwcMode.dpiY = static_cast<float>(dpiY) / 1000.f;
        }

        modes.push_back(hwcMode);
    }
    return modes;
}

ftl::Expected<hal::HWConfigId, status_t> HWComposer::getActiveMode(
        PhysicalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, ftl::Unexpected(BAD_INDEX));
    const auto hwcId = *fromPhysicalDisplayId(displayId);

    hal::HWConfigId configId;
    const auto error = static_cast<hal::Error>(mComposer->getActiveConfig(hwcId, &configId));
    if (error == hal::Error::BAD_CONFIG) {
        return ftl::Unexpected(NO_INIT);
    }

    RETURN_IF_HWC_ERROR_FOR("getActiveConfig", error, displayId, ftl::Unexpected(UNKNOWN_ERROR));
    return configId;
}

// Composer 2.4

ui::DisplayConnectionType HWComposer::getDisplayConnectionType(PhysicalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, ui::DisplayConnectionType::Internal);
    const auto& hwcDisplay = mDisplayData.at(displayId).hwcDisplay;

    if (const auto connectionType = hwcDisplay->getConnectionType()) {
        return connectionType.value();
    } else {
        LOG_HWC_ERROR(__func__, connectionType.error(), displayId);
        return hwcDisplay->getId() == mPrimaryHwcDisplayId ? ui::DisplayConnectionType::Internal
                                                           : ui::DisplayConnectionType::External;
    }
}

bool HWComposer::isVsyncPeriodSwitchSupported(PhysicalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, false);
    return mDisplayData.at(displayId).hwcDisplay->isVsyncPeriodSwitchSupported();
}

ftl::Expected<nsecs_t, status_t> HWComposer::getDisplayVsyncPeriod(
        PhysicalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, ftl::Unexpected(BAD_INDEX));

    if (!isVsyncPeriodSwitchSupported(displayId)) {
        return ftl::Unexpected(INVALID_OPERATION);
    }

    const auto hwcId = *fromPhysicalDisplayId(displayId);
    Hwc2::VsyncPeriodNanos vsyncPeriodNanos = 0;
    const auto error =
            static_cast<hal::Error>(mComposer->getDisplayVsyncPeriod(hwcId, &vsyncPeriodNanos));
    RETURN_IF_HWC_ERROR(error, displayId, ftl::Unexpected(UNKNOWN_ERROR));
    return static_cast<nsecs_t>(vsyncPeriodNanos);
}

std::vector<ui::ColorMode> HWComposer::getColorModes(PhysicalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    std::vector<ui::ColorMode> modes;
    auto error = mDisplayData.at(displayId).hwcDisplay->getColorModes(&modes);
    RETURN_IF_HWC_ERROR(error, displayId, {});
    return modes;
}

status_t HWComposer::setActiveColorMode(PhysicalDisplayId displayId, ui::ColorMode mode,
                                        ui::RenderIntent renderIntent) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    auto error = displayData.hwcDisplay->setColorMode(mode, renderIntent);
    RETURN_IF_HWC_ERROR_FOR(("setColorMode(" + decodeColorMode(mode) + ", " +
                             decodeRenderIntent(renderIntent) + ")")
                                    .c_str(),
                            error, displayId, UNKNOWN_ERROR);

    return NO_ERROR;
}

void HWComposer::setVsyncEnabled(PhysicalDisplayId displayId, hal::Vsync enabled) {
    RETURN_IF_INVALID_DISPLAY(displayId);
    auto& displayData = mDisplayData[displayId];

    // NOTE: we use our own internal lock here because we have to call
    // into the HWC with the lock held, and we want to make sure
    // that even if HWC blocks (which it shouldn't), it won't
    // affect other threads.
    std::lock_guard lock(displayData.vsyncEnabledLock);
    if (enabled == displayData.vsyncEnabled) {
        return;
    }

    ATRACE_CALL();
    auto error = displayData.hwcDisplay->setVsyncEnabled(enabled);
    RETURN_IF_HWC_ERROR(error, displayId);

    displayData.vsyncEnabled = enabled;

    ATRACE_INT(ftl::Concat("HW_VSYNC_ON_", displayId.value).c_str(),
               enabled == hal::Vsync::ENABLE ? 1 : 0);
}

status_t HWComposer::setClientTarget(HalDisplayId displayId, uint32_t slot,
                                     const sp<Fence>& acquireFence, const sp<GraphicBuffer>& target,
                                     ui::Dataspace dataspace, float hdrSdrRatio) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    ALOGV("%s for display %s", __FUNCTION__, to_string(displayId).c_str());
    auto& hwcDisplay = mDisplayData[displayId].hwcDisplay;
    auto error = hwcDisplay->setClientTarget(slot, target, acquireFence, dataspace, hdrSdrRatio);
    RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    return NO_ERROR;
}

status_t HWComposer::getDeviceCompositionChanges(
        HalDisplayId displayId, bool frameUsesClientComposition,
        std::optional<std::chrono::steady_clock::time_point> earliestPresentTime,
        nsecs_t expectedPresentTime, Fps frameInterval,
        std::optional<android::HWComposer::DeviceRequestedChanges>* outChanges) {
    ATRACE_CALL();

    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    auto& hwcDisplay = displayData.hwcDisplay;
    if (!hwcDisplay->isConnected()) {
        return NO_ERROR;
    }

    uint32_t numTypes = 0;
    uint32_t numRequests = 0;

    hal::Error error = hal::Error::NONE;

    // First try to skip validate altogether. We can do that when
    // 1. The previous frame has not been presented yet or already passed the
    // earliest time to present. Otherwise, we may present a frame too early.
    // 2. There is no client composition. Otherwise, we first need to render the
    // client target buffer.
    const bool canSkipValidate = [&] {
        // We must call validate if we have client composition
        if (frameUsesClientComposition) {
            return false;
        }

        // If composer supports getting the expected present time, we can skip
        // as composer will make sure to prevent early presentation
        if (!earliestPresentTime) {
            return true;
        }

        // composer doesn't support getting the expected present time. We can only
        // skip validate if we know that we are not going to present early.
        return std::chrono::steady_clock::now() >= *earliestPresentTime;
    }();

    displayData.validateWasSkipped = false;
    ATRACE_FORMAT("NextFrameInterval %d_Hz", frameInterval.getIntValue());
    if (canSkipValidate) {
        sp<Fence> outPresentFence = Fence::NO_FENCE;
        uint32_t state = UINT32_MAX;
        error = hwcDisplay->presentOrValidate(expectedPresentTime, frameInterval.getPeriodNsecs(),
                                              &numTypes, &numRequests, &outPresentFence, &state);
        if (!hasChangesError(error)) {
            RETURN_IF_HWC_ERROR_FOR("presentOrValidate", error, displayId, UNKNOWN_ERROR);
        }
        if (state == 1) { //Present Succeeded.
            std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;
            error = hwcDisplay->getReleaseFences(&releaseFences);
            displayData.releaseFences = std::move(releaseFences);
            displayData.lastPresentFence = outPresentFence;
            displayData.validateWasSkipped = true;
            displayData.presentError = error;
            return NO_ERROR;
        }
        // Present failed but Validate ran.
    } else {
        error = hwcDisplay->validate(expectedPresentTime, frameInterval.getPeriodNsecs(), &numTypes,
                                     &numRequests);
    }
    ALOGV("SkipValidate failed, Falling back to SLOW validate/present");
    if (!hasChangesError(error)) {
        RETURN_IF_HWC_ERROR_FOR("validate", error, displayId, BAD_INDEX);
    }

    android::HWComposer::DeviceRequestedChanges::ChangedTypes changedTypes;
    changedTypes.reserve(numTypes);
    error = hwcDisplay->getChangedCompositionTypes(&changedTypes);
    RETURN_IF_HWC_ERROR_FOR("getChangedCompositionTypes", error, displayId, BAD_INDEX);

    auto displayRequests = static_cast<hal::DisplayRequest>(0);
    android::HWComposer::DeviceRequestedChanges::LayerRequests layerRequests;
    layerRequests.reserve(numRequests);
    error = hwcDisplay->getRequests(&displayRequests, &layerRequests);
    RETURN_IF_HWC_ERROR_FOR("getRequests", error, displayId, BAD_INDEX);

    DeviceRequestedChanges::ClientTargetProperty clientTargetProperty;
    error = hwcDisplay->getClientTargetProperty(&clientTargetProperty);

    outChanges->emplace(DeviceRequestedChanges{std::move(changedTypes), std::move(displayRequests),
                                               std::move(layerRequests),
                                               std::move(clientTargetProperty)});
    error = hwcDisplay->acceptChanges();
    RETURN_IF_HWC_ERROR_FOR("acceptChanges", error, displayId, BAD_INDEX);

    return NO_ERROR;
}

sp<Fence> HWComposer::getPresentFence(HalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, Fence::NO_FENCE);
    return mDisplayData.at(displayId).lastPresentFence;
}

nsecs_t HWComposer::getPresentTimestamp(PhysicalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, 0);
    return mDisplayData.at(displayId).lastPresentTimestamp;
}

sp<Fence> HWComposer::getLayerReleaseFence(HalDisplayId displayId, HWC2::Layer* layer) const {
    RETURN_IF_INVALID_DISPLAY(displayId, Fence::NO_FENCE);
    const auto& displayFences = mDisplayData.at(displayId).releaseFences;
    auto fence = displayFences.find(layer);
    if (fence == displayFences.end()) {
        ALOGV("getLayerReleaseFence: Release fence not found");
        return Fence::NO_FENCE;
    }
    return fence->second;
}

status_t HWComposer::presentAndGetReleaseFences(
        HalDisplayId displayId,
        std::optional<std::chrono::steady_clock::time_point> earliestPresentTime) {
    ATRACE_CALL();

    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    auto& hwcDisplay = displayData.hwcDisplay;

    if (displayData.validateWasSkipped) {
        // explicitly flush all pending commands
        auto error = static_cast<hal::Error>(mComposer->executeCommands(hwcDisplay->getId()));
        RETURN_IF_HWC_ERROR_FOR("executeCommands", error, displayId, UNKNOWN_ERROR);
        RETURN_IF_HWC_ERROR_FOR("present", displayData.presentError, displayId, UNKNOWN_ERROR);
        return NO_ERROR;
    }

    if (earliestPresentTime) {
        ATRACE_NAME("wait for earliest present time");
        std::this_thread::sleep_until(*earliestPresentTime);
    }

    auto error = hwcDisplay->present(&displayData.lastPresentFence);
    RETURN_IF_HWC_ERROR_FOR("present", error, displayId, UNKNOWN_ERROR);

    std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;
    error = hwcDisplay->getReleaseFences(&releaseFences);
    RETURN_IF_HWC_ERROR_FOR("getReleaseFences", error, displayId, UNKNOWN_ERROR);

    displayData.releaseFences = std::move(releaseFences);

    return NO_ERROR;
}

status_t HWComposer::setPowerMode(PhysicalDisplayId displayId, hal::PowerMode mode) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    if (mode == hal::PowerMode::OFF) {
        setVsyncEnabled(displayId, hal::Vsync::DISABLE);
    }

    const auto& displayData = mDisplayData[displayId];
    auto& hwcDisplay = displayData.hwcDisplay;
    switch (mode) {
        case hal::PowerMode::OFF:
        case hal::PowerMode::ON:
            ALOGV("setPowerMode: Calling HWC %s", to_string(mode).c_str());
            {
                auto error = hwcDisplay->setPowerMode(mode);
                if (error != hal::Error::NONE) {
                    LOG_HWC_ERROR(("setPowerMode(" + to_string(mode) + ")").c_str(), error,
                                  displayId);
                }
            }
            break;
        case hal::PowerMode::DOZE:
        case hal::PowerMode::DOZE_SUSPEND:
            ALOGV("setPowerMode: Calling HWC %s", to_string(mode).c_str());
            {
                bool supportsDoze = false;
                const auto queryDozeError = hwcDisplay->supportsDoze(&supportsDoze);

                // queryDozeError might be NO_RESOURCES, in the case of a display that has never
                // been turned on. In that case, attempt to set to DOZE anyway.
                if (!supportsDoze && queryDozeError == hal::Error::NONE) {
                    mode = hal::PowerMode::ON;
                }

                auto error = hwcDisplay->setPowerMode(mode);
                if (error != hal::Error::NONE) {
                    LOG_HWC_ERROR(("setPowerMode(" + to_string(mode) + ")").c_str(), error,
                                  displayId);
                    // If the display had never been turned on, so its doze
                    // support was unknown, it may truly not support doze. Try
                    // switching it to ON instead.
                    if (queryDozeError == hal::Error::NO_RESOURCES) {
                        ALOGD("%s: failed to set %s to %s. Trying again with ON", __func__,
                              to_string(displayId).c_str(), to_string(mode).c_str());
                        error = hwcDisplay->setPowerMode(hal::PowerMode::ON);
                        if (error != hal::Error::NONE) {
                            LOG_HWC_ERROR("setPowerMode(ON)", error, displayId);
                        }
                    }
                }
            }
            break;
        default:
            ALOGV("setPowerMode: Not calling HWC");
            break;
    }

    return NO_ERROR;
}

status_t HWComposer::setActiveModeWithConstraints(
        PhysicalDisplayId displayId, hal::HWConfigId hwcModeId,
        const hal::VsyncPeriodChangeConstraints& constraints,
        hal::VsyncPeriodChangeTimeline* outTimeline) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto error = mDisplayData[displayId].hwcDisplay->setActiveConfigWithConstraints(hwcModeId,
                                                                                    constraints,
                                                                                    outTimeline);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::setColorTransform(HalDisplayId displayId, const mat4& transform) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    auto error = displayData.hwcDisplay->setColorTransform(transform);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

void HWComposer::disconnectDisplay(HalDisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId);
    auto& displayData = mDisplayData[displayId];
    const auto hwcDisplayId = displayData.hwcDisplay->getId();

    mPhysicalDisplayIdMap.erase(hwcDisplayId);
    mDisplayData.erase(displayId);

    // Reset the primary display ID if we're disconnecting it.
    // This way isHeadless() will return false, which is necessary
    // because getPrimaryDisplayId() will crash.
    if (mPrimaryHwcDisplayId == hwcDisplayId) {
        mPrimaryHwcDisplayId.reset();
    }
}

status_t HWComposer::setOutputBuffer(HalVirtualDisplayId displayId, const sp<Fence>& acquireFence,
                                     const sp<GraphicBuffer>& buffer) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto& displayData = mDisplayData[displayId];

    auto error = displayData.hwcDisplay->setOutputBuffer(buffer, acquireFence);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

void HWComposer::clearReleaseFences(HalDisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId);
    mDisplayData[displayId].releaseFences.clear();
}

status_t HWComposer::getHdrCapabilities(HalDisplayId displayId, HdrCapabilities* outCapabilities) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& hwcDisplay = mDisplayData[displayId].hwcDisplay;
    auto error = hwcDisplay->getHdrCapabilities(outCapabilities);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

const aidl::android::hardware::graphics::composer3::OverlayProperties&
HWComposer::getOverlaySupport() const {
    return mOverlayProperties;
}

int32_t HWComposer::getSupportedPerFrameMetadata(HalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, 0);
    return mDisplayData.at(displayId).hwcDisplay->getSupportedPerFrameMetadata();
}

std::vector<ui::RenderIntent> HWComposer::getRenderIntents(HalDisplayId displayId,
                                                           ui::ColorMode colorMode) const {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    std::vector<ui::RenderIntent> renderIntents;
    auto error = mDisplayData.at(displayId).hwcDisplay->getRenderIntents(colorMode, &renderIntents);
    RETURN_IF_HWC_ERROR(error, displayId, {});
    return renderIntents;
}

mat4 HWComposer::getDataspaceSaturationMatrix(HalDisplayId displayId, ui::Dataspace dataspace) {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    mat4 matrix;
    auto error = mDisplayData[displayId].hwcDisplay->getDataspaceSaturationMatrix(dataspace,
            &matrix);
    RETURN_IF_HWC_ERROR(error, displayId, {});
    return matrix;
}

status_t HWComposer::getDisplayedContentSamplingAttributes(HalDisplayId displayId,
                                                           ui::PixelFormat* outFormat,
                                                           ui::Dataspace* outDataspace,
                                                           uint8_t* outComponentMask) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mDisplayData[displayId]
                    .hwcDisplay->getDisplayedContentSamplingAttributes(outFormat, outDataspace,
                                                                       outComponentMask);
    if (error == hal::Error::UNSUPPORTED) RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::setDisplayContentSamplingEnabled(HalDisplayId displayId, bool enabled,
                                                      uint8_t componentMask, uint64_t maxFrames) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mDisplayData[displayId].hwcDisplay->setDisplayContentSamplingEnabled(enabled,
                                                                                 componentMask,
                                                                                 maxFrames);

    if (error == hal::Error::UNSUPPORTED) RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    if (error == hal::Error::BAD_PARAMETER) RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::getDisplayedContentSample(HalDisplayId displayId, uint64_t maxFrames,
                                               uint64_t timestamp, DisplayedFrameStats* outStats) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mDisplayData[displayId].hwcDisplay->getDisplayedContentSample(maxFrames, timestamp,
                                                                          outStats);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

ftl::Future<status_t> HWComposer::setDisplayBrightness(
        PhysicalDisplayId displayId, float brightness, float brightnessNits,
        const Hwc2::Composer::DisplayBrightnessOptions& options) {
    RETURN_IF_INVALID_DISPLAY(displayId, ftl::yield<status_t>(BAD_INDEX));
    auto& display = mDisplayData[displayId].hwcDisplay;

    return display->setDisplayBrightness(brightness, brightnessNits, options)
            .then([displayId](hal::Error error) -> status_t {
                if (error == hal::Error::UNSUPPORTED) {
                    RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
                }
                if (error == hal::Error::BAD_PARAMETER) {
                    RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
                }
                RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
                return NO_ERROR;
            });
}

bool HWComposer::getValidateSkipped(HalDisplayId displayId) const {
    if (mDisplayData.count(displayId) == 0) {
        return false;
    }
    return mDisplayData.at(displayId).validateWasSkipped;
}

status_t HWComposer::setBootDisplayMode(PhysicalDisplayId displayId,
                                        hal::HWConfigId displayModeId) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->setBootDisplayConfig(displayModeId);
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::clearBootDisplayMode(PhysicalDisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->clearBootDisplayConfig();
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

std::optional<hal::HWConfigId> HWComposer::getPreferredBootDisplayMode(
        PhysicalDisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId, std::nullopt);
    hal::HWConfigId displayModeId;
    const auto error =
            mDisplayData[displayId].hwcDisplay->getPreferredBootDisplayConfig(&displayModeId);
    if (error != hal::Error::NONE) {
        LOG_DISPLAY_ERROR(displayId, to_string(error).c_str());
        return std::nullopt;
    }
    return displayModeId;
}

std::vector<HdrConversionCapability> HWComposer::getHdrConversionCapabilities() const {
    return mHdrConversionCapabilities;
}

status_t HWComposer::setHdrConversionStrategy(
        HdrConversionStrategy hdrConversionStrategy,
        aidl::android::hardware::graphics::common::Hdr* outPreferredHdrOutputType) {
    const auto error =
            mComposer->setHdrConversionStrategy(hdrConversionStrategy, outPreferredHdrOutputType);
    if (error != hal::Error::NONE) {
        ALOGE("Error in setting HDR conversion strategy %s", to_string(error).c_str());
        return INVALID_OPERATION;
    }
    return NO_ERROR;
}

status_t HWComposer::setRefreshRateChangedCallbackDebugEnabled(PhysicalDisplayId displayId,
                                                               bool enabled) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mComposer->setRefreshRateChangedCallbackDebugEnabled(mDisplayData[displayId]
                                                                         .hwcDisplay->getId(),
                                                                 enabled);
    if (error != hal::Error::NONE) {
        ALOGE("Error in setting refresh refresh rate change callback debug enabled %s",
              to_string(error).c_str());
        return INVALID_OPERATION;
    }
    return NO_ERROR;
}

status_t HWComposer::notifyExpectedPresent(PhysicalDisplayId displayId,
                                           TimePoint expectedPresentTime, Fps frameInterval) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    ATRACE_FORMAT("%s ExpectedPresentTime in %.2fms frameInterval %.2fms", __func__,
                  ticks<std::milli, float>(expectedPresentTime - TimePoint::now()),
                  ticks<std::milli, float>(Duration::fromNs(frameInterval.getPeriodNsecs())));
    const auto error = mComposer->notifyExpectedPresent(mDisplayData[displayId].hwcDisplay->getId(),
                                                        expectedPresentTime.ns(),
                                                        frameInterval.getPeriodNsecs());
    if (error != hal::Error::NONE) {
        ALOGE("Error in notifyExpectedPresent call %s", to_string(error).c_str());
        return INVALID_OPERATION;
    }
    return NO_ERROR;
}

status_t HWComposer::getDisplayDecorationSupport(
        PhysicalDisplayId displayId,
        std::optional<aidl::android::hardware::graphics::common::DisplayDecorationSupport>*
                support) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->getDisplayDecorationSupport(support);
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::setAutoLowLatencyMode(PhysicalDisplayId displayId, bool on) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->setAutoLowLatencyMode(on);
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::getSupportedContentTypes(
        PhysicalDisplayId displayId,
        std::vector<hal::ContentType>* outSupportedContentTypes) const {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData.at(displayId).hwcDisplay->getSupportedContentTypes(
            outSupportedContentTypes);

    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);

    return NO_ERROR;
}

status_t HWComposer::setContentType(PhysicalDisplayId displayId, hal::ContentType contentType) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->setContentType(contentType);
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);

    return NO_ERROR;
}

const std::unordered_map<std::string, bool>& HWComposer::getSupportedLayerGenericMetadata() const {
    return mSupportedLayerGenericMetadata;
}

void HWComposer::dump(std::string& result) const {
    result.append(mComposer->dumpDebugInfo());
}

std::optional<PhysicalDisplayId> HWComposer::toPhysicalDisplayId(
        hal::HWDisplayId hwcDisplayId) const {
    if (const auto it = mPhysicalDisplayIdMap.find(hwcDisplayId);
        it != mPhysicalDisplayIdMap.end()) {
        return it->second;
    }
    return {};
}

std::optional<hal::HWDisplayId> HWComposer::fromPhysicalDisplayId(
        PhysicalDisplayId displayId) const {
    if (const auto it = mDisplayData.find(displayId); it != mDisplayData.end()) {
        return it->second.hwcDisplay->getId();
    }
    return {};
}

bool HWComposer::shouldIgnoreHotplugConnect(hal::HWDisplayId hwcDisplayId,
                                            bool hasDisplayIdentificationData) const {
    if (mHasMultiDisplaySupport && !hasDisplayIdentificationData) {
        ALOGE("Ignoring connection of display %" PRIu64 " without identification data",
              hwcDisplayId);
        return true;
    }

    // Legacy mode only supports IDs LEGACY_DISPLAY_TYPE_PRIMARY and LEGACY_DISPLAY_TYPE_EXTERNAL.
    if (!mHasMultiDisplaySupport && mPhysicalDisplayIdMap.size() == 2) {
        ALOGE("Ignoring connection of tertiary display %" PRIu64, hwcDisplayId);
        return true;
    }

    return false;
}

std::optional<DisplayIdentificationInfo> HWComposer::onHotplugConnect(
        hal::HWDisplayId hwcDisplayId) {
    std::optional<DisplayIdentificationInfo> info;
    if (const auto displayId = toPhysicalDisplayId(hwcDisplayId)) {
        info = DisplayIdentificationInfo{.id = *displayId,
                                         .name = std::string(),
                                         .deviceProductInfo = std::nullopt};
        if (mUpdateDeviceProductInfoOnHotplugReconnect) {
            uint8_t port;
            DisplayIdentificationData data;
            getDisplayIdentificationData(hwcDisplayId, &port, &data);
            if (auto newInfo = parseDisplayIdentificationData(port, data)) {
                info->deviceProductInfo = std::move(newInfo->deviceProductInfo);
            } else {
                ALOGE("Failed to parse identification data for display %" PRIu64, hwcDisplayId);
            }
        }
    } else {
        uint8_t port;
        DisplayIdentificationData data;
        const bool hasDisplayIdentificationData =
                getDisplayIdentificationData(hwcDisplayId, &port, &data);
        if (mPhysicalDisplayIdMap.empty()) {
            mHasMultiDisplaySupport = hasDisplayIdentificationData;
            ALOGI("Switching to %s multi-display mode",
                  mHasMultiDisplaySupport ? "generalized" : "legacy");
        }

        if (shouldIgnoreHotplugConnect(hwcDisplayId, hasDisplayIdentificationData)) {
            return {};
        }

        info = [this, hwcDisplayId, &port, &data, hasDisplayIdentificationData] {
            const bool isPrimary = !mPrimaryHwcDisplayId;
            if (mHasMultiDisplaySupport) {
                if (const auto info = parseDisplayIdentificationData(port, data)) {
                    return *info;
                }
                ALOGE("Failed to parse identification data for display %" PRIu64, hwcDisplayId);
            } else {
                ALOGW_IF(hasDisplayIdentificationData,
                         "Ignoring identification data for display %" PRIu64, hwcDisplayId);
                port = isPrimary ? LEGACY_DISPLAY_TYPE_PRIMARY : LEGACY_DISPLAY_TYPE_EXTERNAL;
            }

            return DisplayIdentificationInfo{.id = PhysicalDisplayId::fromPort(port),
                                             .name = isPrimary ? "Primary display"
                                                               : "Secondary display",
                                             .deviceProductInfo = std::nullopt};
        }();

        mComposer->onHotplugConnect(hwcDisplayId);
    }

    if (!isConnected(info->id)) {
        allocatePhysicalDisplay(hwcDisplayId, info->id);
    }
    return info;
}

std::optional<DisplayIdentificationInfo> HWComposer::onHotplugDisconnect(
        hal::HWDisplayId hwcDisplayId) {
    LOG_ALWAYS_FATAL_IF(hwcDisplayId == mPrimaryHwcDisplayId,
                        "Primary display cannot be disconnected.");

    const auto displayId = toPhysicalDisplayId(hwcDisplayId);
    if (!displayId) {
        LOG_HWC_DISPLAY_ERROR(hwcDisplayId, "Invalid HWC display");
        return {};
    }

    if (!isConnected(*displayId)) {
        LOG_HWC_DISPLAY_ERROR(hwcDisplayId, "Already disconnected");
        return {};
    }

    // The display will later be destroyed by a call to HWComposer::disconnectDisplay. For now, mark
    // it as disconnected.
    mDisplayData.at(*displayId).hwcDisplay->setConnected(false);
    mComposer->onHotplugDisconnect(hwcDisplayId);
    return DisplayIdentificationInfo{.id = *displayId};
}

void HWComposer::loadCapabilities() {
    static_assert(sizeof(hal::Capability) == sizeof(int32_t), "Capability size has changed");
    auto capabilities = mComposer->getCapabilities();
    for (auto capability : capabilities) {
        mCapabilities.emplace(capability);
    }
}

void HWComposer::loadOverlayProperties() {
    mComposer->getOverlaySupport(&mOverlayProperties);
}

void HWComposer::loadHdrConversionCapabilities() {
    const auto error = mComposer->getHdrConversionCapabilities(&mHdrConversionCapabilities);
    if (error != hal::Error::NONE) {
        ALOGE("Error in fetching HDR conversion capabilities %s", to_string(error).c_str());
        mHdrConversionCapabilities = {};
    }
}

status_t HWComposer::setIdleTimerEnabled(PhysicalDisplayId displayId,
                                         std::chrono::milliseconds timeout) {
    ATRACE_CALL();
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->setIdleTimerEnabled(timeout);
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

bool HWComposer::hasDisplayIdleTimerCapability(PhysicalDisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, false);
    return mDisplayData.at(displayId).hwcDisplay->hasDisplayIdleTimerCapability();
}

Hwc2::AidlTransform HWComposer::getPhysicalDisplayOrientation(PhysicalDisplayId displayId) const {
    ATRACE_CALL();
    RETURN_IF_INVALID_DISPLAY(displayId, Hwc2::AidlTransform::NONE);
    Hwc2::AidlTransform outTransform;
    const auto& hwcDisplay = mDisplayData.at(displayId).hwcDisplay;
    const auto error = hwcDisplay->getPhysicalDisplayOrientation(&outTransform);
    RETURN_IF_HWC_ERROR(error, displayId, Hwc2::AidlTransform::NONE);
    return outTransform;
}

void HWComposer::loadLayerMetadataSupport() {
    mSupportedLayerGenericMetadata.clear();

    std::vector<Hwc2::IComposerClient::LayerGenericMetadataKey> supportedMetadataKeyInfo;
    const auto error = mComposer->getLayerGenericMetadataKeys(&supportedMetadataKeyInfo);
    if (error != hardware::graphics::composer::V2_4::Error::NONE) {
        if (error != hardware::graphics::composer::V2_4::Error::UNSUPPORTED) {
            ALOGE("%s: %s failed: %s (%d)", __FUNCTION__, "getLayerGenericMetadataKeys",
                  toString(error).c_str(), static_cast<int32_t>(error));
        }
        return;
    }

    for (const auto& [name, mandatory] : supportedMetadataKeyInfo) {
        mSupportedLayerGenericMetadata.emplace(name, mandatory);
    }
}

} // namespace impl
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
