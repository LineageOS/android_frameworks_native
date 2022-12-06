/*
 * Copyright 2018 The Android Open Source Project
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

#pragma once

#include <compositionengine/Output.h>
#include <gmock/gmock.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include "DisplayHardware/HWComposer.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

namespace android {
namespace mock {

namespace hal = android::hardware::graphics::composer::hal;

class HWComposer : public android::HWComposer {
public:
    HWComposer();
    ~HWComposer() override;

    MOCK_METHOD1(setCallback, void(HWC2::ComposerCallback&));
    MOCK_CONST_METHOD3(getDisplayIdentificationData,
                       bool(hal::HWDisplayId, uint8_t*, DisplayIdentificationData*));
    MOCK_CONST_METHOD1(hasCapability,
                       bool(aidl::android::hardware::graphics::composer3::Capability));
    MOCK_CONST_METHOD2(hasDisplayCapability,
                       bool(HalDisplayId,
                            aidl::android::hardware::graphics::composer3::DisplayCapability));

    MOCK_CONST_METHOD0(getMaxVirtualDisplayCount, size_t());
    MOCK_CONST_METHOD0(getMaxVirtualDisplayDimension, size_t());
    MOCK_METHOD3(allocateVirtualDisplay, bool(HalVirtualDisplayId, ui::Size, ui::PixelFormat*));
    MOCK_METHOD2(allocatePhysicalDisplay, void(hal::HWDisplayId, PhysicalDisplayId));

    MOCK_METHOD1(createLayer, std::shared_ptr<HWC2::Layer>(HalDisplayId));
    MOCK_METHOD6(getDeviceCompositionChanges,
                 status_t(HalDisplayId, bool, std::chrono::steady_clock::time_point,
                          const std::shared_ptr<FenceTime>&, nsecs_t,
                          std::optional<android::HWComposer::DeviceRequestedChanges>*));
    MOCK_METHOD5(setClientTarget,
                 status_t(HalDisplayId, uint32_t, const sp<Fence>&, const sp<GraphicBuffer>&,
                          ui::Dataspace));
    MOCK_METHOD3(presentAndGetReleaseFences,
                 status_t(HalDisplayId, std::chrono::steady_clock::time_point,
                          const std::shared_ptr<FenceTime>&));
    MOCK_METHOD2(setPowerMode, status_t(PhysicalDisplayId, hal::PowerMode));
    MOCK_METHOD2(setActiveConfig, status_t(HalDisplayId, size_t));
    MOCK_METHOD2(setColorTransform, status_t(HalDisplayId, const mat4&));
    MOCK_METHOD1(disconnectDisplay, void(HalDisplayId));
    MOCK_CONST_METHOD1(hasDeviceComposition, bool(const std::optional<DisplayId>&));
    MOCK_CONST_METHOD1(getPresentFence, sp<Fence>(HalDisplayId));
    MOCK_CONST_METHOD2(getLayerReleaseFence, sp<Fence>(HalDisplayId, HWC2::Layer*));
    MOCK_METHOD3(setOutputBuffer,
                 status_t(HalVirtualDisplayId, const sp<Fence>&, const sp<GraphicBuffer>&));
    MOCK_METHOD1(clearReleaseFences, void(HalDisplayId));
    MOCK_METHOD2(getHdrCapabilities, status_t(HalDisplayId, HdrCapabilities*));
    MOCK_CONST_METHOD1(getSupportedPerFrameMetadata, int32_t(HalDisplayId));
    MOCK_CONST_METHOD2(getRenderIntents,
                       std::vector<ui::RenderIntent>(HalDisplayId, ui::ColorMode));
    MOCK_METHOD2(getDataspaceSaturationMatrix, mat4(HalDisplayId, ui::Dataspace));
    MOCK_METHOD4(getDisplayedContentSamplingAttributes,
                 status_t(HalDisplayId, ui::PixelFormat*, ui::Dataspace*, uint8_t*));
    MOCK_METHOD4(setDisplayContentSamplingEnabled, status_t(HalDisplayId, bool, uint8_t, uint64_t));
    MOCK_METHOD4(getDisplayedContentSample,
                 status_t(HalDisplayId, uint64_t, uint64_t, DisplayedFrameStats*));
    MOCK_METHOD(ftl::Future<status_t>, setDisplayBrightness,
                (PhysicalDisplayId, float, float, const Hwc2::Composer::DisplayBrightnessOptions&),
                (override));
    MOCK_METHOD2(getDisplayBrightnessSupport, status_t(PhysicalDisplayId, bool*));

    MOCK_METHOD2(onHotplug,
                 std::optional<DisplayIdentificationInfo>(hal::HWDisplayId, hal::Connection));
    MOCK_CONST_METHOD0(updatesDeviceProductInfoOnHotplugReconnect, bool());
    MOCK_METHOD2(onVsync, bool(hal::HWDisplayId, int64_t));
    MOCK_METHOD2(setVsyncEnabled, void(PhysicalDisplayId, hal::Vsync));
    MOCK_CONST_METHOD1(isConnected, bool(PhysicalDisplayId));
    MOCK_CONST_METHOD1(getModes, std::vector<HWComposer::HWCDisplayMode>(PhysicalDisplayId));
    MOCK_CONST_METHOD1(getActiveMode, std::optional<hal::HWConfigId>(PhysicalDisplayId));
    MOCK_CONST_METHOD1(getColorModes, std::vector<ui::ColorMode>(PhysicalDisplayId));
    MOCK_METHOD3(setActiveColorMode, status_t(PhysicalDisplayId, ui::ColorMode, ui::RenderIntent));
    MOCK_CONST_METHOD0(isUsingVrComposer, bool());
    MOCK_CONST_METHOD1(getDisplayConnectionType, ui::DisplayConnectionType(PhysicalDisplayId));
    MOCK_CONST_METHOD1(isVsyncPeriodSwitchSupported, bool(PhysicalDisplayId));
    MOCK_CONST_METHOD2(getDisplayVsyncPeriod, status_t(PhysicalDisplayId, nsecs_t*));
    MOCK_METHOD4(setActiveModeWithConstraints,
                 status_t(PhysicalDisplayId, hal::HWConfigId,
                          const hal::VsyncPeriodChangeConstraints&,
                          hal::VsyncPeriodChangeTimeline*));
    MOCK_METHOD2(setBootDisplayMode, status_t(PhysicalDisplayId, hal::HWConfigId));
    MOCK_METHOD1(clearBootDisplayMode, status_t(PhysicalDisplayId));
    MOCK_METHOD1(getPreferredBootDisplayMode, std::optional<hal::HWConfigId>(PhysicalDisplayId));
    MOCK_METHOD0(getBootDisplayModeSupport, bool());
    MOCK_METHOD2(setAutoLowLatencyMode, status_t(PhysicalDisplayId, bool));
    MOCK_METHOD(status_t, getSupportedContentTypes,
                (PhysicalDisplayId, std::vector<hal::ContentType>*), (const, override));
    MOCK_METHOD2(setContentType, status_t(PhysicalDisplayId, hal::ContentType));
    MOCK_CONST_METHOD0(getSupportedLayerGenericMetadata,
                       const std::unordered_map<std::string, bool>&());

    MOCK_CONST_METHOD1(dump, void(std::string&));
    MOCK_CONST_METHOD0(getComposer, android::Hwc2::Composer*());

    MOCK_METHOD(hal::HWDisplayId, getPrimaryHwcDisplayId, (), (const, override));
    MOCK_METHOD(PhysicalDisplayId, getPrimaryDisplayId, (), (const, override));
    MOCK_METHOD(bool, isHeadless, (), (const, override));

    MOCK_METHOD(std::optional<PhysicalDisplayId>, toPhysicalDisplayId, (hal::HWDisplayId),
                (const, override));
    MOCK_METHOD(std::optional<hal::HWDisplayId>, fromPhysicalDisplayId, (PhysicalDisplayId),
                (const, override));
    MOCK_METHOD2(getDisplayDecorationSupport,
                 status_t(PhysicalDisplayId,
                          std::optional<aidl::android::hardware::graphics::common::
                                                DisplayDecorationSupport>* support));
    MOCK_METHOD2(setIdleTimerEnabled, status_t(PhysicalDisplayId, std::chrono::milliseconds));
    MOCK_METHOD(bool, hasDisplayIdleTimerCapability, (PhysicalDisplayId), (const, override));
    MOCK_METHOD(Hwc2::AidlTransform, getPhysicalDisplayOrientation, (PhysicalDisplayId),
                (const, override));
    MOCK_METHOD(bool, getValidateSkipped, (HalDisplayId), (const, override));
};

} // namespace mock
} // namespace android
