/*
 * Copyright 2021 The Android Open Source Project
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

#include <gmock/gmock.h>

#include "DisplayHardware/HWC2.h"

namespace android::HWC2::mock {

class Display : public HWC2::Display {
public:
    Display();
    ~Display() override;

    MOCK_METHOD(hal::HWDisplayId, getId, (), (const, override));
    MOCK_METHOD(bool, isConnected, (), (const, override));
    MOCK_METHOD(void, setConnected, (bool), (override));
    MOCK_METHOD(bool, hasCapability,
                (aidl::android::hardware::graphics::composer3::DisplayCapability),
                (const, override));
    MOCK_METHOD(bool, isVsyncPeriodSwitchSupported, (), (const, override));
    MOCK_METHOD(void, onLayerDestroyed, (hal::HWLayerId), (override));

    MOCK_METHOD(hal::Error, acceptChanges, (), (override));
    MOCK_METHOD((base::expected<std::shared_ptr<HWC2::Layer>, hal::Error>), createLayer, (),
                (override));
    MOCK_METHOD(hal::Error, getChangedCompositionTypes,
                ((std::unordered_map<Layer *,
                                     aidl::android::hardware::graphics::composer3::Composition> *)),
                (override));
    MOCK_METHOD(hal::Error, getColorModes, (std::vector<hal::ColorMode> *), (const, override));
    MOCK_METHOD(int32_t, getSupportedPerFrameMetadata, (), (const, override));
    MOCK_METHOD(hal::Error, getRenderIntents, (hal::ColorMode, std::vector<hal::RenderIntent> *),
                (const, override));
    MOCK_METHOD(hal::Error, getDataspaceSaturationMatrix, (hal::Dataspace, android::mat4 *),
                (override));
    MOCK_METHOD(hal::Error, getName, (std::string *), (const, override));
    MOCK_METHOD(hal::Error, getRequests,
                (hal::DisplayRequest *, (std::unordered_map<Layer *, hal::LayerRequest> *)),
                (override));
    MOCK_METHOD((ftl::Expected<ui::DisplayConnectionType, hal::Error>), getConnectionType, (),
                (const, override));
    MOCK_METHOD(hal::Error, supportsDoze, (bool *), (const, override));
    MOCK_METHOD(hal::Error, getHdrCapabilities, (android::HdrCapabilities *), (const, override));
    MOCK_METHOD(hal::Error, getDisplayedContentSamplingAttributes,
                (hal::PixelFormat *, hal::Dataspace *, uint8_t *), (const, override));
    MOCK_METHOD(hal::Error, setDisplayContentSamplingEnabled, (bool, uint8_t, uint64_t),
                (const, override));
    MOCK_METHOD(hal::Error, getDisplayedContentSample,
                (uint64_t, uint64_t, android::DisplayedFrameStats *), (const, override));
    MOCK_METHOD(hal::Error, getReleaseFences,
                ((std::unordered_map<Layer *, android::sp<android::Fence>> *)), (const, override));
    MOCK_METHOD(hal::Error, present, (android::sp<android::Fence> *), (override));
    MOCK_METHOD(hal::Error, setClientTarget,
                (uint32_t, const android::sp<android::GraphicBuffer>&,
                 const android::sp<android::Fence>&, hal::Dataspace, float),
                (override));
    MOCK_METHOD(hal::Error, setColorMode, (hal::ColorMode, hal::RenderIntent), (override));
    MOCK_METHOD(hal::Error, setColorTransform, (const android::mat4 &), (override));
    MOCK_METHOD(hal::Error, setOutputBuffer,
                (const android::sp<android::GraphicBuffer> &, const android::sp<android::Fence> &),
                (override));
    MOCK_METHOD(hal::Error, setPowerMode, (hal::PowerMode), (override));
    MOCK_METHOD(hal::Error, setVsyncEnabled, (hal::Vsync), (override));
    MOCK_METHOD(hal::Error, validate, (nsecs_t, int32_t, uint32_t*, uint32_t*), (override));
    MOCK_METHOD(hal::Error, presentOrValidate,
                (nsecs_t, int32_t, uint32_t*, uint32_t*, android::sp<android::Fence>*, uint32_t*),
                (override));
    MOCK_METHOD(ftl::Future<hal::Error>, setDisplayBrightness,
                (float, float, const Hwc2::Composer::DisplayBrightnessOptions &), (override));
    MOCK_METHOD(hal::Error, setActiveConfigWithConstraints,
                (hal::HWConfigId, const hal::VsyncPeriodChangeConstraints &,
                 hal::VsyncPeriodChangeTimeline *),
                (override));
    MOCK_METHOD(hal::Error, setBootDisplayConfig, (hal::HWConfigId), (override));
    MOCK_METHOD(hal::Error, clearBootDisplayConfig, (), (override));
    MOCK_METHOD(hal::Error, getPreferredBootDisplayConfig, (hal::HWConfigId *), (const, override));
    MOCK_METHOD(hal::Error, setAutoLowLatencyMode, (bool), (override));
    MOCK_METHOD(hal::Error, getSupportedContentTypes, (std::vector<hal::ContentType> *),
                (const, override));
    MOCK_METHOD(hal::Error, setContentType, (hal::ContentType), (override));
    MOCK_METHOD(
            hal::Error, getClientTargetProperty,
            (aidl::android::hardware::graphics::composer3::ClientTargetPropertyWithBrightness *),
            (override));
    MOCK_METHOD(
            hal::Error, getDisplayDecorationSupport,
            (std::optional<aidl::android::hardware::graphics::common::DisplayDecorationSupport> *),
            (override));
    MOCK_METHOD(hal::Error, setIdleTimerEnabled, (std::chrono::milliseconds), (override));
    MOCK_METHOD(bool, hasDisplayIdleTimerCapability, (), (const override));
    MOCK_METHOD(hal::Error, getPhysicalDisplayOrientation, (Hwc2::AidlTransform *),
                (const override));
    MOCK_METHOD(hal::Error, getOverlaySupport,
                (aidl::android::hardware::graphics::composer3::OverlayProperties *),
                (const override));
};

class Layer : public HWC2::Layer {
public:
    Layer();
    ~Layer() override;

    MOCK_METHOD(hal::HWLayerId, getId, (), (const, override));
    MOCK_METHOD(hal::Error, setCursorPosition, (int32_t, int32_t), (override));
    MOCK_METHOD(hal::Error, setBuffer,
                (uint32_t, const android::sp<android::GraphicBuffer> &,
                 const android::sp<android::Fence> &),
                (override));
    MOCK_METHOD(hal::Error, setSurfaceDamage, (const android::Region &), (override));
    MOCK_METHOD(hal::Error, setBlendMode, (hal::BlendMode), (override));
    MOCK_METHOD(hal::Error, setColor, (aidl::android::hardware::graphics::composer3::Color),
                (override));
    MOCK_METHOD(hal::Error, setCompositionType,
                (aidl::android::hardware::graphics::composer3::Composition), (override));
    MOCK_METHOD(hal::Error, setDataspace, (android::ui::Dataspace), (override));
    MOCK_METHOD(hal::Error, setPerFrameMetadata, (const int32_t, const android::HdrMetadata &),
                (override));
    MOCK_METHOD(hal::Error, setDisplayFrame, (const android::Rect &), (override));
    MOCK_METHOD(hal::Error, setPlaneAlpha, (float), (override));
    MOCK_METHOD(hal::Error, setSidebandStream, (const native_handle_t *), (override));
    MOCK_METHOD(hal::Error, setSourceCrop, (const android::FloatRect &), (override));
    MOCK_METHOD(hal::Error, setTransform, (hal::Transform), (override));
    MOCK_METHOD(hal::Error, setVisibleRegion, (const android::Region &), (override));
    MOCK_METHOD(hal::Error, setZOrder, (uint32_t), (override));
    MOCK_METHOD(hal::Error, setColorTransform, (const android::mat4 &), (override));
    MOCK_METHOD(hal::Error, setLayerGenericMetadata,
                (const std::string &, bool, const std::vector<uint8_t> &), (override));
    MOCK_METHOD(hal::Error, setBrightness, (float), (override));
    MOCK_METHOD(hal::Error, setBlockingRegion, (const android::Region &), (override));
};

} // namespace android::HWC2::mock
