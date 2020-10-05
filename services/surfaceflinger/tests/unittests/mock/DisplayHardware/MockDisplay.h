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

#pragma once

#include <gmock/gmock.h>

#include "DisplayHardware/HWC2.h"

using android::HWC2::Layer;

namespace android {
namespace Hwc2 {
namespace mock {

namespace hal = android::hardware::graphics::composer::hal;

class Display : public HWC2::Display {
public:
    using Layer = ::Layer;

    Display();
    ~Display();

    MOCK_CONST_METHOD0(getId, hal::HWDisplayId());
    MOCK_CONST_METHOD0(isConnected, bool());
    MOCK_METHOD1(setConnected, void(bool));
    MOCK_CONST_METHOD0(getCapabilities, const std::unordered_set<hal::DisplayCapability>&());

    MOCK_METHOD0(acceptChanges, hal::Error());
    MOCK_METHOD1(createLayer, hal::Error(Layer**));
    MOCK_METHOD1(destroyLayer, hal::Error(Layer*));
    MOCK_CONST_METHOD1(getActiveConfig, hal::Error(std::shared_ptr<const Config>*));
    MOCK_CONST_METHOD1(getActiveConfigIndex, hal::Error(int* outIndex));
    MOCK_METHOD1(getChangedCompositionTypes,
                 hal::Error(std::unordered_map<Layer*, hal::Composition>*));
    MOCK_CONST_METHOD1(getColorModes, hal::Error(std::vector<hal::ColorMode>*));

    MOCK_CONST_METHOD0(getSupportedPerFrameMetadata, int32_t());
    MOCK_CONST_METHOD2(getRenderIntents,
                       hal::Error(hal::ColorMode, std::vector<hal::RenderIntent>*));
    MOCK_METHOD2(getDataspaceSaturationMatrix, hal::Error(hal::Dataspace, android::mat4*));
    MOCK_CONST_METHOD0(getConfigs, std::vector<std::shared_ptr<const Config>>());

    MOCK_CONST_METHOD1(getName, hal::Error(std::string*));
    MOCK_METHOD2(getRequests,
                 hal::Error(hal::DisplayRequest*, std::unordered_map<Layer*, hal::LayerRequest>*));
    MOCK_CONST_METHOD1(getType, hal::Error(hal::DisplayType*));
    MOCK_CONST_METHOD1(supportsDoze, hal::Error(bool*));
    MOCK_CONST_METHOD1(getHdrCapabilities, hal::Error(android::HdrCapabilities*));
    MOCK_CONST_METHOD3(getDisplayedContentSamplingAttributes,
                       hal::Error(hal::PixelFormat*, hal::Dataspace*, uint8_t*));
    MOCK_CONST_METHOD3(setDisplayContentSamplingEnabled, hal::Error(bool, uint8_t, uint64_t));
    MOCK_CONST_METHOD3(getDisplayedContentSample,
                       hal::Error(uint64_t, uint64_t, android::DisplayedFrameStats*));
    MOCK_CONST_METHOD1(
            getReleaseFences,
            hal::Error(std::unordered_map<Layer*, android::sp<android::Fence>>* outFences));
    MOCK_METHOD1(present, hal::Error(android::sp<android::Fence>*));
    MOCK_METHOD1(setActiveConfig, hal::Error(const std::shared_ptr<const HWC2::Display::Config>&));
    MOCK_METHOD4(setClientTarget,
                 hal::Error(uint32_t, const android::sp<android::GraphicBuffer>&,
                            const android::sp<android::Fence>&, hal::Dataspace));
    MOCK_METHOD2(setColorMode, hal::Error(hal::ColorMode, hal::RenderIntent));
    MOCK_METHOD2(setColorTransform, hal::Error(const android::mat4&, hal::ColorTransform));
    MOCK_METHOD2(setOutputBuffer,
                 hal::Error(const android::sp<android::GraphicBuffer>&,
                            const android::sp<android::Fence>&));
    MOCK_METHOD1(setPowerMode, hal::Error(hal::PowerMode));
    MOCK_METHOD1(setVsyncEnabled, hal::Error(hal::Vsync));
    MOCK_METHOD2(validate, hal::Error(uint32_t*, uint32_t*));
    MOCK_METHOD4(presentOrValidate,
                 hal::Error(uint32_t*, uint32_t*, android::sp<android::Fence>*, uint32_t*));
    MOCK_METHOD1(setDisplayBrightness, std::future<hal::Error>(float));
    MOCK_CONST_METHOD1(getDisplayVsyncPeriod, hal::Error(nsecs_t*));
    MOCK_METHOD3(setActiveConfigWithConstraints,
                 hal::Error(const std::shared_ptr<const HWC2::Display::Config>&,
                            const hal::VsyncPeriodChangeConstraints&,
                            hal::VsyncPeriodChangeTimeline*));
    MOCK_METHOD1(setAutoLowLatencyMode, hal::Error(bool on));
    MOCK_CONST_METHOD1(getSupportedContentTypes, hal::Error(std::vector<hal::ContentType>*));
    MOCK_METHOD1(setContentType, hal::Error(hal::ContentType));
    MOCK_METHOD1(getClientTargetProperty, hal::Error(hal::ClientTargetProperty*));
    MOCK_CONST_METHOD1(getConnectionType, hal::Error(android::DisplayConnectionType*));
    MOCK_CONST_METHOD0(isVsyncPeriodSwitchSupported, bool());
};

} // namespace mock
} // namespace Hwc2
} // namespace android
