/*
 * Copyright 2017 The Android Open Source Project
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

#include <chrono>

#include <composer-hal/2.1/ComposerClient.h>
#include <composer-hal/2.2/ComposerClient.h>
#include <composer-hal/2.3/ComposerClient.h>
#include <composer-hal/2.4/ComposerClient.h>
#include <utils/Condition.h>

#include "MockComposerHal.h"
#include "RenderState.h"

using namespace android::hardware::graphics::common;
using namespace android::hardware::graphics::composer;
using namespace android::hardware::graphics::composer::V2_4;
using namespace android::hardware::graphics::composer::V2_4::hal;
using namespace android::hardware;
using namespace std::chrono_literals;

namespace {
class LayerImpl;
class Frame;
class DelayedEventGenerator;
} // namespace

namespace android {
class SurfaceComposerClient;
} // namespace android

namespace sftest {
// NOTE: The ID's need to be exactly these. VR composer and parts of
// the SurfaceFlinger assume the display IDs to have these values
// despite the enum being documented as a display type.
// TODO: Reference to actual documentation
constexpr Display PRIMARY_DISPLAY = static_cast<Display>(HWC_DISPLAY_PRIMARY);
constexpr Display EXTERNAL_DISPLAY = static_cast<Display>(HWC_DISPLAY_EXTERNAL);

class FakeComposerClient : public ComposerHal {
public:
    FakeComposerClient();
    virtual ~FakeComposerClient();

    void setMockHal(MockComposerHal* mockHal) { mMockHal = mockHal; }

    bool hasCapability(hwc2_capability_t capability) override;

    std::string dumpDebugInfo() override;
    void registerEventCallback(EventCallback* callback) override;
    void unregisterEventCallback() override;

    uint32_t getMaxVirtualDisplayCount() override;
    V2_1::Error createVirtualDisplay(uint32_t width, uint32_t height, V1_0::PixelFormat* format,
                                     Display* outDisplay) override;
    V2_1::Error destroyVirtualDisplay(Display display) override;
    V2_1::Error createLayer(Display display, Layer* outLayer) override;
    V2_1::Error destroyLayer(Display display, Layer layer) override;

    V2_1::Error getActiveConfig(Display display, Config* outConfig) override;
    V2_1::Error getClientTargetSupport(Display display, uint32_t width, uint32_t height,
                                       V1_0::PixelFormat format,
                                       V1_0::Dataspace dataspace) override;
    V2_1::Error getColorModes(Display display, hidl_vec<V1_0::ColorMode>* outModes) override;
    V2_1::Error getDisplayAttribute(Display display, Config config,
                                    V2_1::IComposerClient::Attribute attribute,
                                    int32_t* outValue) override;
    V2_1::Error getDisplayConfigs(Display display, hidl_vec<Config>* outConfigs) override;
    V2_1::Error getDisplayName(Display display, hidl_string* outName) override;
    V2_1::Error getDisplayType(Display display, IComposerClient::DisplayType* outType) override;
    V2_1::Error getDozeSupport(Display display, bool* outSupport) override;
    V2_1::Error getHdrCapabilities(Display display, hidl_vec<V1_0::Hdr>* outTypes,
                                   float* outMaxLuminance, float* outMaxAverageLuminance,
                                   float* outMinLuminance) override;

    V2_1::Error setActiveConfig(Display display, Config config) override;
    V2_1::Error setColorMode(Display display, V1_0::ColorMode mode) override;
    V2_1::Error setPowerMode(Display display, V2_1::IComposerClient::PowerMode mode) override;
    V2_1::Error setVsyncEnabled(Display display, IComposerClient::Vsync enabled) override;

    V2_1::Error setColorTransform(Display display, const float* matrix, int32_t hint) override;
    V2_1::Error setClientTarget(Display display, buffer_handle_t target, int32_t acquireFence,
                                int32_t dataspace, const std::vector<hwc_rect_t>& damage) override;
    V2_1::Error setOutputBuffer(Display display, buffer_handle_t buffer,
                                int32_t releaseFence) override;
    V2_1::Error validateDisplay(Display display, std::vector<Layer>* outChangedLayers,
                                std::vector<IComposerClient::Composition>* outCompositionTypes,
                                uint32_t* outDisplayRequestMask,
                                std::vector<Layer>* outRequestedLayers,
                                std::vector<uint32_t>* outRequestMasks) override;
    V2_1::Error acceptDisplayChanges(Display display) override;
    V2_1::Error presentDisplay(Display display, int32_t* outPresentFence,
                               std::vector<Layer>* outLayers,
                               std::vector<int32_t>* outReleaseFences) override;

    V2_1::Error setLayerCursorPosition(Display display, Layer layer, int32_t x, int32_t y) override;
    V2_1::Error setLayerBuffer(Display display, Layer layer, buffer_handle_t buffer,
                               int32_t acquireFence) override;
    V2_1::Error setLayerSurfaceDamage(Display display, Layer layer,
                                      const std::vector<hwc_rect_t>& damage) override;
    V2_1::Error setLayerBlendMode(Display display, Layer layer, int32_t mode) override;
    V2_1::Error setLayerColor(Display display, Layer layer, IComposerClient::Color color) override;
    V2_1::Error setLayerCompositionType(Display display, Layer layer, int32_t type) override;
    V2_1::Error setLayerDataspace(Display display, Layer layer, int32_t dataspace) override;
    V2_1::Error setLayerDisplayFrame(Display display, Layer layer,
                                     const hwc_rect_t& frame) override;
    V2_1::Error setLayerPlaneAlpha(Display display, Layer layer, float alpha) override;
    V2_1::Error setLayerSidebandStream(Display display, Layer layer,
                                       buffer_handle_t stream) override;
    V2_1::Error setLayerSourceCrop(Display display, Layer layer, const hwc_frect_t& crop) override;
    V2_1::Error setLayerTransform(Display display, Layer layer, int32_t transform) override;
    V2_1::Error setLayerVisibleRegion(Display display, Layer layer,
                                      const std::vector<hwc_rect_t>& visible) override;
    V2_1::Error setLayerZOrder(Display display, Layer layer, uint32_t z) override;

    // Composer 2.2
    V2_1::Error getPerFrameMetadataKeys(
            Display display,
            std::vector<V2_2::IComposerClient::PerFrameMetadataKey>* outKeys) override;
    V2_1::Error setLayerPerFrameMetadata(
            Display display, Layer layer,
            const std::vector<V2_2::IComposerClient::PerFrameMetadata>& metadata) override;

    V2_1::Error getReadbackBufferAttributes(
            Display display, graphics::common::V1_1::PixelFormat* outFormat,
            graphics::common::V1_1::Dataspace* outDataspace) override;
    V2_1::Error setReadbackBuffer(Display display, const native_handle_t* bufferHandle,
                                  android::base::unique_fd fenceFd) override;
    V2_1::Error getReadbackBufferFence(Display display,
                                       android::base::unique_fd* outFenceFd) override;
    V2_1::Error createVirtualDisplay_2_2(uint32_t width, uint32_t height,
                                         graphics::common::V1_1::PixelFormat* format,
                                         Display* outDisplay) override;
    V2_1::Error getClientTargetSupport_2_2(Display display, uint32_t width, uint32_t height,
                                           graphics::common::V1_1::PixelFormat format,
                                           graphics::common::V1_1::Dataspace dataspace) override;
    V2_1::Error setPowerMode_2_2(Display display, V2_2::IComposerClient::PowerMode mode) override;

    V2_1::Error setLayerFloatColor(Display display, Layer layer,
                                   V2_2::IComposerClient::FloatColor color) override;

    V2_1::Error getColorModes_2_2(Display display,
                                  hidl_vec<graphics::common::V1_1::ColorMode>* outModes) override;
    V2_1::Error getRenderIntents(
            Display display, graphics::common::V1_1::ColorMode mode,
            std::vector<graphics::common::V1_1::RenderIntent>* outIntents) override;
    V2_1::Error setColorMode_2_2(Display display, graphics::common::V1_1::ColorMode mode,
                                 graphics::common::V1_1::RenderIntent intent) override;

    std::array<float, 16> getDataspaceSaturationMatrix(
            graphics::common::V1_1::Dataspace dataspace) override;

    // Composer 2.3
    V2_1::Error getPerFrameMetadataKeys_2_3(
            Display display,
            std::vector<V2_3::IComposerClient::PerFrameMetadataKey>* outKeys) override;

    V2_1::Error setColorMode_2_3(Display display, graphics::common::V1_2::ColorMode mode,
                                 graphics::common::V1_1::RenderIntent intent) override;

    V2_1::Error getRenderIntents_2_3(
            Display display, graphics::common::V1_2::ColorMode mode,
            std::vector<graphics::common::V1_1::RenderIntent>* outIntents) override;

    V2_1::Error getColorModes_2_3(Display display,
                                  hidl_vec<graphics::common::V1_2::ColorMode>* outModes) override;

    V2_1::Error getClientTargetSupport_2_3(Display display, uint32_t width, uint32_t height,
                                           graphics::common::V1_2::PixelFormat format,
                                           graphics::common::V1_2::Dataspace dataspace) override;
    V2_1::Error getReadbackBufferAttributes_2_3(
            Display display, graphics::common::V1_2::PixelFormat* outFormat,
            graphics::common::V1_2::Dataspace* outDataspace) override;
    V2_1::Error getHdrCapabilities_2_3(Display display,
                                       hidl_vec<graphics::common::V1_2::Hdr>* outTypes,
                                       float* outMaxLuminance, float* outMaxAverageLuminance,
                                       float* outMinLuminance) override;
    V2_1::Error setLayerPerFrameMetadata_2_3(
            Display display, Layer layer,
            const std::vector<V2_3::IComposerClient::PerFrameMetadata>& metadata) override;
    V2_1::Error getDisplayIdentificationData(Display display, uint8_t* outPort,
                                             std::vector<uint8_t>* outData) override;
    V2_1::Error setLayerColorTransform(Display display, Layer layer, const float* matrix) override;
    V2_1::Error getDisplayedContentSamplingAttributes(
            uint64_t display, graphics::common::V1_2::PixelFormat& format,
            graphics::common::V1_2::Dataspace& dataspace,
            hidl_bitfield<V2_3::IComposerClient::FormatColorComponent>& componentMask) override;
    V2_1::Error setDisplayedContentSamplingEnabled(
            uint64_t display, V2_3::IComposerClient::DisplayedContentSampling enable,
            hidl_bitfield<V2_3::IComposerClient::FormatColorComponent> componentMask,
            uint64_t maxFrames) override;
    V2_1::Error getDisplayedContentSample(uint64_t display, uint64_t maxFrames, uint64_t timestamp,
                                          uint64_t& frameCount,
                                          hidl_vec<uint64_t>& sampleComponent0,
                                          hidl_vec<uint64_t>& sampleComponent1,
                                          hidl_vec<uint64_t>& sampleComponent2,
                                          hidl_vec<uint64_t>& sampleComponent3) override;
    V2_1::Error getDisplayCapabilities(
            Display display,
            std::vector<V2_3::IComposerClient::DisplayCapability>* outCapabilities) override;
    V2_1::Error setLayerPerFrameMetadataBlobs(
            Display display, Layer layer,
            std::vector<V2_3::IComposerClient::PerFrameMetadataBlob>& blobs) override;
    V2_1::Error getDisplayBrightnessSupport(Display display, bool* outSupport) override;
    V2_1::Error setDisplayBrightness(Display display, float brightness) override;

    // Composer 2.4
    void registerEventCallback_2_4(EventCallback_2_4* callback) override;

    void unregisterEventCallback_2_4() override;

    V2_4::Error getDisplayCapabilities_2_4(
            Display display,
            std::vector<V2_4::IComposerClient::DisplayCapability>* outCapabilities) override;
    V2_4::Error getDisplayConnectionType(
            Display display, V2_4::IComposerClient::DisplayConnectionType* outType) override;
    V2_4::Error getDisplayAttribute_2_4(Display display, Config config,
                                        IComposerClient::Attribute attribute,
                                        int32_t* outValue) override;
    V2_4::Error getDisplayVsyncPeriod(Display display,
                                      V2_4::VsyncPeriodNanos* outVsyncPeriod) override;
    V2_4::Error setActiveConfigWithConstraints(
            Display display, Config config,
            const V2_4::IComposerClient::VsyncPeriodChangeConstraints& vsyncPeriodChangeConstraints,
            VsyncPeriodChangeTimeline* outTimeline) override;
    V2_4::Error setAutoLowLatencyMode(Display display, bool on) override;
    V2_4::Error getSupportedContentTypes(
            Display display,
            std::vector<IComposerClient::ContentType>* outSupportedContentTypes) override;
    V2_4::Error setContentType(Display display, IComposerClient::ContentType type) override;
    V2_4::Error validateDisplay_2_4(
            Display display, std::vector<Layer>* outChangedLayers,
            std::vector<IComposerClient::Composition>* outCompositionTypes,
            uint32_t* outDisplayRequestMask, std::vector<Layer>* outRequestedLayers,
            std::vector<uint32_t>* outRequestMasks,
            IComposerClient::ClientTargetProperty* outClientTargetProperty) override;
    V2_4::Error setLayerGenericMetadata(Display display, Layer layer, const std::string& key,
                                        bool mandatory, const std::vector<uint8_t>& value) override;
    V2_4::Error getLayerGenericMetadataKeys(
            std::vector<IComposerClient::LayerGenericMetadataKey>* outKeys) override;

    void setClient(ComposerClient* client);

    void requestVSync(uint64_t vsyncTime = 0);
    // We don't want tests hanging, so always use a timeout. Remember
    // to always check the number of frames with test ASSERT_!
    // Wait until next frame is rendered after requesting vsync.
    void runVSyncAndWait(std::chrono::nanoseconds maxWait = 100ms);
    void runVSyncAfter(std::chrono::nanoseconds wait);

    int getFrameCount() const;
    // We don't want tests hanging, so always use a timeout. Remember
    // to always check the number of frames with test ASSERT_!
    void waitUntilFrame(int targetFrame, std::chrono::nanoseconds maxWait = 100ms) const;
    std::vector<RenderState> getFrameRects(int frame) const;
    std::vector<RenderState> getLatestFrame() const;
    void clearFrames();

    void onSurfaceFlingerStart();
    void onSurfaceFlingerStop();

    int getLayerCount() const;
    Layer getLayer(size_t index) const;

    void hotplugDisplay(Display display, IComposerCallback::Connection state);
    void refreshDisplay(Display display);

private:
    LayerImpl& getLayerImpl(Layer handle);

    EventCallback* mEventCallback;
    EventCallback_2_4* mEventCallback_2_4;
    Config mCurrentConfig;
    bool mVsyncEnabled;
    std::vector<std::unique_ptr<LayerImpl>> mLayers;
    std::vector<std::unique_ptr<Frame>> mFrames;
    // Using a pointer to hide the implementation into the CPP file.
    std::unique_ptr<DelayedEventGenerator> mDelayedEventGenerator;
    android::sp<android::SurfaceComposerClient> mSurfaceComposer; // For VSync injections
    mutable android::Mutex mStateMutex;
    mutable android::Condition mFramesAvailable;

    MockComposerHal* mMockHal = nullptr;
};

} // namespace sftest
