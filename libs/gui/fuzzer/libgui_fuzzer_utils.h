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
#include <android/gui/BnRegionSamplingListener.h>
#include <android/gui/BnSurfaceComposer.h>
#include <android/gui/BnSurfaceComposerClient.h>
#include <android/gui/IDisplayEventConnection.h>
#include <android/gui/ISurfaceComposerClient.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gui/BLASTBufferQueue.h>
#include <gui/DisplayEventDispatcher.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/LayerDebugInfo.h>
#include <gui/LayerState.h>
#include <gui/bufferqueue/1.0/H2BGraphicBufferProducer.h>
#include <gui/bufferqueue/2.0/H2BGraphicBufferProducer.h>
#include <ui/fuzzer/FuzzableDataspaces.h>

namespace android {

constexpr uint32_t kOrientation[] = {
        ui::Transform::ROT_0,  ui::Transform::FLIP_H,  ui::Transform::FLIP_V,
        ui::Transform::ROT_90, ui::Transform::ROT_180, ui::Transform::ROT_270,
};

Rect getRect(FuzzedDataProvider* fdp) {
    const int32_t left = fdp->ConsumeIntegral<int32_t>();
    const int32_t top = fdp->ConsumeIntegral<int32_t>();
    const int32_t right = fdp->ConsumeIntegral<int32_t>();
    const int32_t bottom = fdp->ConsumeIntegral<int32_t>();
    return Rect(left, top, right, bottom);
}

gui::DisplayBrightness getBrightness(FuzzedDataProvider* fdp) {
    static constexpr float kMinBrightness = 0;
    static constexpr float kMaxBrightness = 1;
    gui::DisplayBrightness brightness;
    brightness.sdrWhitePoint =
            fdp->ConsumeFloatingPointInRange<float>(kMinBrightness, kMaxBrightness);
    brightness.sdrWhitePointNits =
            fdp->ConsumeFloatingPointInRange<float>(kMinBrightness, kMaxBrightness);
    brightness.displayBrightness =
            fdp->ConsumeFloatingPointInRange<float>(kMinBrightness, kMaxBrightness);
    brightness.displayBrightnessNits =
            fdp->ConsumeFloatingPointInRange<float>(kMinBrightness, kMaxBrightness);
    return brightness;
}

class FakeBnSurfaceComposer : public gui::BnSurfaceComposer {
public:
    MOCK_METHOD(binder::Status, bootFinished, (), (override));
    MOCK_METHOD(binder::Status, createDisplayEventConnection,
                (gui::ISurfaceComposer::VsyncSource, gui::ISurfaceComposer::EventRegistration,
                 const sp<IBinder>& /*layerHandle*/, sp<gui::IDisplayEventConnection>*),
                (override));
    MOCK_METHOD(binder::Status, createConnection, (sp<gui::ISurfaceComposerClient>*), (override));
    MOCK_METHOD(binder::Status, createDisplay, (const std::string&, bool, float, sp<IBinder>*),
                (override));
    MOCK_METHOD(binder::Status, destroyDisplay, (const sp<IBinder>&), (override));
    MOCK_METHOD(binder::Status, getPhysicalDisplayIds, (std::vector<int64_t>*), (override));
    MOCK_METHOD(binder::Status, getPhysicalDisplayToken, (int64_t, sp<IBinder>*), (override));
    MOCK_METHOD(binder::Status, setPowerMode, (const sp<IBinder>&, int), (override));
    MOCK_METHOD(binder::Status, getSupportedFrameTimestamps, (std::vector<FrameEvent>*),
                (override));
    MOCK_METHOD(binder::Status, getDisplayStats, (const sp<IBinder>&, gui::DisplayStatInfo*),
                (override));
    MOCK_METHOD(binder::Status, getDisplayState, (const sp<IBinder>&, gui::DisplayState*),
                (override));
    MOCK_METHOD(binder::Status, getStaticDisplayInfo, (int64_t, gui::StaticDisplayInfo*),
                (override));
    MOCK_METHOD(binder::Status, getDynamicDisplayInfoFromId, (int64_t, gui::DynamicDisplayInfo*),
                (override));
    MOCK_METHOD(binder::Status, getDynamicDisplayInfoFromToken,
                (const sp<IBinder>&, gui::DynamicDisplayInfo*), (override));
    MOCK_METHOD(binder::Status, getDisplayNativePrimaries,
                (const sp<IBinder>&, gui::DisplayPrimaries*), (override));
    MOCK_METHOD(binder::Status, setActiveColorMode, (const sp<IBinder>&, int), (override));
    MOCK_METHOD(binder::Status, setBootDisplayMode, (const sp<IBinder>&, int), (override));
    MOCK_METHOD(binder::Status, clearBootDisplayMode, (const sp<IBinder>&), (override));
    MOCK_METHOD(binder::Status, getBootDisplayModeSupport, (bool*), (override));
    MOCK_METHOD(binder::Status, getHdrConversionCapabilities,
                (std::vector<gui::HdrConversionCapability>*), (override));
    MOCK_METHOD(binder::Status, setHdrConversionStrategy,
                (const gui::HdrConversionStrategy&, int32_t*), (override));
    MOCK_METHOD(binder::Status, getHdrOutputConversionSupport, (bool*), (override));
    MOCK_METHOD(binder::Status, setAutoLowLatencyMode, (const sp<IBinder>&, bool), (override));
    MOCK_METHOD(binder::Status, setGameContentType, (const sp<IBinder>&, bool), (override));
    MOCK_METHOD(binder::Status, captureDisplay,
                (const DisplayCaptureArgs&, const sp<IScreenCaptureListener>&), (override));
    MOCK_METHOD(binder::Status, captureDisplayById, (int64_t, const sp<IScreenCaptureListener>&),
                (override));
    MOCK_METHOD(binder::Status, captureLayers,
                (const LayerCaptureArgs&, const sp<IScreenCaptureListener>&), (override));
    MOCK_METHOD(binder::Status, clearAnimationFrameStats, (), (override));
    MOCK_METHOD(binder::Status, getAnimationFrameStats, (gui::FrameStats*), (override));
    MOCK_METHOD(binder::Status, overrideHdrTypes, (const sp<IBinder>&, const std::vector<int32_t>&),
                (override));
    MOCK_METHOD(binder::Status, onPullAtom, (int32_t, gui::PullAtomData*), (override));
    MOCK_METHOD(binder::Status, getLayerDebugInfo, (std::vector<gui::LayerDebugInfo>*), (override));
    MOCK_METHOD(binder::Status, getColorManagement, (bool*), (override));
    MOCK_METHOD(binder::Status, getCompositionPreference, (gui::CompositionPreference*),
                (override));
    MOCK_METHOD(binder::Status, getDisplayedContentSamplingAttributes,
                (const sp<IBinder>&, gui::ContentSamplingAttributes*), (override));
    MOCK_METHOD(binder::Status, setDisplayContentSamplingEnabled,
                (const sp<IBinder>&, bool, int8_t, int64_t), (override));
    MOCK_METHOD(binder::Status, getDisplayedContentSample,
                (const sp<IBinder>&, int64_t, int64_t, gui::DisplayedFrameStats*), (override));
    MOCK_METHOD(binder::Status, getProtectedContentSupport, (bool*), (override));
    MOCK_METHOD(binder::Status, isWideColorDisplay, (const sp<IBinder>&, bool*), (override));
    MOCK_METHOD(binder::Status, addRegionSamplingListener,
                (const gui::ARect&, const sp<IBinder>&, const sp<gui::IRegionSamplingListener>&),
                (override));
    MOCK_METHOD(binder::Status, removeRegionSamplingListener,
                (const sp<gui::IRegionSamplingListener>&), (override));
    MOCK_METHOD(binder::Status, addFpsListener, (int32_t, const sp<gui::IFpsListener>&),
                (override));
    MOCK_METHOD(binder::Status, removeFpsListener, (const sp<gui::IFpsListener>&), (override));
    MOCK_METHOD(binder::Status, addTunnelModeEnabledListener,
                (const sp<gui::ITunnelModeEnabledListener>&), (override));
    MOCK_METHOD(binder::Status, removeTunnelModeEnabledListener,
                (const sp<gui::ITunnelModeEnabledListener>&), (override));
    MOCK_METHOD(binder::Status, setDesiredDisplayModeSpecs,
                (const sp<IBinder>&, const gui::DisplayModeSpecs&), (override));
    MOCK_METHOD(binder::Status, getDesiredDisplayModeSpecs,
                (const sp<IBinder>&, gui::DisplayModeSpecs*), (override));
    MOCK_METHOD(binder::Status, getDisplayBrightnessSupport, (const sp<IBinder>&, bool*),
                (override));
    MOCK_METHOD(binder::Status, setDisplayBrightness,
                (const sp<IBinder>&, const gui::DisplayBrightness&), (override));
    MOCK_METHOD(binder::Status, addHdrLayerInfoListener,
                (const sp<IBinder>&, const sp<gui::IHdrLayerInfoListener>&), (override));
    MOCK_METHOD(binder::Status, removeHdrLayerInfoListener,
                (const sp<IBinder>&, const sp<gui::IHdrLayerInfoListener>&), (override));
    MOCK_METHOD(binder::Status, notifyPowerBoost, (int), (override));
    MOCK_METHOD(binder::Status, setGlobalShadowSettings,
                (const gui::Color&, const gui::Color&, float, float, float), (override));
    MOCK_METHOD(binder::Status, getDisplayDecorationSupport,
                (const sp<IBinder>&, std::optional<gui::DisplayDecorationSupport>*), (override));
    MOCK_METHOD(binder::Status, setOverrideFrameRate, (int32_t, float), (override));
    MOCK_METHOD(binder::Status, updateSmallAreaDetection,
                (const std::vector<int32_t>&, const std::vector<float>&), (override));
    MOCK_METHOD(binder::Status, setSmallAreaDetectionThreshold, (int32_t, float), (override));
    MOCK_METHOD(binder::Status, getGpuContextPriority, (int32_t*), (override));
    MOCK_METHOD(binder::Status, getMaxAcquiredBufferCount, (int32_t*), (override));
    MOCK_METHOD(binder::Status, addWindowInfosListener,
                (const sp<gui::IWindowInfosListener>&, gui::WindowInfosListenerInfo*), (override));
    MOCK_METHOD(binder::Status, removeWindowInfosListener, (const sp<gui::IWindowInfosListener>&),
                (override));
    MOCK_METHOD(binder::Status, getOverlaySupport, (gui::OverlayProperties*), (override));
    MOCK_METHOD(binder::Status, getStalledTransactionInfo,
                (int32_t, std::optional<gui::StalledTransactionInfo>*), (override));
};

class FakeBnSurfaceComposerClient : public gui::BnSurfaceComposerClient {
public:
    MOCK_METHOD(binder::Status, createSurface,
                (const std::string& name, int32_t flags, const sp<IBinder>& parent,
                 const gui::LayerMetadata& metadata, gui::CreateSurfaceResult* outResult),
                (override));

    MOCK_METHOD(binder::Status, clearLayerFrameStats, (const sp<IBinder>& handle), (override));

    MOCK_METHOD(binder::Status, getLayerFrameStats,
                (const sp<IBinder>& handle, gui::FrameStats* outStats), (override));

    MOCK_METHOD(binder::Status, mirrorSurface,
                (const sp<IBinder>& mirrorFromHandle, gui::CreateSurfaceResult* outResult),
                (override));

    MOCK_METHOD(binder::Status, mirrorDisplay,
                (int64_t displayId, gui::CreateSurfaceResult* outResult), (override));
};

class FakeDisplayEventDispatcher : public DisplayEventDispatcher {
public:
    FakeDisplayEventDispatcher(const sp<Looper>& looper,
                               gui::ISurfaceComposer::VsyncSource vsyncSource,
                               gui::ISurfaceComposer::EventRegistration eventRegistration)
          : DisplayEventDispatcher(looper, vsyncSource, eventRegistration){};

    MOCK_METHOD4(dispatchVsync, void(nsecs_t, PhysicalDisplayId, uint32_t, VsyncEventData));
    MOCK_METHOD3(dispatchHotplug, void(nsecs_t, PhysicalDisplayId, bool));
    MOCK_METHOD4(dispatchModeChanged, void(nsecs_t, PhysicalDisplayId, int32_t, nsecs_t));
    MOCK_METHOD2(dispatchNullEvent, void(nsecs_t, PhysicalDisplayId));
    MOCK_METHOD3(dispatchFrameRateOverrides,
                 void(nsecs_t, PhysicalDisplayId, std::vector<FrameRateOverride>));
};

} // namespace android

namespace android::hardware {

namespace graphics::bufferqueue::V1_0::utils {

class FakeGraphicBufferProducerV1 : public HGraphicBufferProducer {
public:
    FakeGraphicBufferProducerV1() {
        ON_CALL(*this, setMaxDequeuedBufferCount).WillByDefault([]() { return 0; });
        ON_CALL(*this, setAsyncMode).WillByDefault([]() { return 0; });
        ON_CALL(*this, detachBuffer).WillByDefault([]() { return 0; });
        ON_CALL(*this, cancelBuffer).WillByDefault([]() { return 0; });
        ON_CALL(*this, disconnect).WillByDefault([]() { return 0; });
        ON_CALL(*this, setSidebandStream).WillByDefault([]() { return 0; });
        ON_CALL(*this, allowAllocation).WillByDefault([]() { return 0; });
        ON_CALL(*this, setGenerationNumber).WillByDefault([]() { return 0; });
        ON_CALL(*this, setSharedBufferMode).WillByDefault([]() { return 0; });
        ON_CALL(*this, setAutoRefresh).WillByDefault([]() { return 0; });
        ON_CALL(*this, setDequeueTimeout).WillByDefault([]() { return 0; });
        ON_CALL(*this, setLegacyBufferDrop).WillByDefault([]() { return 0; });
    };
    MOCK_METHOD2(requestBuffer, Return<void>(int, requestBuffer_cb));
    MOCK_METHOD1(setMaxDequeuedBufferCount, Return<int32_t>(int32_t));
    MOCK_METHOD1(setAsyncMode, Return<int32_t>(bool));
    MOCK_METHOD6(dequeueBuffer,
                 Return<void>(uint32_t, uint32_t, graphics::common::V1_0::PixelFormat, uint32_t,
                              bool, dequeueBuffer_cb));
    MOCK_METHOD1(detachBuffer, Return<int32_t>(int));
    MOCK_METHOD1(detachNextBuffer, Return<void>(detachNextBuffer_cb));
    MOCK_METHOD2(attachBuffer, Return<void>(const media::V1_0::AnwBuffer&, attachBuffer_cb));
    MOCK_METHOD3(
            queueBuffer,
            Return<void>(
                    int,
                    const graphics::bufferqueue::V1_0::IGraphicBufferProducer::QueueBufferInput&,
                    queueBuffer_cb));
    MOCK_METHOD2(cancelBuffer, Return<int32_t>(int, const hidl_handle&));
    MOCK_METHOD2(query, Return<void>(int32_t, query_cb));
    MOCK_METHOD4(connect,
                 Return<void>(const sp<graphics::bufferqueue::V1_0::IProducerListener>&, int32_t,
                              bool, connect_cb));
    MOCK_METHOD2(disconnect,
                 Return<int32_t>(
                         int, graphics::bufferqueue::V1_0::IGraphicBufferProducer::DisconnectMode));
    MOCK_METHOD1(setSidebandStream, Return<int32_t>(const hidl_handle&));
    MOCK_METHOD4(allocateBuffers,
                 Return<void>(uint32_t, uint32_t, graphics::common::V1_0::PixelFormat, uint32_t));
    MOCK_METHOD1(allowAllocation, Return<int32_t>(bool));
    MOCK_METHOD1(setGenerationNumber, Return<int32_t>(uint32_t));
    MOCK_METHOD1(getConsumerName, Return<void>(getConsumerName_cb));
    MOCK_METHOD1(setSharedBufferMode, Return<int32_t>(bool));
    MOCK_METHOD1(setAutoRefresh, Return<int32_t>(bool));
    MOCK_METHOD1(setDequeueTimeout, Return<int32_t>(nsecs_t));
    MOCK_METHOD1(setLegacyBufferDrop, Return<int32_t>(bool));
    MOCK_METHOD1(getLastQueuedBuffer, Return<void>(getLastQueuedBuffer_cb));
    MOCK_METHOD1(getFrameTimestamps, Return<void>(getFrameTimestamps_cb));
    MOCK_METHOD1(getUniqueId, Return<void>(getUniqueId_cb));
};

}; // namespace graphics::bufferqueue::V1_0::utils

namespace graphics::bufferqueue::V2_0::utils {

class FakeGraphicBufferProducerV2 : public HGraphicBufferProducer {
public:
    FakeGraphicBufferProducerV2() {
        ON_CALL(*this, setMaxDequeuedBufferCount).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, setAsyncMode).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, detachBuffer).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, cancelBuffer).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, disconnect).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, allocateBuffers).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, allowAllocation).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, setGenerationNumber).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, setDequeueTimeout).WillByDefault([]() { return Status::OK; });
        ON_CALL(*this, getUniqueId).WillByDefault([]() { return 0; });
    };
    MOCK_METHOD2(requestBuffer, Return<void>(int, requestBuffer_cb));
    MOCK_METHOD1(setMaxDequeuedBufferCount, Return<graphics::bufferqueue::V2_0::Status>(int));
    MOCK_METHOD1(setAsyncMode, Return<graphics::bufferqueue::V2_0::Status>(bool));
    MOCK_METHOD2(
            dequeueBuffer,
            Return<void>(
                    const graphics::bufferqueue::V2_0::IGraphicBufferProducer::DequeueBufferInput&,
                    dequeueBuffer_cb));
    MOCK_METHOD1(detachBuffer, Return<graphics::bufferqueue::V2_0::Status>(int));
    MOCK_METHOD1(detachNextBuffer, Return<void>(detachNextBuffer_cb));
    MOCK_METHOD3(attachBuffer,
                 Return<void>(const graphics::common::V1_2::HardwareBuffer&, uint32_t,
                              attachBuffer_cb));
    MOCK_METHOD3(
            queueBuffer,
            Return<void>(
                    int,
                    const graphics::bufferqueue::V2_0::IGraphicBufferProducer::QueueBufferInput&,
                    queueBuffer_cb));
    MOCK_METHOD2(cancelBuffer,
                 Return<graphics::bufferqueue::V2_0::Status>(int, const hidl_handle&));
    MOCK_METHOD2(query, Return<void>(int32_t, query_cb));
    MOCK_METHOD4(connect,
                 Return<void>(const sp<graphics::bufferqueue::V2_0::IProducerListener>&,
                              graphics::bufferqueue::V2_0::ConnectionType, bool, connect_cb));
    MOCK_METHOD1(disconnect,
                 Return<graphics::bufferqueue::V2_0::Status>(
                         graphics::bufferqueue::V2_0::ConnectionType));
    MOCK_METHOD4(allocateBuffers,
                 Return<graphics::bufferqueue::V2_0::Status>(uint32_t, uint32_t, uint32_t,
                                                             uint64_t));
    MOCK_METHOD1(allowAllocation, Return<graphics::bufferqueue::V2_0::Status>(bool));
    MOCK_METHOD1(setGenerationNumber, Return<graphics::bufferqueue::V2_0::Status>(uint32_t));
    MOCK_METHOD1(getConsumerName, Return<void>(getConsumerName_cb));
    MOCK_METHOD1(setDequeueTimeout, Return<graphics::bufferqueue::V2_0::Status>(int64_t));
    MOCK_METHOD0(getUniqueId, Return<uint64_t>());
};

}; // namespace graphics::bufferqueue::V2_0::utils
}; // namespace android::hardware
