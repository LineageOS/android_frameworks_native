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

#include <compositionengine/Display.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/CompositionEngine.h>
#include <compositionengine/impl/Display.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <ftl/fake_guard.h>
#include <gui/LayerDebugInfo.h>
#include <gui/ScreenCaptureResults.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/mock/GraphicBufferProducer.h>
#include <ui/DisplayStatInfo.h>
#include <ui/DynamicDisplayInfo.h>

#include "DisplayDevice.h"
#include "DisplayHardware/ComposerHal.h"
#include "FrameTimeline/FrameTimeline.h"
#include "FrameTracer/FrameTracer.h"
#include "FrontEnd/LayerHandle.h"
#include "Layer.h"
#include "NativeWindowSurface.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/MessageQueue.h"
#include "Scheduler/RefreshRateSelector.h"
#include "Scheduler/VSyncTracker.h"
#include "Scheduler/VsyncConfiguration.h"
#include "Scheduler/VsyncController.h"
#include "Scheduler/VsyncModulator.h"
#include "StartPropertySetThread.h"
#include "SurfaceFlinger.h"
#include "SurfaceFlingerDefaultFactory.h"
#include "ThreadContext.h"
#include "TimeStats/TimeStats.h"
#include "surfaceflinger_scheduler_fuzzer.h"

#include "renderengine/mock/RenderEngine.h"
#include "scheduler/TimeKeeper.h"
#include "tests/unittests/mock/DisplayHardware/MockComposer.h"
#include "tests/unittests/mock/DisplayHardware/MockDisplayMode.h"
#include "tests/unittests/mock/DisplayHardware/MockHWC2.h"
#include "tests/unittests/mock/DisplayHardware/MockPowerAdvisor.h"
#include "tests/unittests/mock/MockEventThread.h"
#include "tests/unittests/mock/MockFrameTimeline.h"
#include "tests/unittests/mock/MockFrameTracer.h"
#include "tests/unittests/mock/MockNativeWindowSurface.h"
#include "tests/unittests/mock/MockTimeStats.h"
#include "tests/unittests/mock/MockVSyncTracker.h"
#include "tests/unittests/mock/MockVsyncController.h"

namespace android {
namespace Hwc2 {

class Composer;

namespace types = hardware::graphics::common;

namespace V2_1 = hardware::graphics::composer::V2_1;
namespace V2_2 = hardware::graphics::composer::V2_2;
namespace V2_3 = hardware::graphics::composer::V2_3;
namespace V2_4 = hardware::graphics::composer::V2_4;

using types::V1_0::ColorTransform;
using types::V1_0::Transform;
using types::V1_1::RenderIntent;
using types::V1_2::ColorMode;
using types::V1_2::Dataspace;
using types::V1_2::PixelFormat;

using V2_1::Config;
using V2_1::Display;
using V2_1::Error;
using V2_1::Layer;
using V2_4::CommandReaderBase;
using V2_4::CommandWriterBase;
using V2_4::IComposer;
using V2_4::IComposerCallback;
using V2_4::IComposerClient;
using V2_4::VsyncPeriodChangeTimeline;
using V2_4::VsyncPeriodNanos;
using DisplayCapability = IComposerClient::DisplayCapability;
using PerFrameMetadata = IComposerClient::PerFrameMetadata;
using PerFrameMetadataKey = IComposerClient::PerFrameMetadataKey;
using PerFrameMetadataBlob = IComposerClient::PerFrameMetadataBlob;
}; // namespace Hwc2

static constexpr hal::HWDisplayId kHwDisplayId = 1000;

static constexpr ui::Hdr kHdrTypes[] = {ui::Hdr::DOLBY_VISION, ui::Hdr::HDR10, ui::Hdr::HLG,
                                        ui::Hdr::HDR10_PLUS};

static constexpr ui::ColorMode kColormodes[] = {ui::ColorMode::NATIVE,
                                                ui::ColorMode::STANDARD_BT601_625,
                                                ui::ColorMode::STANDARD_BT601_625_UNADJUSTED,
                                                ui::ColorMode::STANDARD_BT601_525,
                                                ui::ColorMode::STANDARD_BT601_525_UNADJUSTED,
                                                ui::ColorMode::STANDARD_BT709,
                                                ui::ColorMode::DCI_P3,
                                                ui::ColorMode::SRGB,
                                                ui::ColorMode::ADOBE_RGB,
                                                ui::ColorMode::DISPLAY_P3,
                                                ui::ColorMode::BT2020,
                                                ui::ColorMode::BT2100_PQ,
                                                ui::ColorMode::BT2100_HLG,
                                                ui::ColorMode::DISPLAY_BT2020};

static constexpr ui::PixelFormat kPixelFormats[] = {ui::PixelFormat::RGBA_8888,
                                                    ui::PixelFormat::RGBX_8888,
                                                    ui::PixelFormat::RGB_888,
                                                    ui::PixelFormat::RGB_565,
                                                    ui::PixelFormat::BGRA_8888,
                                                    ui::PixelFormat::YCBCR_422_SP,
                                                    ui::PixelFormat::YCRCB_420_SP,
                                                    ui::PixelFormat::YCBCR_422_I,
                                                    ui::PixelFormat::RGBA_FP16,
                                                    ui::PixelFormat::RAW16,
                                                    ui::PixelFormat::BLOB,
                                                    ui::PixelFormat::IMPLEMENTATION_DEFINED,
                                                    ui::PixelFormat::YCBCR_420_888,
                                                    ui::PixelFormat::RAW_OPAQUE,
                                                    ui::PixelFormat::RAW10,
                                                    ui::PixelFormat::RAW12,
                                                    ui::PixelFormat::RGBA_1010102,
                                                    ui::PixelFormat::Y8,
                                                    ui::PixelFormat::Y16,
                                                    ui::PixelFormat::YV12,
                                                    ui::PixelFormat::DEPTH_16,
                                                    ui::PixelFormat::DEPTH_24,
                                                    ui::PixelFormat::DEPTH_24_STENCIL_8,
                                                    ui::PixelFormat::DEPTH_32F,
                                                    ui::PixelFormat::DEPTH_32F_STENCIL_8,
                                                    ui::PixelFormat::STENCIL_8,
                                                    ui::PixelFormat::YCBCR_P010,
                                                    ui::PixelFormat::HSV_888};

inline VsyncId getFuzzedVsyncId(FuzzedDataProvider& fdp) {
    return VsyncId{fdp.ConsumeIntegral<int64_t>()};
}

inline TimePoint getFuzzedTimePoint(FuzzedDataProvider& fdp) {
    return TimePoint::fromNs(fdp.ConsumeIntegral<nsecs_t>());
}

inline Duration getFuzzedDuration(FuzzedDataProvider& fdp) {
    return Duration::fromNs(fdp.ConsumeIntegral<nsecs_t>());
}

inline FloatRect getFuzzedFloatRect(FuzzedDataProvider* fdp) {
    return FloatRect(fdp->ConsumeFloatingPoint<float>() /*left*/,
                     fdp->ConsumeFloatingPoint<float>() /*right*/,
                     fdp->ConsumeFloatingPoint<float>() /*top*/,
                     fdp->ConsumeFloatingPoint<float>() /*bottom*/);
}

inline HdrMetadata getFuzzedHdrMetadata(FuzzedDataProvider* fdp) {
    HdrMetadata hdrMetadata;
    if (fdp->ConsumeBool()) {
        hdrMetadata.cta8613.maxContentLightLevel = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.cta8613.maxFrameAverageLightLevel = fdp->ConsumeFloatingPoint<float>();

        hdrMetadata.validTypes |= HdrMetadata::CTA861_3;
    } else {
        hdrMetadata.smpte2086.displayPrimaryRed.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryRed.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryGreen.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryGreen.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryBlue.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryBlue.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.whitePoint.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.whitePoint.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.minLuminance = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.maxLuminance = fdp->ConsumeFloatingPoint<float>();

        hdrMetadata.validTypes |= HdrMetadata::SMPTE2086;
    }
    return hdrMetadata;
}

class EventThread;

namespace hal = android::hardware::graphics::composer::hal;

struct FakePhaseOffsets : scheduler::VsyncConfiguration {
    static constexpr nsecs_t FAKE_PHASE_OFFSET_NS = 0;
    static constexpr auto FAKE_DURATION_OFFSET_NS = std::chrono::nanoseconds(0);

    scheduler::VsyncConfigSet getConfigsForRefreshRate(Fps) const override {
        return getCurrentConfigs();
    }

    scheduler::VsyncConfigSet getCurrentConfigs() const override {
        return {{FAKE_PHASE_OFFSET_NS, FAKE_PHASE_OFFSET_NS, FAKE_DURATION_OFFSET_NS,
                 FAKE_DURATION_OFFSET_NS},
                {FAKE_PHASE_OFFSET_NS, FAKE_PHASE_OFFSET_NS, FAKE_DURATION_OFFSET_NS,
                 FAKE_DURATION_OFFSET_NS},
                {FAKE_PHASE_OFFSET_NS, FAKE_PHASE_OFFSET_NS, FAKE_DURATION_OFFSET_NS,
                 FAKE_DURATION_OFFSET_NS},
                FAKE_DURATION_OFFSET_NS};
    }

    void reset() override {}
    void setRefreshRateFps(Fps) override {}
    void dump(std::string &) const override {}
};

namespace scheduler {

class TestableScheduler : public Scheduler, private ICompositor {
public:
    TestableScheduler(const std::shared_ptr<scheduler::RefreshRateSelector>& selectorPtr,
                      sp<VsyncModulator> modulatorPtr, ISchedulerCallback& callback,
                      IVsyncTrackerCallback& vsyncTrackerCallback)
          : TestableScheduler(std::make_unique<android::mock::VsyncController>(),
                              std::make_shared<android::mock::VSyncTracker>(), selectorPtr,
                              std::move(modulatorPtr), callback, vsyncTrackerCallback) {}

    TestableScheduler(std::unique_ptr<VsyncController> controller,
                      VsyncSchedule::TrackerPtr tracker,
                      std::shared_ptr<RefreshRateSelector> selectorPtr,
                      sp<VsyncModulator> modulatorPtr, ISchedulerCallback& callback,
                      IVsyncTrackerCallback& vsyncTrackerCallback)
          : Scheduler(*this, callback, Feature::kContentDetection, std::move(modulatorPtr),
                      vsyncTrackerCallback) {
        const auto displayId = selectorPtr->getActiveMode().modePtr->getPhysicalDisplayId();
        registerDisplayInternal(displayId, std::move(selectorPtr),
                                std::shared_ptr<VsyncSchedule>(
                                        new VsyncSchedule(displayId, std::move(tracker),
                                                          std::make_shared<FuzzImplVSyncDispatch>(),
                                                          std::move(controller))));
    }

    ConnectionHandle createConnection(std::unique_ptr<EventThread> eventThread) {
        return Scheduler::createConnection(std::move(eventThread));
    }

    auto &mutableLayerHistory() { return mLayerHistory; }

    auto refreshRateSelector() { return pacesetterSelectorPtr(); }

    void replaceTouchTimer(int64_t millis) {
        if (mTouchTimer) {
            mTouchTimer.reset();
        }
        mTouchTimer.emplace(
                "Testable Touch timer", std::chrono::milliseconds(millis),
                [this] { touchTimerCallback(TimerState::Reset); },
                [this] { touchTimerCallback(TimerState::Expired); });
        mTouchTimer->start();
    }

    bool isTouchActive() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        return mPolicy.touch == Scheduler::TouchState::Active;
    }

    void dispatchCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        return Scheduler::dispatchCachedReportedMode();
    }

    void clearCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.cachedModeChangedParams.reset();
    }

    void onNonPrimaryDisplayModeChanged(ConnectionHandle handle, const FrameRateMode &mode) {
        return Scheduler::onNonPrimaryDisplayModeChanged(handle, mode);
    }

    using Scheduler::setVsyncConfig;

private:
    // ICompositor overrides:
    void configure() override {}
    bool commit(PhysicalDisplayId, const scheduler::FrameTargets&) override { return false; }
    CompositeResultsPerDisplay composite(PhysicalDisplayId,
                                         const scheduler::FrameTargeters&) override {
        return {};
    }
    void sample() override {}

    // MessageQueue overrides:
    void scheduleFrame() override {}
    void postMessage(sp<MessageHandler>&& handler) override { handler->handleMessage(Message()); }
};

} // namespace scheduler

namespace surfaceflinger::test {

class Factory final : public surfaceflinger::Factory {
    struct NoOpMessageQueue : android::impl::MessageQueue {
        using android::impl::MessageQueue::MessageQueue;
        void onFrameSignal(ICompositor&, VsyncId, TimePoint) override {}
    };

public:
    ~Factory() = default;

    std::unique_ptr<HWComposer> createHWComposer(const std::string&) override { return nullptr; }

    std::unique_ptr<MessageQueue> createMessageQueue(ICompositor& compositor) {
        return std::make_unique<NoOpMessageQueue>(compositor);
    }

    std::unique_ptr<scheduler::VsyncConfiguration> createVsyncConfiguration(
            Fps /*currentRefreshRate*/) override {
        return std::make_unique<FakePhaseOffsets>();
    }

    std::unique_ptr<scheduler::Scheduler> createScheduler(
            const std::shared_ptr<scheduler::RefreshRateSelector>&,
            scheduler::ISchedulerCallback&) {
        return nullptr;
    }

    sp<StartPropertySetThread> createStartPropertySetThread(bool timestampPropertyValue) override {
        return sp<StartPropertySetThread>::make(timestampPropertyValue);
    }

    sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs &creationArgs) override {
        return sp<DisplayDevice>::make(creationArgs);
    }

    sp<GraphicBuffer> createGraphicBuffer(uint32_t width, uint32_t height, PixelFormat format,
                                          uint32_t layerCount, uint64_t usage,
                                          std::string requestorName) override {
        return sp<GraphicBuffer>::make(width, height, format, layerCount, usage, requestorName);
    }

    void createBufferQueue(sp<IGraphicBufferProducer> *outProducer,
                           sp<IGraphicBufferConsumer> *outConsumer,
                           bool consumerIsSurfaceFlinger) override {
        if (!mCreateBufferQueue) {
            BufferQueue::createBufferQueue(outProducer, outConsumer, consumerIsSurfaceFlinger);
            return;
        }
        mCreateBufferQueue(outProducer, outConsumer, consumerIsSurfaceFlinger);
    }

    std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer> &producer) override {
        if (!mCreateNativeWindowSurface) return nullptr;
        return mCreateNativeWindowSurface(producer);
    }

    std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() override {
        return compositionengine::impl::createCompositionEngine();
    }

    sp<Layer> createBufferStateLayer(const LayerCreationArgs &) override { return nullptr; }

    sp<Layer> createEffectLayer(const LayerCreationArgs &args) override {
        return sp<Layer>::make(args);
    }

    sp<LayerFE> createLayerFE(const std::string &layerName) override {
        return sp<LayerFE>::make(layerName);
    }

    std::unique_ptr<FrameTracer> createFrameTracer() override {
        return std::make_unique<android::mock::FrameTracer>();
    }

    std::unique_ptr<frametimeline::FrameTimeline> createFrameTimeline(
            std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid = 0) override {
        return std::make_unique<android::mock::FrameTimeline>(timeStats, surfaceFlingerPid);
    }

    using CreateBufferQueueFunction =
            std::function<void(sp<IGraphicBufferProducer> * /* outProducer */,
                               sp<IGraphicBufferConsumer> * /* outConsumer */,
                               bool /* consumerIsSurfaceFlinger */)>;
    CreateBufferQueueFunction mCreateBufferQueue;

    using CreateNativeWindowSurfaceFunction =
            std::function<std::unique_ptr<surfaceflinger::NativeWindowSurface>(
                    const sp<IGraphicBufferProducer> &)>;
    CreateNativeWindowSurfaceFunction mCreateNativeWindowSurface;

    using CreateCompositionEngineFunction =
            std::function<std::unique_ptr<compositionengine::CompositionEngine>()>;
    CreateCompositionEngineFunction mCreateCompositionEngine;
};

} // namespace surfaceflinger::test

// TODO(b/189053744) : Create a common test/mock library for surfaceflinger
class TestableSurfaceFlinger final : private scheduler::ISchedulerCallback,
                                     private scheduler::IVsyncTrackerCallback {
public:
    using HotplugEvent = SurfaceFlinger::HotplugEvent;

    SurfaceFlinger *flinger() { return mFlinger.get(); }
    scheduler::TestableScheduler *scheduler() { return mScheduler; }

    void initializeDisplays() {
        FTL_FAKE_GUARD(kMainThreadContext, mFlinger->initializeDisplays());
    }

    void setGlobalShadowSettings(FuzzedDataProvider *fdp) {
        const half4 ambientColor{fdp->ConsumeFloatingPoint<float>(),
                                 fdp->ConsumeFloatingPoint<float>(),
                                 fdp->ConsumeFloatingPoint<float>(),
                                 fdp->ConsumeFloatingPoint<float>()};
        const half4 spotColor{fdp->ConsumeFloatingPoint<float>(),
                              fdp->ConsumeFloatingPoint<float>(),
                              fdp->ConsumeFloatingPoint<float>(),
                              fdp->ConsumeFloatingPoint<float>()};
        float lightPosY = fdp->ConsumeFloatingPoint<float>();
        float lightPosZ = fdp->ConsumeFloatingPoint<float>();
        float lightRadius = fdp->ConsumeFloatingPoint<float>();
        mFlinger->setGlobalShadowSettings(ambientColor, spotColor, lightPosY, lightPosZ,
                                          lightRadius);
    }

    void onPullAtom(FuzzedDataProvider *fdp) {
        const int32_t atomId = fdp->ConsumeIntegral<uint8_t>();
        std::vector<uint8_t> pulledData = fdp->ConsumeRemainingBytes<uint8_t>();
        bool success = fdp->ConsumeBool();
        mFlinger->onPullAtom(atomId, &pulledData, &success);
    }

    void fuzzDumpsysAndDebug(FuzzedDataProvider *fdp) {
        std::string result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->appendSfConfigString(result);
        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->listLayersLocked(result);

        using DumpArgs = Vector<String16>;
        DumpArgs dumpArgs;
        dumpArgs.push_back(String16(fdp->ConsumeRandomLengthString().c_str()));
        mFlinger->clearStatsLocked(dumpArgs, result);

        mFlinger->dumpTimeStats(dumpArgs, fdp->ConsumeBool(), result);
        FTL_FAKE_GUARD(kMainThreadContext,
                       mFlinger->logFrameStats(TimePoint::fromNs(fdp->ConsumeIntegral<nsecs_t>())));

        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->dumpFrameTimeline(dumpArgs, result);

        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->dumpRawDisplayIdentificationData(dumpArgs, result);

        perfetto::protos::LayersProto layersProto =
                mFlinger->dumpDrawingStateProto(fdp->ConsumeIntegral<uint32_t>());
        mFlinger->dumpOffscreenLayersProto(layersProto);
        mFlinger->dumpDisplayProto();

        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->dumpHwc(result);

        mFlinger->calculateColorMatrix(fdp->ConsumeFloatingPoint<float>());
        mFlinger->updateColorMatrixLocked();
        mFlinger->CheckTransactCodeCredentials(fdp->ConsumeIntegral<uint32_t>());
    }

    void getCompositionPreference() {
        ui::Dataspace outDataspace;
        ui::PixelFormat outPixelFormat;
        ui::Dataspace outWideColorGamutDataspace;
        ui::PixelFormat outWideColorGamutPixelFormat;
        mFlinger->getCompositionPreference(&outDataspace, &outPixelFormat,
                                           &outWideColorGamutDataspace,
                                           &outWideColorGamutPixelFormat);
    }

    void overrideHdrTypes(const sp<IBinder>& display, FuzzedDataProvider* fdp) {
        std::vector<ui::Hdr> hdrTypes;
        hdrTypes.push_back(fdp->PickValueInArray(kHdrTypes));
        mFlinger->overrideHdrTypes(display, hdrTypes);
    }

    void getDisplayedContentSample(const sp<IBinder>& display, FuzzedDataProvider* fdp) {
        DisplayedFrameStats outDisplayedFrameStats;
        mFlinger->getDisplayedContentSample(display, fdp->ConsumeIntegral<uint64_t>(),
                                            fdp->ConsumeIntegral<uint64_t>(),
                                            &outDisplayedFrameStats);
    }

    void getDisplayStats(const sp<IBinder>& display) {
        android::DisplayStatInfo stats;
        mFlinger->getDisplayStats(display, &stats);
    }

    void getDisplayState(const sp<IBinder>& display) {
        ui::DisplayState displayState;
        mFlinger->getDisplayState(display, &displayState);
    }

    void getStaticDisplayInfo(int64_t displayId) {
        ui::StaticDisplayInfo staticDisplayInfo;
        mFlinger->getStaticDisplayInfo(displayId, &staticDisplayInfo);
    }

    void getDynamicDisplayInfo(int64_t displayId) {
        android::ui::DynamicDisplayInfo dynamicDisplayInfo;
        mFlinger->getDynamicDisplayInfoFromId(displayId, &dynamicDisplayInfo);
    }
    void getDisplayNativePrimaries(const sp<IBinder>& display) {
        android::ui::DisplayPrimaries displayPrimaries;
        mFlinger->getDisplayNativePrimaries(display, displayPrimaries);
    }

    void getDesiredDisplayModeSpecs(const sp<IBinder>& display) {
        gui::DisplayModeSpecs _;
        mFlinger->getDesiredDisplayModeSpecs(display, &_);
    }

    // TODO(b/248317436): extend to cover all displays for multi-display devices
    static std::optional<PhysicalDisplayId> getFirstDisplayId() {
        std::vector<PhysicalDisplayId> ids = SurfaceComposerClient::getPhysicalDisplayIds();
        if (ids.empty()) return {};
        return ids.front();
    }

    std::pair<sp<IBinder>, PhysicalDisplayId> fuzzBoot(FuzzedDataProvider* fdp) {
        mFlinger->callingThreadHasUnscopedSurfaceFlingerAccess(fdp->ConsumeBool());
        const sp<Client> client = sp<Client>::make(mFlinger);

        DisplayIdGenerator<HalVirtualDisplayId> kGenerator;
        HalVirtualDisplayId halVirtualDisplayId = kGenerator.generateId().value();

        ui::Size uiSize{fdp->ConsumeIntegral<int32_t>(), fdp->ConsumeIntegral<int32_t>()};
        ui::PixelFormat pixelFormat{};
        mFlinger->getHwComposer().allocateVirtualDisplay(halVirtualDisplayId, uiSize, &pixelFormat);

        PhysicalDisplayId physicalDisplayId = getFirstDisplayId().value_or(
                PhysicalDisplayId::fromPort(fdp->ConsumeIntegral<uint8_t>()));
        mFlinger->getHwComposer().allocatePhysicalDisplay(kHwDisplayId, physicalDisplayId);

        sp<IBinder> display =
                mFlinger->createDisplay(String8(fdp->ConsumeRandomLengthString().c_str()),
                                        fdp->ConsumeBool());

        initializeDisplays();
        mFlinger->getPhysicalDisplayToken(physicalDisplayId);

        mFlinger->mStartPropertySetThread =
                mFlinger->getFactory().createStartPropertySetThread(fdp->ConsumeBool());

        mFlinger->bootFinished();

        return {display, physicalDisplayId};
    }

    void fuzzSurfaceFlinger(const uint8_t *data, size_t size) {
        FuzzedDataProvider mFdp(data, size);

        const auto [display, displayId] = fuzzBoot(&mFdp);

        sp<IGraphicBufferProducer> bufferProducer = sp<mock::GraphicBufferProducer>::make();

        mFlinger->createDisplayEventConnection();

        getDisplayStats(display);
        getDisplayState(display);
        getStaticDisplayInfo(displayId.value);
        getDynamicDisplayInfo(displayId.value);
        getDisplayNativePrimaries(display);

        mFlinger->setAutoLowLatencyMode(display, mFdp.ConsumeBool());
        mFlinger->setGameContentType(display, mFdp.ConsumeBool());
        mFlinger->setPowerMode(display, mFdp.ConsumeIntegral<int>());

        overrideHdrTypes(display, &mFdp);

        onPullAtom(&mFdp);

        getCompositionPreference();
        getDisplayedContentSample(display, &mFdp);
        getDesiredDisplayModeSpecs(display);

        bool outSupport;
        mFlinger->getDisplayBrightnessSupport(display, &outSupport);

        mFlinger->notifyPowerBoost(mFdp.ConsumeIntegral<int32_t>());

        setGlobalShadowSettings(&mFdp);

        mFlinger->binderDied(display);
        mFlinger->onFirstRef();

        mFlinger->updateInputFlinger(VsyncId{}, TimePoint{});
        mFlinger->updateCursorAsync();

        mutableScheduler().setVsyncConfig({.sfOffset = mFdp.ConsumeIntegral<nsecs_t>(),
                                           .appOffset = mFdp.ConsumeIntegral<nsecs_t>(),
                                           .sfWorkDuration = getFuzzedDuration(mFdp),
                                           .appWorkDuration = getFuzzedDuration(mFdp)},
                                          getFuzzedDuration(mFdp));

        {
            ftl::FakeGuard guard(kMainThreadContext);

            mFlinger->commitTransactionsLegacy();
            mFlinger->flushTransactionQueues(getFuzzedVsyncId(mFdp));

            scheduler::FrameTargeter frameTargeter(displayId, mFdp.ConsumeBool());
            mFlinger->onCompositionPresented(displayId, ftl::init::map(displayId, &frameTargeter),
                                             mFdp.ConsumeIntegral<nsecs_t>());
        }

        mFlinger->setTransactionFlags(mFdp.ConsumeIntegral<uint32_t>());
        mFlinger->clearTransactionFlags(mFdp.ConsumeIntegral<uint32_t>());
        mFlinger->commitOffscreenLayers();

        mFlinger->frameIsEarly(getFuzzedTimePoint(mFdp), getFuzzedVsyncId(mFdp));
        mFlinger->computeLayerBounds();
        mFlinger->startBootAnim();

        mFlinger->readPersistentProperties();

        mFlinger->exceedsMaxRenderTargetSize(mFdp.ConsumeIntegral<uint32_t>(),
                                             mFdp.ConsumeIntegral<uint32_t>());

        mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mFdp.ConsumeIntegral<uid_t>());

        mFlinger->enableHalVirtualDisplays(mFdp.ConsumeBool());

        fuzzDumpsysAndDebug(&mFdp);

        mFlinger->destroyDisplay(display);
    }

    void setupRenderEngine(std::unique_ptr<renderengine::RenderEngine> renderEngine) {
        mFlinger->mRenderEngine = std::move(renderEngine);
        mFlinger->mCompositionEngine->setRenderEngine(mFlinger->mRenderEngine.get());
    }

    void setupComposer(std::unique_ptr<Hwc2::Composer> composer) {
        mFlinger->mCompositionEngine->setHwComposer(
                std::make_unique<impl::HWComposer>(std::move(composer)));
    }

    void setupTimeStats(const std::shared_ptr<TimeStats> &timeStats) {
        mFlinger->mCompositionEngine->setTimeStats(timeStats);
    }

    // The ISchedulerCallback argument can be nullptr for a no-op implementation.
    void setupScheduler(std::unique_ptr<scheduler::VsyncController> vsyncController,
                        std::shared_ptr<scheduler::VSyncTracker> vsyncTracker,
                        std::unique_ptr<EventThread> appEventThread,
                        std::unique_ptr<EventThread> sfEventThread,
                        scheduler::ISchedulerCallback* callback = nullptr,
                        scheduler::IVsyncTrackerCallback* vsyncTrackerCallback = nullptr,
                        bool hasMultipleModes = false) {
        constexpr DisplayModeId kModeId60{0};
        DisplayModes modes = makeModes(mock::createDisplayMode(kModeId60, 60_Hz));

        if (hasMultipleModes) {
            constexpr DisplayModeId kModeId90{1};
            modes.try_emplace(kModeId90, mock::createDisplayMode(kModeId90, 90_Hz));
        }

        mRefreshRateSelector = std::make_shared<scheduler::RefreshRateSelector>(modes, kModeId60);
        const auto fps = mRefreshRateSelector->getActiveMode().modePtr->getVsyncRate();
        mFlinger->mVsyncConfiguration = mFactory.createVsyncConfiguration(fps);

        mFlinger->mRefreshRateStats =
                std::make_unique<scheduler::RefreshRateStats>(*mFlinger->mTimeStats, fps,
                                                              hal::PowerMode::OFF);

        auto modulatorPtr = sp<scheduler::VsyncModulator>::make(
                mFlinger->mVsyncConfiguration->getCurrentConfigs());

        mScheduler = new scheduler::TestableScheduler(std::move(vsyncController),
                                                      std::move(vsyncTracker), mRefreshRateSelector,
                                                      std::move(modulatorPtr), *(callback ?: this),
                                                      *(vsyncTrackerCallback ?: this));

        mFlinger->mAppConnectionHandle = mScheduler->createConnection(std::move(appEventThread));
        mFlinger->mSfConnectionHandle = mScheduler->createConnection(std::move(sfEventThread));
        resetScheduler(mScheduler);
    }

    void resetScheduler(scheduler::Scheduler *scheduler) { mFlinger->mScheduler.reset(scheduler); }

    scheduler::TestableScheduler &mutableScheduler() const { return *mScheduler; }

    using CreateBufferQueueFunction = surfaceflinger::test::Factory::CreateBufferQueueFunction;
    void setCreateBufferQueueFunction(CreateBufferQueueFunction f) {
        mFactory.mCreateBufferQueue = f;
    }

    using CreateNativeWindowSurfaceFunction =
            surfaceflinger::test::Factory::CreateNativeWindowSurfaceFunction;
    void setCreateNativeWindowSurface(CreateNativeWindowSurfaceFunction f) {
        mFactory.mCreateNativeWindowSurface = f;
    }

    void setInternalDisplayPrimaries(const ui::DisplayPrimaries &primaries) {
        memcpy(&mFlinger->mInternalDisplayPrimaries, &primaries, sizeof(ui::DisplayPrimaries));
    }

    static auto &mutableLayerDrawingState(const sp<Layer> &layer) { return layer->mDrawingState; }

    auto &mutableStateLock() { return mFlinger->mStateLock; }

    static auto findOutputLayerForDisplay(const sp<Layer> &layer,
                                          const sp<const DisplayDevice> &display) {
        return layer->findOutputLayerForDisplay(display.get());
    }

    /* ------------------------------------------------------------------------
     * Forwarding for functions being tested
     */

    void enableHalVirtualDisplays(bool enable) { mFlinger->enableHalVirtualDisplays(enable); }

    void commitTransactionsLocked(uint32_t transactionFlags) FTL_FAKE_GUARD(kMainThreadContext) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        mFlinger->commitTransactionsLocked(transactionFlags);
    }

    auto setDisplayStateLocked(const DisplayState &s) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        return mFlinger->setDisplayStateLocked(s);
    }

    auto notifyPowerBoost(int32_t boostId) { return mFlinger->notifyPowerBoost(boostId); }

    // Allow reading display state without locking, as if called on the SF main thread.
    auto setPowerModeInternal(const sp<DisplayDevice> &display,
                              hal::PowerMode mode) NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->setPowerModeInternal(display, mode);
    }

    auto &getTransactionQueue() { return mFlinger->mTransactionHandler.mLocklessTransactionQueue; }
    auto &getPendingTransactionQueue() {
        return mFlinger->mTransactionHandler.mPendingTransactionQueues;
    }

    auto setTransactionState(
            const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& states,
            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
            const InputWindowCommands& inputWindowCommands, int64_t desiredPresentTime,
            bool isAutoTimestamp, const std::vector<client_cache_t>& uncacheBuffers,
            bool hasListenerCallbacks, std::vector<ListenerCallbacks>& listenerCallbacks,
            uint64_t transactionId, const std::vector<uint64_t>& mergedTransactionIds) {
        return mFlinger->setTransactionState(frameTimelineInfo, states, displays, flags, applyToken,
                                             inputWindowCommands, desiredPresentTime,
                                             isAutoTimestamp, uncacheBuffers, hasListenerCallbacks,
                                             listenerCallbacks, transactionId,
                                             mergedTransactionIds);
    }

    auto flushTransactionQueues() {
        ftl::FakeGuard guard(kMainThreadContext);
        return mFlinger->flushTransactionQueues(VsyncId{0});
    }

    auto onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
        return mFlinger->onTransact(code, data, reply, flags);
    }

    auto getGpuContextPriority() { return mFlinger->getGpuContextPriority(); }

    auto calculateMaxAcquiredBufferCount(Fps refreshRate,
                                         std::chrono::nanoseconds presentLatency) const {
        return SurfaceFlinger::calculateMaxAcquiredBufferCount(refreshRate, presentLatency);
    }

    /* Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */
    auto& mutableSupportsWideColor() { return mFlinger->mSupportsWideColor; }
    auto& mutableCurrentState() { return mFlinger->mCurrentState; }
    auto& mutableDisplays() { return mFlinger->mDisplays; }
    auto& mutableDrawingState() { return mFlinger->mDrawingState; }

    auto fromHandle(const sp<IBinder> &handle) { return LayerHandle::getLayer(handle); }

    ~TestableSurfaceFlinger() {
        mutableDisplays().clear();
        mutableCurrentState().displays.clear();
        mutableDrawingState().displays.clear();
        mFlinger->mScheduler.reset();
        mFlinger->mCompositionEngine->setHwComposer(std::unique_ptr<HWComposer>());
        mFlinger->mRenderEngine = std::unique_ptr<renderengine::RenderEngine>();
        mFlinger->mCompositionEngine->setRenderEngine(mFlinger->mRenderEngine.get());
    }

private:
    void requestHardwareVsync(PhysicalDisplayId, bool) override {}
    void requestDisplayModes(std::vector<display::DisplayModeRequest>) override {}
    void kernelTimerChanged(bool) override {}
    void triggerOnFrameRateOverridesChanged() override {}
    void onChoreographerAttached() override {}

    // IVsyncTrackerCallback overrides
    void onVsyncGenerated(TimePoint, ftl::NonNull<DisplayModePtr>, Fps) override {}

    surfaceflinger::test::Factory mFactory;
    sp<SurfaceFlinger> mFlinger =
            sp<SurfaceFlinger>::make(mFactory, SurfaceFlinger::SkipInitialization);
    scheduler::TestableScheduler *mScheduler = nullptr;
    std::shared_ptr<scheduler::RefreshRateSelector> mRefreshRateSelector;
};

} // namespace android
