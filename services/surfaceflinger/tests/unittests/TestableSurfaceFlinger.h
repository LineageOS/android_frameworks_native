/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <algorithm>
#include <chrono>
#include <variant>

#include <compositionengine/Display.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/CompositionEngine.h>
#include <compositionengine/impl/Display.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/mock/DisplaySurface.h>
#include <gui/ScreenCaptureResults.h>

#include "BufferQueueLayer.h"
#include "BufferStateLayer.h"
#include "ContainerLayer.h"
#include "DisplayDevice.h"
#include "EffectLayer.h"
#include "FakeVsyncConfiguration.h"
#include "FrameTracer/FrameTracer.h"
#include "Layer.h"
#include "NativeWindowSurface.h"
#include "Scheduler/MessageQueue.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "StartPropertySetThread.h"
#include "SurfaceFlinger.h"
#include "SurfaceFlingerDefaultFactory.h"
#include "SurfaceInterceptor.h"
#include "TestableScheduler.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockFrameTimeline.h"
#include "mock/MockFrameTracer.h"
#include "mock/MockSchedulerCallback.h"

namespace android {

class EventThread;

namespace renderengine {

class RenderEngine;

} // namespace renderengine

namespace Hwc2 {

class Composer;

} // namespace Hwc2

namespace hal = android::hardware::graphics::composer::hal;

namespace surfaceflinger::test {

class Factory final : public surfaceflinger::Factory {
public:
    ~Factory() = default;

    std::unique_ptr<HWComposer> createHWComposer(const std::string&) override {
        return nullptr;
    }

    std::unique_ptr<scheduler::VsyncConfiguration> createVsyncConfiguration(
            Fps /*currentRefreshRate*/) override {
        return std::make_unique<scheduler::FakePhaseOffsets>();
    }

    sp<SurfaceInterceptor> createSurfaceInterceptor() override {
        return new android::impl::SurfaceInterceptor();
    }

    sp<StartPropertySetThread> createStartPropertySetThread(bool timestampPropertyValue) override {
        return new StartPropertySetThread(timestampPropertyValue);
    }

    sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs& creationArgs) override {
        return new DisplayDevice(creationArgs);
    }

    sp<GraphicBuffer> createGraphicBuffer(uint32_t width, uint32_t height, PixelFormat format,
                                          uint32_t layerCount, uint64_t usage,
                                          std::string requestorName) override {
        return new GraphicBuffer(width, height, format, layerCount, usage, requestorName);
    }

    void createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                           sp<IGraphicBufferConsumer>* outConsumer,
                           bool consumerIsSurfaceFlinger) override {
        if (!mCreateBufferQueue) {
            BufferQueue::createBufferQueue(outProducer, outConsumer, consumerIsSurfaceFlinger);
            return;
        }
        mCreateBufferQueue(outProducer, outConsumer, consumerIsSurfaceFlinger);
    }

    sp<IGraphicBufferProducer> createMonitoredProducer(const sp<IGraphicBufferProducer>& producer,
                                                       const sp<SurfaceFlinger>& flinger,
                                                       const wp<Layer>& layer) override {
        return new MonitoredProducer(producer, flinger, layer);
    }

    sp<BufferLayerConsumer> createBufferLayerConsumer(const sp<IGraphicBufferConsumer>& consumer,
                                                      renderengine::RenderEngine& renderEngine,
                                                      uint32_t textureName, Layer* layer) override {
        return new BufferLayerConsumer(consumer, renderEngine, textureName, layer);
    }

    std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer>& producer) override {
        if (!mCreateNativeWindowSurface) return nullptr;
        return mCreateNativeWindowSurface(producer);
    }

    std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() override {
        return compositionengine::impl::createCompositionEngine();
    }

    sp<BufferQueueLayer> createBufferQueueLayer(const LayerCreationArgs&) override {
        return nullptr;
    }

    sp<BufferStateLayer> createBufferStateLayer(const LayerCreationArgs&) override {
        return nullptr;
    }

    sp<EffectLayer> createEffectLayer(const LayerCreationArgs&) override { return nullptr; }

    sp<ContainerLayer> createContainerLayer(const LayerCreationArgs&) override {
        return nullptr;
    }

    std::unique_ptr<FrameTracer> createFrameTracer() override {
        return std::make_unique<mock::FrameTracer>();
    }

    std::unique_ptr<frametimeline::FrameTimeline> createFrameTimeline(
            std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid = 0) override {
        return std::make_unique<mock::FrameTimeline>(timeStats, surfaceFlingerPid);
    }

    using CreateBufferQueueFunction =
            std::function<void(sp<IGraphicBufferProducer>* /* outProducer */,
                               sp<IGraphicBufferConsumer>* /* outConsumer */,
                               bool /* consumerIsSurfaceFlinger */)>;
    CreateBufferQueueFunction mCreateBufferQueue;

    using CreateNativeWindowSurfaceFunction =
            std::function<std::unique_ptr<surfaceflinger::NativeWindowSurface>(
                    const sp<IGraphicBufferProducer>&)>;
    CreateNativeWindowSurfaceFunction mCreateNativeWindowSurface;

    using CreateCompositionEngineFunction =
            std::function<std::unique_ptr<compositionengine::CompositionEngine>()>;
    CreateCompositionEngineFunction mCreateCompositionEngine;
};

} // namespace surfaceflinger::test

class TestableSurfaceFlinger {
public:
    using HotplugEvent = SurfaceFlinger::HotplugEvent;

    TestableSurfaceFlinger(sp<SurfaceFlinger> flinger = nullptr) : mFlinger(flinger) {
        if (!mFlinger) {
            mFlinger = sp<SurfaceFlinger>::make(mFactory, SurfaceFlinger::SkipInitialization);
        }
        mFlinger->mAnimationTransactionTimeout = ms2ns(10);
    }

    SurfaceFlinger* flinger() { return mFlinger.get(); }
    scheduler::TestableScheduler* scheduler() { return mScheduler; }

    // Extend this as needed for accessing SurfaceFlinger private (and public)
    // functions.

    void setupRenderEngine(std::unique_ptr<renderengine::RenderEngine> renderEngine) {
        mFlinger->mCompositionEngine->setRenderEngine(std::move(renderEngine));
    }

    void setupComposer(std::unique_ptr<Hwc2::Composer> composer) {
        mFlinger->mCompositionEngine->setHwComposer(
                std::make_unique<impl::HWComposer>(std::move(composer)));
    }

    void setupPowerAdvisor(std::unique_ptr<Hwc2::PowerAdvisor> powerAdvisor) {
        mFlinger->mPowerAdvisor = std::move(powerAdvisor);
    }

    void setupTimeStats(const std::shared_ptr<TimeStats>& timeStats) {
        mFlinger->mCompositionEngine->setTimeStats(timeStats);
    }

    enum class SchedulerCallbackImpl { kNoOp, kMock };

    static constexpr struct OneDisplayMode {
    } kOneDisplayMode;

    static constexpr struct TwoDisplayModes {
    } kTwoDisplayModes;

    using RefreshRateConfigsPtr = std::shared_ptr<scheduler::RefreshRateConfigs>;

    using DisplayModesVariant =
            std::variant<OneDisplayMode, TwoDisplayModes, RefreshRateConfigsPtr>;

    void setupScheduler(std::unique_ptr<scheduler::VsyncController> vsyncController,
                        std::unique_ptr<scheduler::VSyncTracker> vsyncTracker,
                        std::unique_ptr<EventThread> appEventThread,
                        std::unique_ptr<EventThread> sfEventThread,
                        SchedulerCallbackImpl callbackImpl = SchedulerCallbackImpl::kNoOp,
                        DisplayModesVariant modesVariant = kOneDisplayMode,
                        bool useNiceMock = false) {
        RefreshRateConfigsPtr configs;
        if (std::holds_alternative<RefreshRateConfigsPtr>(modesVariant)) {
            configs = std::move(std::get<RefreshRateConfigsPtr>(modesVariant));
        } else {
            constexpr DisplayModeId kModeId60{0};
            DisplayModes modes = makeModes(mock::createDisplayMode(kModeId60, 60_Hz));

            if (std::holds_alternative<TwoDisplayModes>(modesVariant)) {
                constexpr DisplayModeId kModeId90{1};
                modes.try_emplace(kModeId90, mock::createDisplayMode(kModeId90, 90_Hz));
            }

            configs = std::make_shared<scheduler::RefreshRateConfigs>(modes, kModeId60);
        }

        const auto fps = configs->getActiveMode()->getFps();
        mFlinger->mVsyncConfiguration = mFactory.createVsyncConfiguration(fps);
        mFlinger->mVsyncModulator = sp<scheduler::VsyncModulator>::make(
                mFlinger->mVsyncConfiguration->getCurrentConfigs());

        mFlinger->mRefreshRateStats =
                std::make_unique<scheduler::RefreshRateStats>(*mFlinger->mTimeStats, fps,
                                                              hal::PowerMode::OFF);

        using Callback = scheduler::ISchedulerCallback;
        Callback& callback = callbackImpl == SchedulerCallbackImpl::kNoOp
                ? static_cast<Callback&>(mNoOpSchedulerCallback)
                : static_cast<Callback&>(mSchedulerCallback);

        if (useNiceMock) {
            mScheduler =
                    new testing::NiceMock<scheduler::TestableScheduler>(std::move(vsyncController),
                                                                        std::move(vsyncTracker),
                                                                        std::move(configs),
                                                                        callback);
        } else {
            mScheduler = new scheduler::TestableScheduler(std::move(vsyncController),
                                                          std::move(vsyncTracker),
                                                          std::move(configs), callback);
        }

        mFlinger->mAppConnectionHandle = mScheduler->createConnection(std::move(appEventThread));
        mFlinger->mSfConnectionHandle = mScheduler->createConnection(std::move(sfEventThread));
        resetScheduler(mScheduler);
    }

    void resetScheduler(scheduler::Scheduler* scheduler) { mFlinger->mScheduler.reset(scheduler); }

    scheduler::TestableScheduler& mutableScheduler() { return *mScheduler; }
    scheduler::mock::SchedulerCallback& mockSchedulerCallback() { return mSchedulerCallback; }

    auto& mutableVsyncModulator() { return mFlinger->mVsyncModulator; }

    using CreateBufferQueueFunction = surfaceflinger::test::Factory::CreateBufferQueueFunction;
    void setCreateBufferQueueFunction(CreateBufferQueueFunction f) {
        mFactory.mCreateBufferQueue = f;
    }

    using CreateNativeWindowSurfaceFunction =
            surfaceflinger::test::Factory::CreateNativeWindowSurfaceFunction;
    void setCreateNativeWindowSurface(CreateNativeWindowSurfaceFunction f) {
        mFactory.mCreateNativeWindowSurface = f;
    }

    void setInternalDisplayPrimaries(const ui::DisplayPrimaries& primaries) {
        memcpy(&mFlinger->mInternalDisplayPrimaries, &primaries, sizeof(ui::DisplayPrimaries));
    }

    static auto& mutableLayerDrawingState(const sp<Layer>& layer) { return layer->mDrawingState; }

    auto& mutableStateLock() { return mFlinger->mStateLock; }

    static auto findOutputLayerForDisplay(const sp<Layer>& layer,
                                          const sp<const DisplayDevice>& display) {
        return layer->findOutputLayerForDisplay(display.get());
    }

    static void setLayerSidebandStream(const sp<Layer>& layer,
                                       const sp<NativeHandle>& sidebandStream) {
        layer->mDrawingState.sidebandStream = sidebandStream;
        layer->mSidebandStream = sidebandStream;
        layer->editCompositionState()->sidebandStream = sidebandStream;
    }

    void setLayerCompositionType(const sp<Layer>& layer,
                                 aidl::android::hardware::graphics::composer3::Composition type) {
        auto outputLayer = findOutputLayerForDisplay(layer, mFlinger->getDefaultDisplayDevice());
        LOG_ALWAYS_FATAL_IF(!outputLayer);
        auto& state = outputLayer->editState();
        LOG_ALWAYS_FATAL_IF(!outputLayer->getState().hwc);
        (*state.hwc).hwcCompositionType = type;
    }

    static void setLayerPotentialCursor(const sp<Layer>& layer, bool potentialCursor) {
        layer->mPotentialCursor = potentialCursor;
    }

    static void setLayerDrawingParent(const sp<Layer>& layer, const sp<Layer>& drawingParent) {
        layer->mDrawingParent = drawingParent;
    }

    void setPowerHintSessionMode(bool early, bool late) {
        mFlinger->mPowerHintSessionMode = {.late = late, .early = early};
    }

    /* ------------------------------------------------------------------------
     * Forwarding for functions being tested
     */

    nsecs_t commit(nsecs_t frameTime, int64_t vsyncId, nsecs_t expectedVSyncTime) {
        mFlinger->commit(frameTime, vsyncId, expectedVSyncTime);
        return frameTime;
    }

    nsecs_t commit(nsecs_t frameTime, int64_t vsyncId) {
        std::chrono::nanoseconds period = 10ms;
        return commit(frameTime, vsyncId, frameTime + period.count());
    }

    nsecs_t commit() {
        const nsecs_t now = systemTime();
        const nsecs_t expectedVsyncTime = now + 10'000'000;
        return commit(now, kVsyncId, expectedVsyncTime);
    }

    void commitAndComposite(const nsecs_t frameTime, const int64_t vsyncId,
                            const nsecs_t expectedVsyncTime) {
        mFlinger->composite(commit(frameTime, vsyncId, expectedVsyncTime), kVsyncId);
    }

    void commitAndComposite() { mFlinger->composite(commit(), kVsyncId); }

    auto createDisplay(const String8& displayName, bool secure) {
        return mFlinger->createDisplay(displayName, secure);
    }

    auto destroyDisplay(const sp<IBinder>& displayToken) {
        return mFlinger->destroyDisplay(displayToken);
    }

    auto getDisplay(const sp<IBinder>& displayToken) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        return mFlinger->getDisplayDeviceLocked(displayToken);
    }

    void enableHalVirtualDisplays(bool enable) { mFlinger->enableHalVirtualDisplays(enable); }

    auto setupNewDisplayDeviceInternal(
            const wp<IBinder>& displayToken,
            std::shared_ptr<compositionengine::Display> compositionDisplay,
            const DisplayDeviceState& state,
            const sp<compositionengine::DisplaySurface>& dispSurface,
            const sp<IGraphicBufferProducer>& producer) NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->setupNewDisplayDeviceInternal(displayToken, compositionDisplay, state,
                                                       dispSurface, producer);
    }

    auto commitTransactionsLocked(uint32_t transactionFlags) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        return mFlinger->commitTransactionsLocked(transactionFlags);
    }

    void onComposerHalHotplug(hal::HWDisplayId hwcDisplayId, hal::Connection connection) {
        mFlinger->onComposerHalHotplug(hwcDisplayId, connection);
    }

    auto setDisplayStateLocked(const DisplayState& s) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        return mFlinger->setDisplayStateLocked(s);
    }

    // Allow reading display state without locking, as if called on the SF main thread.
    auto onInitializeDisplays() NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->onInitializeDisplays();
    }

    auto notifyPowerBoost(int32_t boostId) { return mFlinger->notifyPowerBoost(boostId); }

    auto setDisplayBrightness(const sp<IBinder>& display,
                              const gui::DisplayBrightness& brightness) {
        return mFlinger->setDisplayBrightness(display, brightness);
    }

    // Allow reading display state without locking, as if called on the SF main thread.
    auto setPowerModeInternal(const sp<DisplayDevice>& display,
                              hal::PowerMode mode) NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->setPowerModeInternal(display, mode);
    }

    auto renderScreenImpl(const RenderArea& renderArea,
                                SurfaceFlinger::TraverseLayersFunction traverseLayers,
                                const std::shared_ptr<renderengine::ExternalTexture>& buffer,
                                bool forSystem, bool regionSampling) {
        ScreenCaptureResults captureResults;
        return mFlinger->renderScreenImpl(renderArea, traverseLayers, buffer, forSystem,
                                                regionSampling, false /* grayscale */,
                                                captureResults);
    }

    auto traverseLayersInLayerStack(ui::LayerStack layerStack, int32_t uid,
                                    const LayerVector::Visitor& visitor) {
        return mFlinger->SurfaceFlinger::traverseLayersInLayerStack(layerStack, uid, visitor);
    }

    auto getDisplayNativePrimaries(const sp<IBinder>& displayToken,
                                   ui::DisplayPrimaries &primaries) {
        return mFlinger->SurfaceFlinger::getDisplayNativePrimaries(displayToken, primaries);
    }

    auto& getTransactionQueue() { return mFlinger->mTransactionQueue; }
    auto& getPendingTransactionQueue() { return mFlinger->mPendingTransactionQueues; }
    auto& getTransactionCommittedSignals() { return mFlinger->mTransactionCommittedSignals; }

    auto setTransactionState(
            const FrameTimelineInfo& frameTimelineInfo, const Vector<ComposerState>& states,
            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
            const InputWindowCommands& inputWindowCommands, int64_t desiredPresentTime,
            bool isAutoTimestamp, const client_cache_t& uncacheBuffer, bool hasListenerCallbacks,
            std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId) {
        return mFlinger->setTransactionState(frameTimelineInfo, states, displays, flags, applyToken,
                                             inputWindowCommands, desiredPresentTime,
                                             isAutoTimestamp, uncacheBuffer, hasListenerCallbacks,
                                             listenerCallbacks, transactionId);
    }

    auto flushTransactionQueues() { return mFlinger->flushTransactionQueues(0); };

    auto onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
        return mFlinger->onTransact(code, data, reply, flags);
    }

    auto getGPUContextPriority() { return mFlinger->getGPUContextPriority(); }

    auto calculateMaxAcquiredBufferCount(Fps refreshRate,
                                         std::chrono::nanoseconds presentLatency) const {
        return SurfaceFlinger::calculateMaxAcquiredBufferCount(refreshRate, presentLatency);
    }

    auto setDesiredDisplayModeSpecs(const sp<IBinder>& displayToken, ui::DisplayModeId defaultMode,
                                    bool allowGroupSwitching, float primaryRefreshRateMin,
                                    float primaryRefreshRateMax, float appRequestRefreshRateMin,
                                    float appRequestRefreshRateMax) {
        return mFlinger->setDesiredDisplayModeSpecs(displayToken, defaultMode, allowGroupSwitching,
                                                    primaryRefreshRateMin, primaryRefreshRateMax,
                                                    appRequestRefreshRateMin,
                                                    appRequestRefreshRateMax);
    }

    void onActiveDisplayChanged(const sp<DisplayDevice>& activeDisplay) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        mFlinger->onActiveDisplayChangedLocked(activeDisplay);
    }

    auto createLayer(LayerCreationArgs& args, sp<IBinder>* outHandle,
                     const sp<IBinder>& parentHandle, int32_t* outLayerId,
                     const sp<Layer>& parentLayer, uint32_t* outTransformHint) {
        return mFlinger->createLayer(args, outHandle, parentHandle, outLayerId, parentLayer,
                                     outTransformHint);
    }

    auto mirrorLayer(const LayerCreationArgs& args, const sp<IBinder>& mirrorFromHandle,
                     sp<IBinder>* outHandle, int32_t* outLayerId) {
        return mFlinger->mirrorLayer(args, mirrorFromHandle, outHandle, outLayerId);
    }

    /* ------------------------------------------------------------------------
     * Read-only access to private data to assert post-conditions.
     */

    const auto& getAnimFrameTracker() const { return mFlinger->mAnimFrameTracker; }
    const auto& getHasPoweredOff() const { return mFlinger->mHasPoweredOff; }
    const auto& getVisibleRegionsDirty() const { return mFlinger->mVisibleRegionsDirty; }
    auto& getHwComposer() const {
        return static_cast<impl::HWComposer&>(mFlinger->getHwComposer());
    }
    auto& getCompositionEngine() const { return mFlinger->getCompositionEngine(); }

    const auto& getCompositorTiming() const { return mFlinger->getBE().mCompositorTiming; }

    mock::FrameTracer* getFrameTracer() const {
        return static_cast<mock::FrameTracer*>(mFlinger->mFrameTracer.get());
    }

    nsecs_t getAnimationTransactionTimeout() const {
        return mFlinger->mAnimationTransactionTimeout;
    }

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */

    const auto& displays() const { return mFlinger->mDisplays; }
    const auto& currentState() const { return mFlinger->mCurrentState; }
    const auto& drawingState() const { return mFlinger->mDrawingState; }
    const auto& transactionFlags() const { return mFlinger->mTransactionFlags; }
    const auto& hwcPhysicalDisplayIdMap() const { return getHwComposer().mPhysicalDisplayIdMap; }

    auto& mutableHasWideColorDisplay() { return SurfaceFlinger::hasWideColorDisplay; }

    auto& mutableCurrentState() { return mFlinger->mCurrentState; }
    auto& mutableDisplayColorSetting() { return mFlinger->mDisplayColorSetting; }
    auto& mutableDisplays() { return mFlinger->mDisplays; }
    auto& mutableDrawingState() { return mFlinger->mDrawingState; }
    auto& mutableGeometryDirty() { return mFlinger->mGeometryDirty; }
    auto& mutableInterceptor() { return mFlinger->mInterceptor; }
    auto& mutableMainThreadId() { return mFlinger->mMainThreadId; }
    auto& mutablePendingHotplugEvents() { return mFlinger->mPendingHotplugEvents; }
    auto& mutablePhysicalDisplayTokens() { return mFlinger->mPhysicalDisplayTokens; }
    auto& mutableTexturePool() { return mFlinger->mTexturePool; }
    auto& mutableTransactionFlags() { return mFlinger->mTransactionFlags; }
    auto& mutableDebugDisableHWC() { return mFlinger->mDebugDisableHWC; }
    auto& mutableMaxRenderTargetSize() { return mFlinger->mMaxRenderTargetSize; }

    auto& mutableHwcDisplayData() { return getHwComposer().mDisplayData; }
    auto& mutableHwcPhysicalDisplayIdMap() { return getHwComposer().mPhysicalDisplayIdMap; }
    auto& mutablePrimaryHwcDisplayId() { return getHwComposer().mPrimaryHwcDisplayId; }
    auto& mutableActiveDisplayToken() { return mFlinger->mActiveDisplayToken; }

    auto fromHandle(const sp<IBinder>& handle) {
        return mFlinger->fromHandle(handle);
    }

    ~TestableSurfaceFlinger() {
        // All these pointer and container clears help ensure that GMock does
        // not report a leaked object, since the SurfaceFlinger instance may
        // still be referenced by something despite our best efforts to destroy
        // it after each test is done.
        mutableDisplays().clear();
        mutableCurrentState().displays.clear();
        mutableDrawingState().displays.clear();
        mutableInterceptor().clear();
        mFlinger->mScheduler.reset();
        mFlinger->mCompositionEngine->setHwComposer(std::unique_ptr<HWComposer>());
        mFlinger->mCompositionEngine->setRenderEngine(
                std::unique_ptr<renderengine::RenderEngine>());
    }

    /* ------------------------------------------------------------------------
     * Wrapper classes for Read-write access to private data to set up
     * preconditions and assert post-conditions.
     */
    struct HWC2Display : public HWC2::impl::Display {
        HWC2Display(
                Hwc2::Composer& composer,
                const std::unordered_set<aidl::android::hardware::graphics::composer3::Capability>&
                        capabilities,
                hal::HWDisplayId id, hal::DisplayType type)
              : HWC2::impl::Display(composer, capabilities, id, type) {}
        ~HWC2Display() {
            // Prevents a call to disable vsyncs.
            mType = hal::DisplayType::INVALID;
        }

        auto& mutableIsConnected() { return this->mIsConnected; }
        auto& mutableLayers() { return this->mLayers; }
    };

    class FakeHwcDisplayInjector {
    public:
        static constexpr hal::HWDisplayId DEFAULT_HWC_DISPLAY_ID = 1000;
        static constexpr ui::Size DEFAULT_RESOLUTION{1920, 1280};
        static constexpr int32_t DEFAULT_VSYNC_PERIOD = 16'666'667;
        static constexpr int32_t DEFAULT_CONFIG_GROUP = 7;
        static constexpr int32_t DEFAULT_DPI = 320;
        static constexpr hal::HWConfigId DEFAULT_ACTIVE_CONFIG = 0;
        static constexpr hal::PowerMode DEFAULT_POWER_MODE = hal::PowerMode::ON;

        FakeHwcDisplayInjector(HalDisplayId displayId, hal::DisplayType hwcDisplayType,
                               bool isPrimary)
              : mDisplayId(displayId), mHwcDisplayType(hwcDisplayType), mIsPrimary(isPrimary) {}

        auto& setHwcDisplayId(hal::HWDisplayId displayId) {
            mHwcDisplayId = displayId;
            return *this;
        }

        auto& setResolution(ui::Size resolution) {
            mResolution = resolution;
            return *this;
        }

        auto& setVsyncPeriod(nsecs_t vsyncPeriod) {
            mVsyncPeriod = vsyncPeriod;
            return *this;
        }

        auto& setDpiX(int32_t dpi) {
            mDpiX = dpi;
            return *this;
        }

        auto& setDpiY(int32_t dpi) {
            mDpiY = dpi;
            return *this;
        }

        auto& setActiveConfig(hal::HWConfigId config) {
            mActiveConfig = config;
            return *this;
        }

        auto& setCapabilities(
                const std::unordered_set<aidl::android::hardware::graphics::composer3::Capability>*
                        capabilities) {
            mCapabilities = capabilities;
            return *this;
        }

        auto& setPowerMode(hal::PowerMode mode) {
            mPowerMode = mode;
            return *this;
        }

        void inject(TestableSurfaceFlinger* flinger, Hwc2::mock::Composer* composer) {
            using ::testing::_;
            using ::testing::DoAll;
            using ::testing::Return;
            using ::testing::SetArgPointee;

            static const std::unordered_set<
                    aidl::android::hardware::graphics::composer3::Capability>
                    defaultCapabilities;
            if (mCapabilities == nullptr) mCapabilities = &defaultCapabilities;

            // Caution - Make sure that any values passed by reference here do
            // not refer to an instance owned by FakeHwcDisplayInjector. This
            // class has temporary lifetime, while the constructed HWC2::Display
            // is much longer lived.
            auto display = std::make_unique<HWC2Display>(*composer, *mCapabilities, mHwcDisplayId,
                                                         mHwcDisplayType);

            display->mutableIsConnected() = true;
            display->setPowerMode(mPowerMode);
            flinger->mutableHwcDisplayData()[mDisplayId].hwcDisplay = std::move(display);

            EXPECT_CALL(*composer, getDisplayConfigs(mHwcDisplayId, _))
                    .WillRepeatedly(
                            DoAll(SetArgPointee<1>(std::vector<hal::HWConfigId>{mActiveConfig}),
                                  Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig, hal::Attribute::WIDTH, _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(mResolution.getWidth()),
                                          Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig, hal::Attribute::HEIGHT,
                                            _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(mResolution.getHeight()),
                                          Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig,
                                            hal::Attribute::VSYNC_PERIOD, _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(static_cast<int32_t>(mVsyncPeriod)),
                                          Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig, hal::Attribute::DPI_X, _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(mDpiX), Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig, hal::Attribute::DPI_Y, _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(mDpiY), Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig,
                                            hal::Attribute::CONFIG_GROUP, _))
                    .WillRepeatedly(
                            DoAll(SetArgPointee<3>(mConfigGroup), Return(hal::Error::NONE)));

            if (mHwcDisplayType == hal::DisplayType::PHYSICAL) {
                const auto physicalId = PhysicalDisplayId::tryCast(mDisplayId);
                LOG_ALWAYS_FATAL_IF(!physicalId);
                flinger->mutableHwcPhysicalDisplayIdMap().emplace(mHwcDisplayId, *physicalId);
                if (mIsPrimary) {
                    flinger->mutablePrimaryHwcDisplayId() = mHwcDisplayId;
                } else {
                    // If there is an external HWC display, there should always be a primary ID
                    // as well. Set it to some arbitrary value.
                    auto& primaryId = flinger->mutablePrimaryHwcDisplayId();
                    if (!primaryId) primaryId = mHwcDisplayId - 1;
                }
            }
        }

    private:
        const HalDisplayId mDisplayId;
        const hal::DisplayType mHwcDisplayType;
        const bool mIsPrimary;

        hal::HWDisplayId mHwcDisplayId = DEFAULT_HWC_DISPLAY_ID;
        ui::Size mResolution = DEFAULT_RESOLUTION;
        nsecs_t mVsyncPeriod = DEFAULT_VSYNC_PERIOD;
        int32_t mDpiX = DEFAULT_DPI;
        int32_t mDpiY = DEFAULT_DPI;
        int32_t mConfigGroup = DEFAULT_CONFIG_GROUP;
        hal::HWConfigId mActiveConfig = DEFAULT_ACTIVE_CONFIG;
        hal::PowerMode mPowerMode = DEFAULT_POWER_MODE;
        const std::unordered_set<aidl::android::hardware::graphics::composer3::Capability>*
                mCapabilities = nullptr;
    };

    class FakeDisplayDeviceInjector {
    public:
        FakeDisplayDeviceInjector(TestableSurfaceFlinger& flinger,
                                  std::shared_ptr<compositionengine::Display> display,
                                  std::optional<ui::DisplayConnectionType> connectionType,
                                  std::optional<hal::HWDisplayId> hwcDisplayId, bool isPrimary)
              : mFlinger(flinger),
                mCreationArgs(flinger.mFlinger.get(), flinger.mFlinger->getHwComposer(),
                              mDisplayToken, display),
                mHwcDisplayId(hwcDisplayId) {
            mCreationArgs.connectionType = connectionType;
            mCreationArgs.isPrimary = isPrimary;
            mCreationArgs.initialPowerMode = hal::PowerMode::ON;
        }

        sp<IBinder> token() const { return mDisplayToken; }

        DisplayDeviceState& mutableDrawingDisplayState() {
            return mFlinger.mutableDrawingState().displays.editValueFor(mDisplayToken);
        }

        DisplayDeviceState& mutableCurrentDisplayState() {
            return mFlinger.mutableCurrentState().displays.editValueFor(mDisplayToken);
        }

        const auto& getDrawingDisplayState() {
            return mFlinger.mutableDrawingState().displays.valueFor(mDisplayToken);
        }

        const auto& getCurrentDisplayState() {
            return mFlinger.mutableCurrentState().displays.valueFor(mDisplayToken);
        }

        const sp<DisplayDevice>& mutableDisplayDevice() {
            return mFlinger.mutableDisplays().get(mDisplayToken)->get();
        }

        // If `configs` is nullptr, the injector creates RefreshRateConfigs from the `modes`.
        // Otherwise, it uses `configs`, which the caller must create using the same `modes`.
        //
        // TODO(b/182939859): Once `modes` can be retrieved from RefreshRateConfigs, remove
        // the `configs` parameter in favor of an alternative setRefreshRateConfigs API.
        auto& setDisplayModes(DisplayModes modes, DisplayModeId activeModeId,
                              std::shared_ptr<scheduler::RefreshRateConfigs> configs = nullptr) {
            mCreationArgs.supportedModes = std::move(modes);
            mCreationArgs.activeModeId = activeModeId;
            mCreationArgs.refreshRateConfigs = std::move(configs);
            return *this;
        }

        auto& setNativeWindow(const sp<ANativeWindow>& nativeWindow) {
            mCreationArgs.nativeWindow = nativeWindow;
            return *this;
        }

        auto& setDisplaySurface(const sp<compositionengine::DisplaySurface>& displaySurface) {
            mCreationArgs.displaySurface = displaySurface;
            return *this;
        }

        auto& setSecure(bool secure) {
            mCreationArgs.isSecure = secure;
            return *this;
        }

        auto& setPowerMode(hal::PowerMode mode) {
            mCreationArgs.initialPowerMode = mode;
            return *this;
        }

        auto& setHwcColorModes(
                const std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>>
                        hwcColorModes) {
            mCreationArgs.hwcColorModes = hwcColorModes;
            return *this;
        }

        auto& setHasWideColorGamut(bool hasWideColorGamut) {
            mCreationArgs.hasWideColorGamut = hasWideColorGamut;
            return *this;
        }

        auto& setPhysicalOrientation(ui::Rotation orientation) {
            mCreationArgs.physicalOrientation = orientation;
            return *this;
        }

        sp<DisplayDevice> inject() NO_THREAD_SAFETY_ANALYSIS {
            const auto displayId = mCreationArgs.compositionDisplay->getDisplayId();

            auto& modes = mCreationArgs.supportedModes;
            auto& activeModeId = mCreationArgs.activeModeId;

            if (displayId && !mCreationArgs.refreshRateConfigs) {
                if (const auto physicalId = PhysicalDisplayId::tryCast(*displayId)) {
                    if (modes.empty()) {
                        constexpr DisplayModeId kModeId{0};
                        DisplayModePtr mode =
                                DisplayMode::Builder(FakeHwcDisplayInjector::DEFAULT_ACTIVE_CONFIG)
                                        .setId(kModeId)
                                        .setPhysicalDisplayId(*physicalId)
                                        .setResolution(FakeHwcDisplayInjector::DEFAULT_RESOLUTION)
                                        .setVsyncPeriod(
                                                FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD)
                                        .setDpiX(FakeHwcDisplayInjector::DEFAULT_DPI)
                                        .setDpiY(FakeHwcDisplayInjector::DEFAULT_DPI)
                                        .setGroup(FakeHwcDisplayInjector::DEFAULT_CONFIG_GROUP)
                                        .build();

                        modes = ftl::init::map(kModeId, std::move(mode));
                        activeModeId = kModeId;
                    }

                    mCreationArgs.refreshRateConfigs =
                            std::make_shared<scheduler::RefreshRateConfigs>(modes, activeModeId);
                }
            }

            DisplayDeviceState state;
            if (const auto type = mCreationArgs.connectionType) {
                LOG_ALWAYS_FATAL_IF(!displayId);
                const auto physicalId = PhysicalDisplayId::tryCast(*displayId);
                LOG_ALWAYS_FATAL_IF(!physicalId);
                LOG_ALWAYS_FATAL_IF(!mHwcDisplayId);

                const auto activeMode = modes.get(activeModeId);
                LOG_ALWAYS_FATAL_IF(!activeMode);

                state.physical = {.id = *physicalId,
                                  .type = *type,
                                  .hwcDisplayId = *mHwcDisplayId,
                                  .deviceProductInfo = {},
                                  .supportedModes = modes,
                                  .activeMode = activeMode->get()};
            }

            state.isSecure = mCreationArgs.isSecure;

            sp<DisplayDevice> display = sp<DisplayDevice>::make(mCreationArgs);
            if (!display->isVirtual()) {
                display->setActiveMode(activeModeId);
            }
            mFlinger.mutableDisplays().emplace_or_replace(mDisplayToken, display);

            mFlinger.mutableCurrentState().displays.add(mDisplayToken, state);
            mFlinger.mutableDrawingState().displays.add(mDisplayToken, state);

            if (const auto& physical = state.physical) {
                mFlinger.mutablePhysicalDisplayTokens().emplace_or_replace(physical->id,
                                                                           mDisplayToken);
            }

            return display;
        }

    private:
        TestableSurfaceFlinger& mFlinger;
        sp<BBinder> mDisplayToken = new BBinder();
        DisplayDeviceCreationArgs mCreationArgs;
        const std::optional<hal::HWDisplayId> mHwcDisplayId;
    };

private:
    constexpr static int64_t kVsyncId = 123;

    surfaceflinger::test::Factory mFactory;
    sp<SurfaceFlinger> mFlinger;
    scheduler::mock::SchedulerCallback mSchedulerCallback;
    scheduler::mock::NoOpSchedulerCallback mNoOpSchedulerCallback;
    scheduler::TestableScheduler* mScheduler = nullptr;
};

} // namespace android
