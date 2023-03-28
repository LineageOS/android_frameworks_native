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
#include <ftl/fake_guard.h>
#include <ftl/match.h>
#include <gui/ScreenCaptureResults.h>

#include <ui/DynamicDisplayInfo.h>
#include "DisplayDevice.h"
#include "FakeVsyncConfiguration.h"
#include "FrameTracer/FrameTracer.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/LayerHandle.h"
#include "Layer.h"
#include "NativeWindowSurface.h"
#include "RenderArea.h"
#include "Scheduler/MessageQueue.h"
#include "Scheduler/RefreshRateSelector.h"
#include "StartPropertySetThread.h"
#include "SurfaceFlinger.h"
#include "SurfaceFlingerDefaultFactory.h"
#include "TestableScheduler.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockEventThread.h"
#include "mock/MockFrameTimeline.h"
#include "mock/MockFrameTracer.h"
#include "mock/MockSchedulerCallback.h"

namespace android {
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

    sp<StartPropertySetThread> createStartPropertySetThread(bool timestampPropertyValue) override {
        return sp<StartPropertySetThread>::make(timestampPropertyValue);
    }

    sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs& creationArgs) override {
        return sp<DisplayDevice>::make(creationArgs);
    }

    sp<GraphicBuffer> createGraphicBuffer(uint32_t width, uint32_t height, PixelFormat format,
                                          uint32_t layerCount, uint64_t usage,
                                          std::string requestorName) override {
        return sp<GraphicBuffer>::make(width, height, format, layerCount, usage, requestorName);
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

    std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer>& producer) override {
        if (!mCreateNativeWindowSurface) return nullptr;
        return mCreateNativeWindowSurface(producer);
    }

    std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() override {
        return compositionengine::impl::createCompositionEngine();
    }

    sp<Layer> createBufferStateLayer(const LayerCreationArgs&) override { return nullptr; }

    sp<Layer> createEffectLayer(const LayerCreationArgs&) override { return nullptr; }

    sp<LayerFE> createLayerFE(const std::string& layerName) override {
        return sp<LayerFE>::make(layerName);
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

struct MockSchedulerOptions {
    PhysicalDisplayId displayId = PhysicalDisplayId::fromPort(0);
    bool useNiceMock = false;
};

} // namespace surfaceflinger::test

class TestableSurfaceFlinger {
public:
    using HotplugEvent = SurfaceFlinger::HotplugEvent;

    TestableSurfaceFlinger(sp<SurfaceFlinger> flinger = nullptr) : mFlinger(flinger) {
        if (!mFlinger) {
            mFlinger = sp<SurfaceFlinger>::make(mFactory, SurfaceFlinger::SkipInitialization);
        }
    }

    SurfaceFlinger* flinger() { return mFlinger.get(); }
    scheduler::TestableScheduler* scheduler() { return mScheduler; }

    // Extend this as needed for accessing SurfaceFlinger private (and public)
    // functions.

    void setupRenderEngine(std::unique_ptr<renderengine::RenderEngine> renderEngine) {
        mFlinger->mRenderEngine = std::move(renderEngine);
        mFlinger->mCompositionEngine->setRenderEngine(mFlinger->mRenderEngine.get());
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

    struct DefaultDisplayMode {
        // The ID of the injected RefreshRateSelector and its default display mode.
        PhysicalDisplayId displayId;
    };

    using RefreshRateSelectorPtr = scheduler::Scheduler::RefreshRateSelectorPtr;

    using DisplayModesVariant = std::variant<DefaultDisplayMode, RefreshRateSelectorPtr>;

    void setupScheduler(std::unique_ptr<scheduler::VsyncController> vsyncController,
                        std::shared_ptr<scheduler::VSyncTracker> vsyncTracker,
                        std::unique_ptr<EventThread> appEventThread,
                        std::unique_ptr<EventThread> sfEventThread,
                        DisplayModesVariant modesVariant,
                        SchedulerCallbackImpl callbackImpl = SchedulerCallbackImpl::kNoOp,
                        bool useNiceMock = false) {
        RefreshRateSelectorPtr selectorPtr = ftl::match(
                modesVariant,
                [](DefaultDisplayMode arg) {
                    constexpr DisplayModeId kModeId60{0};
                    return std::make_shared<scheduler::RefreshRateSelector>(
                            makeModes(mock::createDisplayMode(arg.displayId, kModeId60, 60_Hz)),
                            kModeId60);
                },
                [](RefreshRateSelectorPtr selectorPtr) { return selectorPtr; });

        const auto fps = selectorPtr->getActiveMode().fps;
        mFlinger->mVsyncConfiguration = mFactory.createVsyncConfiguration(fps);

        mFlinger->mRefreshRateStats =
                std::make_unique<scheduler::RefreshRateStats>(*mFlinger->mTimeStats, fps,
                                                              hal::PowerMode::OFF);

        mTokenManager = std::make_unique<frametimeline::impl::TokenManager>();

        using Callback = scheduler::ISchedulerCallback;
        Callback& callback = callbackImpl == SchedulerCallbackImpl::kNoOp
                ? static_cast<Callback&>(mNoOpSchedulerCallback)
                : static_cast<Callback&>(mSchedulerCallback);

        auto modulatorPtr = sp<scheduler::VsyncModulator>::make(
                mFlinger->mVsyncConfiguration->getCurrentConfigs());

        if (useNiceMock) {
            mScheduler =
                    new testing::NiceMock<scheduler::TestableScheduler>(std::move(vsyncController),
                                                                        std::move(vsyncTracker),
                                                                        std::move(selectorPtr),
                                                                        std::move(modulatorPtr),
                                                                        callback);
        } else {
            mScheduler = new scheduler::TestableScheduler(std::move(vsyncController),
                                                          std::move(vsyncTracker),
                                                          std::move(selectorPtr),
                                                          std::move(modulatorPtr), callback);
        }

        mScheduler->initVsync(mScheduler->getVsyncSchedule()->getDispatch(), *mTokenManager, 0ms);

        mScheduler->mutableAppConnectionHandle() =
                mScheduler->createConnection(std::move(appEventThread));

        mFlinger->mAppConnectionHandle = mScheduler->mutableAppConnectionHandle();
        mFlinger->mSfConnectionHandle = mScheduler->createConnection(std::move(sfEventThread));
        resetScheduler(mScheduler);
    }

    void setupMockScheduler(test::MockSchedulerOptions options = {}) {
        using testing::_;
        using testing::Return;

        auto eventThread = makeMock<mock::EventThread>(options.useNiceMock);
        auto sfEventThread = makeMock<mock::EventThread>(options.useNiceMock);

        EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*eventThread, createEventConnection(_, _))
                .WillOnce(Return(sp<EventThreadConnection>::make(eventThread.get(),
                                                                 mock::EventThread::kCallingUid,
                                                                 ResyncCallback())));

        EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
                .WillOnce(Return(sp<EventThreadConnection>::make(sfEventThread.get(),
                                                                 mock::EventThread::kCallingUid,
                                                                 ResyncCallback())));

        auto vsyncController = makeMock<mock::VsyncController>(options.useNiceMock);
        auto vsyncTracker = makeSharedMock<mock::VSyncTracker>(options.useNiceMock);

        EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
        EXPECT_CALL(*vsyncTracker, currentPeriod())
                .WillRepeatedly(Return(FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD));
        EXPECT_CALL(*vsyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
        setupScheduler(std::move(vsyncController), std::move(vsyncTracker), std::move(eventThread),
                       std::move(sfEventThread), DefaultDisplayMode{options.displayId},
                       SchedulerCallbackImpl::kNoOp, options.useNiceMock);
    }

    void resetScheduler(scheduler::Scheduler* scheduler) { mFlinger->mScheduler.reset(scheduler); }

    scheduler::TestableScheduler& mutableScheduler() { return *mScheduler; }
    scheduler::mock::SchedulerCallback& mockSchedulerCallback() { return mSchedulerCallback; }

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
        layer->editLayerSnapshot()->sidebandStream = sidebandStream;
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

    /* ------------------------------------------------------------------------
     * Forwarding for functions being tested
     */

    void configure() { mFlinger->configure(); }

    void configureAndCommit() {
        configure();
        commitTransactionsLocked(eDisplayTransactionNeeded);
    }

    TimePoint commit(TimePoint frameTime, VsyncId vsyncId, TimePoint expectedVsyncTime) {
        mFlinger->commit(frameTime, vsyncId, expectedVsyncTime);
        return frameTime;
    }

    TimePoint commit(TimePoint frameTime, VsyncId vsyncId) {
        return commit(frameTime, vsyncId, frameTime + Period(10ms));
    }

    TimePoint commit() {
        const TimePoint frameTime = scheduler::SchedulerClock::now();
        return commit(frameTime, kVsyncId);
    }

    void commitAndComposite(TimePoint frameTime, VsyncId vsyncId, TimePoint expectedVsyncTime) {
        mFlinger->composite(commit(frameTime, vsyncId, expectedVsyncTime), vsyncId);
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

    void commitTransactionsLocked(uint32_t transactionFlags) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        ftl::FakeGuard guard(kMainThreadContext);
        mFlinger->commitTransactionsLocked(transactionFlags);
    }

    void onComposerHalHotplug(hal::HWDisplayId hwcDisplayId, hal::Connection connection) {
        mFlinger->onComposerHalHotplug(hwcDisplayId, connection);
    }

    auto setDisplayStateLocked(const DisplayState& s) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        return mFlinger->setDisplayStateLocked(s);
    }

    void initializeDisplays() FTL_FAKE_GUARD(kMainThreadContext) { mFlinger->initializeDisplays(); }

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

    auto renderScreenImpl(std::shared_ptr<const RenderArea> renderArea,
                          SurfaceFlinger::GetLayerSnapshotsFunction traverseLayers,
                          const std::shared_ptr<renderengine::ExternalTexture>& buffer,
                          bool forSystem, bool regionSampling) {
        ScreenCaptureResults captureResults;
        return FTL_FAKE_GUARD(kMainThreadContext,
                              mFlinger->renderScreenImpl(std::move(renderArea), traverseLayers,
                                                         buffer, forSystem, regionSampling,
                                                         false /* grayscale */, captureResults));
    }

    auto traverseLayersInLayerStack(ui::LayerStack layerStack, int32_t uid,
                                    const LayerVector::Visitor& visitor) {
        return mFlinger->SurfaceFlinger::traverseLayersInLayerStack(layerStack, uid, visitor);
    }

    auto getDisplayNativePrimaries(const sp<IBinder>& displayToken,
                                   ui::DisplayPrimaries &primaries) {
        return mFlinger->SurfaceFlinger::getDisplayNativePrimaries(displayToken, primaries);
    }

    auto& getTransactionQueue() { return mFlinger->mTransactionHandler.mLocklessTransactionQueue; }
    auto& getPendingTransactionQueue() {
        return mFlinger->mTransactionHandler.mPendingTransactionQueues;
    }
    size_t getPendingTransactionCount() {
        return mFlinger->mTransactionHandler.mPendingTransactionCount.load();
    }

    auto setTransactionState(const FrameTimelineInfo& frameTimelineInfo,
                             Vector<ComposerState>& states, const Vector<DisplayState>& displays,
                             uint32_t flags, const sp<IBinder>& applyToken,
                             const InputWindowCommands& inputWindowCommands,
                             int64_t desiredPresentTime, bool isAutoTimestamp,
                             const std::vector<client_cache_t>& uncacheBuffers,
                             bool hasListenerCallbacks,
                             std::vector<ListenerCallbacks>& listenerCallbacks,
                             uint64_t transactionId) {
        return mFlinger->setTransactionState(frameTimelineInfo, states, displays, flags, applyToken,
                                             inputWindowCommands, desiredPresentTime,
                                             isAutoTimestamp, uncacheBuffers, hasListenerCallbacks,
                                             listenerCallbacks, transactionId);
    }

    auto setTransactionStateInternal(TransactionState& transaction) {
        return mFlinger->mTransactionHandler.queueTransaction(std::move(transaction));
    }

    auto flushTransactionQueues() {
        return FTL_FAKE_GUARD(kMainThreadContext, mFlinger->flushTransactionQueues(kVsyncId));
    }

    auto onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
        return mFlinger->onTransact(code, data, reply, flags);
    }

    auto getGpuContextPriority() { return mFlinger->getGpuContextPriority(); }

    auto calculateMaxAcquiredBufferCount(Fps refreshRate,
                                         std::chrono::nanoseconds presentLatency) const {
        return SurfaceFlinger::calculateMaxAcquiredBufferCount(refreshRate, presentLatency);
    }

    auto setDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                    const gui::DisplayModeSpecs& specs) {
        return mFlinger->setDesiredDisplayModeSpecs(displayToken, specs);
    }

    void onActiveDisplayChanged(const DisplayDevice* inactiveDisplayPtr,
                                const DisplayDevice& activeDisplay) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        ftl::FakeGuard guard(kMainThreadContext);
        mFlinger->onActiveDisplayChangedLocked(inactiveDisplayPtr, activeDisplay);
    }

    auto createLayer(LayerCreationArgs& args, const sp<IBinder>& parentHandle,
                     gui::CreateSurfaceResult& outResult) {
        args.parentHandle = parentHandle;
        return mFlinger->createLayer(args, outResult);
    }

    auto mirrorLayer(const LayerCreationArgs& args, const sp<IBinder>& mirrorFromHandle,
                     gui::CreateSurfaceResult& outResult) {
        return mFlinger->mirrorLayer(args, mirrorFromHandle, outResult);
    }

    void updateLayerMetadataSnapshot() { mFlinger->updateLayerMetadataSnapshot(); }

    void getDynamicDisplayInfoFromToken(const sp<IBinder>& displayToken,
                                        ui::DynamicDisplayInfo* dynamicDisplayInfo) {
        mFlinger->getDynamicDisplayInfoFromToken(displayToken, dynamicDisplayInfo);
    }

    /* ------------------------------------------------------------------------
     * Read-only access to private data to assert post-conditions.
     */

    const auto& getVisibleRegionsDirty() const { return mFlinger->mVisibleRegionsDirty; }
    auto& getHwComposer() const {
        return static_cast<impl::HWComposer&>(mFlinger->getHwComposer());
    }
    auto& getCompositionEngine() const { return mFlinger->getCompositionEngine(); }

    mock::FrameTracer* getFrameTracer() const {
        return static_cast<mock::FrameTracer*>(mFlinger->mFrameTracer.get());
    }

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */

    const auto& displays() const { return mFlinger->mDisplays; }
    const auto& physicalDisplays() const { return mFlinger->mPhysicalDisplays; }
    const auto& currentState() const { return mFlinger->mCurrentState; }
    const auto& drawingState() const { return mFlinger->mDrawingState; }
    const auto& transactionFlags() const { return mFlinger->mTransactionFlags; }

    const auto& hwcPhysicalDisplayIdMap() const { return getHwComposer().mPhysicalDisplayIdMap; }
    const auto& hwcDisplayData() const { return getHwComposer().mDisplayData; }

    auto& mutableSupportsWideColor() { return mFlinger->mSupportsWideColor; }

    auto& mutableCurrentState() { return mFlinger->mCurrentState; }
    auto& mutableDisplayColorSetting() { return mFlinger->mDisplayColorSetting; }
    auto& mutableDisplays() { return mFlinger->mDisplays; }
    auto& mutablePhysicalDisplays() { return mFlinger->mPhysicalDisplays; }
    auto& mutableDrawingState() { return mFlinger->mDrawingState; }
    auto& mutableGeometryDirty() { return mFlinger->mGeometryDirty; }
    auto& mutableMainThreadId() { return mFlinger->mMainThreadId; }
    auto& mutablePendingHotplugEvents() { return mFlinger->mPendingHotplugEvents; }
    auto& mutableTexturePool() { return mFlinger->mTexturePool; }
    auto& mutableTransactionFlags() { return mFlinger->mTransactionFlags; }
    auto& mutableDebugDisableHWC() { return mFlinger->mDebugDisableHWC; }
    auto& mutableMaxRenderTargetSize() { return mFlinger->mMaxRenderTargetSize; }

    auto& mutableHwcDisplayData() { return getHwComposer().mDisplayData; }
    auto& mutableHwcPhysicalDisplayIdMap() { return getHwComposer().mPhysicalDisplayIdMap; }
    auto& mutablePrimaryHwcDisplayId() { return getHwComposer().mPrimaryHwcDisplayId; }
    auto& mutableActiveDisplayId() { return mFlinger->mActiveDisplayId; }

    auto fromHandle(const sp<IBinder>& handle) { return LayerHandle::getLayer(handle); }

    ~TestableSurfaceFlinger() {
        // All these pointer and container clears help ensure that GMock does
        // not report a leaked object, since the SurfaceFlinger instance may
        // still be referenced by something despite our best efforts to destroy
        // it after each test is done.
        mutableDisplays().clear();
        mutableCurrentState().displays.clear();
        mutableDrawingState().displays.clear();
        mFlinger->mScheduler.reset();
        mFlinger->mCompositionEngine->setHwComposer(std::unique_ptr<HWComposer>());
        mFlinger->mRenderEngine = std::unique_ptr<renderengine::RenderEngine>();
        mFlinger->mCompositionEngine->setRenderEngine(mFlinger->mRenderEngine.get());
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

        auto& setPowerMode(std::optional<hal::PowerMode> mode) {
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

            if (mPowerMode) {
                display->setPowerMode(*mPowerMode);
            }

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
        std::optional<hal::PowerMode> mPowerMode = DEFAULT_POWER_MODE;
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
                mCreationArgs(flinger.mFlinger, flinger.mFlinger->getHwComposer(), mDisplayToken,
                              display),
                mConnectionType(connectionType),
                mHwcDisplayId(hwcDisplayId) {
            mCreationArgs.isPrimary = isPrimary;
            mCreationArgs.initialPowerMode = hal::PowerMode::ON;
        }

        sp<IBinder> token() const { return mDisplayToken; }

        auto physicalDisplay() const {
            return ftl::Optional(mCreationArgs.compositionDisplay->getDisplayId())
                    .and_then(&PhysicalDisplayId::tryCast)
                    .and_then(display::getPhysicalDisplay(mFlinger.physicalDisplays()));
        }

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

        auto& setDisplayModes(DisplayModes modes, DisplayModeId activeModeId) {
            mDisplayModes = std::move(modes);
            mCreationArgs.activeModeId = activeModeId;
            mCreationArgs.refreshRateSelector = nullptr;
            return *this;
        }

        auto& setRefreshRateSelector(RefreshRateSelectorPtr selectorPtr) {
            mDisplayModes = selectorPtr->displayModes();
            mCreationArgs.activeModeId = selectorPtr->getActiveMode().modePtr->getId();
            mCreationArgs.refreshRateSelector = std::move(selectorPtr);
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

        auto& setPowerMode(std::optional<hal::PowerMode> mode) {
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

        auto& skipRegisterDisplay() {
            mRegisterDisplay = false;
            return *this;
        }

        sp<DisplayDevice> inject() NO_THREAD_SAFETY_ANALYSIS {
            const auto displayId = mCreationArgs.compositionDisplay->getDisplayId();

            auto& modes = mDisplayModes;
            auto& activeModeId = mCreationArgs.activeModeId;

            if (displayId && !mCreationArgs.refreshRateSelector) {
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

                    mCreationArgs.refreshRateSelector =
                            std::make_shared<scheduler::RefreshRateSelector>(modes, activeModeId);
                }
            }

            sp<DisplayDevice> display = sp<DisplayDevice>::make(mCreationArgs);
            mFlinger.mutableDisplays().emplace_or_replace(mDisplayToken, display);

            DisplayDeviceState state;
            state.isSecure = mCreationArgs.isSecure;

            if (mConnectionType) {
                LOG_ALWAYS_FATAL_IF(!displayId);
                const auto physicalIdOpt = PhysicalDisplayId::tryCast(*displayId);
                LOG_ALWAYS_FATAL_IF(!physicalIdOpt);
                const auto physicalId = *physicalIdOpt;

                if (mCreationArgs.isPrimary) {
                    mFlinger.mutableActiveDisplayId() = physicalId;
                }

                LOG_ALWAYS_FATAL_IF(!mHwcDisplayId);

                const auto activeMode = modes.get(activeModeId);
                LOG_ALWAYS_FATAL_IF(!activeMode);
                const auto fps = activeMode->get()->getFps();

                state.physical = {.id = physicalId,
                                  .hwcDisplayId = *mHwcDisplayId,
                                  .activeMode = activeMode->get()};

                mFlinger.mutablePhysicalDisplays().emplace_or_replace(physicalId, mDisplayToken,
                                                                      physicalId, *mConnectionType,
                                                                      std::move(modes),
                                                                      ui::ColorModes(),
                                                                      std::nullopt);

                if (mFlinger.scheduler() && mRegisterDisplay) {
                    mFlinger.scheduler()->registerDisplay(physicalId,
                                                          display->holdRefreshRateSelector());
                }

                display->setActiveMode(activeModeId, fps, fps);
            }

            mFlinger.mutableCurrentState().displays.add(mDisplayToken, state);
            mFlinger.mutableDrawingState().displays.add(mDisplayToken, state);

            return display;
        }

    private:
        TestableSurfaceFlinger& mFlinger;
        sp<BBinder> mDisplayToken = sp<BBinder>::make();
        DisplayDeviceCreationArgs mCreationArgs;
        DisplayModes mDisplayModes;
        bool mRegisterDisplay = true;
        const std::optional<ui::DisplayConnectionType> mConnectionType;
        const std::optional<hal::HWDisplayId> mHwcDisplayId;
    };

private:
    template <typename T>
    static std::unique_ptr<T> makeMock(bool useNiceMock) {
        return useNiceMock ? std::make_unique<testing::NiceMock<T>>() : std::make_unique<T>();
    }

    template <typename T>
    static std::shared_ptr<T> makeSharedMock(bool useNiceMock) {
        return useNiceMock ? std::make_shared<testing::NiceMock<T>>() : std::make_shared<T>();
    }

    static constexpr VsyncId kVsyncId{123};

    surfaceflinger::test::Factory mFactory;
    sp<SurfaceFlinger> mFlinger;
    scheduler::mock::SchedulerCallback mSchedulerCallback;
    scheduler::mock::NoOpSchedulerCallback mNoOpSchedulerCallback;
    std::unique_ptr<frametimeline::impl::TokenManager> mTokenManager;
    scheduler::TestableScheduler* mScheduler = nullptr;
};

} // namespace android
