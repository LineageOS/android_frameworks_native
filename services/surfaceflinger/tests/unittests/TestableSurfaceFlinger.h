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
#include "mock/MockFrameTimeline.h"
#include "mock/MockFrameTracer.h"

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

    std::unique_ptr<MessageQueue> createMessageQueue() override {
        return std::make_unique<android::impl::MessageQueue>();
    }

    std::unique_ptr<scheduler::VsyncConfiguration> createVsyncConfiguration(
            Fps /*currentRefreshRate*/) override {
        return std::make_unique<scheduler::FakePhaseOffsets>();
    }

    std::unique_ptr<Scheduler> createScheduler(
            const std::shared_ptr<scheduler::RefreshRateConfigs>&, ISchedulerCallback&) override {
        return nullptr;
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

class TestableSurfaceFlinger final : private ISchedulerCallback {
public:
    using HotplugEvent = SurfaceFlinger::HotplugEvent;

    SurfaceFlinger* flinger() { return mFlinger.get(); }
    TestableScheduler* scheduler() { return mScheduler; }

    // Extend this as needed for accessing SurfaceFlinger private (and public)
    // functions.

    void setupRenderEngine(std::unique_ptr<renderengine::RenderEngine> renderEngine) {
        mFlinger->mCompositionEngine->setRenderEngine(std::move(renderEngine));
    }

    void setupComposer(std::unique_ptr<Hwc2::Composer> composer) {
        mFlinger->mCompositionEngine->setHwComposer(
                std::make_unique<impl::HWComposer>(std::move(composer)));
    }

    void setupTimeStats(const std::shared_ptr<TimeStats>& timeStats) {
        mFlinger->mCompositionEngine->setTimeStats(timeStats);
    }

    // The ISchedulerCallback argument can be nullptr for a no-op implementation.
    void setupScheduler(std::unique_ptr<scheduler::VsyncController> vsyncController,
                        std::unique_ptr<scheduler::VSyncTracker> vsyncTracker,
                        std::unique_ptr<EventThread> appEventThread,
                        std::unique_ptr<EventThread> sfEventThread,
                        ISchedulerCallback* callback = nullptr, bool hasMultipleModes = false) {
        DisplayModes modes{DisplayMode::Builder(0)
                                   .setId(DisplayModeId(0))
                                   .setPhysicalDisplayId(PhysicalDisplayId(0))
                                   .setVsyncPeriod(16'666'667)
                                   .setGroup(0)
                                   .build()};

        if (hasMultipleModes) {
            modes.emplace_back(DisplayMode::Builder(1)
                                       .setId(DisplayModeId(1))
                                       .setPhysicalDisplayId(PhysicalDisplayId(0))
                                       .setVsyncPeriod(11'111'111)
                                       .setGroup(0)
                                       .build());
        }

        const auto currMode = DisplayModeId(0);
        mRefreshRateConfigs = std::make_shared<scheduler::RefreshRateConfigs>(modes, currMode);
        const auto currFps = mRefreshRateConfigs->getCurrentRefreshRate().getFps();
        mFlinger->mVsyncConfiguration = mFactory.createVsyncConfiguration(currFps);
        mFlinger->mVsyncModulator = sp<scheduler::VsyncModulator>::make(
                mFlinger->mVsyncConfiguration->getCurrentConfigs());
        mFlinger->mRefreshRateStats =
                std::make_unique<scheduler::RefreshRateStats>(*mFlinger->mTimeStats, currFps,
                                                              /*powerMode=*/hal::PowerMode::OFF);

        mScheduler = new TestableScheduler(std::move(vsyncController), std::move(vsyncTracker),
                                           mRefreshRateConfigs, *(callback ?: this));

        mFlinger->mAppConnectionHandle = mScheduler->createConnection(std::move(appEventThread));
        mFlinger->mSfConnectionHandle = mScheduler->createConnection(std::move(sfEventThread));
        resetScheduler(mScheduler);
    }

    void resetScheduler(Scheduler* scheduler) { mFlinger->mScheduler.reset(scheduler); }

    TestableScheduler& mutableScheduler() const { return *mScheduler; }

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

    void setLayerCompositionType(const sp<Layer>& layer, hal::Composition type) {
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

    auto createDisplay(const String8& displayName, bool secure) {
        return mFlinger->createDisplay(displayName, secure);
    }

    auto destroyDisplay(const sp<IBinder>& displayToken) {
        return mFlinger->destroyDisplay(displayToken);
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

    auto handleTransactionLocked(uint32_t transactionFlags) {
        Mutex::Autolock _l(mFlinger->mStateLock);
        return mFlinger->handleTransactionLocked(transactionFlags);
    }

    void onComposerHalHotplug(hal::HWDisplayId hwcDisplayId, hal::Connection connection) {
        mFlinger->onComposerHalHotplug(hwcDisplayId, connection);
    }

    auto setDisplayStateLocked(const DisplayState& s) {
        Mutex::Autolock _l(mFlinger->mStateLock);
        return mFlinger->setDisplayStateLocked(s);
    }

    // Allow reading display state without locking, as if called on the SF main thread.
    auto onInitializeDisplays() NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->onInitializeDisplays();
    }

    auto notifyPowerBoost(int32_t boostId) { return mFlinger->notifyPowerBoost(boostId); }

    // Allow reading display state without locking, as if called on the SF main thread.
    auto setPowerModeInternal(const sp<DisplayDevice>& display,
                              hal::PowerMode mode) NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->setPowerModeInternal(display, mode);
    }

    auto onMessageReceived(int32_t what) {
        return mFlinger->onMessageReceived(what, /*vsyncId=*/0, systemTime());
    }

    auto renderScreenImplLocked(const RenderArea& renderArea,
                                SurfaceFlinger::TraverseLayersFunction traverseLayers,
                                const std::shared_ptr<renderengine::ExternalTexture>& buffer,
                                bool forSystem, bool regionSampling) {
        ScreenCaptureResults captureResults;
        return mFlinger->renderScreenImplLocked(renderArea, traverseLayers, buffer, forSystem,
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

    auto flushTransactionQueues() { return mFlinger->flushTransactionQueues(); };

    auto onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
        return mFlinger->onTransact(code, data, reply, flags);
    }

    auto getGPUContextPriority() { return mFlinger->getGPUContextPriority(); }

    auto calculateMaxAcquiredBufferCount(Fps refreshRate,
                                         std::chrono::nanoseconds presentLatency) const {
        return SurfaceFlinger::calculateMaxAcquiredBufferCount(refreshRate, presentLatency);
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

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */

    auto& mutableHasWideColorDisplay() { return SurfaceFlinger::hasWideColorDisplay; }
    auto& mutableUseColorManagement() { return SurfaceFlinger::useColorManagement; }

    auto& mutableCurrentState() { return mFlinger->mCurrentState; }
    auto& mutableDisplayColorSetting() { return mFlinger->mDisplayColorSetting; }
    auto& mutableDisplays() { return mFlinger->mDisplays; }
    auto& mutableDrawingState() { return mFlinger->mDrawingState; }
    auto& mutableEventQueue() { return mFlinger->mEventQueue; }
    auto& mutableGeometryInvalid() { return mFlinger->mGeometryInvalid; }
    auto& mutableInterceptor() { return mFlinger->mInterceptor; }
    auto& mutableMainThreadId() { return mFlinger->mMainThreadId; }
    auto& mutablePendingHotplugEvents() { return mFlinger->mPendingHotplugEvents; }
    auto& mutablePhysicalDisplayTokens() { return mFlinger->mPhysicalDisplayTokens; }
    auto& mutableTexturePool() { return mFlinger->mTexturePool; }
    auto& mutableTransactionFlags() { return mFlinger->mTransactionFlags; }
    auto& mutablePowerAdvisor() { return mFlinger->mPowerAdvisor; }
    auto& mutableDebugDisableHWC() { return mFlinger->mDebugDisableHWC; }
    auto& mutableMaxRenderTargetSize() { return mFlinger->mMaxRenderTargetSize; }

    auto& mutableHwcDisplayData() { return getHwComposer().mDisplayData; }
    auto& mutableHwcPhysicalDisplayIdMap() { return getHwComposer().mPhysicalDisplayIdMap; }
    auto& mutableInternalHwcDisplayId() { return getHwComposer().mInternalHwcDisplayId; }
    auto& mutableExternalHwcDisplayId() { return getHwComposer().mExternalHwcDisplayId; }
    auto& mutableUseFrameRateApi() { return mFlinger->useFrameRateApi; }
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
        mutableEventQueue().reset();
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
        HWC2Display(Hwc2::Composer& composer,
                    const std::unordered_set<hal::Capability>& capabilities, hal::HWDisplayId id,
                    hal::DisplayType type)
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
        static constexpr int32_t DEFAULT_WIDTH = 1920;
        static constexpr int32_t DEFAULT_HEIGHT = 1280;
        static constexpr int32_t DEFAULT_VSYNC_PERIOD = 16'666'666;
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

        auto& setWidth(int32_t width) {
            mWidth = width;
            return *this;
        }

        auto& setHeight(int32_t height) {
            mHeight = height;
            return *this;
        }

        auto& setVsyncPeriod(int32_t vsyncPeriod) {
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

        auto& setCapabilities(const std::unordered_set<hal::Capability>* capabilities) {
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

            static const std::unordered_set<hal::Capability> defaultCapabilities;
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
                    .WillRepeatedly(DoAll(SetArgPointee<3>(mWidth), Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig, hal::Attribute::HEIGHT,
                                            _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(mHeight), Return(hal::Error::NONE)));

            EXPECT_CALL(*composer,
                        getDisplayAttribute(mHwcDisplayId, mActiveConfig,
                                            hal::Attribute::VSYNC_PERIOD, _))
                    .WillRepeatedly(
                            DoAll(SetArgPointee<3>(mVsyncPeriod), Return(hal::Error::NONE)));

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
                    flinger->mutableInternalHwcDisplayId() = mHwcDisplayId;
                } else {
                    // If there is an external HWC display there should always be an internal ID
                    // as well. Set it to some arbitrary value.
                    auto& internalId = flinger->mutableInternalHwcDisplayId();
                    if (!internalId) internalId = mHwcDisplayId - 1;
                    flinger->mutableExternalHwcDisplayId() = mHwcDisplayId;
                }
            }
        }

    private:
        const HalDisplayId mDisplayId;
        const hal::DisplayType mHwcDisplayType;
        const bool mIsPrimary;

        hal::HWDisplayId mHwcDisplayId = DEFAULT_HWC_DISPLAY_ID;
        int32_t mWidth = DEFAULT_WIDTH;
        int32_t mHeight = DEFAULT_HEIGHT;
        int32_t mVsyncPeriod = DEFAULT_VSYNC_PERIOD;
        int32_t mDpiX = DEFAULT_DPI;
        int32_t mDpiY = DEFAULT_DPI;
        int32_t mConfigGroup = DEFAULT_CONFIG_GROUP;
        hal::HWConfigId mActiveConfig = DEFAULT_ACTIVE_CONFIG;
        hal::PowerMode mPowerMode = DEFAULT_POWER_MODE;
        const std::unordered_set<hal::Capability>* mCapabilities = nullptr;
    };

    class FakeDisplayDeviceInjector {
    public:
        FakeDisplayDeviceInjector(TestableSurfaceFlinger& flinger,
                                  std::shared_ptr<compositionengine::Display> compositionDisplay,
                                  std::optional<ui::DisplayConnectionType> connectionType,
                                  std::optional<hal::HWDisplayId> hwcDisplayId, bool isPrimary)
              : mFlinger(flinger),
                mCreationArgs(flinger.mFlinger.get(), flinger.mFlinger->getHwComposer(),
                              mDisplayToken, compositionDisplay),
                mHwcDisplayId(hwcDisplayId) {
            mCreationArgs.connectionType = connectionType;
            mCreationArgs.isPrimary = isPrimary;

            mActiveModeId = DisplayModeId(0);
            DisplayModePtr activeMode =
                    DisplayMode::Builder(FakeHwcDisplayInjector::DEFAULT_ACTIVE_CONFIG)
                            .setId(mActiveModeId)
                            .setPhysicalDisplayId(PhysicalDisplayId(0))
                            .setWidth(FakeHwcDisplayInjector::DEFAULT_WIDTH)
                            .setHeight(FakeHwcDisplayInjector::DEFAULT_HEIGHT)
                            .setVsyncPeriod(FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD)
                            .setDpiX(FakeHwcDisplayInjector::DEFAULT_DPI)
                            .setDpiY(FakeHwcDisplayInjector::DEFAULT_DPI)
                            .setGroup(0)
                            .build();

            DisplayModes modes{activeMode};
            mCreationArgs.supportedModes = modes;
            mCreationArgs.refreshRateConfigs = flinger.mRefreshRateConfigs;
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

        auto& mutableDisplayDevice() { return mFlinger.mutableDisplays()[mDisplayToken]; }

        auto& setActiveMode(DisplayModeId mode) {
            mActiveModeId = mode;
            return *this;
        }

        auto& setSupportedModes(DisplayModes mode) {
            mCreationArgs.supportedModes = mode;
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

            DisplayDeviceState state;
            if (const auto type = mCreationArgs.connectionType) {
                LOG_ALWAYS_FATAL_IF(!displayId);
                const auto physicalId = PhysicalDisplayId::tryCast(*displayId);
                LOG_ALWAYS_FATAL_IF(!physicalId);
                LOG_ALWAYS_FATAL_IF(!mHwcDisplayId);
                state.physical = {.id = *physicalId, .type = *type, .hwcDisplayId = *mHwcDisplayId};
            }

            state.isSecure = mCreationArgs.isSecure;

            sp<DisplayDevice> device = new DisplayDevice(mCreationArgs);
            if (!device->isVirtual()) {
                device->setActiveMode(mActiveModeId);
            }
            mFlinger.mutableDisplays().emplace(mDisplayToken, device);
            mFlinger.mutableCurrentState().displays.add(mDisplayToken, state);
            mFlinger.mutableDrawingState().displays.add(mDisplayToken, state);

            if (const auto& physical = state.physical) {
                mFlinger.mutablePhysicalDisplayTokens()[physical->id] = mDisplayToken;
            }

            return device;
        }

    private:
        TestableSurfaceFlinger& mFlinger;
        sp<BBinder> mDisplayToken = new BBinder();
        DisplayDeviceCreationArgs mCreationArgs;
        const std::optional<hal::HWDisplayId> mHwcDisplayId;
        DisplayModeId mActiveModeId;
    };

private:
    void setVsyncEnabled(bool) override {}
    void changeRefreshRate(const Scheduler::RefreshRate&, Scheduler::ModeEvent) override {}
    void repaintEverythingForHWC() override {}
    void kernelTimerChanged(bool) override {}
    void triggerOnFrameRateOverridesChanged() {}

    surfaceflinger::test::Factory mFactory;
    sp<SurfaceFlinger> mFlinger = new SurfaceFlinger(mFactory, SurfaceFlinger::SkipInitialization);
    TestableScheduler* mScheduler = nullptr;
    std::shared_ptr<scheduler::RefreshRateConfigs> mRefreshRateConfigs;
};

} // namespace android
