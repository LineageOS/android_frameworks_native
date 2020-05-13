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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "CompositionTest"

#include <compositionengine/Display.h>
#include <compositionengine/mock/DisplaySurface.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/IProducerListener.h>
#include <gui/LayerMetadata.h>
#include <log/log.h>
#include <renderengine/mock/Framebuffer.h>
#include <renderengine/mock/Image.h>
#include <renderengine/mock/RenderEngine.h>
#include <system/window.h>
#include <utils/String8.h>

#include "BufferQueueLayer.h"
#include "EffectLayer.h"
#include "Layer.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockComposer.h"
#include "mock/DisplayHardware/MockPowerAdvisor.h"
#include "mock/MockDispSync.h"
#include "mock/MockEventControlThread.h"
#include "mock/MockEventThread.h"
#include "mock/MockMessageQueue.h"
#include "mock/MockTimeStats.h"
#include "mock/system/window/MockNativeWindow.h"

namespace android {
namespace {

namespace hal = android::hardware::graphics::composer::hal;

using hal::Error;
using hal::IComposer;
using hal::IComposerClient;
using hal::PowerMode;
using hal::Transform;

using testing::_;
using testing::AtLeast;
using testing::Between;
using testing::ByMove;
using testing::DoAll;
using testing::Field;
using testing::Invoke;
using testing::IsNull;
using testing::Mock;
using testing::NotNull;
using testing::Ref;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;
using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

constexpr hal::HWDisplayId HWC_DISPLAY = FakeHwcDisplayInjector::DEFAULT_HWC_DISPLAY_ID;
constexpr hal::HWLayerId HWC_LAYER = 5000;
constexpr Transform DEFAULT_TRANSFORM = static_cast<Transform>(0);

constexpr DisplayId DEFAULT_DISPLAY_ID = DisplayId{42};
constexpr int DEFAULT_DISPLAY_WIDTH = 1920;
constexpr int DEFAULT_DISPLAY_HEIGHT = 1024;

constexpr int DEFAULT_CONFIG_ID = 0;
constexpr int DEFAULT_TEXTURE_ID = 6000;
constexpr int DEFAULT_LAYER_STACK = 7000;

constexpr int DEFAULT_DISPLAY_MAX_LUMINANCE = 500;

constexpr int DEFAULT_SIDEBAND_STREAM = 51;

class CompositionTest : public testing::Test {
public:
    CompositionTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

        mFlinger.mutableEventQueue().reset(mMessageQueue);
        setupScheduler();

        EXPECT_CALL(*mNativeWindow, query(NATIVE_WINDOW_WIDTH, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_WIDTH), Return(0)));
        EXPECT_CALL(*mNativeWindow, query(NATIVE_WINDOW_HEIGHT, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_HEIGHT), Return(0)));

        mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
        mFlinger.setupTimeStats(std::shared_ptr<TimeStats>(mTimeStats));
        setupComposer(0);
    }

    ~CompositionTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void setupComposer(int virtualDisplayCount) {
        mComposer = new Hwc2::mock::Composer();
        EXPECT_CALL(*mComposer, getMaxVirtualDisplayCount()).WillOnce(Return(virtualDisplayCount));
        mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));

        Mock::VerifyAndClear(mComposer);
    }

    void setupScheduler() {
        auto eventThread = std::make_unique<mock::EventThread>();
        auto sfEventThread = std::make_unique<mock::EventThread>();

        EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*eventThread, createEventConnection(_, _))
                .WillOnce(Return(
                        new EventThreadConnection(eventThread.get(), ResyncCallback(),
                                                  ISurfaceComposer::eConfigChangedSuppress)));

        EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
                .WillOnce(Return(
                        new EventThreadConnection(sfEventThread.get(), ResyncCallback(),
                                                  ISurfaceComposer::eConfigChangedSuppress)));

        auto primaryDispSync = std::make_unique<mock::DispSync>();

        EXPECT_CALL(*primaryDispSync, computeNextRefresh(0, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(*primaryDispSync, getPeriod())
                .WillRepeatedly(Return(FakeHwcDisplayInjector::DEFAULT_REFRESH_RATE));
        EXPECT_CALL(*primaryDispSync, expectedPresentTime(_)).WillRepeatedly(Return(0));

        mFlinger.setupScheduler(std::move(primaryDispSync),
                                std::make_unique<mock::EventControlThread>(),
                                std::move(eventThread), std::move(sfEventThread));
    }

    void setupForceGeometryDirty() {
        // TODO: This requires the visible region and other related
        // state to be set, and is problematic for BufferLayers since they are
        // not visible without a buffer (and setting up a buffer looks like a
        // pain)
        // mFlinger.mutableVisibleRegionsDirty() = true;

        mFlinger.mutableGeometryInvalid() = true;
    }

    template <typename Case>
    void displayRefreshCompositionDirtyGeometry();

    template <typename Case>
    void displayRefreshCompositionDirtyFrame();

    template <typename Case>
    void captureScreenComposition();

    std::unordered_set<hal::Capability> mDefaultCapabilities = {hal::Capability::SIDEBAND_STREAM};

    bool mDisplayOff = false;
    TestableSurfaceFlinger mFlinger;
    sp<DisplayDevice> mDisplay;
    sp<DisplayDevice> mExternalDisplay;
    sp<compositionengine::mock::DisplaySurface> mDisplaySurface =
            new compositionengine::mock::DisplaySurface();
    mock::NativeWindow* mNativeWindow = new mock::NativeWindow();

    sp<GraphicBuffer> mBuffer = new GraphicBuffer();
    ANativeWindowBuffer* mNativeWindowBuffer = mBuffer->getNativeBuffer();

    Hwc2::mock::Composer* mComposer = nullptr;
    renderengine::mock::RenderEngine* mRenderEngine = new renderengine::mock::RenderEngine();
    mock::TimeStats* mTimeStats = new mock::TimeStats();
    mock::MessageQueue* mMessageQueue = new mock::MessageQueue();
    Hwc2::mock::PowerAdvisor mPowerAdvisor;

    sp<Fence> mClientTargetAcquireFence = Fence::NO_FENCE;

    sp<GraphicBuffer> mCaptureScreenBuffer;
};

template <typename LayerCase>
void CompositionTest::displayRefreshCompositionDirtyGeometry() {
    setupForceGeometryDirty();
    LayerCase::setupForDirtyGeometry(this);

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.onMessageReceived(MessageQueue::INVALIDATE);
    mFlinger.onMessageReceived(MessageQueue::REFRESH);

    LayerCase::cleanup(this);
}

template <typename LayerCase>
void CompositionTest::displayRefreshCompositionDirtyFrame() {
    LayerCase::setupForDirtyFrame(this);

    // --------------------------------------------------------------------
    // Invocation

    mFlinger.onMessageReceived(MessageQueue::INVALIDATE);
    mFlinger.onMessageReceived(MessageQueue::REFRESH);

    LayerCase::cleanup(this);
}

template <typename LayerCase>
void CompositionTest::captureScreenComposition() {
    LayerCase::setupForScreenCapture(this);

    const Rect sourceCrop(0, 0, DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT);
    constexpr bool useIdentityTransform = true;
    constexpr bool forSystem = true;
    constexpr bool regionSampling = false;

    DisplayRenderArea renderArea(mDisplay, sourceCrop, DEFAULT_DISPLAY_WIDTH,
                                 DEFAULT_DISPLAY_HEIGHT, ui::Dataspace::V0_SRGB,
                                 ui::Transform::ROT_0);

    auto traverseLayers = [this](const LayerVector::Visitor& visitor) {
        return mFlinger.traverseLayersInDisplay(mDisplay, visitor);
    };

    // TODO: Eliminate expensive/real allocation if possible.
    const uint32_t usage = GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
            GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;
    mCaptureScreenBuffer = new GraphicBuffer(renderArea.getReqWidth(), renderArea.getReqHeight(),
                                             HAL_PIXEL_FORMAT_RGBA_8888, 1, usage, "screenshot");

    int fd = -1;
    status_t result =
            mFlinger.captureScreenImplLocked(renderArea, traverseLayers, mCaptureScreenBuffer.get(),
                                             useIdentityTransform, forSystem, &fd, regionSampling);
    if (fd >= 0) {
        close(fd);
    }

    EXPECT_EQ(NO_ERROR, result);

    LayerCase::cleanup(this);
}

/* ------------------------------------------------------------------------
 * Variants for each display configuration which can be tested
 */

template <typename Derived>
struct BaseDisplayVariant {
    static constexpr bool IS_SECURE = true;
    static constexpr hal::PowerMode INIT_POWER_MODE = hal::PowerMode::ON;

    static void setupPreconditions(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, setPowerMode(HWC_DISPLAY, Derived::INIT_POWER_MODE))
                .WillOnce(Return(Error::NONE));

        FakeHwcDisplayInjector(DEFAULT_DISPLAY_ID, hal::DisplayType::PHYSICAL, true /* isPrimary */)
                .setCapabilities(&test->mDefaultCapabilities)
                .setPowerMode(Derived::INIT_POWER_MODE)
                .inject(&test->mFlinger, test->mComposer);
        Mock::VerifyAndClear(test->mComposer);

        EXPECT_CALL(*test->mNativeWindow, query(NATIVE_WINDOW_WIDTH, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_WIDTH), Return(0)));
        EXPECT_CALL(*test->mNativeWindow, query(NATIVE_WINDOW_HEIGHT, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_HEIGHT), Return(0)));
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_SET_BUFFERS_FORMAT)).Times(1);
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_API_CONNECT)).Times(1);
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_SET_USAGE64)).Times(1);

        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();

        auto ceDisplayArgs =
                compositionengine::DisplayCreationArgsBuilder()
                        .setPhysical({DEFAULT_DISPLAY_ID, DisplayConnectionType::Internal})
                        .setPixels({DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT})
                        .setIsSecure(Derived::IS_SECURE)
                        .setLayerStackId(DEFAULT_LAYER_STACK)
                        .setPowerAdvisor(&test->mPowerAdvisor)
                        .setName(std::string("Injected display for ") +
                                 test_info->test_case_name() + "." + test_info->name())
                        .build();

        auto compositionDisplay =
                compositionengine::impl::createDisplay(test->mFlinger.getCompositionEngine(),
                                                       ceDisplayArgs);

        test->mDisplay = FakeDisplayDeviceInjector(test->mFlinger, compositionDisplay,
                                                   DisplayConnectionType::Internal, HWC_DISPLAY,
                                                   true /* isPrimary */)
                                 .setDisplaySurface(test->mDisplaySurface)
                                 .setNativeWindow(test->mNativeWindow)
                                 .setSecure(Derived::IS_SECURE)
                                 .setPowerMode(Derived::INIT_POWER_MODE)
                                 .inject();
        Mock::VerifyAndClear(test->mNativeWindow);
        test->mDisplay->setLayerStack(DEFAULT_LAYER_STACK);
    }

    template <typename Case>
    static void setupPreconditionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, getDisplayCapabilities(HWC_DISPLAY, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hwc2::DisplayCapability>({})),
                                Return(Error::NONE)));
    }

    template <typename Case>
    static void setupCommonCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer,
                    setColorTransform(HWC_DISPLAY, _, Hwc2::ColorTransform::IDENTITY))
                .Times(1);
        EXPECT_CALL(*test->mComposer, getDisplayRequests(HWC_DISPLAY, _, _, _)).Times(1);
        EXPECT_CALL(*test->mComposer, acceptDisplayChanges(HWC_DISPLAY)).Times(1);
        EXPECT_CALL(*test->mComposer, presentDisplay(HWC_DISPLAY, _)).Times(1);
        EXPECT_CALL(*test->mComposer, getReleaseFences(HWC_DISPLAY, _, _)).Times(1);

        EXPECT_CALL(*test->mRenderEngine, useNativeFenceSync()).WillRepeatedly(Return(true));

        EXPECT_CALL(*test->mDisplaySurface, onFrameCommitted()).Times(1);
        EXPECT_CALL(*test->mDisplaySurface, advanceFrame()).Times(1);

        Case::CompositionType::setupHwcSetCallExpectations(test);
        Case::CompositionType::setupHwcGetCallExpectations(test);
    }

    template <typename Case>
    static void setupCommonScreensCaptureCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mRenderEngine, drawLayers)
                .WillRepeatedly([](const renderengine::DisplaySettings& displaySettings,
                                   const std::vector<const renderengine::LayerSettings*>&,
                                   ANativeWindowBuffer*, const bool, base::unique_fd&&,
                                   base::unique_fd*) -> status_t {
                    EXPECT_EQ(DEFAULT_DISPLAY_MAX_LUMINANCE, displaySettings.maxLuminance);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.physicalDisplay);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.clip);
                    return NO_ERROR;
                });
    }

    static void setupNonEmptyFrameCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mDisplaySurface, beginFrame(true)).Times(1);
    }

    static void setupEmptyFrameCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mDisplaySurface, beginFrame(false)).Times(1);
    }

    static void setupHwcCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, presentOrValidateDisplay(HWC_DISPLAY, _, _, _, _)).Times(1);

        EXPECT_CALL(*test->mDisplaySurface,
                    prepareFrame(compositionengine::DisplaySurface::COMPOSITION_HWC))
                .Times(1);
    }

    static void setupHwcClientCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, presentOrValidateDisplay(HWC_DISPLAY, _, _, _, _)).Times(1);
    }

    static void setupHwcForcedClientCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, validateDisplay(HWC_DISPLAY, _, _)).Times(1);
    }

    static void setupRECompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mDisplaySurface,
                    prepareFrame(compositionengine::DisplaySurface::COMPOSITION_GPU))
                .Times(1);
        EXPECT_CALL(*test->mDisplaySurface, getClientTargetAcquireFence())
                .WillRepeatedly(ReturnRef(test->mClientTargetAcquireFence));

        EXPECT_CALL(*test->mNativeWindow, queueBuffer(_, _)).WillOnce(Return(0));
        EXPECT_CALL(*test->mNativeWindow, dequeueBuffer(_, _))
                .WillOnce(DoAll(SetArgPointee<0>(test->mNativeWindowBuffer), SetArgPointee<1>(-1),
                                Return(0)));
        EXPECT_CALL(*test->mRenderEngine, drawLayers)
                .WillRepeatedly([](const renderengine::DisplaySettings& displaySettings,
                                   const std::vector<const renderengine::LayerSettings*>&,
                                   ANativeWindowBuffer*, const bool, base::unique_fd&&,
                                   base::unique_fd*) -> status_t {
                    EXPECT_EQ(DEFAULT_DISPLAY_MAX_LUMINANCE, displaySettings.maxLuminance);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.physicalDisplay);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.clip);
                    EXPECT_EQ(ui::Dataspace::UNKNOWN, displaySettings.outputDataspace);
                    return NO_ERROR;
                });
    }

    template <typename Case>
    static void setupRELayerCompositionCallExpectations(CompositionTest* test) {
        Case::Layer::setupRECompositionCallExpectations(test);
    }

    template <typename Case>
    static void setupRELayerScreenshotCompositionCallExpectations(CompositionTest* test) {
        Case::Layer::setupREScreenshotCompositionCallExpectations(test);
    }
};

struct DefaultDisplaySetupVariant : public BaseDisplayVariant<DefaultDisplaySetupVariant> {};

struct InsecureDisplaySetupVariant : public BaseDisplayVariant<InsecureDisplaySetupVariant> {
    static constexpr bool IS_SECURE = false;

    template <typename Case>
    static void setupRELayerCompositionCallExpectations(CompositionTest* test) {
        Case::Layer::setupInsecureRECompositionCallExpectations(test);
    }

    template <typename Case>
    static void setupRELayerScreenshotCompositionCallExpectations(CompositionTest* test) {
        Case::Layer::setupInsecureREScreenshotCompositionCallExpectations(test);
    }
};

struct PoweredOffDisplaySetupVariant : public BaseDisplayVariant<PoweredOffDisplaySetupVariant> {
    static constexpr hal::PowerMode INIT_POWER_MODE = hal::PowerMode::OFF;

    template <typename Case>
    static void setupPreconditionCallExpectations(CompositionTest*) {}

    template <typename Case>
    static void setupCommonCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mRenderEngine, useNativeFenceSync()).WillRepeatedly(Return(true));

        // TODO: This seems like an unnecessary call if display is powered off.
        EXPECT_CALL(*test->mComposer,
                    setColorTransform(HWC_DISPLAY, _, Hwc2::ColorTransform::IDENTITY))
                .Times(1);

        // TODO: This seems like an unnecessary call if display is powered off.
        Case::CompositionType::setupHwcSetCallExpectations(test);
    }

    static void setupHwcCompositionCallExpectations(CompositionTest*) {}
    static void setupHwcClientCompositionCallExpectations(CompositionTest*) {}
    static void setupHwcForcedClientCompositionCallExpectations(CompositionTest*) {}

    static void setupRECompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mRenderEngine, useNativeFenceSync()).WillRepeatedly(Return(true));

        // TODO: This seems like an unnecessary call if display is powered off.
        EXPECT_CALL(*test->mDisplaySurface, getClientTargetAcquireFence())
                .WillRepeatedly(ReturnRef(test->mClientTargetAcquireFence));
    }

    template <typename Case>
    static void setupRELayerCompositionCallExpectations(CompositionTest*) {}
};

/* ------------------------------------------------------------------------
 * Variants for each layer configuration which can be tested
 */

template <typename LayerProperties>
struct BaseLayerProperties {
    static constexpr uint32_t WIDTH = 100;
    static constexpr uint32_t HEIGHT = 100;
    static constexpr PixelFormat FORMAT = PIXEL_FORMAT_RGBA_8888;
    static constexpr uint64_t USAGE =
            GraphicBuffer::USAGE_SW_READ_NEVER | GraphicBuffer::USAGE_SW_WRITE_NEVER;
    static constexpr android_dataspace DATASPACE = HAL_DATASPACE_UNKNOWN;
    static constexpr uint32_t SCALING_MODE = 0;
    static constexpr uint32_t TRANSFORM = 0;
    static constexpr uint32_t LAYER_FLAGS = 0;
    static constexpr float COLOR[] = {1.f, 1.f, 1.f, 1.f};
    static constexpr IComposerClient::BlendMode BLENDMODE =
            IComposerClient::BlendMode::PREMULTIPLIED;

    static void enqueueBuffer(CompositionTest*, sp<BufferQueueLayer> layer) {
        auto producer = layer->getProducer();

        IGraphicBufferProducer::QueueBufferOutput qbo;
        status_t result = producer->connect(nullptr, NATIVE_WINDOW_API_EGL, false, &qbo);
        if (result != NO_ERROR) {
            ALOGE("Failed to connect() (%d)", result);
            return;
        }

        int slot;
        sp<Fence> fence;
        result = producer->dequeueBuffer(&slot, &fence, LayerProperties::WIDTH,
                                         LayerProperties::HEIGHT, LayerProperties::FORMAT,
                                         LayerProperties::USAGE, nullptr, nullptr);
        if (result != IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION) {
            ALOGE("Failed to dequeueBuffer() (%d)", result);
            return;
        }

        sp<GraphicBuffer> buffer;
        result = producer->requestBuffer(slot, &buffer);
        if (result != NO_ERROR) {
            ALOGE("Failed to requestBuffer() (%d)", result);
            return;
        }

        IGraphicBufferProducer::QueueBufferInput qbi(systemTime(), false /* isAutoTimestamp */,
                                                     LayerProperties::DATASPACE,
                                                     Rect(LayerProperties::WIDTH,
                                                          LayerProperties::HEIGHT),
                                                     LayerProperties::SCALING_MODE,
                                                     LayerProperties::TRANSFORM, Fence::NO_FENCE);
        result = producer->queueBuffer(slot, qbi, &qbo);
        if (result != NO_ERROR) {
            ALOGE("Failed to queueBuffer (%d)", result);
            return;
        }
    }

    static void setupLatchedBuffer(CompositionTest* test, sp<BufferQueueLayer> layer) {
        // TODO: Eliminate the complexity of actually creating a buffer
        EXPECT_CALL(*test->mRenderEngine, getMaxTextureSize()).WillOnce(Return(16384));
        EXPECT_CALL(*test->mRenderEngine, getMaxViewportDims()).WillOnce(Return(16384));
        status_t err =
                layer->setDefaultBufferProperties(LayerProperties::WIDTH, LayerProperties::HEIGHT,
                                                  LayerProperties::FORMAT);
        ASSERT_EQ(NO_ERROR, err);
        Mock::VerifyAndClear(test->mRenderEngine);

        EXPECT_CALL(*test->mMessageQueue, invalidate()).Times(1);
        enqueueBuffer(test, layer);
        Mock::VerifyAndClearExpectations(test->mMessageQueue);

        EXPECT_CALL(*test->mRenderEngine, useNativeFenceSync()).WillRepeatedly(Return(true));
        bool ignoredRecomputeVisibleRegions;
        layer->latchBuffer(ignoredRecomputeVisibleRegions, 0, 0);
        Mock::VerifyAndClear(test->mRenderEngine);
    }

    static void setupLayerState(CompositionTest* test, sp<BufferQueueLayer> layer) {
        setupLatchedBuffer(test, layer);
    }

    static void setupBufferLayerPostFrameCallExpectations(CompositionTest* test) {
        // BufferLayer::onPostComposition(), when there is no present fence
        EXPECT_CALL(*test->mComposer, getActiveConfig(HWC_DISPLAY, _))
                .WillOnce(DoAll(SetArgPointee<1>(DEFAULT_CONFIG_ID), Return(Error::NONE)));
    }

    static void setupHwcSetGeometryCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            // TODO: Coverage of other values
            EXPECT_CALL(*test->mComposer,
                        setLayerBlendMode(HWC_DISPLAY, HWC_LAYER, LayerProperties::BLENDMODE))
                    .Times(1);
            // TODO: Coverage of other values for origin
            EXPECT_CALL(*test->mComposer,
                        setLayerDisplayFrame(HWC_DISPLAY, HWC_LAYER,
                                             IComposerClient::Rect({0, 0, LayerProperties::WIDTH,
                                                                    LayerProperties::HEIGHT})))
                    .Times(1);
            EXPECT_CALL(*test->mComposer,
                        setLayerPlaneAlpha(HWC_DISPLAY, HWC_LAYER, LayerProperties::COLOR[3]))
                    .Times(1);
            // TODO: Coverage of other values
            EXPECT_CALL(*test->mComposer, setLayerZOrder(HWC_DISPLAY, HWC_LAYER, 0u)).Times(1);
            // TODO: Coverage of other values
            EXPECT_CALL(*test->mComposer, setLayerInfo(HWC_DISPLAY, HWC_LAYER, 0u, 0u)).Times(1);

            // These expectations retire on saturation as the code path these
            // expectations are for appears to make an extra call to them.
            // TODO: Investigate this extra call
            EXPECT_CALL(*test->mComposer,
                        setLayerTransform(HWC_DISPLAY, HWC_LAYER, DEFAULT_TRANSFORM))
                    .Times(AtLeast(1))
                    .RetiresOnSaturation();
        }
    }

    static void setupHwcSetSourceCropBufferCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            EXPECT_CALL(*test->mComposer,
                        setLayerSourceCrop(HWC_DISPLAY, HWC_LAYER,
                                           IComposerClient::FRect({0.f, 0.f, LayerProperties::WIDTH,
                                                                   LayerProperties::HEIGHT})))
                    .Times(1);
        }
    }

    static void setupHwcSetSourceCropColorCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            EXPECT_CALL(*test->mComposer,
                        setLayerSourceCrop(HWC_DISPLAY, HWC_LAYER,
                                           IComposerClient::FRect({0.f, 0.f, 0.f, 0.f})))
                    .Times(1);
        }
    }

    static void setupHwcSetPerFrameCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            EXPECT_CALL(*test->mComposer,
                        setLayerVisibleRegion(HWC_DISPLAY, HWC_LAYER,
                                              std::vector<IComposerClient::Rect>(
                                                      {IComposerClient::Rect(
                                                              {0, 0, LayerProperties::WIDTH,
                                                               LayerProperties::HEIGHT})})))
                    .Times(1);
        }
    }

    static void setupHwcSetPerFrameColorCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            EXPECT_CALL(*test->mComposer, setLayerSurfaceDamage(HWC_DISPLAY, HWC_LAYER, _))
                    .Times(1);

            // TODO: use COLOR
            EXPECT_CALL(*test->mComposer,
                        setLayerColor(HWC_DISPLAY, HWC_LAYER,
                                      IComposerClient::Color({0xff, 0xff, 0xff, 0xff})))
                    .Times(1);
        }
    }

    static void setupHwcSetPerFrameBufferCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            EXPECT_CALL(*test->mComposer, setLayerSurfaceDamage(HWC_DISPLAY, HWC_LAYER, _))
                    .Times(1);
            EXPECT_CALL(*test->mComposer, setLayerBuffer(HWC_DISPLAY, HWC_LAYER, _, _, _)).Times(1);
        }

        setupBufferLayerPostFrameCallExpectations(test);
    }

    static void setupREBufferCompositionCommonCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mRenderEngine, drawLayers)
                .WillOnce([](const renderengine::DisplaySettings& displaySettings,
                             const std::vector<const renderengine::LayerSettings*>& layerSettings,
                             ANativeWindowBuffer*, const bool, base::unique_fd&&,
                             base::unique_fd*) -> status_t {
                    EXPECT_EQ(DEFAULT_DISPLAY_MAX_LUMINANCE, displaySettings.maxLuminance);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.physicalDisplay);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.clip);
                    // screen capture adds an additional color layer as an alpha
                    // prefill, so gtet the back layer.
                    if (layerSettings.empty()) {
                        ADD_FAILURE() << "layerSettings was not expected to be empty in "
                                         "setupREBufferCompositionCommonCallExpectations "
                                         "verification lambda";
                        return NO_ERROR;
                    }
                    const renderengine::LayerSettings* layer = layerSettings.back();
                    EXPECT_THAT(layer->source.buffer.buffer, Not(IsNull()));
                    EXPECT_THAT(layer->source.buffer.fence, Not(IsNull()));
                    EXPECT_EQ(DEFAULT_TEXTURE_ID, layer->source.buffer.textureName);
                    EXPECT_EQ(false, layer->source.buffer.isY410BT2020);
                    EXPECT_EQ(true, layer->source.buffer.usePremultipliedAlpha);
                    EXPECT_EQ(false, layer->source.buffer.isOpaque);
                    EXPECT_EQ(0.0, layer->geometry.roundedCornersRadius);
                    EXPECT_EQ(ui::Dataspace::UNKNOWN, layer->sourceDataspace);
                    EXPECT_EQ(LayerProperties::COLOR[3], layer->alpha);
                    return NO_ERROR;
                });
    }

    static void setupREBufferCompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupREBufferCompositionCommonCallExpectations(test);
    }

    static void setupInsecureREBufferCompositionCallExpectations(CompositionTest* test) {
        setupREBufferCompositionCallExpectations(test);
    }

    static void setupREBufferScreenshotCompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupREBufferCompositionCommonCallExpectations(test);
    }

    static void setupInsecureREBufferScreenshotCompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupREBufferCompositionCommonCallExpectations(test);
    }

    static void setupREColorCompositionCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mRenderEngine, drawLayers)
                .WillOnce([](const renderengine::DisplaySettings& displaySettings,
                             const std::vector<const renderengine::LayerSettings*>& layerSettings,
                             ANativeWindowBuffer*, const bool, base::unique_fd&&,
                             base::unique_fd*) -> status_t {
                    EXPECT_EQ(DEFAULT_DISPLAY_MAX_LUMINANCE, displaySettings.maxLuminance);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.physicalDisplay);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.clip);
                    // screen capture adds an additional color layer as an alpha
                    // prefill, so get the back layer.
                    if (layerSettings.empty()) {
                        ADD_FAILURE()
                                << "layerSettings was not expected to be empty in "
                                   "setupREColorCompositionCallExpectations verification lambda";
                        return NO_ERROR;
                    }
                    const renderengine::LayerSettings* layer = layerSettings.back();
                    EXPECT_THAT(layer->source.buffer.buffer, IsNull());
                    EXPECT_EQ(half3(LayerProperties::COLOR[0], LayerProperties::COLOR[1],
                                    LayerProperties::COLOR[2]),
                              layer->source.solidColor);
                    EXPECT_EQ(0.0, layer->geometry.roundedCornersRadius);
                    EXPECT_EQ(ui::Dataspace::UNKNOWN, layer->sourceDataspace);
                    EXPECT_EQ(LayerProperties::COLOR[3], layer->alpha);
                    return NO_ERROR;
                });
    }

    static void setupREColorScreenshotCompositionCallExpectations(CompositionTest* test) {
        setupREColorCompositionCallExpectations(test);
    }
};

struct DefaultLayerProperties : public BaseLayerProperties<DefaultLayerProperties> {};

struct EffectLayerProperties : public BaseLayerProperties<EffectLayerProperties> {
    static constexpr IComposerClient::BlendMode BLENDMODE = IComposerClient::BlendMode::NONE;
};

struct SidebandLayerProperties : public BaseLayerProperties<SidebandLayerProperties> {
    using Base = BaseLayerProperties<SidebandLayerProperties>;
    static constexpr IComposerClient::BlendMode BLENDMODE = IComposerClient::BlendMode::NONE;

    static void setupLayerState(CompositionTest* test, sp<BufferQueueLayer> layer) {
        sp<NativeHandle> stream =
                NativeHandle::create(reinterpret_cast<native_handle_t*>(DEFAULT_SIDEBAND_STREAM),
                                     false);
        test->mFlinger.setLayerSidebandStream(layer, stream);
    }

    static void setupHwcSetSourceCropBufferCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer,
                    setLayerSourceCrop(HWC_DISPLAY, HWC_LAYER,
                                       IComposerClient::FRect({0.f, 0.f, -1.f, -1.f})))
                .Times(1);
    }

    static void setupHwcSetPerFrameBufferCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer,
                    setLayerSidebandStream(HWC_DISPLAY, HWC_LAYER,
                                           reinterpret_cast<native_handle_t*>(
                                                   DEFAULT_SIDEBAND_STREAM)))
                .WillOnce(Return(Error::NONE));

        EXPECT_CALL(*test->mComposer, setLayerSurfaceDamage(HWC_DISPLAY, HWC_LAYER, _)).Times(1);
    }

    static void setupREBufferCompositionCommonCallExpectations(CompositionTest* /*test*/) {}
};

struct SecureLayerProperties : public BaseLayerProperties<SecureLayerProperties> {
    using Base = BaseLayerProperties<SecureLayerProperties>;

    static constexpr uint32_t LAYER_FLAGS = ISurfaceComposerClient::eSecure;

    static void setupInsecureREBufferCompositionCommonCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mRenderEngine, drawLayers)
                .WillOnce([](const renderengine::DisplaySettings& displaySettings,
                             const std::vector<const renderengine::LayerSettings*>& layerSettings,
                             ANativeWindowBuffer*, const bool, base::unique_fd&&,
                             base::unique_fd*) -> status_t {
                    EXPECT_EQ(DEFAULT_DISPLAY_MAX_LUMINANCE, displaySettings.maxLuminance);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.physicalDisplay);
                    EXPECT_EQ(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                              displaySettings.clip);
                    // screen capture adds an additional color layer as an alpha
                    // prefill, so get the back layer.
                    if (layerSettings.empty()) {
                        ADD_FAILURE() << "layerSettings was not expected to be empty in "
                                         "setupInsecureREBufferCompositionCommonCallExpectations "
                                         "verification lambda";
                        return NO_ERROR;
                    }
                    const renderengine::LayerSettings* layer = layerSettings.back();
                    EXPECT_THAT(layer->source.buffer.buffer, IsNull());
                    EXPECT_EQ(half3(0.0f, 0.0f, 0.0f), layer->source.solidColor);
                    EXPECT_EQ(0.0, layer->geometry.roundedCornersRadius);
                    EXPECT_EQ(ui::Dataspace::UNKNOWN, layer->sourceDataspace);
                    EXPECT_EQ(1.0f, layer->alpha);
                    return NO_ERROR;
                });
    }

    static void setupInsecureREBufferCompositionCallExpectations(CompositionTest* test) {
        setupInsecureREBufferCompositionCommonCallExpectations(test);
        Base::setupBufferLayerPostFrameCallExpectations(test);
    }

    static void setupInsecureREBufferScreenshotCompositionCallExpectations(CompositionTest* test) {
        setupInsecureREBufferCompositionCommonCallExpectations(test);
    }
};

struct CursorLayerProperties : public BaseLayerProperties<CursorLayerProperties> {
    using Base = BaseLayerProperties<CursorLayerProperties>;

    static void setupLayerState(CompositionTest* test, sp<BufferQueueLayer> layer) {
        Base::setupLayerState(test, layer);
        test->mFlinger.setLayerPotentialCursor(layer, true);
    }
};

struct NoLayerVariant {
    using FlingerLayerType = sp<BufferQueueLayer>;

    static FlingerLayerType createLayer(CompositionTest*) { return FlingerLayerType(); }
    static void injectLayer(CompositionTest*, FlingerLayerType) {}
    static void cleanupInjectedLayers(CompositionTest*) {}

    static void setupCallExpectationsForDirtyGeometry(CompositionTest*) {}
    static void setupCallExpectationsForDirtyFrame(CompositionTest*) {}
};

template <typename LayerProperties>
struct BaseLayerVariant {
    template <typename L, typename F>
    static sp<L> createLayerWithFactory(CompositionTest* test, F factory) {
        EXPECT_CALL(*test->mMessageQueue, postMessage(_)).Times(0);

        sp<L> layer = factory();

        // Layer should be registered with scheduler.
        EXPECT_EQ(1, test->mFlinger.scheduler()->layerHistorySize());

        Mock::VerifyAndClear(test->mComposer);
        Mock::VerifyAndClear(test->mRenderEngine);
        Mock::VerifyAndClearExpectations(test->mMessageQueue);

        auto& layerDrawingState = test->mFlinger.mutableLayerDrawingState(layer);
        layerDrawingState.layerStack = DEFAULT_LAYER_STACK;
        layerDrawingState.active.w = 100;
        layerDrawingState.active.h = 100;
        layerDrawingState.color = half4(LayerProperties::COLOR[0], LayerProperties::COLOR[1],
                                        LayerProperties::COLOR[2], LayerProperties::COLOR[3]);
        layer->computeBounds(FloatRect(0, 0, 100, 100), ui::Transform(), 0.f /* shadowRadius */);

        return layer;
    }

    static void injectLayer(CompositionTest* test, sp<Layer> layer) {
        EXPECT_CALL(*test->mComposer, createLayer(HWC_DISPLAY, _))
                .WillOnce(DoAll(SetArgPointee<1>(HWC_LAYER), Return(Error::NONE)));

        auto outputLayer = test->mDisplay->getCompositionDisplay()->injectOutputLayerForTest(
                layer->getCompositionEngineLayerFE());
        outputLayer->editState().visibleRegion = Region(Rect(0, 0, 100, 100));
        outputLayer->editState().outputSpaceVisibleRegion = Region(Rect(0, 0, 100, 100));

        Mock::VerifyAndClear(test->mComposer);

        test->mFlinger.mutableDrawingState().layersSortedByZ.add(layer);
    }

    static void cleanupInjectedLayers(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, destroyLayer(HWC_DISPLAY, HWC_LAYER))
                .WillOnce(Return(Error::NONE));

        test->mDisplay->getCompositionDisplay()->clearOutputLayers();
        test->mFlinger.mutableDrawingState().layersSortedByZ.clear();

        // Layer should be unregistered with scheduler.
        test->mFlinger.onMessageReceived(MessageQueue::INVALIDATE);
        EXPECT_EQ(0, test->mFlinger.scheduler()->layerHistorySize());
    }
};

template <typename LayerProperties>
struct EffectLayerVariant : public BaseLayerVariant<LayerProperties> {
    using Base = BaseLayerVariant<LayerProperties>;
    using FlingerLayerType = sp<EffectLayer>;

    static FlingerLayerType createLayer(CompositionTest* test) {
        FlingerLayerType layer = Base::template createLayerWithFactory<EffectLayer>(test, [test]() {
            return new EffectLayer(
                    LayerCreationArgs(test->mFlinger.mFlinger.get(), sp<Client>(), "test-layer",
                                      LayerProperties::WIDTH, LayerProperties::HEIGHT,
                                      LayerProperties::LAYER_FLAGS, LayerMetadata()));
        });

        auto& layerDrawingState = test->mFlinger.mutableLayerDrawingState(layer);
        layerDrawingState.crop_legacy = Rect(0, 0, LayerProperties::HEIGHT, LayerProperties::WIDTH);
        return layer;
    }

    static void setupRECompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupREColorCompositionCallExpectations(test);
    }

    static void setupREScreenshotCompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupREColorScreenshotCompositionCallExpectations(test);
    }

    static void setupCallExpectationsForDirtyGeometry(CompositionTest* test) {
        LayerProperties::setupHwcSetGeometryCallExpectations(test);
        LayerProperties::setupHwcSetSourceCropColorCallExpectations(test);
    }

    static void setupCallExpectationsForDirtyFrame(CompositionTest* test) {
        LayerProperties::setupHwcSetPerFrameCallExpectations(test);
        LayerProperties::setupHwcSetPerFrameColorCallExpectations(test);
    }
};

template <typename LayerProperties>
struct BufferLayerVariant : public BaseLayerVariant<LayerProperties> {
    using Base = BaseLayerVariant<LayerProperties>;
    using FlingerLayerType = sp<BufferQueueLayer>;

    static FlingerLayerType createLayer(CompositionTest* test) {
        test->mFlinger.mutableTexturePool().push_back(DEFAULT_TEXTURE_ID);

        FlingerLayerType layer =
                Base::template createLayerWithFactory<BufferQueueLayer>(test, [test]() {
                    sp<Client> client;
                    LayerCreationArgs args(test->mFlinger.mFlinger.get(), client, "test-layer",
                                           LayerProperties::WIDTH, LayerProperties::HEIGHT,
                                           LayerProperties::LAYER_FLAGS, LayerMetadata());
                    args.textureName = test->mFlinger.mutableTexturePool().back();
                    return new BufferQueueLayer(args);
                });

        LayerProperties::setupLayerState(test, layer);

        return layer;
    }

    static void cleanupInjectedLayers(CompositionTest* test) {
        EXPECT_CALL(*test->mMessageQueue, postMessage(_)).Times(1);
        Base::cleanupInjectedLayers(test);
    }

    static void setupCallExpectationsForDirtyGeometry(CompositionTest* test) {
        LayerProperties::setupHwcSetGeometryCallExpectations(test);
        LayerProperties::setupHwcSetSourceCropBufferCallExpectations(test);
    }

    static void setupCallExpectationsForDirtyFrame(CompositionTest* test) {
        LayerProperties::setupHwcSetPerFrameCallExpectations(test);
        LayerProperties::setupHwcSetPerFrameBufferCallExpectations(test);
    }

    static void setupRECompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupREBufferCompositionCallExpectations(test);
    }

    static void setupInsecureRECompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupInsecureREBufferCompositionCallExpectations(test);
    }

    static void setupREScreenshotCompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupREBufferScreenshotCompositionCallExpectations(test);
    }

    static void setupInsecureREScreenshotCompositionCallExpectations(CompositionTest* test) {
        LayerProperties::setupInsecureREBufferScreenshotCompositionCallExpectations(test);
    }
};

/* ------------------------------------------------------------------------
 * Variants to control how the composition type is changed
 */

struct NoCompositionTypeVariant {
    static void setupHwcSetCallExpectations(CompositionTest*) {}

    static void setupHwcGetCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, getChangedCompositionTypes(HWC_DISPLAY, _, _)).Times(1);
    }
};

template <IComposerClient::Composition CompositionType>
struct KeepCompositionTypeVariant {
    static constexpr hal::Composition TYPE = CompositionType;

    static void setupHwcSetCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            EXPECT_CALL(*test->mComposer,
                        setLayerCompositionType(HWC_DISPLAY, HWC_LAYER, CompositionType))
                    .Times(1);
        }
    }

    static void setupHwcGetCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, getChangedCompositionTypes(HWC_DISPLAY, _, _)).Times(1);
    }
};

template <IComposerClient::Composition InitialCompositionType,
          IComposerClient::Composition FinalCompositionType>
struct ChangeCompositionTypeVariant {
    static constexpr hal::Composition TYPE = FinalCompositionType;

    static void setupHwcSetCallExpectations(CompositionTest* test) {
        if (!test->mDisplayOff) {
            EXPECT_CALL(*test->mComposer,
                        setLayerCompositionType(HWC_DISPLAY, HWC_LAYER, InitialCompositionType))
                    .Times(1);
        }
    }

    static void setupHwcGetCallExpectations(CompositionTest* test) {
        EXPECT_CALL(*test->mComposer, getChangedCompositionTypes(HWC_DISPLAY, _, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hwc2::Layer>{
                                        static_cast<Hwc2::Layer>(HWC_LAYER)}),
                                SetArgPointee<2>(std::vector<IComposerClient::Composition>{
                                        FinalCompositionType}),
                                Return(Error::NONE)));
    }
};

/* ------------------------------------------------------------------------
 * Variants to select how the composition is expected to be handled
 */

struct CompositionResultBaseVariant {
    static void setupLayerState(CompositionTest*, sp<Layer>) {}

    template <typename Case>
    static void setupCallExpectationsForDirtyGeometry(CompositionTest* test) {
        Case::Layer::setupCallExpectationsForDirtyGeometry(test);
    }

    template <typename Case>
    static void setupCallExpectationsForDirtyFrame(CompositionTest* test) {
        Case::Layer::setupCallExpectationsForDirtyFrame(test);
    }
};

struct NoCompositionResultVariant : public CompositionResultBaseVariant {
    template <typename Case>
    static void setupCallExpectations(CompositionTest* test) {
        Case::Display::setupEmptyFrameCompositionCallExpectations(test);
        Case::Display::setupHwcCompositionCallExpectations(test);
    }
};

struct HwcCompositionResultVariant : public CompositionResultBaseVariant {
    template <typename Case>
    static void setupCallExpectations(CompositionTest* test) {
        Case::Display::setupNonEmptyFrameCompositionCallExpectations(test);
        Case::Display::setupHwcCompositionCallExpectations(test);
    }
};

struct RECompositionResultVariant : public CompositionResultBaseVariant {
    template <typename Case>
    static void setupCallExpectations(CompositionTest* test) {
        Case::Display::setupNonEmptyFrameCompositionCallExpectations(test);
        Case::Display::setupHwcClientCompositionCallExpectations(test);
        Case::Display::setupRECompositionCallExpectations(test);
        Case::Display::template setupRELayerCompositionCallExpectations<Case>(test);
    }
};

struct ForcedClientCompositionResultVariant : public CompositionResultBaseVariant {
    static void setupLayerState(CompositionTest* test, sp<Layer> layer) {
        const auto outputLayer =
                TestableSurfaceFlinger::findOutputLayerForDisplay(layer, test->mDisplay);
        LOG_FATAL_IF(!outputLayer);
        outputLayer->editState().forceClientComposition = true;
    }

    template <typename Case>
    static void setupCallExpectations(CompositionTest* test) {
        Case::Display::setupNonEmptyFrameCompositionCallExpectations(test);
        Case::Display::setupHwcForcedClientCompositionCallExpectations(test);
        Case::Display::setupRECompositionCallExpectations(test);
        Case::Display::template setupRELayerCompositionCallExpectations<Case>(test);
    }

    template <typename Case>
    static void setupCallExpectationsForDirtyGeometry(CompositionTest*) {}

    template <typename Case>
    static void setupCallExpectationsForDirtyFrame(CompositionTest*) {}
};

struct ForcedClientCompositionViaDebugOptionResultVariant : public CompositionResultBaseVariant {
    static void setupLayerState(CompositionTest* test, sp<Layer>) {
        test->mFlinger.mutableDebugDisableHWC() = true;
    }

    template <typename Case>
    static void setupCallExpectations(CompositionTest* test) {
        Case::Display::setupNonEmptyFrameCompositionCallExpectations(test);
        Case::Display::setupHwcForcedClientCompositionCallExpectations(test);
        Case::Display::setupRECompositionCallExpectations(test);
        Case::Display::template setupRELayerCompositionCallExpectations<Case>(test);
    }

    template <typename Case>
    static void setupCallExpectationsForDirtyGeometry(CompositionTest*) {}

    template <typename Case>
    static void setupCallExpectationsForDirtyFrame(CompositionTest*) {}
};

struct EmptyScreenshotResultVariant {
    static void setupLayerState(CompositionTest*, sp<Layer>) {}

    template <typename Case>
    static void setupCallExpectations(CompositionTest*) {}
};

struct REScreenshotResultVariant : public EmptyScreenshotResultVariant {
    using Base = EmptyScreenshotResultVariant;

    template <typename Case>
    static void setupCallExpectations(CompositionTest* test) {
        Base::template setupCallExpectations<Case>(test);
        Case::Display::template setupRELayerScreenshotCompositionCallExpectations<Case>(test);
    }
};

/* ------------------------------------------------------------------------
 * Composition test case, containing all the variants being tested
 */

template <typename DisplayCase, typename LayerCase, typename CompositionTypeCase,
          typename CompositionResultCase>
struct CompositionCase {
    using ThisCase =
            CompositionCase<DisplayCase, LayerCase, CompositionTypeCase, CompositionResultCase>;
    using Display = DisplayCase;
    using Layer = LayerCase;
    using CompositionType = CompositionTypeCase;
    using CompositionResult = CompositionResultCase;

    static void setupCommon(CompositionTest* test) {
        Display::template setupPreconditionCallExpectations<ThisCase>(test);
        Display::setupPreconditions(test);

        auto layer = Layer::createLayer(test);
        Layer::injectLayer(test, layer);
        CompositionResult::setupLayerState(test, layer);
    }

    static void setupForDirtyGeometry(CompositionTest* test) {
        setupCommon(test);

        Display::template setupCommonCompositionCallExpectations<ThisCase>(test);
        CompositionResult::template setupCallExpectationsForDirtyGeometry<ThisCase>(test);
        CompositionResult::template setupCallExpectationsForDirtyFrame<ThisCase>(test);
        CompositionResult::template setupCallExpectations<ThisCase>(test);
    }

    static void setupForDirtyFrame(CompositionTest* test) {
        setupCommon(test);

        Display::template setupCommonCompositionCallExpectations<ThisCase>(test);
        CompositionResult::template setupCallExpectationsForDirtyFrame<ThisCase>(test);
        CompositionResult::template setupCallExpectations<ThisCase>(test);
    }

    static void setupForScreenCapture(CompositionTest* test) {
        setupCommon(test);

        Display::template setupCommonScreensCaptureCallExpectations<ThisCase>(test);
        CompositionResult::template setupCallExpectations<ThisCase>(test);
    }

    static void cleanup(CompositionTest* test) {
        Layer::cleanupInjectedLayers(test);

        for (auto& displayData : test->mFlinger.mutableHwcDisplayData()) {
            static_cast<TestableSurfaceFlinger::HWC2Display*>(displayData.second.hwcDisplay.get())
                    ->mutableLayers()
                    .clear();
        }
    }
};

/* ------------------------------------------------------------------------
 * Composition cases to test
 */

TEST_F(CompositionTest, noLayersDoesMinimalWorkWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<DefaultDisplaySetupVariant, NoLayerVariant, NoCompositionTypeVariant,
                            NoCompositionResultVariant>>();
}

TEST_F(CompositionTest, noLayersDoesMinimalWorkWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, NoLayerVariant, NoCompositionTypeVariant,
                            NoCompositionResultVariant>>();
}

TEST_F(CompositionTest, noLayersDoesMinimalWorkToCaptureScreen) {
    captureScreenComposition<
            CompositionCase<DefaultDisplaySetupVariant, NoLayerVariant, NoCompositionTypeVariant,
                            EmptyScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Simple buffer layers
 */

TEST_F(CompositionTest, HWCComposedNormalBufferLayerWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::DEVICE>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, HWCComposedNormalBufferLayerWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::DEVICE>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, REComposedNormalBufferLayer) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
                            ChangeCompositionTypeVariant<IComposerClient::Composition::DEVICE,
                                                         IComposerClient::Composition::CLIENT>,
                            RECompositionResultVariant>>();
}

TEST_F(CompositionTest, captureScreenNormalBufferLayer) {
    captureScreenComposition<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
                            NoCompositionTypeVariant, REScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Single-color layers
 */

TEST_F(CompositionTest, HWCComposedEffectLayerWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<DefaultDisplaySetupVariant, EffectLayerVariant<EffectLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::SOLID_COLOR>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, HWCComposedEffectLayerWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, EffectLayerVariant<EffectLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::SOLID_COLOR>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, REComposedEffectLayer) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, EffectLayerVariant<EffectLayerProperties>,
                            ChangeCompositionTypeVariant<IComposerClient::Composition::SOLID_COLOR,
                                                         IComposerClient::Composition::CLIENT>,
                            RECompositionResultVariant>>();
}

TEST_F(CompositionTest, captureScreenEffectLayer) {
    captureScreenComposition<
            CompositionCase<DefaultDisplaySetupVariant, EffectLayerVariant<EffectLayerProperties>,
                            NoCompositionTypeVariant, REScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Layers with sideband buffers
 */

TEST_F(CompositionTest, HWCComposedSidebandBufferLayerWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SidebandLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::SIDEBAND>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, HWCComposedSidebandBufferLayerWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SidebandLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::SIDEBAND>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, REComposedSidebandBufferLayer) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SidebandLayerProperties>,
                            ChangeCompositionTypeVariant<IComposerClient::Composition::SIDEBAND,
                                                         IComposerClient::Composition::CLIENT>,
                            RECompositionResultVariant>>();
}

TEST_F(CompositionTest, captureScreenSidebandBufferLayer) {
    captureScreenComposition<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SidebandLayerProperties>,
                            NoCompositionTypeVariant, REScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Layers with ISurfaceComposerClient::eSecure, on a secure display
 */

TEST_F(CompositionTest, HWCComposedSecureBufferLayerWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SecureLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::DEVICE>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, HWCComposedSecureBufferLayerWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SecureLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::DEVICE>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, REComposedSecureBufferLayer) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SecureLayerProperties>,
                            ChangeCompositionTypeVariant<IComposerClient::Composition::DEVICE,
                                                         IComposerClient::Composition::CLIENT>,
                            RECompositionResultVariant>>();
}

TEST_F(CompositionTest, captureScreenSecureBufferLayerOnSecureDisplay) {
    captureScreenComposition<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<SecureLayerProperties>,
                            NoCompositionTypeVariant, REScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Layers with ISurfaceComposerClient::eSecure, on a non-secure display
 */

TEST_F(CompositionTest, HWCComposedSecureBufferLayerOnInsecureDisplayWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<InsecureDisplaySetupVariant, BufferLayerVariant<SecureLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::CLIENT>,
                            ForcedClientCompositionResultVariant>>();
}

TEST_F(CompositionTest, HWCComposedSecureBufferLayerOnInsecureDisplayWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<InsecureDisplaySetupVariant, BufferLayerVariant<SecureLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::CLIENT>,
                            ForcedClientCompositionResultVariant>>();
}

TEST_F(CompositionTest, captureScreenSecureBufferLayerOnInsecureDisplay) {
    captureScreenComposition<
            CompositionCase<InsecureDisplaySetupVariant, BufferLayerVariant<SecureLayerProperties>,
                            NoCompositionTypeVariant, REScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Cursor layers
 */

TEST_F(CompositionTest, HWCComposedCursorLayerWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<CursorLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::CURSOR>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, HWCComposedCursorLayerWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<CursorLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::CURSOR>,
                            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, REComposedCursorLayer) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<CursorLayerProperties>,
                            ChangeCompositionTypeVariant<IComposerClient::Composition::CURSOR,
                                                         IComposerClient::Composition::CLIENT>,
                            RECompositionResultVariant>>();
}

TEST_F(CompositionTest, captureScreenCursorLayer) {
    captureScreenComposition<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<CursorLayerProperties>,
                            NoCompositionTypeVariant, REScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Simple buffer layer on a display which is powered off.
 */

TEST_F(CompositionTest, displayOffHWCComposedNormalBufferLayerWithDirtyGeometry) {
    mDisplayOff = true;
    displayRefreshCompositionDirtyGeometry<CompositionCase<
            PoweredOffDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
            KeepCompositionTypeVariant<IComposerClient::Composition::DEVICE>,
            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, displayOffHWCComposedNormalBufferLayerWithDirtyFrame) {
    mDisplayOff = true;
    displayRefreshCompositionDirtyFrame<CompositionCase<
            PoweredOffDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
            KeepCompositionTypeVariant<IComposerClient::Composition::DEVICE>,
            HwcCompositionResultVariant>>();
}

TEST_F(CompositionTest, displayOffREComposedNormalBufferLayer) {
    mDisplayOff = true;
    displayRefreshCompositionDirtyFrame<CompositionCase<
            PoweredOffDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
            ChangeCompositionTypeVariant<IComposerClient::Composition::DEVICE,
                                         IComposerClient::Composition::CLIENT>,
            RECompositionResultVariant>>();
}

TEST_F(CompositionTest, captureScreenNormalBufferLayerOnPoweredOffDisplay) {
    captureScreenComposition<CompositionCase<
            PoweredOffDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
            NoCompositionTypeVariant, REScreenshotResultVariant>>();
}

/* ------------------------------------------------------------------------
 *  Client composition forced through debug/developer settings
 */

TEST_F(CompositionTest, DebugOptionForcingClientCompositionOfBufferLayerWithDirtyGeometry) {
    displayRefreshCompositionDirtyGeometry<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::CLIENT>,
                            ForcedClientCompositionViaDebugOptionResultVariant>>();
}

TEST_F(CompositionTest, DebugOptionForcingClientCompositionOfBufferLayerWithDirtyFrame) {
    displayRefreshCompositionDirtyFrame<
            CompositionCase<DefaultDisplaySetupVariant, BufferLayerVariant<DefaultLayerProperties>,
                            KeepCompositionTypeVariant<IComposerClient::Composition::CLIENT>,
                            ForcedClientCompositionViaDebugOptionResultVariant>>();
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
