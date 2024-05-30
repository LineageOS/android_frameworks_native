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

#include <cmath>

#include <compositionengine/DisplayColorProfileCreationArgs.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/DisplaySurface.h>
#include <compositionengine/RenderSurfaceCreationArgs.h>
#include <compositionengine/impl/Display.h>
#include <compositionengine/impl/RenderSurface.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/DisplaySurface.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/NativeWindow.h>
#include <compositionengine/mock/OutputLayer.h>
#include <compositionengine/mock/RenderSurface.h>
#include <gtest/gtest.h>
#include <renderengine/mock/FakeExternalTexture.h>
#include <renderengine/mock/RenderEngine.h>

#include <ui/Rect.h>
#include <ui/StaticDisplayInfo.h>

#include "MockHWC2.h"
#include "MockHWComposer.h"
#include "MockPowerAdvisor.h"
#include "ftl/future.h"

#include <aidl/android/hardware/graphics/composer3/Composition.h>

using aidl::android::hardware::graphics::composer3::Capability;
using aidl::android::hardware::graphics::composer3::Composition;
using aidl::android::hardware::graphics::composer3::DimmingStage;

namespace android::compositionengine {
namespace {

namespace hal = android::hardware::graphics::composer::hal;

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Eq;
using testing::InSequence;
using testing::NiceMock;
using testing::Pointee;
using testing::Ref;
using testing::Return;
using testing::ReturnRef;
using testing::Sequence;
using testing::SetArgPointee;
using testing::StrictMock;

constexpr PhysicalDisplayId DEFAULT_DISPLAY_ID = PhysicalDisplayId::fromPort(123u);
constexpr HalVirtualDisplayId HAL_VIRTUAL_DISPLAY_ID{456u};
constexpr GpuVirtualDisplayId GPU_VIRTUAL_DISPLAY_ID{789u};

constexpr ui::Size DEFAULT_RESOLUTION{1920, 1080};

struct Layer {
    Layer() {
        EXPECT_CALL(*outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE));
        EXPECT_CALL(*outputLayer, getHwcLayer()).WillRepeatedly(Return(&hwc2Layer));
    }

    sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
    StrictMock<mock::OutputLayer>* outputLayer = new StrictMock<mock::OutputLayer>();
    StrictMock<HWC2::mock::Layer> hwc2Layer;
};

struct LayerNoHWC2Layer {
    LayerNoHWC2Layer() {
        EXPECT_CALL(*outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE));
        EXPECT_CALL(*outputLayer, getHwcLayer()).WillRepeatedly(Return(nullptr));
    }

    sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
    StrictMock<mock::OutputLayer>* outputLayer = new StrictMock<mock::OutputLayer>();
};

struct DisplayTestCommon : public testing::Test {
    // Uses the full implementation of a display
    class FullImplDisplay : public impl::Display {
    public:
        using impl::Display::injectOutputLayerForTest;
        virtual void injectOutputLayerForTest(std::unique_ptr<compositionengine::OutputLayer>) = 0;
    };

    // Uses a special implementation with key internal member functions set up
    // as mock implementations, to allow for easier testing.
    struct PartialMockDisplay : public impl::Display {
        PartialMockDisplay(const compositionengine::CompositionEngine& compositionEngine)
              : mCompositionEngine(compositionEngine) {}

        // compositionengine::Output overrides
        const OutputCompositionState& getState() const override { return mState; }
        OutputCompositionState& editState() override { return mState; }

        // compositionengine::impl::Output overrides
        const CompositionEngine& getCompositionEngine() const override {
            return mCompositionEngine;
        };

        size_t getOutputLayerCount() const override { return 1u; }

        // Mock implementation overrides
        MOCK_CONST_METHOD1(getOutputLayerOrderedByZByIndex,
                           compositionengine::OutputLayer*(size_t));
        MOCK_METHOD2(ensureOutputLayer,
                     compositionengine::OutputLayer*(std::optional<size_t>, const sp<LayerFE>&));
        MOCK_METHOD0(finalizePendingOutputLayers, void());
        MOCK_METHOD0(clearOutputLayers, void());
        MOCK_CONST_METHOD1(dumpState, void(std::string&));
        MOCK_METHOD1(injectOutputLayerForTest, compositionengine::OutputLayer*(const sp<LayerFE>&));
        MOCK_METHOD1(injectOutputLayerForTest, void(std::unique_ptr<OutputLayer>));
        MOCK_CONST_METHOD0(anyLayersRequireClientComposition, bool());
        MOCK_CONST_METHOD0(allLayersRequireClientComposition, bool());
        MOCK_METHOD1(applyChangedTypesToLayers, void(const impl::Display::ChangedTypes&));
        MOCK_METHOD1(applyDisplayRequests, void(const impl::Display::DisplayRequests&));
        MOCK_METHOD1(applyLayerRequestsToLayers, void(const impl::Display::LayerRequests&));

        const compositionengine::CompositionEngine& mCompositionEngine;
        impl::OutputCompositionState mState;
    };

    static std::string getDisplayNameFromCurrentTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        return std::string("display for ") + test_info->test_case_name() + "." + test_info->name();
    }

    template <typename Display>
    static std::shared_ptr<Display> createDisplay(
            const compositionengine::CompositionEngine& compositionEngine,
            compositionengine::DisplayCreationArgs args) {
        args.name = getDisplayNameFromCurrentTest();
        return impl::createDisplayTemplated<Display>(compositionEngine, args);
    }

    template <typename Display>
    static std::shared_ptr<StrictMock<Display>> createPartialMockDisplay(
            const compositionengine::CompositionEngine& compositionEngine,
            compositionengine::DisplayCreationArgs args) {
        args.name = getDisplayNameFromCurrentTest();
        auto display = std::make_shared<StrictMock<Display>>(compositionEngine);

        display->setConfiguration(args);

        return display;
    }

    DisplayTestCommon() {
        EXPECT_CALL(mCompositionEngine, getHwComposer()).WillRepeatedly(ReturnRef(mHwComposer));
        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
        EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
        EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
        EXPECT_CALL(mPowerAdvisor, usePowerHintSession()).WillRepeatedly(Return(false));
    }

    DisplayCreationArgs getDisplayCreationArgsForPhysicalDisplay() {
        return DisplayCreationArgsBuilder()
                .setId(DEFAULT_DISPLAY_ID)
                .setPixels(DEFAULT_RESOLUTION)
                .setIsSecure(true)
                .setPowerAdvisor(&mPowerAdvisor)
                .build();
    }

    DisplayCreationArgs getDisplayCreationArgsForGpuVirtualDisplay() {
        return DisplayCreationArgsBuilder()
                .setId(GPU_VIRTUAL_DISPLAY_ID)
                .setPixels(DEFAULT_RESOLUTION)
                .setIsSecure(false)
                .setPowerAdvisor(&mPowerAdvisor)
                .build();
    }

    StrictMock<android::mock::HWComposer> mHwComposer;
    StrictMock<Hwc2::mock::PowerAdvisor> mPowerAdvisor;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    sp<mock::NativeWindow> mNativeWindow = sp<StrictMock<mock::NativeWindow>>::make();
};

struct PartialMockDisplayTestCommon : public DisplayTestCommon {
    using Display = DisplayTestCommon::PartialMockDisplay;
    std::shared_ptr<Display> mDisplay =
            createPartialMockDisplay<Display>(mCompositionEngine,
                                              getDisplayCreationArgsForPhysicalDisplay());

    android::HWComposer::DeviceRequestedChanges mDeviceRequestedChanges{
            {{nullptr, Composition::CLIENT}},
            hal::DisplayRequest::FLIP_CLIENT_TARGET,
            {{nullptr, hal::LayerRequest::CLEAR_CLIENT_TARGET}},
            {DEFAULT_DISPLAY_ID.value,
             {aidl::android::hardware::graphics::common::PixelFormat::RGBA_8888,
              aidl::android::hardware::graphics::common::Dataspace::UNKNOWN},
             -1.f,
             DimmingStage::NONE},
    };

    void chooseCompositionStrategy(Display* display) {
        std::optional<android::HWComposer::DeviceRequestedChanges> changes;
        bool success = display->chooseCompositionStrategy(&changes);
        display->resetCompositionStrategy();
        if (success) {
            display->applyCompositionStrategy(changes);
        }
    }
};

struct FullDisplayImplTestCommon : public DisplayTestCommon {
    using Display = DisplayTestCommon::FullImplDisplay;
    std::shared_ptr<Display> mDisplay =
            createDisplay<Display>(mCompositionEngine, getDisplayCreationArgsForPhysicalDisplay());
};

struct DisplayWithLayersTestCommon : public FullDisplayImplTestCommon {
    DisplayWithLayersTestCommon() {
        mDisplay->injectOutputLayerForTest(
                std::unique_ptr<compositionengine::OutputLayer>(mLayer1.outputLayer));
        mDisplay->injectOutputLayerForTest(
                std::unique_ptr<compositionengine::OutputLayer>(mLayer2.outputLayer));
        mDisplay->injectOutputLayerForTest(
                std::unique_ptr<compositionengine::OutputLayer>(mLayer3.outputLayer));
        mResultWithBuffer.buffer = std::make_shared<
                renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                         1ULL /* bufferId */,
                                                         HAL_PIXEL_FORMAT_RGBA_8888,
                                                         0ULL /*usage*/);
    }

    Layer mLayer1;
    Layer mLayer2;
    LayerNoHWC2Layer mLayer3;
    StrictMock<HWC2::mock::Layer> hwc2LayerUnknown;
    std::shared_ptr<Display> mDisplay =
            createDisplay<Display>(mCompositionEngine, getDisplayCreationArgsForPhysicalDisplay());
    impl::GpuCompositionResult mResultWithBuffer;
    impl::GpuCompositionResult mResultWithoutBuffer;
};

/*
 * Basic construction
 */

struct DisplayCreationTest : public DisplayTestCommon {
    using Display = DisplayTestCommon::FullImplDisplay;
};

TEST_F(DisplayCreationTest, createPhysicalInternalDisplay) {
    auto display =
            impl::createDisplay(mCompositionEngine, getDisplayCreationArgsForPhysicalDisplay());
    EXPECT_TRUE(display->isSecure());
    EXPECT_FALSE(display->isVirtual());
    EXPECT_EQ(DEFAULT_DISPLAY_ID, display->getId());
}

TEST_F(DisplayCreationTest, createGpuVirtualDisplay) {
    auto display =
            impl::createDisplay(mCompositionEngine, getDisplayCreationArgsForGpuVirtualDisplay());
    EXPECT_FALSE(display->isSecure());
    EXPECT_TRUE(display->isVirtual());
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(display->getId()));
}

/*
 * Display::setConfiguration()
 */

using DisplaySetConfigurationTest = PartialMockDisplayTestCommon;

TEST_F(DisplaySetConfigurationTest, configuresPhysicalDisplay) {
    mDisplay->setConfiguration(DisplayCreationArgsBuilder()
                                       .setId(DEFAULT_DISPLAY_ID)
                                       .setPixels(DEFAULT_RESOLUTION)
                                       .setIsSecure(true)
                                       .setPowerAdvisor(&mPowerAdvisor)
                                       .setName(getDisplayNameFromCurrentTest())
                                       .build());

    EXPECT_EQ(DEFAULT_DISPLAY_ID, mDisplay->getId());
    EXPECT_TRUE(mDisplay->isSecure());
    EXPECT_FALSE(mDisplay->isVirtual());
    EXPECT_FALSE(mDisplay->isValid());

    const auto& filter = mDisplay->getState().layerFilter;
    EXPECT_EQ(ui::INVALID_LAYER_STACK, filter.layerStack);
    EXPECT_FALSE(filter.toInternalDisplay);
}

TEST_F(DisplaySetConfigurationTest, configuresHalVirtualDisplay) {
    mDisplay->setConfiguration(DisplayCreationArgsBuilder()
                                       .setId(HAL_VIRTUAL_DISPLAY_ID)
                                       .setPixels(DEFAULT_RESOLUTION)
                                       .setIsSecure(false)
                                       .setPowerAdvisor(&mPowerAdvisor)
                                       .setName(getDisplayNameFromCurrentTest())
                                       .build());

    EXPECT_EQ(HAL_VIRTUAL_DISPLAY_ID, mDisplay->getId());
    EXPECT_FALSE(mDisplay->isSecure());
    EXPECT_TRUE(mDisplay->isVirtual());
    EXPECT_FALSE(mDisplay->isValid());

    const auto& filter = mDisplay->getState().layerFilter;
    EXPECT_EQ(ui::INVALID_LAYER_STACK, filter.layerStack);
    EXPECT_FALSE(filter.toInternalDisplay);
}

TEST_F(DisplaySetConfigurationTest, configuresGpuVirtualDisplay) {
    mDisplay->setConfiguration(DisplayCreationArgsBuilder()
                                       .setId(GPU_VIRTUAL_DISPLAY_ID)
                                       .setPixels(DEFAULT_RESOLUTION)
                                       .setIsSecure(false)
                                       .setPowerAdvisor(&mPowerAdvisor)
                                       .setName(getDisplayNameFromCurrentTest())
                                       .build());

    EXPECT_EQ(GPU_VIRTUAL_DISPLAY_ID, mDisplay->getId());
    EXPECT_FALSE(mDisplay->isSecure());
    EXPECT_TRUE(mDisplay->isVirtual());
    EXPECT_FALSE(mDisplay->isValid());

    const auto& filter = mDisplay->getState().layerFilter;
    EXPECT_EQ(ui::INVALID_LAYER_STACK, filter.layerStack);
    EXPECT_FALSE(filter.toInternalDisplay);
}

/*
 * Display::disconnect()
 */

using DisplayDisconnectTest = PartialMockDisplayTestCommon;

TEST_F(DisplayDisconnectTest, disconnectsDisplay) {
    // The first call to disconnect will disconnect the display with the HWC.
    EXPECT_CALL(mHwComposer, disconnectDisplay(HalDisplayId(DEFAULT_DISPLAY_ID))).Times(1);
    mDisplay->disconnect();

    // Subsequent calls will do nothing,
    EXPECT_CALL(mHwComposer, disconnectDisplay(HalDisplayId(DEFAULT_DISPLAY_ID))).Times(0);
    mDisplay->disconnect();
}

/*
 * Display::setColorTransform()
 */

using DisplaySetColorTransformTest = PartialMockDisplayTestCommon;

TEST_F(DisplaySetColorTransformTest, setsTransform) {
    // No change does nothing
    CompositionRefreshArgs refreshArgs;
    refreshArgs.colorTransformMatrix = std::nullopt;
    mDisplay->setColorTransform(refreshArgs);

    // Identity matrix sets an identity state value
    const mat4 kIdentity;

    EXPECT_CALL(mHwComposer, setColorTransform(HalDisplayId(DEFAULT_DISPLAY_ID), kIdentity))
            .Times(1);

    refreshArgs.colorTransformMatrix = kIdentity;
    mDisplay->setColorTransform(refreshArgs);

    // Non-identity matrix sets a non-identity state value
    const mat4 kNonIdentity = mat4() * 2;

    EXPECT_CALL(mHwComposer, setColorTransform(HalDisplayId(DEFAULT_DISPLAY_ID), kNonIdentity))
            .Times(1);

    refreshArgs.colorTransformMatrix = kNonIdentity;
    mDisplay->setColorTransform(refreshArgs);
}

/*
 * Display::setColorMode()
 */

using DisplaySetColorModeTest = PartialMockDisplayTestCommon;

TEST_F(DisplaySetColorModeTest, setsModeUnlessNoChange) {
    using ColorProfile = Output::ColorProfile;

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    mDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));
    mock::DisplayColorProfile* colorProfile = new StrictMock<mock::DisplayColorProfile>();
    mDisplay->setDisplayColorProfileForTest(std::unique_ptr<DisplayColorProfile>(colorProfile));

    // These values are expected to be the initial state.
    ASSERT_EQ(ui::ColorMode::NATIVE, mDisplay->getState().colorMode);
    ASSERT_EQ(ui::Dataspace::UNKNOWN, mDisplay->getState().dataspace);
    ASSERT_EQ(ui::RenderIntent::COLORIMETRIC, mDisplay->getState().renderIntent);

    // Otherwise if the values are unchanged, nothing happens
    mDisplay->setColorProfile(ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                                           ui::RenderIntent::COLORIMETRIC});

    EXPECT_EQ(ui::ColorMode::NATIVE, mDisplay->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::COLORIMETRIC, mDisplay->getState().renderIntent);

    // Otherwise if the values are different, updates happen
    EXPECT_CALL(*renderSurface, setBufferDataspace(ui::Dataspace::DISPLAY_P3)).Times(1);
    EXPECT_CALL(mHwComposer,
                setActiveColorMode(DEFAULT_DISPLAY_ID, ui::ColorMode::DISPLAY_P3,
                                   ui::RenderIntent::TONE_MAP_COLORIMETRIC))
            .Times(1);

    mDisplay->setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                           ui::RenderIntent::TONE_MAP_COLORIMETRIC});

    EXPECT_EQ(ui::ColorMode::DISPLAY_P3, mDisplay->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mDisplay->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::TONE_MAP_COLORIMETRIC, mDisplay->getState().renderIntent);
}

TEST_F(DisplaySetColorModeTest, doesNothingForVirtualDisplay) {
    using ColorProfile = Output::ColorProfile;

    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    std::shared_ptr<impl::Display> virtualDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::DisplayColorProfile* colorProfile = new StrictMock<mock::DisplayColorProfile>();
    virtualDisplay->setDisplayColorProfileForTest(
            std::unique_ptr<DisplayColorProfile>(colorProfile));

    virtualDisplay->setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3,
                                                 ui::Dataspace::DISPLAY_P3,
                                                 ui::RenderIntent::TONE_MAP_COLORIMETRIC});

    EXPECT_EQ(ui::ColorMode::NATIVE, virtualDisplay->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, virtualDisplay->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::COLORIMETRIC, virtualDisplay->getState().renderIntent);
}

/*
 * Display::createDisplayColorProfile()
 */

using DisplayCreateColorProfileTest = PartialMockDisplayTestCommon;

TEST_F(DisplayCreateColorProfileTest, setsDisplayColorProfile) {
    EXPECT_TRUE(mDisplay->getDisplayColorProfile() == nullptr);
    mDisplay->createDisplayColorProfile(
            DisplayColorProfileCreationArgs{false, HdrCapabilities(), 0,
                                            DisplayColorProfileCreationArgs::HwcColorModes()});
    EXPECT_TRUE(mDisplay->getDisplayColorProfile() != nullptr);
}

/*
 * Display::createRenderSurface()
 */

using DisplayCreateRenderSurfaceTest = PartialMockDisplayTestCommon;

TEST_F(DisplayCreateRenderSurfaceTest, setsRenderSurface) {
    EXPECT_CALL(*mNativeWindow, disconnect(NATIVE_WINDOW_API_EGL)).WillRepeatedly(Return(NO_ERROR));
    EXPECT_TRUE(mDisplay->getRenderSurface() == nullptr);
    mDisplay->createRenderSurface(RenderSurfaceCreationArgsBuilder()
                                          .setDisplayWidth(640)
                                          .setDisplayHeight(480)
                                          .setNativeWindow(mNativeWindow)
                                          .build());
    EXPECT_TRUE(mDisplay->getRenderSurface() != nullptr);
}

/*
 * Display::createOutputLayer()
 */

using DisplayCreateOutputLayerTest = FullDisplayImplTestCommon;

TEST_F(DisplayCreateOutputLayerTest, setsHwcLayer) {
    sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
    auto hwcLayer = std::make_shared<StrictMock<HWC2::mock::Layer>>();

    EXPECT_CALL(mHwComposer, createLayer(HalDisplayId(DEFAULT_DISPLAY_ID)))
            .WillOnce(Return(hwcLayer));

    auto outputLayer = mDisplay->createOutputLayer(layerFE);

    EXPECT_EQ(hwcLayer.get(), outputLayer->getHwcLayer());

    outputLayer.reset();
}

/*
 * Display::setReleasedLayers()
 */

using DisplaySetReleasedLayersTest = DisplayWithLayersTestCommon;

TEST_F(DisplaySetReleasedLayersTest, doesNothingIfGpuDisplay) {
    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    std::shared_ptr<impl::Display> gpuDisplay = impl::createDisplay(mCompositionEngine, args);

    sp<mock::LayerFE> layerXLayerFE = sp<StrictMock<mock::LayerFE>>::make();

    {
        Output::ReleasedLayers releasedLayers;
        releasedLayers.emplace_back(layerXLayerFE);
        gpuDisplay->setReleasedLayers(std::move(releasedLayers));
    }

    CompositionRefreshArgs refreshArgs;
    refreshArgs.layersWithQueuedFrames.push_back(layerXLayerFE);

    gpuDisplay->setReleasedLayers(refreshArgs);

    const auto& releasedLayers = gpuDisplay->getReleasedLayersForTest();
    ASSERT_EQ(1u, releasedLayers.size());
}

TEST_F(DisplaySetReleasedLayersTest, doesNothingIfNoLayersWithQueuedFrames) {
    sp<mock::LayerFE> layerXLayerFE = sp<StrictMock<mock::LayerFE>>::make();

    {
        Output::ReleasedLayers releasedLayers;
        releasedLayers.emplace_back(layerXLayerFE);
        mDisplay->setReleasedLayers(std::move(releasedLayers));
    }

    CompositionRefreshArgs refreshArgs;
    mDisplay->setReleasedLayers(refreshArgs);

    const auto& releasedLayers = mDisplay->getReleasedLayersForTest();
    ASSERT_EQ(1u, releasedLayers.size());
}

TEST_F(DisplaySetReleasedLayersTest, setReleasedLayers) {
    sp<mock::LayerFE> unknownLayer = sp<StrictMock<mock::LayerFE>>::make();

    CompositionRefreshArgs refreshArgs;
    refreshArgs.layersWithQueuedFrames.push_back(mLayer1.layerFE);
    refreshArgs.layersWithQueuedFrames.push_back(mLayer2.layerFE);
    refreshArgs.layersWithQueuedFrames.push_back(unknownLayer);

    mDisplay->setReleasedLayers(refreshArgs);

    const auto& releasedLayers = mDisplay->getReleasedLayersForTest();
    ASSERT_EQ(2u, releasedLayers.size());
    ASSERT_EQ(mLayer1.layerFE.get(), releasedLayers[0].promote().get());
    ASSERT_EQ(mLayer2.layerFE.get(), releasedLayers[1].promote().get());
}

/*
 * Display::chooseCompositionStrategy()
 */

using DisplayChooseCompositionStrategyTest = PartialMockDisplayTestCommon;

TEST_F(DisplayChooseCompositionStrategyTest, takesEarlyOutIfGpuDisplay) {
    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    std::shared_ptr<Display> gpuDisplay =
            createPartialMockDisplay<Display>(mCompositionEngine, args);
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(gpuDisplay->getId()));

    chooseCompositionStrategy(gpuDisplay.get());

    auto& state = gpuDisplay->getState();
    EXPECT_TRUE(state.usesClientComposition);
    EXPECT_FALSE(state.usesDeviceComposition);
}

TEST_F(DisplayChooseCompositionStrategyTest, takesEarlyOutOnHwcError) {
    EXPECT_CALL(*mDisplay, anyLayersRequireClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer,
                getDeviceCompositionChanges(HalDisplayId(DEFAULT_DISPLAY_ID), false, _, _, _, _))
            .WillOnce(Return(INVALID_OPERATION));

    chooseCompositionStrategy(mDisplay.get());

    auto& state = mDisplay->getState();
    EXPECT_TRUE(state.usesClientComposition);
    EXPECT_FALSE(state.usesDeviceComposition);
    EXPECT_FALSE(state.previousDeviceRequestedChanges.has_value());
}

TEST_F(DisplayChooseCompositionStrategyTest, normalOperation) {
    // Since two calls are made to anyLayersRequireClientComposition with different return
    // values, use a Sequence to control the matching so the values are returned in a known
    // order.
    Sequence s;
    EXPECT_CALL(*mDisplay, anyLayersRequireClientComposition())
            .InSequence(s)
            .WillOnce(Return(true));
    EXPECT_CALL(*mDisplay, anyLayersRequireClientComposition())
            .InSequence(s)
            .WillOnce(Return(false));

    EXPECT_CALL(mHwComposer,
                getDeviceCompositionChanges(HalDisplayId(DEFAULT_DISPLAY_ID), true, _, _, _, _))
            .WillOnce(testing::DoAll(testing::SetArgPointee<5>(mDeviceRequestedChanges),
                                     Return(NO_ERROR)));
    EXPECT_CALL(*mDisplay, applyChangedTypesToLayers(mDeviceRequestedChanges.changedTypes))
            .Times(1);
    EXPECT_CALL(*mDisplay, applyDisplayRequests(mDeviceRequestedChanges.displayRequests)).Times(1);
    EXPECT_CALL(*mDisplay, applyLayerRequestsToLayers(mDeviceRequestedChanges.layerRequests))
            .Times(1);
    EXPECT_CALL(*mDisplay, allLayersRequireClientComposition()).WillOnce(Return(false));

    chooseCompositionStrategy(mDisplay.get());

    auto& state = mDisplay->getState();
    EXPECT_FALSE(state.usesClientComposition);
    EXPECT_TRUE(state.usesDeviceComposition);
}

TEST_F(DisplayChooseCompositionStrategyTest, normalOperationWithDisplayBrightness) {
    // Since two calls are made to anyLayersRequireClientComposition with different return
    // values, use a Sequence to control the matching so the values are returned in a known
    // order.
    constexpr float kDisplayBrightness = 0.5f;
    constexpr float kDisplayBrightnessNits = 200.f;
    EXPECT_CALL(mHwComposer,
                setDisplayBrightness(DEFAULT_DISPLAY_ID, kDisplayBrightness, kDisplayBrightnessNits,
                                     Hwc2::Composer::DisplayBrightnessOptions{.applyImmediately =
                                                                                      false}))
            .WillOnce(Return(ByMove(ftl::yield<status_t>(NO_ERROR))));

    mDisplay->setNextBrightness(kDisplayBrightness);
    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    EXPECT_CALL(*renderSurface, beginFrame(_)).Times(1);
    mDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));
    mDisplay->editState().displayBrightnessNits = kDisplayBrightnessNits;
    mDisplay->beginFrame();

    auto& state = mDisplay->getState();
    EXPECT_FALSE(state.displayBrightness.has_value());
}

TEST_F(DisplayChooseCompositionStrategyTest, normalOperationWithChanges) {
    // Since two calls are made to anyLayersRequireClientComposition with different return
    // values, use a Sequence to control the matching so the values are returned in a known
    // order.
    Sequence s;
    EXPECT_CALL(*mDisplay, anyLayersRequireClientComposition())
            .InSequence(s)
            .WillOnce(Return(true));
    EXPECT_CALL(*mDisplay, anyLayersRequireClientComposition())
            .InSequence(s)
            .WillOnce(Return(false));

    EXPECT_CALL(mHwComposer,
                getDeviceCompositionChanges(HalDisplayId(DEFAULT_DISPLAY_ID), true, _, _, _, _))
            .WillOnce(DoAll(SetArgPointee<5>(mDeviceRequestedChanges), Return(NO_ERROR)));
    EXPECT_CALL(*mDisplay, applyChangedTypesToLayers(mDeviceRequestedChanges.changedTypes))
            .Times(1);
    EXPECT_CALL(*mDisplay, applyDisplayRequests(mDeviceRequestedChanges.displayRequests)).Times(1);
    EXPECT_CALL(*mDisplay, applyLayerRequestsToLayers(mDeviceRequestedChanges.layerRequests))
            .Times(1);
    EXPECT_CALL(*mDisplay, allLayersRequireClientComposition()).WillOnce(Return(false));

    chooseCompositionStrategy(mDisplay.get());

    auto& state = mDisplay->getState();
    EXPECT_FALSE(state.usesClientComposition);
    EXPECT_TRUE(state.usesDeviceComposition);
}

/*
 * Display::getSkipColorTransform()
 */

using DisplayGetSkipColorTransformTest = DisplayWithLayersTestCommon;
using aidl::android::hardware::graphics::composer3::DisplayCapability;

TEST_F(DisplayGetSkipColorTransformTest, checksCapabilityIfGpuDisplay) {
    EXPECT_CALL(mHwComposer, hasCapability(Capability::SKIP_CLIENT_COLOR_TRANSFORM))
            .WillOnce(Return(true));
    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    auto gpuDisplay{impl::createDisplay(mCompositionEngine, args)};
    EXPECT_TRUE(gpuDisplay->getSkipColorTransform());
}

TEST_F(DisplayGetSkipColorTransformTest, checksDisplayCapability) {
    EXPECT_CALL(mHwComposer,
                hasDisplayCapability(HalDisplayId(DEFAULT_DISPLAY_ID),
                                     DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM))
            .WillOnce(Return(true));
    EXPECT_TRUE(mDisplay->getSkipColorTransform());
}

/*
 * Display::anyLayersRequireClientComposition()
 */

using DisplayAnyLayersRequireClientCompositionTest = DisplayWithLayersTestCommon;

TEST_F(DisplayAnyLayersRequireClientCompositionTest, returnsFalse) {
    EXPECT_CALL(*mLayer1.outputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayer2.outputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayer3.outputLayer, requiresClientComposition()).WillOnce(Return(false));

    EXPECT_FALSE(mDisplay->anyLayersRequireClientComposition());
}

TEST_F(DisplayAnyLayersRequireClientCompositionTest, returnsTrue) {
    EXPECT_CALL(*mLayer1.outputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayer2.outputLayer, requiresClientComposition()).WillOnce(Return(true));

    EXPECT_TRUE(mDisplay->anyLayersRequireClientComposition());
}

/*
 * Display::allLayersRequireClientComposition()
 */

using DisplayAllLayersRequireClientCompositionTest = DisplayWithLayersTestCommon;

TEST_F(DisplayAllLayersRequireClientCompositionTest, returnsTrue) {
    EXPECT_CALL(*mLayer1.outputLayer, requiresClientComposition()).WillOnce(Return(true));
    EXPECT_CALL(*mLayer2.outputLayer, requiresClientComposition()).WillOnce(Return(true));
    EXPECT_CALL(*mLayer3.outputLayer, requiresClientComposition()).WillOnce(Return(true));

    EXPECT_TRUE(mDisplay->allLayersRequireClientComposition());
}

TEST_F(DisplayAllLayersRequireClientCompositionTest, returnsFalse) {
    EXPECT_CALL(*mLayer1.outputLayer, requiresClientComposition()).WillOnce(Return(true));
    EXPECT_CALL(*mLayer2.outputLayer, requiresClientComposition()).WillOnce(Return(false));

    EXPECT_FALSE(mDisplay->allLayersRequireClientComposition());
}

/*
 * Display::applyChangedTypesToLayers()
 */

using DisplayApplyChangedTypesToLayersTest = DisplayWithLayersTestCommon;

TEST_F(DisplayApplyChangedTypesToLayersTest, takesEarlyOutIfNoChangedLayers) {
    mDisplay->applyChangedTypesToLayers(impl::Display::ChangedTypes());
}

TEST_F(DisplayApplyChangedTypesToLayersTest, appliesChanges) {
    EXPECT_CALL(*mLayer1.outputLayer, applyDeviceCompositionTypeChange(Composition::CLIENT))
            .Times(1);
    EXPECT_CALL(*mLayer2.outputLayer, applyDeviceCompositionTypeChange(Composition::DEVICE))
            .Times(1);

    mDisplay->applyChangedTypesToLayers(impl::Display::ChangedTypes{
            {&mLayer1.hwc2Layer, Composition::CLIENT},
            {&mLayer2.hwc2Layer, Composition::DEVICE},
            {&hwc2LayerUnknown, Composition::SOLID_COLOR},
    });
}

/*
 * Display::applyDisplayRequests()
 */

using DisplayApplyDisplayRequestsTest = DisplayWithLayersTestCommon;

TEST_F(DisplayApplyDisplayRequestsTest, handlesNoRequests) {
    mDisplay->applyDisplayRequests(static_cast<hal::DisplayRequest>(0));

    auto& state = mDisplay->getState();
    EXPECT_FALSE(state.flipClientTarget);
}

TEST_F(DisplayApplyDisplayRequestsTest, handlesFlipClientTarget) {
    mDisplay->applyDisplayRequests(hal::DisplayRequest::FLIP_CLIENT_TARGET);

    auto& state = mDisplay->getState();
    EXPECT_TRUE(state.flipClientTarget);
}

TEST_F(DisplayApplyDisplayRequestsTest, handlesWriteClientTargetToOutput) {
    mDisplay->applyDisplayRequests(hal::DisplayRequest::WRITE_CLIENT_TARGET_TO_OUTPUT);

    auto& state = mDisplay->getState();
    EXPECT_FALSE(state.flipClientTarget);
}

TEST_F(DisplayApplyDisplayRequestsTest, handlesAllRequestFlagsSet) {
    mDisplay->applyDisplayRequests(static_cast<hal::DisplayRequest>(~0));

    auto& state = mDisplay->getState();
    EXPECT_TRUE(state.flipClientTarget);
}

/*
 * Display::applyLayerRequestsToLayers()
 */

using DisplayApplyLayerRequestsToLayersTest = DisplayWithLayersTestCommon;

TEST_F(DisplayApplyLayerRequestsToLayersTest, preparesAllLayers) {
    EXPECT_CALL(*mLayer1.outputLayer, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer2.outputLayer, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer3.outputLayer, prepareForDeviceLayerRequests()).Times(1);

    mDisplay->applyLayerRequestsToLayers(impl::Display::LayerRequests());
}

TEST_F(DisplayApplyLayerRequestsToLayersTest, appliesDeviceLayerRequests) {
    EXPECT_CALL(*mLayer1.outputLayer, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer2.outputLayer, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer3.outputLayer, prepareForDeviceLayerRequests()).Times(1);

    EXPECT_CALL(*mLayer1.outputLayer,
                applyDeviceLayerRequest(Hwc2::IComposerClient::LayerRequest::CLEAR_CLIENT_TARGET))
            .Times(1);

    mDisplay->applyLayerRequestsToLayers(impl::Display::LayerRequests{
            {&mLayer1.hwc2Layer, hal::LayerRequest::CLEAR_CLIENT_TARGET},
            {&hwc2LayerUnknown, hal::LayerRequest::CLEAR_CLIENT_TARGET},
    });
}

/*
 * Display::applyClientTargetRequests()
 */

using DisplayApplyClientTargetRequests = DisplayWithLayersTestCommon;

TEST_F(DisplayApplyLayerRequestsToLayersTest, applyClientTargetRequests) {
    static constexpr float kWhitePointNits = 800.f;

    Display::ClientTargetProperty clientTargetProperty = {
            .clientTargetProperty =
                    {
                            .pixelFormat =
                                    aidl::android::hardware::graphics::common::PixelFormat::RGB_565,
                            .dataspace = aidl::android::hardware::graphics::common::Dataspace::
                                    STANDARD_BT470M,
                    },
            .brightness = kWhitePointNits,
            .dimmingStage = aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF,
    };

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    mDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    EXPECT_CALL(*renderSurface,
                setBufferPixelFormat(static_cast<ui::PixelFormat>(
                        clientTargetProperty.clientTargetProperty.pixelFormat)));
    EXPECT_CALL(*renderSurface,
                setBufferDataspace(static_cast<ui::Dataspace>(
                        clientTargetProperty.clientTargetProperty.dataspace)));
    mDisplay->applyClientTargetRequests(clientTargetProperty);

    auto& state = mDisplay->getState();
    EXPECT_EQ(clientTargetProperty.clientTargetProperty.dataspace,
              static_cast<aidl::android::hardware::graphics::common::Dataspace>(state.dataspace));
    EXPECT_EQ(kWhitePointNits, state.clientTargetBrightness);
    EXPECT_EQ(aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF,
              state.clientTargetDimmingStage);
}

/*
 * Display::presentFrame()
 */

using DisplayPresentAndGetFrameFencesTest = DisplayWithLayersTestCommon;

TEST_F(DisplayPresentAndGetFrameFencesTest, returnsNoFencesOnGpuDisplay) {
    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    auto gpuDisplay{impl::createDisplay(mCompositionEngine, args)};

    auto result = gpuDisplay->presentFrame();

    ASSERT_TRUE(result.presentFence.get());
    EXPECT_FALSE(result.presentFence->isValid());
    EXPECT_EQ(0u, result.layerFences.size());
}

TEST_F(DisplayPresentAndGetFrameFencesTest, returnsPresentAndLayerFences) {
    sp<Fence> presentFence = sp<Fence>::make();
    sp<Fence> layer1Fence = sp<Fence>::make();
    sp<Fence> layer2Fence = sp<Fence>::make();

    EXPECT_CALL(mHwComposer, presentAndGetReleaseFences(HalDisplayId(DEFAULT_DISPLAY_ID), _))
            .Times(1);
    EXPECT_CALL(mHwComposer, getPresentFence(HalDisplayId(DEFAULT_DISPLAY_ID)))
            .WillOnce(Return(presentFence));
    EXPECT_CALL(mHwComposer,
                getLayerReleaseFence(HalDisplayId(DEFAULT_DISPLAY_ID), &mLayer1.hwc2Layer))
            .WillOnce(Return(layer1Fence));
    EXPECT_CALL(mHwComposer,
                getLayerReleaseFence(HalDisplayId(DEFAULT_DISPLAY_ID), &mLayer2.hwc2Layer))
            .WillOnce(Return(layer2Fence));
    EXPECT_CALL(mHwComposer, clearReleaseFences(HalDisplayId(DEFAULT_DISPLAY_ID))).Times(1);

    auto result = mDisplay->presentFrame();

    EXPECT_EQ(presentFence, result.presentFence);

    EXPECT_EQ(2u, result.layerFences.size());
    ASSERT_EQ(1u, result.layerFences.count(&mLayer1.hwc2Layer));
    EXPECT_EQ(layer1Fence, result.layerFences[&mLayer1.hwc2Layer]);
    ASSERT_EQ(1u, result.layerFences.count(&mLayer2.hwc2Layer));
    EXPECT_EQ(layer2Fence, result.layerFences[&mLayer2.hwc2Layer]);
}

/*
 * Display::setExpensiveRenderingExpected()
 */

using DisplaySetExpensiveRenderingExpectedTest = DisplayWithLayersTestCommon;

TEST_F(DisplaySetExpensiveRenderingExpectedTest, forwardsToPowerAdvisor) {
    EXPECT_CALL(mPowerAdvisor, setExpensiveRenderingExpected(DEFAULT_DISPLAY_ID, true)).Times(1);
    mDisplay->setExpensiveRenderingExpected(true);

    EXPECT_CALL(mPowerAdvisor, setExpensiveRenderingExpected(DEFAULT_DISPLAY_ID, false)).Times(1);
    mDisplay->setExpensiveRenderingExpected(false);
}

/*
 * Display::finishFrame()
 */

using DisplayFinishFrameTest = DisplayWithLayersTestCommon;

TEST_F(DisplayFinishFrameTest, doesNotSkipCompositionIfNotDirtyOnHwcDisplay) {
    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    mDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect no calls to queueBuffer if composition was skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_, _)).Times(1);

    // Expect a call to signal no expensive rendering since there is no client composition.
    EXPECT_CALL(mPowerAdvisor, setExpensiveRenderingExpected(DEFAULT_DISPLAY_ID, false));

    mDisplay->editState().isEnabled = true;
    mDisplay->editState().usesClientComposition = false;
    mDisplay->editState().layerStackSpace.setContent(Rect(0, 0, 1, 1));
    mDisplay->editState().dirtyRegion = Region::INVALID_REGION;

    mDisplay->finishFrame(std::move(mResultWithBuffer));
}

TEST_F(DisplayFinishFrameTest, skipsCompositionIfNotDirty) {
    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    std::shared_ptr<impl::Display> gpuDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    gpuDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect no calls to queueBuffer if composition was skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_, _)).Times(0);
    EXPECT_CALL(*renderSurface, beginFrame(false));

    gpuDisplay->editState().isEnabled = true;
    gpuDisplay->editState().usesClientComposition = false;
    gpuDisplay->editState().layerStackSpace.setContent(Rect(0, 0, 1, 1));
    gpuDisplay->editState().dirtyRegion = Region::INVALID_REGION;
    gpuDisplay->editState().lastCompositionHadVisibleLayers = true;

    gpuDisplay->beginFrame();
    gpuDisplay->finishFrame(std::move(mResultWithoutBuffer));
}

TEST_F(DisplayFinishFrameTest, skipsCompositionIfEmpty) {
    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    std::shared_ptr<impl::Display> gpuDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    gpuDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect no calls to queueBuffer if composition was skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_, _)).Times(0);
    EXPECT_CALL(*renderSurface, beginFrame(false));

    gpuDisplay->editState().isEnabled = true;
    gpuDisplay->editState().usesClientComposition = false;
    gpuDisplay->editState().layerStackSpace.setContent(Rect(0, 0, 1, 1));
    gpuDisplay->editState().dirtyRegion = Region(Rect(0, 0, 1, 1));
    gpuDisplay->editState().lastCompositionHadVisibleLayers = false;

    gpuDisplay->beginFrame();
    gpuDisplay->finishFrame(std::move(mResultWithoutBuffer));
}

TEST_F(DisplayFinishFrameTest, performsCompositionIfDirtyAndNotEmpty) {
    auto args = getDisplayCreationArgsForGpuVirtualDisplay();
    std::shared_ptr<impl::Display> gpuDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    gpuDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect a single call to queueBuffer when composition is not skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_, _)).Times(1);
    EXPECT_CALL(*renderSurface, beginFrame(true));

    gpuDisplay->editState().isEnabled = true;
    gpuDisplay->editState().usesClientComposition = false;
    gpuDisplay->editState().layerStackSpace.setContent(Rect(0, 0, 1, 1));
    gpuDisplay->editState().dirtyRegion = Region(Rect(0, 0, 1, 1));
    gpuDisplay->editState().lastCompositionHadVisibleLayers = true;

    gpuDisplay->beginFrame();
    gpuDisplay->finishFrame(std::move(mResultWithBuffer));
}

/*
 * Display functional tests
 */

struct DisplayFunctionalTest : public testing::Test {
    class Display : public impl::Display {
    public:
        using impl::Display::injectOutputLayerForTest;
        virtual void injectOutputLayerForTest(std::unique_ptr<compositionengine::OutputLayer>) = 0;
    };

    DisplayFunctionalTest() {
        EXPECT_CALL(mCompositionEngine, getHwComposer()).WillRepeatedly(ReturnRef(mHwComposer));
        mDisplay = createDisplay();
        mRenderSurface = createRenderSurface();
        mDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    NiceMock<android::mock::HWComposer> mHwComposer;
    NiceMock<Hwc2::mock::PowerAdvisor> mPowerAdvisor;
    NiceMock<mock::CompositionEngine> mCompositionEngine;
    sp<mock::NativeWindow> mNativeWindow = sp<NiceMock<mock::NativeWindow>>::make();
    sp<mock::DisplaySurface> mDisplaySurface = sp<NiceMock<mock::DisplaySurface>>::make();
    std::shared_ptr<Display> mDisplay;
    impl::RenderSurface* mRenderSurface;

    std::shared_ptr<Display> createDisplay() {
        return impl::createDisplayTemplated<Display>(mCompositionEngine,
                                                     DisplayCreationArgsBuilder()
                                                             .setId(DEFAULT_DISPLAY_ID)
                                                             .setPixels(DEFAULT_RESOLUTION)
                                                             .setIsSecure(true)
                                                             .setPowerAdvisor(&mPowerAdvisor)
                                                             .build());
        ;
    }

    impl::RenderSurface* createRenderSurface() {
        return new impl::RenderSurface{mCompositionEngine, *mDisplay,
                                       RenderSurfaceCreationArgsBuilder()
                                               .setDisplayWidth(DEFAULT_RESOLUTION.width)
                                               .setDisplayHeight(DEFAULT_RESOLUTION.height)
                                               .setNativeWindow(mNativeWindow)
                                               .setDisplaySurface(mDisplaySurface)
                                               .build()};
    }
};

TEST_F(DisplayFunctionalTest, presentFrameAndReleaseLayersCriticalCallsAreOrdered) {
    InSequence seq;

    mDisplay->editState().isEnabled = true;

    EXPECT_CALL(mHwComposer, presentAndGetReleaseFences(_, _));
    EXPECT_CALL(*mDisplaySurface, onFrameCommitted());
    constexpr bool kFlushEvenWhenDisabled = false;
    mDisplay->presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

} // namespace
} // namespace android::compositionengine
