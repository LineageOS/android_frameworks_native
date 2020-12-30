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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

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
#include <renderengine/mock/RenderEngine.h>
#include <ui/DisplayInfo.h>
#include <ui/Rect.h>

#include "MockHWC2.h"
#include "MockHWComposer.h"
#include "MockPowerAdvisor.h"

namespace android::compositionengine {
namespace {

namespace hal = android::hardware::graphics::composer::hal;

using testing::_;
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

constexpr PhysicalDisplayId DEFAULT_DISPLAY_ID = PhysicalDisplayId{42};
// TODO(b/160679868) Use VirtualDisplayId
constexpr PhysicalDisplayId VIRTUAL_DISPLAY_ID = PhysicalDisplayId{43};
constexpr int32_t DEFAULT_DISPLAY_WIDTH = 1920;
constexpr int32_t DEFAULT_DISPLAY_HEIGHT = 1080;
constexpr int32_t DEFAULT_LAYER_STACK = 123;

struct Layer {
    Layer() {
        EXPECT_CALL(*outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE));
        EXPECT_CALL(*outputLayer, getHwcLayer()).WillRepeatedly(Return(&hwc2Layer));
    }

    sp<mock::LayerFE> layerFE = new StrictMock<mock::LayerFE>();
    StrictMock<mock::OutputLayer>* outputLayer = new StrictMock<mock::OutputLayer>();
    StrictMock<HWC2::mock::Layer> hwc2Layer;
};

struct LayerNoHWC2Layer {
    LayerNoHWC2Layer() {
        EXPECT_CALL(*outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE));
        EXPECT_CALL(*outputLayer, getHwcLayer()).WillRepeatedly(Return(nullptr));
    }

    sp<mock::LayerFE> layerFE = new StrictMock<mock::LayerFE>();
    StrictMock<mock::OutputLayer>* outputLayer = new StrictMock<mock::OutputLayer>();
};

struct DisplayTestCommon : public testing::Test {
    // Uses the full implementation of a display
    class FullImplDisplay : public impl::Display {
    public:
        using impl::Display::injectOutputLayerForTest;
        virtual void injectOutputLayerForTest(std::unique_ptr<compositionengine::OutputLayer>) = 0;

        using impl::Display::maybeAllocateDisplayIdForVirtualDisplay;
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

        // Mock implementation overrides
        MOCK_CONST_METHOD0(getOutputLayerCount, size_t());
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
    }

    DisplayCreationArgs getDisplayCreationArgsForPhysicalHWCDisplay() {
        return DisplayCreationArgsBuilder()
                .setPhysical({DEFAULT_DISPLAY_ID, DisplayConnectionType::Internal})
                .setPixels({DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT})
                .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                .setIsSecure(true)
                .setLayerStackId(DEFAULT_LAYER_STACK)
                .setPowerAdvisor(&mPowerAdvisor)
                .build();
    }

    DisplayCreationArgs getDisplayCreationArgsForNonHWCVirtualDisplay() {
        return DisplayCreationArgsBuilder()
                .setUseHwcVirtualDisplays(false)
                .setGpuVirtualDisplayIdGenerator(mGpuDisplayIdGenerator)
                .setPixels({DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT})
                .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                .setIsSecure(false)
                .setLayerStackId(DEFAULT_LAYER_STACK)
                .setPowerAdvisor(&mPowerAdvisor)
                .build();
    }

    StrictMock<android::mock::HWComposer> mHwComposer;
    StrictMock<Hwc2::mock::PowerAdvisor> mPowerAdvisor;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    sp<mock::NativeWindow> mNativeWindow = new StrictMock<mock::NativeWindow>();
    RandomDisplayIdGenerator<GpuVirtualDisplayId> mGpuDisplayIdGenerator;
};

struct PartialMockDisplayTestCommon : public DisplayTestCommon {
    using Display = DisplayTestCommon::PartialMockDisplay;
    std::shared_ptr<Display> mDisplay =
            createPartialMockDisplay<Display>(mCompositionEngine,
                                              getDisplayCreationArgsForPhysicalHWCDisplay());
};

struct FullDisplayImplTestCommon : public DisplayTestCommon {
    using Display = DisplayTestCommon::FullImplDisplay;
    std::shared_ptr<Display> mDisplay =
            createDisplay<Display>(mCompositionEngine,
                                   getDisplayCreationArgsForPhysicalHWCDisplay());
};

struct DisplayWithLayersTestCommon : public FullDisplayImplTestCommon {
    DisplayWithLayersTestCommon() {
        mDisplay->injectOutputLayerForTest(
                std::unique_ptr<compositionengine::OutputLayer>(mLayer1.outputLayer));
        mDisplay->injectOutputLayerForTest(
                std::unique_ptr<compositionengine::OutputLayer>(mLayer2.outputLayer));
        mDisplay->injectOutputLayerForTest(
                std::unique_ptr<compositionengine::OutputLayer>(mLayer3.outputLayer));
    }

    Layer mLayer1;
    Layer mLayer2;
    LayerNoHWC2Layer mLayer3;
    StrictMock<HWC2::mock::Layer> hwc2LayerUnknown;
    std::shared_ptr<Display> mDisplay =
            createDisplay<Display>(mCompositionEngine,
                                   getDisplayCreationArgsForPhysicalHWCDisplay());
};

/*
 * Basic construction
 */

struct DisplayCreationTest : public DisplayTestCommon {
    using Display = DisplayTestCommon::FullImplDisplay;
};

TEST_F(DisplayCreationTest, createPhysicalInternalDisplay) {
    auto display =
            impl::createDisplay(mCompositionEngine, getDisplayCreationArgsForPhysicalHWCDisplay());
    EXPECT_TRUE(display->isSecure());
    EXPECT_FALSE(display->isVirtual());
    EXPECT_EQ(DEFAULT_DISPLAY_ID, display->getId());
}

TEST_F(DisplayCreationTest, createNonHwcVirtualDisplay) {
    auto display = impl::createDisplay(mCompositionEngine,
                                       getDisplayCreationArgsForNonHWCVirtualDisplay());
    EXPECT_FALSE(display->isSecure());
    EXPECT_TRUE(display->isVirtual());
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(display->getId()));
}

/*
 * Display::setConfiguration()
 */

using DisplaySetConfigurationTest = PartialMockDisplayTestCommon;

TEST_F(DisplaySetConfigurationTest, configuresInternalSecurePhysicalDisplay) {
    mDisplay->setConfiguration(
            DisplayCreationArgsBuilder()
                    .setUseHwcVirtualDisplays(true)
                    .setPhysical({DEFAULT_DISPLAY_ID, DisplayConnectionType::Internal})
                    .setPixels(ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_WIDTH))
                    .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                    .setIsSecure(true)
                    .setLayerStackId(DEFAULT_LAYER_STACK)
                    .setPowerAdvisor(&mPowerAdvisor)
                    .setName(getDisplayNameFromCurrentTest())
                    .build());

    EXPECT_EQ(DEFAULT_DISPLAY_ID, mDisplay->getId());
    EXPECT_TRUE(mDisplay->isSecure());
    EXPECT_FALSE(mDisplay->isVirtual());
    EXPECT_EQ(DEFAULT_LAYER_STACK, mDisplay->getState().layerStackId);
    EXPECT_TRUE(mDisplay->getState().layerStackInternal);
    EXPECT_FALSE(mDisplay->isValid());
}

TEST_F(DisplaySetConfigurationTest, configuresExternalInsecurePhysicalDisplay) {
    mDisplay->setConfiguration(
            DisplayCreationArgsBuilder()
                    .setUseHwcVirtualDisplays(true)
                    .setPhysical({DEFAULT_DISPLAY_ID, DisplayConnectionType::External})
                    .setPixels(ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_WIDTH))
                    .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                    .setIsSecure(false)
                    .setLayerStackId(DEFAULT_LAYER_STACK)
                    .setPowerAdvisor(&mPowerAdvisor)
                    .setName(getDisplayNameFromCurrentTest())
                    .build());

    EXPECT_EQ(DEFAULT_DISPLAY_ID, mDisplay->getId());
    EXPECT_FALSE(mDisplay->isSecure());
    EXPECT_FALSE(mDisplay->isVirtual());
    EXPECT_EQ(DEFAULT_LAYER_STACK, mDisplay->getState().layerStackId);
    EXPECT_FALSE(mDisplay->getState().layerStackInternal);
    EXPECT_FALSE(mDisplay->isValid());
}

TEST_F(DisplaySetConfigurationTest, configuresHwcBackedVirtualDisplay) {
    EXPECT_CALL(mHwComposer,
                allocateVirtualDisplay(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_WIDTH,
                                       Pointee(Eq(static_cast<ui::PixelFormat>(
                                               PIXEL_FORMAT_RGBA_8888)))))
            .WillOnce(Return(VIRTUAL_DISPLAY_ID));

    mDisplay->setConfiguration(
            DisplayCreationArgsBuilder()
                    .setUseHwcVirtualDisplays(true)
                    .setPixels(ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_WIDTH))
                    .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                    .setIsSecure(false)
                    .setLayerStackId(DEFAULT_LAYER_STACK)
                    .setPowerAdvisor(&mPowerAdvisor)
                    .setName(getDisplayNameFromCurrentTest())
                    .build());

    EXPECT_EQ(VIRTUAL_DISPLAY_ID, mDisplay->getId());
    EXPECT_FALSE(mDisplay->isSecure());
    EXPECT_TRUE(mDisplay->isVirtual());
    EXPECT_EQ(DEFAULT_LAYER_STACK, mDisplay->getState().layerStackId);
    EXPECT_FALSE(mDisplay->getState().layerStackInternal);
    EXPECT_FALSE(mDisplay->isValid());
}

TEST_F(DisplaySetConfigurationTest, configuresNonHwcBackedVirtualDisplayIfHwcAllocationFails) {
    EXPECT_CALL(mHwComposer,
                allocateVirtualDisplay(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_WIDTH,
                                       Pointee(Eq(static_cast<ui::PixelFormat>(
                                               PIXEL_FORMAT_RGBA_8888)))))
            .WillOnce(Return(std::nullopt));

    mDisplay->setConfiguration(
            DisplayCreationArgsBuilder()
                    .setUseHwcVirtualDisplays(true)
                    .setGpuVirtualDisplayIdGenerator(mGpuDisplayIdGenerator)
                    .setPixels(ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_WIDTH))
                    .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                    .setIsSecure(false)
                    .setLayerStackId(DEFAULT_LAYER_STACK)
                    .setPowerAdvisor(&mPowerAdvisor)
                    .setName(getDisplayNameFromCurrentTest())
                    .build());

    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(mDisplay->getId()));
    EXPECT_FALSE(mDisplay->isSecure());
    EXPECT_TRUE(mDisplay->isVirtual());
    EXPECT_EQ(DEFAULT_LAYER_STACK, mDisplay->getState().layerStackId);
    EXPECT_FALSE(mDisplay->getState().layerStackInternal);
    EXPECT_FALSE(mDisplay->isValid());
}

TEST_F(DisplaySetConfigurationTest, configuresNonHwcBackedVirtualDisplayIfShouldNotUseHwc) {
    mDisplay->setConfiguration(
            DisplayCreationArgsBuilder()
                    .setUseHwcVirtualDisplays(false)
                    .setGpuVirtualDisplayIdGenerator(mGpuDisplayIdGenerator)
                    .setPixels(ui::Size(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_WIDTH))
                    .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                    .setIsSecure(false)
                    .setLayerStackId(DEFAULT_LAYER_STACK)
                    .setPowerAdvisor(&mPowerAdvisor)
                    .setName(getDisplayNameFromCurrentTest())
                    .build());

    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(mDisplay->getId()));
    EXPECT_FALSE(mDisplay->isSecure());
    EXPECT_TRUE(mDisplay->isVirtual());
    EXPECT_EQ(DEFAULT_LAYER_STACK, mDisplay->getState().layerStackId);
    EXPECT_FALSE(mDisplay->getState().layerStackInternal);
    EXPECT_FALSE(mDisplay->isValid());
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

    EXPECT_CALL(*colorProfile, getTargetDataspace(_, _, _))
            .WillRepeatedly(Return(ui::Dataspace::UNKNOWN));

    // These values are expected to be the initial state.
    ASSERT_EQ(ui::ColorMode::NATIVE, mDisplay->getState().colorMode);
    ASSERT_EQ(ui::Dataspace::UNKNOWN, mDisplay->getState().dataspace);
    ASSERT_EQ(ui::RenderIntent::COLORIMETRIC, mDisplay->getState().renderIntent);
    ASSERT_EQ(ui::Dataspace::UNKNOWN, mDisplay->getState().targetDataspace);

    // Otherwise if the values are unchanged, nothing happens
    mDisplay->setColorProfile(ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                                           ui::RenderIntent::COLORIMETRIC, ui::Dataspace::UNKNOWN});

    EXPECT_EQ(ui::ColorMode::NATIVE, mDisplay->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::COLORIMETRIC, mDisplay->getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay->getState().targetDataspace);

    // Otherwise if the values are different, updates happen
    EXPECT_CALL(*renderSurface, setBufferDataspace(ui::Dataspace::DISPLAY_P3)).Times(1);
    EXPECT_CALL(mHwComposer,
                setActiveColorMode(DEFAULT_DISPLAY_ID, ui::ColorMode::DISPLAY_P3,
                                   ui::RenderIntent::TONE_MAP_COLORIMETRIC))
            .Times(1);

    mDisplay->setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                           ui::RenderIntent::TONE_MAP_COLORIMETRIC,
                                           ui::Dataspace::UNKNOWN});

    EXPECT_EQ(ui::ColorMode::DISPLAY_P3, mDisplay->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mDisplay->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::TONE_MAP_COLORIMETRIC, mDisplay->getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay->getState().targetDataspace);
}

TEST_F(DisplaySetColorModeTest, doesNothingForVirtualDisplay) {
    using ColorProfile = Output::ColorProfile;

    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    std::shared_ptr<impl::Display> virtualDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::DisplayColorProfile* colorProfile = new StrictMock<mock::DisplayColorProfile>();
    virtualDisplay->setDisplayColorProfileForTest(
            std::unique_ptr<DisplayColorProfile>(colorProfile));

    EXPECT_CALL(*colorProfile,
                getTargetDataspace(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                   ui::Dataspace::UNKNOWN))
            .WillOnce(Return(ui::Dataspace::UNKNOWN));

    virtualDisplay->setColorProfile(
            ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                         ui::RenderIntent::TONE_MAP_COLORIMETRIC, ui::Dataspace::UNKNOWN});

    EXPECT_EQ(ui::ColorMode::NATIVE, virtualDisplay->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, virtualDisplay->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::COLORIMETRIC, virtualDisplay->getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, virtualDisplay->getState().targetDataspace);
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
    mDisplay->createRenderSurface(RenderSurfaceCreationArgs{640, 480, mNativeWindow, nullptr});
    EXPECT_TRUE(mDisplay->getRenderSurface() != nullptr);
}

/*
 * Display::createOutputLayer()
 */

using DisplayCreateOutputLayerTest = FullDisplayImplTestCommon;

TEST_F(DisplayCreateOutputLayerTest, setsHwcLayer) {
    sp<mock::LayerFE> layerFE = new StrictMock<mock::LayerFE>();
    StrictMock<HWC2::mock::Layer> hwcLayer;

    EXPECT_CALL(mHwComposer, createLayer(HalDisplayId(DEFAULT_DISPLAY_ID)))
            .WillOnce(Return(&hwcLayer));

    auto outputLayer = mDisplay->createOutputLayer(layerFE);

    EXPECT_EQ(&hwcLayer, outputLayer->getHwcLayer());

    EXPECT_CALL(mHwComposer, destroyLayer(HalDisplayId(DEFAULT_DISPLAY_ID), &hwcLayer));
    outputLayer.reset();
}

/*
 * Display::setReleasedLayers()
 */

using DisplaySetReleasedLayersTest = DisplayWithLayersTestCommon;

TEST_F(DisplaySetReleasedLayersTest, doesNothingIfNotHwcDisplay) {
    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    std::shared_ptr<impl::Display> nonHwcDisplay = impl::createDisplay(mCompositionEngine, args);

    sp<mock::LayerFE> layerXLayerFE = new StrictMock<mock::LayerFE>();

    {
        Output::ReleasedLayers releasedLayers;
        releasedLayers.emplace_back(layerXLayerFE);
        nonHwcDisplay->setReleasedLayers(std::move(releasedLayers));
    }

    CompositionRefreshArgs refreshArgs;
    refreshArgs.layersWithQueuedFrames.push_back(layerXLayerFE);

    nonHwcDisplay->setReleasedLayers(refreshArgs);

    const auto& releasedLayers = nonHwcDisplay->getReleasedLayersForTest();
    ASSERT_EQ(1, releasedLayers.size());
}

TEST_F(DisplaySetReleasedLayersTest, doesNothingIfNoLayersWithQueuedFrames) {
    sp<mock::LayerFE> layerXLayerFE = new StrictMock<mock::LayerFE>();

    {
        Output::ReleasedLayers releasedLayers;
        releasedLayers.emplace_back(layerXLayerFE);
        mDisplay->setReleasedLayers(std::move(releasedLayers));
    }

    CompositionRefreshArgs refreshArgs;
    mDisplay->setReleasedLayers(refreshArgs);

    const auto& releasedLayers = mDisplay->getReleasedLayersForTest();
    ASSERT_EQ(1, releasedLayers.size());
}

TEST_F(DisplaySetReleasedLayersTest, setReleasedLayers) {
    sp<mock::LayerFE> unknownLayer = new StrictMock<mock::LayerFE>();

    CompositionRefreshArgs refreshArgs;
    refreshArgs.layersWithQueuedFrames.push_back(mLayer1.layerFE);
    refreshArgs.layersWithQueuedFrames.push_back(mLayer2.layerFE);
    refreshArgs.layersWithQueuedFrames.push_back(unknownLayer);

    mDisplay->setReleasedLayers(refreshArgs);

    const auto& releasedLayers = mDisplay->getReleasedLayersForTest();
    ASSERT_EQ(2, releasedLayers.size());
    ASSERT_EQ(mLayer1.layerFE.get(), releasedLayers[0].promote().get());
    ASSERT_EQ(mLayer2.layerFE.get(), releasedLayers[1].promote().get());
}

/*
 * Display::chooseCompositionStrategy()
 */

using DisplayChooseCompositionStrategyTest = PartialMockDisplayTestCommon;

TEST_F(DisplayChooseCompositionStrategyTest, takesEarlyOutIfNotAHwcDisplay) {
    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    std::shared_ptr<Display> nonHwcDisplay =
            createPartialMockDisplay<Display>(mCompositionEngine, args);
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(nonHwcDisplay->getId()));

    nonHwcDisplay->chooseCompositionStrategy();

    auto& state = nonHwcDisplay->getState();
    EXPECT_TRUE(state.usesClientComposition);
    EXPECT_FALSE(state.usesDeviceComposition);
}

TEST_F(DisplayChooseCompositionStrategyTest, takesEarlyOutOnHwcError) {
    EXPECT_CALL(*mDisplay, anyLayersRequireClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer,
                getDeviceCompositionChanges(HalDisplayId(DEFAULT_DISPLAY_ID), false, _))
            .WillOnce(Return(INVALID_OPERATION));

    mDisplay->chooseCompositionStrategy();

    auto& state = mDisplay->getState();
    EXPECT_TRUE(state.usesClientComposition);
    EXPECT_FALSE(state.usesDeviceComposition);
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

    EXPECT_CALL(mHwComposer, getDeviceCompositionChanges(HalDisplayId(DEFAULT_DISPLAY_ID), true, _))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mDisplay, allLayersRequireClientComposition()).WillOnce(Return(false));

    mDisplay->chooseCompositionStrategy();

    auto& state = mDisplay->getState();
    EXPECT_FALSE(state.usesClientComposition);
    EXPECT_TRUE(state.usesDeviceComposition);
}

TEST_F(DisplayChooseCompositionStrategyTest, normalOperationWithChanges) {
    android::HWComposer::DeviceRequestedChanges changes{
            {{nullptr, hal::Composition::CLIENT}},
            hal::DisplayRequest::FLIP_CLIENT_TARGET,
            {{nullptr, hal::LayerRequest::CLEAR_CLIENT_TARGET}},
            {hal::PixelFormat::RGBA_8888, hal::Dataspace::UNKNOWN},
    };

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

    EXPECT_CALL(mHwComposer, getDeviceCompositionChanges(HalDisplayId(DEFAULT_DISPLAY_ID), true, _))
            .WillOnce(DoAll(SetArgPointee<2>(changes), Return(NO_ERROR)));
    EXPECT_CALL(*mDisplay, applyChangedTypesToLayers(changes.changedTypes)).Times(1);
    EXPECT_CALL(*mDisplay, applyDisplayRequests(changes.displayRequests)).Times(1);
    EXPECT_CALL(*mDisplay, applyLayerRequestsToLayers(changes.layerRequests)).Times(1);
    EXPECT_CALL(*mDisplay, allLayersRequireClientComposition()).WillOnce(Return(false));

    mDisplay->chooseCompositionStrategy();

    auto& state = mDisplay->getState();
    EXPECT_FALSE(state.usesClientComposition);
    EXPECT_TRUE(state.usesDeviceComposition);
}

/*
 * Display::getSkipColorTransform()
 */

using DisplayGetSkipColorTransformTest = DisplayWithLayersTestCommon;

TEST_F(DisplayGetSkipColorTransformTest, checksCapabilityIfNonHwcDisplay) {
    EXPECT_CALL(mHwComposer, hasCapability(hal::Capability::SKIP_CLIENT_COLOR_TRANSFORM))
            .WillOnce(Return(true));
    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    auto nonHwcDisplay{impl::createDisplay(mCompositionEngine, args)};
    EXPECT_TRUE(nonHwcDisplay->getSkipColorTransform());
}

TEST_F(DisplayGetSkipColorTransformTest, checksDisplayCapability) {
    EXPECT_CALL(mHwComposer,
                hasDisplayCapability(HalDisplayId(DEFAULT_DISPLAY_ID),
                                     hal::DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM))
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
    EXPECT_CALL(*mLayer1.outputLayer,
                applyDeviceCompositionTypeChange(Hwc2::IComposerClient::Composition::CLIENT))
            .Times(1);
    EXPECT_CALL(*mLayer2.outputLayer,
                applyDeviceCompositionTypeChange(Hwc2::IComposerClient::Composition::DEVICE))
            .Times(1);

    mDisplay->applyChangedTypesToLayers(impl::Display::ChangedTypes{
            {&mLayer1.hwc2Layer, hal::Composition::CLIENT},
            {&mLayer2.hwc2Layer, hal::Composition::DEVICE},
            {&hwc2LayerUnknown, hal::Composition::SOLID_COLOR},
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
 * Display::presentAndGetFrameFences()
 */

using DisplayPresentAndGetFrameFencesTest = DisplayWithLayersTestCommon;

TEST_F(DisplayPresentAndGetFrameFencesTest, returnsNoFencesOnNonHwcDisplay) {
    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    auto nonHwcDisplay{impl::createDisplay(mCompositionEngine, args)};

    auto result = nonHwcDisplay->presentAndGetFrameFences();

    ASSERT_TRUE(result.presentFence.get());
    EXPECT_FALSE(result.presentFence->isValid());
    EXPECT_EQ(0u, result.layerFences.size());
}

TEST_F(DisplayPresentAndGetFrameFencesTest, returnsPresentAndLayerFences) {
    sp<Fence> presentFence = new Fence();
    sp<Fence> layer1Fence = new Fence();
    sp<Fence> layer2Fence = new Fence();

    EXPECT_CALL(mHwComposer, presentAndGetReleaseFences(HalDisplayId(DEFAULT_DISPLAY_ID))).Times(1);
    EXPECT_CALL(mHwComposer, getPresentFence(HalDisplayId(DEFAULT_DISPLAY_ID)))
            .WillOnce(Return(presentFence));
    EXPECT_CALL(mHwComposer,
                getLayerReleaseFence(HalDisplayId(DEFAULT_DISPLAY_ID), &mLayer1.hwc2Layer))
            .WillOnce(Return(layer1Fence));
    EXPECT_CALL(mHwComposer,
                getLayerReleaseFence(HalDisplayId(DEFAULT_DISPLAY_ID), &mLayer2.hwc2Layer))
            .WillOnce(Return(layer2Fence));
    EXPECT_CALL(mHwComposer, clearReleaseFences(HalDisplayId(DEFAULT_DISPLAY_ID))).Times(1);

    auto result = mDisplay->presentAndGetFrameFences();

    EXPECT_EQ(presentFence, result.presentFence);

    EXPECT_EQ(2u, result.layerFences.size());
    ASSERT_EQ(1, result.layerFences.count(&mLayer1.hwc2Layer));
    EXPECT_EQ(layer1Fence, result.layerFences[&mLayer1.hwc2Layer]);
    ASSERT_EQ(1, result.layerFences.count(&mLayer2.hwc2Layer));
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
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(1);

    // Expect a call to signal no expensive rendering since there is no client composition.
    EXPECT_CALL(mPowerAdvisor, setExpensiveRenderingExpected(DEFAULT_DISPLAY_ID, false));

    mDisplay->editState().isEnabled = true;
    mDisplay->editState().usesClientComposition = false;
    mDisplay->editState().layerStackSpace.content = Rect(0, 0, 1, 1);
    mDisplay->editState().dirtyRegion = Region::INVALID_REGION;

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = false;

    mDisplay->finishFrame(refreshArgs);
}

TEST_F(DisplayFinishFrameTest, skipsCompositionIfNotDirty) {
    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    std::shared_ptr<impl::Display> nonHwcDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    nonHwcDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect no calls to queueBuffer if composition was skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(0);

    nonHwcDisplay->editState().isEnabled = true;
    nonHwcDisplay->editState().usesClientComposition = false;
    nonHwcDisplay->editState().layerStackSpace.content = Rect(0, 0, 1, 1);
    nonHwcDisplay->editState().dirtyRegion = Region::INVALID_REGION;

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = false;

    nonHwcDisplay->finishFrame(refreshArgs);
}

TEST_F(DisplayFinishFrameTest, performsCompositionIfDirty) {
    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    std::shared_ptr<impl::Display> nonHwcDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    nonHwcDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect a single call to queueBuffer when composition is not skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(1);

    nonHwcDisplay->editState().isEnabled = true;
    nonHwcDisplay->editState().usesClientComposition = false;
    nonHwcDisplay->editState().layerStackSpace.content = Rect(0, 0, 1, 1);
    nonHwcDisplay->editState().dirtyRegion = Region(Rect(0, 0, 1, 1));

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = false;

    nonHwcDisplay->finishFrame(refreshArgs);
}

TEST_F(DisplayFinishFrameTest, performsCompositionIfRepaintEverything) {
    auto args = getDisplayCreationArgsForNonHWCVirtualDisplay();
    std::shared_ptr<impl::Display> nonHwcDisplay = impl::createDisplay(mCompositionEngine, args);

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    nonHwcDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect a single call to queueBuffer when composition is not skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(1);

    nonHwcDisplay->editState().isEnabled = true;
    nonHwcDisplay->editState().usesClientComposition = false;
    nonHwcDisplay->editState().layerStackSpace.content = Rect(0, 0, 1, 1);
    nonHwcDisplay->editState().dirtyRegion = Region::INVALID_REGION;

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = true;

    nonHwcDisplay->finishFrame(refreshArgs);
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

        mDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    NiceMock<android::mock::HWComposer> mHwComposer;
    NiceMock<Hwc2::mock::PowerAdvisor> mPowerAdvisor;
    NiceMock<mock::CompositionEngine> mCompositionEngine;
    sp<mock::NativeWindow> mNativeWindow = new NiceMock<mock::NativeWindow>();
    sp<mock::DisplaySurface> mDisplaySurface = new NiceMock<mock::DisplaySurface>();
    std::shared_ptr<Display> mDisplay = impl::createDisplayTemplated<
            Display>(mCompositionEngine,
                     DisplayCreationArgsBuilder()
                             .setPhysical({DEFAULT_DISPLAY_ID, DisplayConnectionType::Internal})
                             .setPixels({DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT})
                             .setPixelFormat(static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888))
                             .setIsSecure(true)
                             .setLayerStackId(DEFAULT_LAYER_STACK)
                             .setPowerAdvisor(&mPowerAdvisor)
                             .build()

    );
    impl::RenderSurface* mRenderSurface =
            new impl::RenderSurface{mCompositionEngine, *mDisplay,
                                    RenderSurfaceCreationArgs{DEFAULT_DISPLAY_WIDTH,
                                                              DEFAULT_DISPLAY_HEIGHT, mNativeWindow,
                                                              mDisplaySurface}};
};

TEST_F(DisplayFunctionalTest, postFramebufferCriticalCallsAreOrdered) {
    InSequence seq;

    mDisplay->editState().isEnabled = true;

    EXPECT_CALL(mHwComposer, presentAndGetReleaseFences(_));
    EXPECT_CALL(*mDisplaySurface, onFrameCommitted());

    mDisplay->postFramebuffer();
}

} // namespace
} // namespace android::compositionengine

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"