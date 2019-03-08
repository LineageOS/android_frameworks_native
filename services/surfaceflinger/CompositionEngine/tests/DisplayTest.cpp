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
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/Layer.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/NativeWindow.h>
#include <compositionengine/mock/OutputLayer.h>
#include <compositionengine/mock/RenderSurface.h>
#include <gtest/gtest.h>

#include "MockHWC2.h"
#include "MockHWComposer.h"
#include "MockPowerAdvisor.h"

namespace android::compositionengine {
namespace {

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::ReturnRef;
using testing::Sequence;
using testing::SetArgPointee;
using testing::StrictMock;

constexpr DisplayId DEFAULT_DISPLAY_ID = DisplayId{42};

struct DisplayTest : public testing::Test {
    DisplayTest() {
        EXPECT_CALL(mCompositionEngine, getHwComposer()).WillRepeatedly(ReturnRef(mHwComposer));
        EXPECT_CALL(*mLayer1, getHwcLayer()).WillRepeatedly(Return(&mHWC2Layer1));
        EXPECT_CALL(*mLayer2, getHwcLayer()).WillRepeatedly(Return(&mHWC2Layer2));
        EXPECT_CALL(*mLayer3, getHwcLayer()).WillRepeatedly(Return(nullptr));

        std::vector<std::unique_ptr<OutputLayer>> layers;
        layers.emplace_back(mLayer1);
        layers.emplace_back(mLayer2);
        layers.emplace_back(mLayer3);
        mDisplay.setOutputLayersOrderedByZ(std::move(layers));
    }

    StrictMock<android::mock::HWComposer> mHwComposer;
    StrictMock<Hwc2::mock::PowerAdvisor> mPowerAdvisor;
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    sp<mock::NativeWindow> mNativeWindow = new StrictMock<mock::NativeWindow>();
    StrictMock<HWC2::mock::Layer> mHWC2Layer1;
    StrictMock<HWC2::mock::Layer> mHWC2Layer2;
    StrictMock<HWC2::mock::Layer> mHWC2LayerUnknown;
    mock::OutputLayer* mLayer1 = new StrictMock<mock::OutputLayer>();
    mock::OutputLayer* mLayer2 = new StrictMock<mock::OutputLayer>();
    mock::OutputLayer* mLayer3 = new StrictMock<mock::OutputLayer>();
    impl::Display mDisplay{mCompositionEngine,
                           DisplayCreationArgsBuilder()
                                   .setDisplayId(DEFAULT_DISPLAY_ID)
                                   .setPowerAdvisor(&mPowerAdvisor)
                                   .build()};
};

/*
 * Basic construction
 */

TEST_F(DisplayTest, canInstantiateDisplay) {
    {
        constexpr DisplayId display1 = DisplayId{123u};
        auto display =
                impl::createDisplay(mCompositionEngine,
                                    DisplayCreationArgsBuilder().setDisplayId(display1).build());
        EXPECT_FALSE(display->isSecure());
        EXPECT_FALSE(display->isVirtual());
        EXPECT_EQ(display1, display->getId());
    }

    {
        constexpr DisplayId display2 = DisplayId{546u};
        auto display = impl::createDisplay(mCompositionEngine,
                                           DisplayCreationArgsBuilder()
                                                   .setIsSecure(true)
                                                   .setDisplayId(display2)
                                                   .build());
        EXPECT_TRUE(display->isSecure());
        EXPECT_FALSE(display->isVirtual());
        EXPECT_EQ(display2, display->getId());
    }

    {
        constexpr DisplayId display3 = DisplayId{789u};
        auto display = impl::createDisplay(mCompositionEngine,
                                           DisplayCreationArgsBuilder()
                                                   .setIsVirtual(true)
                                                   .setDisplayId(display3)
                                                   .build());
        EXPECT_FALSE(display->isSecure());
        EXPECT_TRUE(display->isVirtual());
        EXPECT_EQ(display3, display->getId());
    }
}

/*
 * Display::disconnect()
 */

TEST_F(DisplayTest, disconnectDisconnectsDisplay) {
    // The first call to disconnect will disconnect the display with the HWC and
    // set mHwcId to -1.
    EXPECT_CALL(mHwComposer, disconnectDisplay(DEFAULT_DISPLAY_ID)).Times(1);
    mDisplay.disconnect();
    EXPECT_FALSE(mDisplay.getId());

    // Subsequent calls will do nothing,
    EXPECT_CALL(mHwComposer, disconnectDisplay(DEFAULT_DISPLAY_ID)).Times(0);
    mDisplay.disconnect();
    EXPECT_FALSE(mDisplay.getId());
}

/*
 * Display::setColorTransform()
 */

TEST_F(DisplayTest, setColorTransformSetsTransform) {
    // No change does nothing
    CompositionRefreshArgs refreshArgs;
    refreshArgs.colorTransformMatrix = std::nullopt;
    mDisplay.setColorTransform(refreshArgs);

    // Identity matrix sets an identity state value
    const mat4 kIdentity;

    EXPECT_CALL(mHwComposer, setColorTransform(DEFAULT_DISPLAY_ID, kIdentity)).Times(1);

    refreshArgs.colorTransformMatrix = kIdentity;
    mDisplay.setColorTransform(refreshArgs);

    // Non-identity matrix sets a non-identity state value
    const mat4 kNonIdentity = mat4() * 2;

    EXPECT_CALL(mHwComposer, setColorTransform(DEFAULT_DISPLAY_ID, kNonIdentity)).Times(1);

    refreshArgs.colorTransformMatrix = kNonIdentity;
    mDisplay.setColorTransform(refreshArgs);
}

/*
 * Display::setColorMode()
 */

TEST_F(DisplayTest, setColorModeSetsModeUnlessNoChange) {
    using ColorProfile = Output::ColorProfile;

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    mDisplay.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));
    mock::DisplayColorProfile* colorProfile = new StrictMock<mock::DisplayColorProfile>();
    mDisplay.setDisplayColorProfileForTest(std::unique_ptr<DisplayColorProfile>(colorProfile));

    EXPECT_CALL(*colorProfile, getTargetDataspace(_, _, _))
            .WillRepeatedly(Return(ui::Dataspace::UNKNOWN));

    // These values are expected to be the initial state.
    ASSERT_EQ(ui::ColorMode::NATIVE, mDisplay.getState().colorMode);
    ASSERT_EQ(ui::Dataspace::UNKNOWN, mDisplay.getState().dataspace);
    ASSERT_EQ(ui::RenderIntent::COLORIMETRIC, mDisplay.getState().renderIntent);
    ASSERT_EQ(ui::Dataspace::UNKNOWN, mDisplay.getState().targetDataspace);

    // If the set values are unchanged, nothing happens
    mDisplay.setColorProfile(ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                                          ui::RenderIntent::COLORIMETRIC, ui::Dataspace::UNKNOWN});

    EXPECT_EQ(ui::ColorMode::NATIVE, mDisplay.getState().colorMode);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay.getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::COLORIMETRIC, mDisplay.getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay.getState().targetDataspace);

    // Otherwise if the values are different, updates happen
    EXPECT_CALL(*renderSurface, setBufferDataspace(ui::Dataspace::DISPLAY_P3)).Times(1);
    EXPECT_CALL(mHwComposer,
                setActiveColorMode(DEFAULT_DISPLAY_ID, ui::ColorMode::DISPLAY_P3,
                                   ui::RenderIntent::TONE_MAP_COLORIMETRIC))
            .Times(1);

    mDisplay.setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                          ui::RenderIntent::TONE_MAP_COLORIMETRIC,
                                          ui::Dataspace::UNKNOWN});

    EXPECT_EQ(ui::ColorMode::DISPLAY_P3, mDisplay.getState().colorMode);
    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mDisplay.getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::TONE_MAP_COLORIMETRIC, mDisplay.getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay.getState().targetDataspace);
}

TEST_F(DisplayTest, setColorModeDoesNothingForVirtualDisplay) {
    using ColorProfile = Output::ColorProfile;

    impl::Display virtualDisplay{mCompositionEngine,
                                 DisplayCreationArgs{false, true, DEFAULT_DISPLAY_ID}};

    mock::DisplayColorProfile* colorProfile = new StrictMock<mock::DisplayColorProfile>();
    virtualDisplay.setDisplayColorProfileForTest(
            std::unique_ptr<DisplayColorProfile>(colorProfile));

    EXPECT_CALL(*colorProfile,
                getTargetDataspace(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                   ui::Dataspace::UNKNOWN))
            .WillOnce(Return(ui::Dataspace::UNKNOWN));

    virtualDisplay.setColorProfile(
            ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                         ui::RenderIntent::TONE_MAP_COLORIMETRIC, ui::Dataspace::UNKNOWN});

    EXPECT_EQ(ui::ColorMode::NATIVE, virtualDisplay.getState().colorMode);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, virtualDisplay.getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::COLORIMETRIC, virtualDisplay.getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mDisplay.getState().targetDataspace);
}

/*
 * Display::createDisplayColorProfile()
 */

TEST_F(DisplayTest, createDisplayColorProfileSetsDisplayColorProfile) {
    EXPECT_TRUE(mDisplay.getDisplayColorProfile() == nullptr);
    mDisplay.createDisplayColorProfile(
            DisplayColorProfileCreationArgs{false, HdrCapabilities(), 0,
                                            DisplayColorProfileCreationArgs::HwcColorModes()});
    EXPECT_TRUE(mDisplay.getDisplayColorProfile() != nullptr);
}

/*
 * Display::createRenderSurface()
 */

TEST_F(DisplayTest, createRenderSurfaceSetsRenderSurface) {
    EXPECT_CALL(*mNativeWindow, disconnect(NATIVE_WINDOW_API_EGL)).WillRepeatedly(Return(NO_ERROR));
    EXPECT_TRUE(mDisplay.getRenderSurface() == nullptr);
    mDisplay.createRenderSurface(RenderSurfaceCreationArgs{640, 480, mNativeWindow, nullptr});
    EXPECT_TRUE(mDisplay.getRenderSurface() != nullptr);
}

/*
 * Display::createOutputLayer()
 */

TEST_F(DisplayTest, createOutputLayerSetsHwcLayer) {
    sp<mock::LayerFE> layerFE = new StrictMock<mock::LayerFE>();
    auto layer = std::make_shared<StrictMock<mock::Layer>>();
    StrictMock<HWC2::mock::Layer> hwcLayer;

    EXPECT_CALL(mHwComposer, createLayer(DEFAULT_DISPLAY_ID)).WillOnce(Return(&hwcLayer));

    auto outputLayer = mDisplay.createOutputLayer(layer, layerFE);

    EXPECT_EQ(&hwcLayer, outputLayer->getHwcLayer());

    EXPECT_CALL(mHwComposer, destroyLayer(DEFAULT_DISPLAY_ID, &hwcLayer));
    outputLayer.reset();
}

/*
 * Display::chooseCompositionStrategy()
 */

struct DisplayChooseCompositionStrategyTest : public testing::Test {
    struct DisplayPartialMock : public impl::Display {
        DisplayPartialMock(const compositionengine::CompositionEngine& compositionEngine,
                           compositionengine::DisplayCreationArgs&& args)
              : impl::Display(compositionEngine, std::move(args)) {}

        // Sets up the helper functions called by chooseCompositionStrategy to
        // use a mock implementations.
        MOCK_CONST_METHOD0(anyLayersRequireClientComposition, bool());
        MOCK_CONST_METHOD0(allLayersRequireClientComposition, bool());
        MOCK_METHOD1(applyChangedTypesToLayers, void(const impl::Display::ChangedTypes&));
        MOCK_METHOD1(applyDisplayRequests, void(const impl::Display::DisplayRequests&));
        MOCK_METHOD1(applyLayerRequestsToLayers, void(const impl::Display::LayerRequests&));
    };

    DisplayChooseCompositionStrategyTest() {
        EXPECT_CALL(mCompositionEngine, getHwComposer()).WillRepeatedly(ReturnRef(mHwComposer));
    }

    StrictMock<android::mock::HWComposer> mHwComposer;
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<DisplayPartialMock>
            mDisplay{mCompositionEngine,
                     DisplayCreationArgsBuilder().setDisplayId(DEFAULT_DISPLAY_ID).build()};
};

TEST_F(DisplayChooseCompositionStrategyTest, takesEarlyOutIfNotAHwcDisplay) {
    impl::Display nonHwcDisplay{mCompositionEngine, DisplayCreationArgsBuilder().build()};
    EXPECT_FALSE(nonHwcDisplay.getId());

    nonHwcDisplay.chooseCompositionStrategy();

    auto& state = nonHwcDisplay.getState();
    EXPECT_TRUE(state.usesClientComposition);
    EXPECT_FALSE(state.usesDeviceComposition);
}

TEST_F(DisplayChooseCompositionStrategyTest, takesEarlyOutOnHwcError) {
    EXPECT_CALL(mDisplay, anyLayersRequireClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer, getDeviceCompositionChanges(DEFAULT_DISPLAY_ID, false, _))
            .WillOnce(Return(INVALID_OPERATION));

    mDisplay.chooseCompositionStrategy();

    auto& state = mDisplay.getState();
    EXPECT_TRUE(state.usesClientComposition);
    EXPECT_FALSE(state.usesDeviceComposition);
}

TEST_F(DisplayChooseCompositionStrategyTest, normalOperation) {
    // Since two calls are made to anyLayersRequireClientComposition with different return values,
    // use a Sequence to control the matching so the values are returned in a known order.
    Sequence s;
    EXPECT_CALL(mDisplay, anyLayersRequireClientComposition()).InSequence(s).WillOnce(Return(true));
    EXPECT_CALL(mDisplay, anyLayersRequireClientComposition())
            .InSequence(s)
            .WillOnce(Return(false));

    EXPECT_CALL(mHwComposer, getDeviceCompositionChanges(DEFAULT_DISPLAY_ID, true, _))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(mDisplay, allLayersRequireClientComposition()).WillOnce(Return(false));

    mDisplay.chooseCompositionStrategy();

    auto& state = mDisplay.getState();
    EXPECT_FALSE(state.usesClientComposition);
    EXPECT_TRUE(state.usesDeviceComposition);
}

TEST_F(DisplayChooseCompositionStrategyTest, normalOperationWithChanges) {
    android::HWComposer::DeviceRequestedChanges changes{
            {{nullptr, HWC2::Composition::Client}},
            HWC2::DisplayRequest::FlipClientTarget,
            {{nullptr, HWC2::LayerRequest::ClearClientTarget}},
    };

    // Since two calls are made to anyLayersRequireClientComposition with different return values,
    // use a Sequence to control the matching so the values are returned in a known order.
    Sequence s;
    EXPECT_CALL(mDisplay, anyLayersRequireClientComposition()).InSequence(s).WillOnce(Return(true));
    EXPECT_CALL(mDisplay, anyLayersRequireClientComposition())
            .InSequence(s)
            .WillOnce(Return(false));

    EXPECT_CALL(mHwComposer, getDeviceCompositionChanges(DEFAULT_DISPLAY_ID, true, _))
            .WillOnce(DoAll(SetArgPointee<2>(changes), Return(NO_ERROR)));
    EXPECT_CALL(mDisplay, applyChangedTypesToLayers(changes.changedTypes)).Times(1);
    EXPECT_CALL(mDisplay, applyDisplayRequests(changes.displayRequests)).Times(1);
    EXPECT_CALL(mDisplay, applyLayerRequestsToLayers(changes.layerRequests)).Times(1);
    EXPECT_CALL(mDisplay, allLayersRequireClientComposition()).WillOnce(Return(false));

    mDisplay.chooseCompositionStrategy();

    auto& state = mDisplay.getState();
    EXPECT_FALSE(state.usesClientComposition);
    EXPECT_TRUE(state.usesDeviceComposition);
}

/*
 * Display::getSkipColorTransform()
 */

TEST_F(DisplayTest, getSkipColorTransformDoesNothingIfNonHwcDisplay) {
    auto nonHwcDisplay{
            impl::createDisplay(mCompositionEngine, DisplayCreationArgsBuilder().build())};
    EXPECT_FALSE(nonHwcDisplay->getSkipColorTransform());
}

TEST_F(DisplayTest, getSkipColorTransformChecksHwcCapability) {
    EXPECT_CALL(mHwComposer,
                hasDisplayCapability(std::make_optional(DEFAULT_DISPLAY_ID),
                                     HWC2::DisplayCapability::SkipClientColorTransform))
            .WillOnce(Return(true));
    EXPECT_TRUE(mDisplay.getSkipColorTransform());
}

/*
 * Display::anyLayersRequireClientComposition()
 */

TEST_F(DisplayTest, anyLayersRequireClientCompositionReturnsFalse) {
    EXPECT_CALL(*mLayer1, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayer2, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayer3, requiresClientComposition()).WillOnce(Return(false));

    EXPECT_FALSE(mDisplay.anyLayersRequireClientComposition());
}

TEST_F(DisplayTest, anyLayersRequireClientCompositionReturnsTrue) {
    EXPECT_CALL(*mLayer1, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayer2, requiresClientComposition()).WillOnce(Return(true));

    EXPECT_TRUE(mDisplay.anyLayersRequireClientComposition());
}

/*
 * Display::allLayersRequireClientComposition()
 */

TEST_F(DisplayTest, allLayersRequireClientCompositionReturnsTrue) {
    EXPECT_CALL(*mLayer1, requiresClientComposition()).WillOnce(Return(true));
    EXPECT_CALL(*mLayer2, requiresClientComposition()).WillOnce(Return(true));
    EXPECT_CALL(*mLayer3, requiresClientComposition()).WillOnce(Return(true));

    EXPECT_TRUE(mDisplay.allLayersRequireClientComposition());
}

TEST_F(DisplayTest, allLayersRequireClientCompositionReturnsFalse) {
    EXPECT_CALL(*mLayer1, requiresClientComposition()).WillOnce(Return(true));
    EXPECT_CALL(*mLayer2, requiresClientComposition()).WillOnce(Return(false));

    EXPECT_FALSE(mDisplay.allLayersRequireClientComposition());
}

/*
 * Display::applyChangedTypesToLayers()
 */

TEST_F(DisplayTest, applyChangedTypesToLayersTakesEarlyOutIfNoChangedLayers) {
    mDisplay.applyChangedTypesToLayers(impl::Display::ChangedTypes());
}

TEST_F(DisplayTest, applyChangedTypesToLayersAppliesChanges) {
    EXPECT_CALL(*mLayer1,
                applyDeviceCompositionTypeChange(Hwc2::IComposerClient::Composition::CLIENT))
            .Times(1);
    EXPECT_CALL(*mLayer2,
                applyDeviceCompositionTypeChange(Hwc2::IComposerClient::Composition::DEVICE))
            .Times(1);

    mDisplay.applyChangedTypesToLayers(impl::Display::ChangedTypes{
            {&mHWC2Layer1, HWC2::Composition::Client},
            {&mHWC2Layer2, HWC2::Composition::Device},
            {&mHWC2LayerUnknown, HWC2::Composition::SolidColor},
    });
}

/*
 * Display::applyDisplayRequests()
 */

TEST_F(DisplayTest, applyDisplayRequestsToLayersHandlesNoRequests) {
    mDisplay.applyDisplayRequests(static_cast<HWC2::DisplayRequest>(0));

    auto& state = mDisplay.getState();
    EXPECT_FALSE(state.flipClientTarget);
}

TEST_F(DisplayTest, applyDisplayRequestsToLayersHandlesFlipClientTarget) {
    mDisplay.applyDisplayRequests(HWC2::DisplayRequest::FlipClientTarget);

    auto& state = mDisplay.getState();
    EXPECT_TRUE(state.flipClientTarget);
}

TEST_F(DisplayTest, applyDisplayRequestsToLayersHandlesWriteClientTargetToOutput) {
    mDisplay.applyDisplayRequests(HWC2::DisplayRequest::WriteClientTargetToOutput);

    auto& state = mDisplay.getState();
    EXPECT_FALSE(state.flipClientTarget);
}

TEST_F(DisplayTest, applyDisplayRequestsToLayersHandlesAllRequestFlagsSet) {
    mDisplay.applyDisplayRequests(static_cast<HWC2::DisplayRequest>(~0));

    auto& state = mDisplay.getState();
    EXPECT_TRUE(state.flipClientTarget);
}

/*
 * Display::applyLayerRequestsToLayers()
 */

TEST_F(DisplayTest, applyLayerRequestsToLayersPreparesAllLayers) {
    EXPECT_CALL(*mLayer1, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer2, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer3, prepareForDeviceLayerRequests()).Times(1);

    mDisplay.applyLayerRequestsToLayers(impl::Display::LayerRequests());
}

TEST_F(DisplayTest, applyLayerRequestsToLayers2) {
    EXPECT_CALL(*mLayer1, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer2, prepareForDeviceLayerRequests()).Times(1);
    EXPECT_CALL(*mLayer3, prepareForDeviceLayerRequests()).Times(1);

    EXPECT_CALL(*mLayer1,
                applyDeviceLayerRequest(Hwc2::IComposerClient::LayerRequest::CLEAR_CLIENT_TARGET))
            .Times(1);

    mDisplay.applyLayerRequestsToLayers(impl::Display::LayerRequests{
            {&mHWC2Layer1, HWC2::LayerRequest::ClearClientTarget},
            {&mHWC2LayerUnknown, HWC2::LayerRequest::ClearClientTarget},
    });
}

/*
 * Display::presentAndGetFrameFences()
 */

TEST_F(DisplayTest, presentAndGetFrameFencesReturnsNoFencesOnNonHwcDisplay) {
    auto nonHwcDisplay{
            impl::createDisplay(mCompositionEngine, DisplayCreationArgsBuilder().build())};

    auto result = nonHwcDisplay->presentAndGetFrameFences();

    ASSERT_TRUE(result.presentFence.get());
    EXPECT_FALSE(result.presentFence->isValid());
    EXPECT_EQ(0u, result.layerFences.size());
}

TEST_F(DisplayTest, presentAndGetFrameFencesReturnsPresentAndLayerFences) {
    sp<Fence> presentFence = new Fence();
    sp<Fence> layer1Fence = new Fence();
    sp<Fence> layer2Fence = new Fence();

    EXPECT_CALL(mHwComposer, presentAndGetReleaseFences(DEFAULT_DISPLAY_ID)).Times(1);
    EXPECT_CALL(mHwComposer, getPresentFence(DEFAULT_DISPLAY_ID)).WillOnce(Return(presentFence));
    EXPECT_CALL(mHwComposer, getLayerReleaseFence(DEFAULT_DISPLAY_ID, &mHWC2Layer1))
            .WillOnce(Return(layer1Fence));
    EXPECT_CALL(mHwComposer, getLayerReleaseFence(DEFAULT_DISPLAY_ID, &mHWC2Layer2))
            .WillOnce(Return(layer2Fence));
    EXPECT_CALL(mHwComposer, clearReleaseFences(DEFAULT_DISPLAY_ID)).Times(1);

    auto result = mDisplay.presentAndGetFrameFences();

    EXPECT_EQ(presentFence, result.presentFence);

    EXPECT_EQ(2u, result.layerFences.size());
    ASSERT_EQ(1, result.layerFences.count(&mHWC2Layer1));
    EXPECT_EQ(layer1Fence, result.layerFences[&mHWC2Layer1]);
    ASSERT_EQ(1, result.layerFences.count(&mHWC2Layer2));
    EXPECT_EQ(layer2Fence, result.layerFences[&mHWC2Layer2]);
}

/*
 * Display::setExpensiveRenderingExpected()
 */

TEST_F(DisplayTest, setExpensiveRenderingExpectedForwardsToPowerAdvisor) {
    EXPECT_CALL(mPowerAdvisor, setExpensiveRenderingExpected(DEFAULT_DISPLAY_ID, true)).Times(1);
    mDisplay.setExpensiveRenderingExpected(true);

    EXPECT_CALL(mPowerAdvisor, setExpensiveRenderingExpected(DEFAULT_DISPLAY_ID, false)).Times(1);
    mDisplay.setExpensiveRenderingExpected(false);
}

/*
 * Display::finishFrame()
 */

TEST_F(DisplayTest, finishFrameDoesNotSkipCompositionIfNotDirtyOnHwcDisplay) {
    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    mDisplay.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect no calls to queueBuffer if composition was skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(1);

    mDisplay.editState().isEnabled = true;
    mDisplay.editState().usesClientComposition = false;
    mDisplay.editState().viewport = Rect(0, 0, 1, 1);
    mDisplay.editState().dirtyRegion = Region::INVALID_REGION;

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = false;

    mDisplay.finishFrame(refreshArgs);
}

TEST_F(DisplayTest, finishFrameSkipsCompositionIfNotDirty) {
    std::shared_ptr<impl::Display> nonHwcDisplay{
            impl::createDisplay(mCompositionEngine, DisplayCreationArgsBuilder().build())};

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    nonHwcDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect no calls to queueBuffer if composition was skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(0);

    nonHwcDisplay->editState().isEnabled = true;
    nonHwcDisplay->editState().usesClientComposition = false;
    nonHwcDisplay->editState().viewport = Rect(0, 0, 1, 1);
    nonHwcDisplay->editState().dirtyRegion = Region::INVALID_REGION;

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = false;

    nonHwcDisplay->finishFrame(refreshArgs);
}

TEST_F(DisplayTest, finishFramePerformsCompositionIfDirty) {
    std::shared_ptr<impl::Display> nonHwcDisplay{
            impl::createDisplay(mCompositionEngine, DisplayCreationArgsBuilder().build())};

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    nonHwcDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect a single call to queueBuffer when composition is not skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(1);

    nonHwcDisplay->editState().isEnabled = true;
    nonHwcDisplay->editState().usesClientComposition = false;
    nonHwcDisplay->editState().viewport = Rect(0, 0, 1, 1);
    nonHwcDisplay->editState().dirtyRegion = Region(Rect(0, 0, 1, 1));

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = false;

    nonHwcDisplay->finishFrame(refreshArgs);
}

TEST_F(DisplayTest, finishFramePerformsCompositionIfRepaintEverything) {
    std::shared_ptr<impl::Display> nonHwcDisplay{
            impl::createDisplay(mCompositionEngine, DisplayCreationArgsBuilder().build())};

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    nonHwcDisplay->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(renderSurface));

    // We expect a single call to queueBuffer when composition is not skipped.
    EXPECT_CALL(*renderSurface, queueBuffer(_)).Times(1);

    nonHwcDisplay->editState().isEnabled = true;
    nonHwcDisplay->editState().usesClientComposition = false;
    nonHwcDisplay->editState().viewport = Rect(0, 0, 1, 1);
    nonHwcDisplay->editState().dirtyRegion = Region::INVALID_REGION;

    CompositionRefreshArgs refreshArgs;
    refreshArgs.repaintEverything = true;

    nonHwcDisplay->finishFrame(refreshArgs);
}

} // namespace
} // namespace android::compositionengine
