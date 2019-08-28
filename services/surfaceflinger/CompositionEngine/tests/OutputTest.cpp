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

#include <compositionengine/impl/LayerCompositionState.h>
#include <compositionengine/impl/Output.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/Layer.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <compositionengine/mock/RenderSurface.h>
#include <gtest/gtest.h>
#include <renderengine/mock/RenderEngine.h>
#include <ui/Rect.h>
#include <ui/Region.h>

#include "RegionMatcher.h"
#include "TransformMatcher.h"

namespace android::compositionengine {
namespace {

using testing::_;
using testing::Return;
using testing::ReturnRef;
using testing::StrictMock;

constexpr auto TR_IDENT = 0u;
constexpr auto TR_ROT_90 = HAL_TRANSFORM_ROT_90;

struct OutputTest : public testing::Test {
    OutputTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));

        mOutput.editState().bounds = kDefaultDisplaySize;
    }

    static const Rect kDefaultDisplaySize;

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    impl::Output mOutput{mCompositionEngine};
};

const Rect OutputTest::kDefaultDisplaySize{100, 200};

/*
 * Basic construction
 */

TEST_F(OutputTest, canInstantiateOutput) {
    // The validation check checks each required component.
    EXPECT_CALL(*mDisplayColorProfile, isValid()).WillOnce(Return(true));
    EXPECT_CALL(*mRenderSurface, isValid()).WillOnce(Return(true));

    EXPECT_TRUE(mOutput.isValid());

    // If we take away the required components, it is no longer valid.
    mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>());

    EXPECT_CALL(*mDisplayColorProfile, isValid()).WillOnce(Return(true));

    EXPECT_FALSE(mOutput.isValid());
}

/*
 * Output::setCompositionEnabled()
 */

TEST_F(OutputTest, setCompositionEnabledDoesNothingIfAlreadyEnabled) {
    mOutput.editState().isEnabled = true;

    mOutput.setCompositionEnabled(true);

    EXPECT_TRUE(mOutput.getState().isEnabled);
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region()));
}

TEST_F(OutputTest, setCompositionEnabledSetsEnabledAndDirtiesEntireOutput) {
    mOutput.editState().isEnabled = false;

    mOutput.setCompositionEnabled(true);

    EXPECT_TRUE(mOutput.getState().isEnabled);
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

TEST_F(OutputTest, setCompositionEnabledSetsDisabledAndDirtiesEntireOutput) {
    mOutput.editState().isEnabled = true;

    mOutput.setCompositionEnabled(false);

    EXPECT_FALSE(mOutput.getState().isEnabled);
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

/*
 * Output::setProjection()
 */

TEST_F(OutputTest, setProjectionTriviallyWorks) {
    const ui::Transform transform{ui::Transform::ROT_180};
    const int32_t orientation = 123;
    const Rect frame{1, 2, 3, 4};
    const Rect viewport{5, 6, 7, 8};
    const Rect scissor{9, 10, 11, 12};
    const bool needsFiltering = true;

    mOutput.setProjection(transform, orientation, frame, viewport, scissor, needsFiltering);

    EXPECT_THAT(mOutput.getState().transform, TransformEq(transform));
    EXPECT_EQ(orientation, mOutput.getState().orientation);
    EXPECT_EQ(frame, mOutput.getState().frame);
    EXPECT_EQ(viewport, mOutput.getState().viewport);
    EXPECT_EQ(scissor, mOutput.getState().scissor);
    EXPECT_EQ(needsFiltering, mOutput.getState().needsFiltering);
}

/*
 * Output::setBounds()
 */

TEST_F(OutputTest, setBoundsSetsSizeAndDirtiesEntireOutput) {
    const ui::Size displaySize{200, 400};

    EXPECT_CALL(*mRenderSurface, setDisplaySize(displaySize)).Times(1);
    EXPECT_CALL(*mRenderSurface, getSize()).WillOnce(ReturnRef(displaySize));

    mOutput.setBounds(displaySize);

    EXPECT_EQ(Rect(displaySize), mOutput.getState().bounds);

    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(Rect(displaySize))));
}

/*
 * Output::setLayerStackFilter()
 */

TEST_F(OutputTest, setLayerStackFilterSetsFilterAndDirtiesEntireOutput) {
    const uint32_t layerStack = 123u;
    mOutput.setLayerStackFilter(layerStack, true);

    EXPECT_TRUE(mOutput.getState().layerStackInternal);
    EXPECT_EQ(layerStack, mOutput.getState().layerStackId);

    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

/*
 * Output::setColorTransform
 */

TEST_F(OutputTest, setColorTransformSetsTransform) {
    // Identity matrix sets an identity state value
    const mat4 identity;

    mOutput.setColorTransform(identity);

    EXPECT_EQ(HAL_COLOR_TRANSFORM_IDENTITY, mOutput.getState().colorTransform);
    EXPECT_EQ(identity, mOutput.getState().colorTransformMat);

    // Since identity is the default, the dirty region should be unchanged (empty)
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region()));

    // Non-identity matrix sets a non-identity state value
    const mat4 nonIdentityHalf = mat4() * 0.5;

    mOutput.setColorTransform(nonIdentityHalf);

    EXPECT_EQ(HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX, mOutput.getState().colorTransform);
    EXPECT_EQ(nonIdentityHalf, mOutput.getState().colorTransformMat);

    // Since this is a state change, the entire output should now be dirty.
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));

    // Non-identity matrix sets a non-identity state value
    const mat4 nonIdentityQuarter = mat4() * 0.25;

    mOutput.setColorTransform(nonIdentityQuarter);

    EXPECT_EQ(HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX, mOutput.getState().colorTransform);
    EXPECT_EQ(nonIdentityQuarter, mOutput.getState().colorTransformMat);

    // Since this is a state change, the entire output should now be dirty.
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

/*
 * Output::setColorMode
 */

TEST_F(OutputTest, setColorModeSetsStateAndDirtiesOutputIfChanged) {
    EXPECT_CALL(*mDisplayColorProfile,
                getTargetDataspace(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                   ui::Dataspace::UNKNOWN))
            .WillOnce(Return(ui::Dataspace::UNKNOWN));
    EXPECT_CALL(*mRenderSurface, setBufferDataspace(ui::Dataspace::DISPLAY_P3)).Times(1);

    mOutput.setColorMode(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                         ui::RenderIntent::TONE_MAP_COLORIMETRIC, ui::Dataspace::UNKNOWN);

    EXPECT_EQ(ui::ColorMode::DISPLAY_P3, mOutput.getState().colorMode);
    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mOutput.getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::TONE_MAP_COLORIMETRIC, mOutput.getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mOutput.getState().targetDataspace);

    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

TEST_F(OutputTest, setColorModeDoesNothingIfNoChange) {
    EXPECT_CALL(*mDisplayColorProfile,
                getTargetDataspace(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                   ui::Dataspace::UNKNOWN))
            .WillOnce(Return(ui::Dataspace::UNKNOWN));

    mOutput.editState().colorMode = ui::ColorMode::DISPLAY_P3;
    mOutput.editState().dataspace = ui::Dataspace::DISPLAY_P3;
    mOutput.editState().renderIntent = ui::RenderIntent::TONE_MAP_COLORIMETRIC;
    mOutput.editState().targetDataspace = ui::Dataspace::UNKNOWN;

    mOutput.setColorMode(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                         ui::RenderIntent::TONE_MAP_COLORIMETRIC, ui::Dataspace::UNKNOWN);

    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region()));
}

/*
 * Output::setRenderSurface()
 */

TEST_F(OutputTest, setRenderSurfaceResetsBounds) {
    const ui::Size newDisplaySize{640, 480};

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    EXPECT_CALL(*renderSurface, getSize()).WillOnce(ReturnRef(newDisplaySize));

    mOutput.setRenderSurface(std::unique_ptr<RenderSurface>(renderSurface));

    EXPECT_EQ(Rect(newDisplaySize), mOutput.getState().bounds);
}

/*
 * Output::getDirtyRegion()
 */

TEST_F(OutputTest, getDirtyRegionWithRepaintEverythingTrue) {
    const Rect viewport{100, 200};
    mOutput.editState().viewport = viewport;
    mOutput.editState().dirtyRegion.set(50, 300);

    {
        Region result = mOutput.getDirtyRegion(true);

        EXPECT_THAT(result, RegionEq(Region(viewport)));
    }
}

TEST_F(OutputTest, getDirtyRegionWithRepaintEverythingFalse) {
    const Rect viewport{100, 200};
    mOutput.editState().viewport = viewport;
    mOutput.editState().dirtyRegion.set(50, 300);

    {
        Region result = mOutput.getDirtyRegion(false);

        // The dirtyRegion should be clipped to the display bounds.
        EXPECT_THAT(result, RegionEq(Region(Rect(50, 200))));
    }
}

/*
 * Output::belongsInOutput()
 */

TEST_F(OutputTest, belongsInOutputFiltersAsExpected) {
    const uint32_t layerStack1 = 123u;
    const uint32_t layerStack2 = 456u;

    // If the output accepts layerStack1 and internal-only layers....
    mOutput.setLayerStackFilter(layerStack1, true);

    // Any layer with layerStack1 belongs to it, internal-only or not.
    EXPECT_TRUE(mOutput.belongsInOutput(layerStack1, false));
    EXPECT_TRUE(mOutput.belongsInOutput(layerStack1, true));
    EXPECT_FALSE(mOutput.belongsInOutput(layerStack2, true));
    EXPECT_FALSE(mOutput.belongsInOutput(layerStack2, false));

    // If the output accepts layerStack21 but not internal-only layers...
    mOutput.setLayerStackFilter(layerStack1, false);

    // Only non-internal layers with layerStack1 belong to it.
    EXPECT_TRUE(mOutput.belongsInOutput(layerStack1, false));
    EXPECT_FALSE(mOutput.belongsInOutput(layerStack1, true));
    EXPECT_FALSE(mOutput.belongsInOutput(layerStack2, true));
    EXPECT_FALSE(mOutput.belongsInOutput(layerStack2, false));
}

/*
 * Output::getOutputLayerForLayer()
 */

TEST_F(OutputTest, getOutputLayerForLayerWorks) {
    mock::OutputLayer* outputLayer1 = new StrictMock<mock::OutputLayer>();
    mock::OutputLayer* outputLayer2 = new StrictMock<mock::OutputLayer>();

    Output::OutputLayers outputLayers;
    outputLayers.emplace_back(std::unique_ptr<OutputLayer>(outputLayer1));
    outputLayers.emplace_back(nullptr);
    outputLayers.emplace_back(std::unique_ptr<OutputLayer>(outputLayer2));
    mOutput.setOutputLayersOrderedByZ(std::move(outputLayers));

    StrictMock<mock::Layer> layer;
    StrictMock<mock::Layer> otherLayer;

    // If the input layer matches the first OutputLayer, it will be returned.
    EXPECT_CALL(*outputLayer1, getLayer()).WillOnce(ReturnRef(layer));
    EXPECT_EQ(outputLayer1, mOutput.getOutputLayerForLayer(&layer));

    // If the input layer matches the second OutputLayer, it will be returned.
    EXPECT_CALL(*outputLayer1, getLayer()).WillOnce(ReturnRef(otherLayer));
    EXPECT_CALL(*outputLayer2, getLayer()).WillOnce(ReturnRef(layer));
    EXPECT_EQ(outputLayer2, mOutput.getOutputLayerForLayer(&layer));

    // If the input layer does not match an output layer, null will be returned.
    EXPECT_CALL(*outputLayer1, getLayer()).WillOnce(ReturnRef(otherLayer));
    EXPECT_CALL(*outputLayer2, getLayer()).WillOnce(ReturnRef(otherLayer));
    EXPECT_EQ(nullptr, mOutput.getOutputLayerForLayer(&layer));
}

/*
 * Output::getOrCreateOutputLayer()
 */

TEST_F(OutputTest, getOrCreateOutputLayerWorks) {
    mock::OutputLayer* existingOutputLayer = new StrictMock<mock::OutputLayer>();

    Output::OutputLayers outputLayers;
    outputLayers.emplace_back(nullptr);
    outputLayers.emplace_back(std::unique_ptr<OutputLayer>(existingOutputLayer));
    mOutput.setOutputLayersOrderedByZ(std::move(outputLayers));

    std::shared_ptr<mock::Layer> layer{new StrictMock<mock::Layer>()};
    sp<LayerFE> layerFE{new StrictMock<mock::LayerFE>()};

    StrictMock<mock::Layer> otherLayer;

    {
        // If there is no OutputLayer corresponding to the input layer, a
        // new OutputLayer is constructed and returned.
        EXPECT_CALL(*existingOutputLayer, getLayer()).WillOnce(ReturnRef(otherLayer));
        auto result = mOutput.getOrCreateOutputLayer(std::nullopt, layer, layerFE);
        EXPECT_NE(existingOutputLayer, result.get());
        EXPECT_TRUE(result.get() != nullptr);
        EXPECT_EQ(layer.get(), &result->getLayer());
        EXPECT_EQ(layerFE.get(), &result->getLayerFE());

        // The entries in the ordered array should be unchanged.
        auto& outputLayers = mOutput.getOutputLayersOrderedByZ();
        EXPECT_EQ(nullptr, outputLayers[0].get());
        EXPECT_EQ(existingOutputLayer, outputLayers[1].get());
    }

    {
        // If there is an existing OutputLayer for the requested layer, an owned
        // pointer is returned
        EXPECT_CALL(*existingOutputLayer, getLayer()).WillOnce(ReturnRef(*layer));
        auto result = mOutput.getOrCreateOutputLayer(std::nullopt, layer, layerFE);
        EXPECT_EQ(existingOutputLayer, result.get());

        // The corresponding entry in the ordered array should be cleared.
        auto& outputLayers = mOutput.getOutputLayersOrderedByZ();
        EXPECT_EQ(nullptr, outputLayers[0].get());
        EXPECT_EQ(nullptr, outputLayers[1].get());
    }
}

/*
 * Output::prepareFrame()
 */

struct OutputPrepareFrameTest : public testing::Test {
    struct OutputPartialMock : public impl::Output {
        OutputPartialMock(const compositionengine::CompositionEngine& compositionEngine)
              : impl::Output(compositionEngine) {}

        // Sets up the helper functions called by prepareFrame to use a mock
        // implementations.
        MOCK_METHOD0(chooseCompositionStrategy, void());
    };

    OutputPrepareFrameTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput{mCompositionEngine};
};

TEST_F(OutputPrepareFrameTest, takesEarlyOutIfNotEnabled) {
    mOutput.editState().isEnabled = false;

    mOutput.prepareFrame();
}

TEST_F(OutputPrepareFrameTest, delegatesToChooseCompositionStrategyAndRenderSurface) {
    mOutput.editState().isEnabled = true;
    mOutput.editState().usesClientComposition = false;
    mOutput.editState().usesDeviceComposition = true;

    EXPECT_CALL(mOutput, chooseCompositionStrategy()).Times(1);
    EXPECT_CALL(*mRenderSurface, prepareFrame(false, true));

    mOutput.prepareFrame();
}

// Note: Use OutputTest and not OutputPrepareFrameTest, so the real
// base chooseCompositionStrategy() is invoked.
TEST_F(OutputTest, prepareFrameSetsClientCompositionOnlyByDefault) {
    mOutput.editState().isEnabled = true;
    mOutput.editState().usesClientComposition = false;
    mOutput.editState().usesDeviceComposition = true;

    EXPECT_CALL(*mRenderSurface, prepareFrame(true, false));

    mOutput.prepareFrame();

    EXPECT_TRUE(mOutput.getState().usesClientComposition);
    EXPECT_FALSE(mOutput.getState().usesDeviceComposition);
}

/*
 * Output::composeSurfaces()
 */

struct OutputComposeSurfacesTest : public testing::Test {
    static constexpr uint32_t kDefaultOutputOrientation = TR_IDENT;
    static constexpr ui::Dataspace kDefaultOutputDataspace = ui::Dataspace::DISPLAY_P3;

    static const Rect kDefaultOutputFrame;
    static const Rect kDefaultOutputViewport;
    static const Rect kDefaultOutputScissor;
    static const mat4 kDefaultColorTransformMat;

    struct OutputPartialMock : public impl::Output {
        OutputPartialMock(const compositionengine::CompositionEngine& compositionEngine)
              : impl::Output(compositionEngine) {}

        // Sets up the helper functions called by composeSurfaces to use a mock
        // implementations.
        MOCK_CONST_METHOD0(getSkipColorTransform, bool());
        MOCK_METHOD2(generateClientCompositionRequests,
                     std::vector<renderengine::LayerSettings>(bool, Region&));
        MOCK_METHOD2(appendRegionFlashRequests,
                     void(const Region&, std::vector<renderengine::LayerSettings>&));
        MOCK_METHOD1(setExpensiveRenderingExpected, void(bool));
    };

    OutputComposeSurfacesTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));

        Output::OutputLayers outputLayers;
        outputLayers.emplace_back(std::unique_ptr<OutputLayer>(mOutputLayer1));
        outputLayers.emplace_back(std::unique_ptr<OutputLayer>(mOutputLayer2));
        mOutput.setOutputLayersOrderedByZ(std::move(outputLayers));

        mOutput.editState().frame = kDefaultOutputFrame;
        mOutput.editState().viewport = kDefaultOutputViewport;
        mOutput.editState().scissor = kDefaultOutputScissor;
        mOutput.editState().transform = ui::Transform{kDefaultOutputOrientation};
        mOutput.editState().orientation = kDefaultOutputOrientation;
        mOutput.editState().dataspace = kDefaultOutputDataspace;
        mOutput.editState().colorTransformMat = kDefaultColorTransformMat;
        mOutput.editState().isSecure = true;
        mOutput.editState().needsFiltering = false;
        mOutput.editState().usesClientComposition = true;
        mOutput.editState().usesDeviceComposition = false;

        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
    }

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    mock::OutputLayer* mOutputLayer1 = new StrictMock<mock::OutputLayer>();
    mock::OutputLayer* mOutputLayer2 = new StrictMock<mock::OutputLayer>();
    StrictMock<OutputPartialMock> mOutput{mCompositionEngine};
    sp<GraphicBuffer> mOutputBuffer = new GraphicBuffer();
};

const Rect OutputComposeSurfacesTest::kDefaultOutputFrame{1001, 1002, 1003, 1004};
const Rect OutputComposeSurfacesTest::kDefaultOutputViewport{1005, 1006, 1007, 1008};
const Rect OutputComposeSurfacesTest::kDefaultOutputScissor{1009, 1010, 1011, 1012};
const mat4 OutputComposeSurfacesTest::kDefaultColorTransformMat{mat4() * 0.5};

// TODO(b/121291683): Expand unit test coverage for composeSurfaces beyond these
// basic tests.

TEST_F(OutputComposeSurfacesTest, doesNothingIfNoClientComposition) {
    mOutput.editState().usesClientComposition = false;

    Region debugRegion;
    base::unique_fd readyFence;
    EXPECT_EQ(true, mOutput.composeSurfaces(debugRegion, &readyFence));
}

TEST_F(OutputComposeSurfacesTest, worksIfNoClientLayersQueued) {
    const Region kDebugRegion{Rect{100, 101, 102, 103}};

    constexpr float kDefaultMaxLuminance = 1.0f;
    constexpr float kDefaultAvgLuminance = 0.7f;
    constexpr float kDefaultMinLuminance = 0.1f;
    HdrCapabilities HdrCapabilities{{},
                                    kDefaultMaxLuminance,
                                    kDefaultAvgLuminance,
                                    kDefaultMinLuminance};

    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillOnce(Return(false));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, true, _, _)).Times(1);

    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillOnce(Return(true));
    EXPECT_CALL(*mDisplayColorProfile, getHdrCapabilities()).WillOnce(ReturnRef(HdrCapabilities));

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillOnce(Return(mOutputBuffer));

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillOnce(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(false, _)).Times(1);
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _)).Times(1);
    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(true)).Times(1);
    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(false)).Times(1);

    base::unique_fd readyFence;
    EXPECT_EQ(true, mOutput.composeSurfaces(kDebugRegion, &readyFence));
}

/*
 * Output::generateClientCompositionRequests()
 */

struct GenerateClientCompositionRequestsTest : public testing::Test {
    struct OutputPartialMock : public impl::Output {
        OutputPartialMock(const compositionengine::CompositionEngine& compositionEngine)
              : impl::Output(compositionEngine) {}

        std::vector<renderengine::LayerSettings> generateClientCompositionRequests(
                bool supportsProtectedContent, Region& clearRegion) override {
            return impl::Output::generateClientCompositionRequests(supportsProtectedContent,
                                                                   clearRegion);
        }
    };

    GenerateClientCompositionRequestsTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput{mCompositionEngine};
};

// TODO(b/121291683): Add more unit test coverage for generateClientCompositionRequests

TEST_F(GenerateClientCompositionRequestsTest, worksForLandscapeModeSplitScreen) {
    // In split-screen landscape mode, the screen is rotated 90 degrees, with
    // one layer on the left covering the left side of the output, and one layer
    // on the right covering that side of the output.

    mock::OutputLayer* leftOutputLayer = new StrictMock<mock::OutputLayer>();
    mock::OutputLayer* rightOutputLayer = new StrictMock<mock::OutputLayer>();

    StrictMock<mock::Layer> leftLayer;
    StrictMock<mock::LayerFE> leftLayerFE;
    StrictMock<mock::Layer> rightLayer;
    StrictMock<mock::LayerFE> rightLayerFE;

    impl::OutputLayerCompositionState leftOutputLayerState;
    leftOutputLayerState.clearClientTarget = false;

    impl::LayerCompositionState leftLayerState;
    leftLayerState.frontEnd.geomVisibleRegion = Region{Rect{0, 0, 1000, 1000}};
    leftLayerState.frontEnd.isOpaque = true;

    const half3 leftLayerColor{1.f, 0.f, 0.f};
    renderengine::LayerSettings leftLayerRESettings;
    leftLayerRESettings.source.solidColor = leftLayerColor;

    impl::OutputLayerCompositionState rightOutputLayerState;
    rightOutputLayerState.clearClientTarget = false;

    impl::LayerCompositionState rightLayerState;
    rightLayerState.frontEnd.geomVisibleRegion = Region{Rect{1000, 0, 2000, 1000}};
    rightLayerState.frontEnd.isOpaque = true;

    const half3 rightLayerColor{0.f, 1.f, 0.f};
    renderengine::LayerSettings rightLayerRESettings;
    rightLayerRESettings.source.solidColor = rightLayerColor;

    EXPECT_CALL(*leftOutputLayer, getState()).WillRepeatedly(ReturnRef(leftOutputLayerState));
    EXPECT_CALL(*leftOutputLayer, getLayer()).WillRepeatedly(ReturnRef(leftLayer));
    EXPECT_CALL(*leftOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(leftLayerFE));
    EXPECT_CALL(*leftOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(*leftOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(leftLayer, getState()).WillRepeatedly(ReturnRef(leftLayerState));
    EXPECT_CALL(leftLayerFE, prepareClientComposition(_)).WillOnce(Return(leftLayerRESettings));

    EXPECT_CALL(*rightOutputLayer, getState()).WillRepeatedly(ReturnRef(rightOutputLayerState));
    EXPECT_CALL(*rightOutputLayer, getLayer()).WillRepeatedly(ReturnRef(rightLayer));
    EXPECT_CALL(*rightOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(rightLayerFE));
    EXPECT_CALL(*rightOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(*rightOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(rightLayer, getState()).WillRepeatedly(ReturnRef(rightLayerState));
    EXPECT_CALL(rightLayerFE, prepareClientComposition(_)).WillOnce(Return(rightLayerRESettings));

    Output::OutputLayers outputLayers;
    outputLayers.emplace_back(std::unique_ptr<OutputLayer>(leftOutputLayer));
    outputLayers.emplace_back(std::unique_ptr<OutputLayer>(rightOutputLayer));
    mOutput.setOutputLayersOrderedByZ(std::move(outputLayers));

    const Rect kPortraitFrame(0, 0, 1000, 2000);
    const Rect kPortraitViewport(0, 0, 2000, 1000);
    const Rect kPortraitScissor(0, 0, 1000, 2000);
    const uint32_t kPortraitOrientation = TR_ROT_90;

    mOutput.editState().frame = kPortraitFrame;
    mOutput.editState().viewport = kPortraitViewport;
    mOutput.editState().scissor = kPortraitScissor;
    mOutput.editState().transform = ui::Transform{kPortraitOrientation};
    mOutput.editState().orientation = kPortraitOrientation;
    mOutput.editState().needsFiltering = true;
    mOutput.editState().isSecure = false;

    constexpr bool supportsProtectedContent = false;
    Region clearRegion;
    auto requests =
            mOutput.generateClientCompositionRequests(supportsProtectedContent, clearRegion);

    ASSERT_EQ(2u, requests.size());
    EXPECT_EQ(leftLayerColor, requests[0].source.solidColor);
    EXPECT_EQ(rightLayerColor, requests[1].source.solidColor);
}

TEST_F(GenerateClientCompositionRequestsTest, ignoresLayersThatDoNotIntersectWithViewport) {
    // Layers whose visible region does not intersect with the viewport will be
    // skipped when generating client composition request state.

    mock::OutputLayer* outputLayer = new StrictMock<mock::OutputLayer>();
    StrictMock<mock::Layer> layer;
    StrictMock<mock::LayerFE> layerFE;

    impl::OutputLayerCompositionState outputLayerState;
    outputLayerState.clearClientTarget = false;

    impl::LayerCompositionState layerState;
    layerState.frontEnd.geomVisibleRegion = Region{Rect{3000, 0, 4000, 1000}};
    layerState.frontEnd.isOpaque = true;

    EXPECT_CALL(*outputLayer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
    EXPECT_CALL(*outputLayer, getLayer()).WillRepeatedly(ReturnRef(layer));
    EXPECT_CALL(*outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(layerFE));
    EXPECT_CALL(*outputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(*outputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(layer, getState()).WillRepeatedly(ReturnRef(layerState));
    EXPECT_CALL(layerFE, prepareClientComposition(_)).Times(0);

    Output::OutputLayers outputLayers;
    outputLayers.emplace_back(std::unique_ptr<OutputLayer>(outputLayer));
    mOutput.setOutputLayersOrderedByZ(std::move(outputLayers));

    const Rect kPortraitFrame(0, 0, 1000, 2000);
    const Rect kPortraitViewport(0, 0, 2000, 1000);
    const Rect kPortraitScissor(0, 0, 1000, 2000);
    const uint32_t kPortraitOrientation = TR_ROT_90;

    mOutput.editState().frame = kPortraitFrame;
    mOutput.editState().viewport = kPortraitViewport;
    mOutput.editState().scissor = kPortraitScissor;
    mOutput.editState().transform = ui::Transform{kPortraitOrientation};
    mOutput.editState().orientation = kPortraitOrientation;
    mOutput.editState().needsFiltering = true;
    mOutput.editState().isSecure = false;

    constexpr bool supportsProtectedContent = false;
    Region clearRegion;
    auto requests =
            mOutput.generateClientCompositionRequests(supportsProtectedContent, clearRegion);

    EXPECT_EQ(0u, requests.size());
}

} // namespace
} // namespace android::compositionengine
