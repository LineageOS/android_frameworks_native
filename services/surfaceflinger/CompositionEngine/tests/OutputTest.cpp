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

#include <android-base/stringprintf.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/impl/Output.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <compositionengine/mock/RenderSurface.h>
#include <gtest/gtest.h>
#include <renderengine/mock/RenderEngine.h>
#include <ui/Rect.h>
#include <ui/Region.h>

#include "CallOrderStateMachineHelper.h"
#include "MockHWC2.h"
#include "RegionMatcher.h"

namespace android::compositionengine {
namespace {

using testing::_;
using testing::ByMove;
using testing::ByRef;
using testing::DoAll;
using testing::ElementsAre;
using testing::ElementsAreArray;
using testing::Eq;
using testing::InSequence;
using testing::Invoke;
using testing::IsEmpty;
using testing::Mock;
using testing::Pointee;
using testing::Property;
using testing::Ref;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;
using testing::StrictMock;

constexpr auto TR_IDENT = 0u;
constexpr auto TR_ROT_90 = HAL_TRANSFORM_ROT_90;
constexpr auto MAX_CLIENT_COMPOSITION_CACHE_SIZE = 3;

const mat4 kIdentity;
const mat4 kNonIdentityHalf = mat4() * 0.5f;
const mat4 kNonIdentityQuarter = mat4() * 0.25f;

constexpr OutputColorSetting kVendorSpecifiedOutputColorSetting =
        static_cast<OutputColorSetting>(0x100);

struct OutputPartialMockBase : public impl::Output {
    // compositionengine::Output overrides
    const OutputCompositionState& getState() const override { return mState; }
    OutputCompositionState& editState() override { return mState; }

    // Use mocks for all the remaining virtual functions
    // not implemented by the base implementation class.
    MOCK_CONST_METHOD0(getOutputLayerCount, size_t());
    MOCK_CONST_METHOD1(getOutputLayerOrderedByZByIndex, compositionengine::OutputLayer*(size_t));
    MOCK_METHOD2(ensureOutputLayer,
                 compositionengine::OutputLayer*(std::optional<size_t>, const sp<LayerFE>&));
    MOCK_METHOD0(finalizePendingOutputLayers, void());
    MOCK_METHOD0(clearOutputLayers, void());
    MOCK_CONST_METHOD1(dumpState, void(std::string&));
    MOCK_CONST_METHOD0(getCompositionEngine, const CompositionEngine&());
    MOCK_METHOD1(injectOutputLayerForTest, compositionengine::OutputLayer*(const sp<LayerFE>&));
    MOCK_METHOD1(injectOutputLayerForTest, void(std::unique_ptr<OutputLayer>));

    impl::OutputCompositionState mState;
};

struct InjectedLayer {
    InjectedLayer() {
        EXPECT_CALL(*outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE.get()));
        EXPECT_CALL(*outputLayer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
        EXPECT_CALL(*outputLayer, editState()).WillRepeatedly(ReturnRef(outputLayerState));

        EXPECT_CALL(*layerFE, getCompositionState()).WillRepeatedly(Return(&layerFEState));
    }

    mock::OutputLayer* outputLayer = {new StrictMock<mock::OutputLayer>};
    sp<StrictMock<mock::LayerFE>> layerFE = new StrictMock<mock::LayerFE>();
    LayerFECompositionState layerFEState;
    impl::OutputLayerCompositionState outputLayerState;
};

struct NonInjectedLayer {
    NonInjectedLayer() {
        EXPECT_CALL(outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE.get()));
        EXPECT_CALL(outputLayer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
        EXPECT_CALL(outputLayer, editState()).WillRepeatedly(ReturnRef(outputLayerState));

        EXPECT_CALL(*layerFE, getCompositionState()).WillRepeatedly(Return(&layerFEState));
    }

    mock::OutputLayer outputLayer;
    sp<StrictMock<mock::LayerFE>> layerFE = new StrictMock<mock::LayerFE>();
    LayerFECompositionState layerFEState;
    impl::OutputLayerCompositionState outputLayerState;
};

struct OutputTest : public testing::Test {
    class Output : public impl::Output {
    public:
        using impl::Output::injectOutputLayerForTest;
        virtual void injectOutputLayerForTest(std::unique_ptr<compositionengine::OutputLayer>) = 0;
    };

    static std::shared_ptr<Output> createOutput(
            const compositionengine::CompositionEngine& compositionEngine) {
        return impl::createOutputTemplated<Output>(compositionEngine);
    }

    OutputTest() {
        mOutput->setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));

        mOutput->editState().bounds = kDefaultDisplaySize;
    }

    void injectOutputLayer(InjectedLayer& layer) {
        mOutput->injectOutputLayerForTest(std::unique_ptr<OutputLayer>(layer.outputLayer));
    }

    void injectNullOutputLayer() {
        mOutput->injectOutputLayerForTest(std::unique_ptr<OutputLayer>(nullptr));
    }

    static const Rect kDefaultDisplaySize;

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    std::shared_ptr<Output> mOutput = createOutput(mCompositionEngine);
};

const Rect OutputTest::kDefaultDisplaySize{100, 200};

using ColorProfile = compositionengine::Output::ColorProfile;

void dumpColorProfile(ColorProfile profile, std::string& result, const char* name) {
    android::base::StringAppendF(&result, "%s (%s[%d] %s[%d] %s[%d] %s[%d]) ", name,
                                 toString(profile.mode).c_str(), profile.mode,
                                 toString(profile.dataspace).c_str(), profile.dataspace,
                                 toString(profile.renderIntent).c_str(), profile.renderIntent,
                                 toString(profile.colorSpaceAgnosticDataspace).c_str(),
                                 profile.colorSpaceAgnosticDataspace);
}

// Checks for a ColorProfile match
MATCHER_P(ColorProfileEq, expected, "") {
    std::string buf;
    buf.append("ColorProfiles are not equal\n");
    dumpColorProfile(expected, buf, "expected value");
    dumpColorProfile(arg, buf, "actual value");
    *result_listener << buf;

    return (expected.mode == arg.mode) && (expected.dataspace == arg.dataspace) &&
            (expected.renderIntent == arg.renderIntent) &&
            (expected.colorSpaceAgnosticDataspace == arg.colorSpaceAgnosticDataspace);
}

/*
 * Basic construction
 */

TEST_F(OutputTest, canInstantiateOutput) {
    // The validation check checks each required component.
    EXPECT_CALL(*mDisplayColorProfile, isValid()).WillOnce(Return(true));
    EXPECT_CALL(*mRenderSurface, isValid()).WillOnce(Return(true));

    EXPECT_TRUE(mOutput->isValid());

    // If we take away the required components, it is no longer valid.
    mOutput->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>());

    EXPECT_CALL(*mDisplayColorProfile, isValid()).WillOnce(Return(true));

    EXPECT_FALSE(mOutput->isValid());
}

/*
 * Output::setCompositionEnabled()
 */

TEST_F(OutputTest, setCompositionEnabledDoesNothingIfAlreadyEnabled) {
    mOutput->editState().isEnabled = true;

    mOutput->setCompositionEnabled(true);

    EXPECT_TRUE(mOutput->getState().isEnabled);
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region()));
}

TEST_F(OutputTest, setCompositionEnabledSetsEnabledAndDirtiesEntireOutput) {
    mOutput->editState().isEnabled = false;

    mOutput->setCompositionEnabled(true);

    EXPECT_TRUE(mOutput->getState().isEnabled);
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

TEST_F(OutputTest, setCompositionEnabledSetsDisabledAndDirtiesEntireOutput) {
    mOutput->editState().isEnabled = true;

    mOutput->setCompositionEnabled(false);

    EXPECT_FALSE(mOutput->getState().isEnabled);
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

/*
 * Output::setProjection()
 */

TEST_F(OutputTest, setProjectionTriviallyWorks) {
    const ui::Transform transform{ui::Transform::ROT_180};
    const int32_t orientation = 123;
    const Rect frame{1, 2, 3, 4};
    const Rect viewport{5, 6, 7, 8};
    const Rect sourceClip{9, 10, 11, 12};
    const Rect destinationClip{13, 14, 15, 16};
    const bool needsFiltering = true;

    mOutput->setProjection(transform, orientation, frame, viewport, sourceClip, destinationClip,
                           needsFiltering);

    EXPECT_THAT(mOutput->getState().transform, transform);
    EXPECT_EQ(orientation, mOutput->getState().orientation);
    EXPECT_EQ(frame, mOutput->getState().frame);
    EXPECT_EQ(viewport, mOutput->getState().viewport);
    EXPECT_EQ(sourceClip, mOutput->getState().sourceClip);
    EXPECT_EQ(destinationClip, mOutput->getState().destinationClip);
    EXPECT_EQ(needsFiltering, mOutput->getState().needsFiltering);
}

/*
 * Output::setBounds()
 */

TEST_F(OutputTest, setBoundsSetsSizeAndDirtiesEntireOutput) {
    const ui::Size displaySize{200, 400};

    EXPECT_CALL(*mRenderSurface, setDisplaySize(displaySize)).Times(1);
    EXPECT_CALL(*mRenderSurface, getSize()).WillOnce(ReturnRef(displaySize));

    mOutput->setBounds(displaySize);

    EXPECT_EQ(Rect(displaySize), mOutput->getState().bounds);

    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(Rect(displaySize))));
}

/*
 * Output::setLayerStackFilter()
 */

TEST_F(OutputTest, setLayerStackFilterSetsFilterAndDirtiesEntireOutput) {
    const uint32_t layerStack = 123u;
    mOutput->setLayerStackFilter(layerStack, true);

    EXPECT_TRUE(mOutput->getState().layerStackInternal);
    EXPECT_EQ(layerStack, mOutput->getState().layerStackId);

    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

/*
 * Output::setColorTransform
 */

TEST_F(OutputTest, setColorTransformWithNoChangeFlaggedSkipsUpdates) {
    mOutput->editState().colorTransformMatrix = kIdentity;

    // If no colorTransformMatrix is set the update should be skipped.
    CompositionRefreshArgs refreshArgs;
    refreshArgs.colorTransformMatrix = std::nullopt;

    mOutput->setColorTransform(refreshArgs);

    // The internal state should be unchanged
    EXPECT_EQ(kIdentity, mOutput->getState().colorTransformMatrix);

    // No dirty region should be set
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region()));
}

TEST_F(OutputTest, setColorTransformWithNoActualChangeSkipsUpdates) {
    mOutput->editState().colorTransformMatrix = kIdentity;

    // Attempting to set the same colorTransformMatrix that is already set should
    // also skip the update.
    CompositionRefreshArgs refreshArgs;
    refreshArgs.colorTransformMatrix = kIdentity;

    mOutput->setColorTransform(refreshArgs);

    // The internal state should be unchanged
    EXPECT_EQ(kIdentity, mOutput->getState().colorTransformMatrix);

    // No dirty region should be set
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region()));
}

TEST_F(OutputTest, setColorTransformPerformsUpdateToIdentity) {
    mOutput->editState().colorTransformMatrix = kNonIdentityHalf;

    // Setting a different colorTransformMatrix should perform the update.
    CompositionRefreshArgs refreshArgs;
    refreshArgs.colorTransformMatrix = kIdentity;

    mOutput->setColorTransform(refreshArgs);

    // The internal state should have been updated
    EXPECT_EQ(kIdentity, mOutput->getState().colorTransformMatrix);

    // The dirtyRegion should be set to the full display size
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

TEST_F(OutputTest, setColorTransformPerformsUpdateForIdentityToHalf) {
    mOutput->editState().colorTransformMatrix = kIdentity;

    // Setting a different colorTransformMatrix should perform the update.
    CompositionRefreshArgs refreshArgs;
    refreshArgs.colorTransformMatrix = kNonIdentityHalf;

    mOutput->setColorTransform(refreshArgs);

    // The internal state should have been updated
    EXPECT_EQ(kNonIdentityHalf, mOutput->getState().colorTransformMatrix);

    // The dirtyRegion should be set to the full display size
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

TEST_F(OutputTest, setColorTransformPerformsUpdateForHalfToQuarter) {
    mOutput->editState().colorTransformMatrix = kNonIdentityHalf;

    // Setting a different colorTransformMatrix should perform the update.
    CompositionRefreshArgs refreshArgs;
    refreshArgs.colorTransformMatrix = kNonIdentityQuarter;

    mOutput->setColorTransform(refreshArgs);

    // The internal state should have been updated
    EXPECT_EQ(kNonIdentityQuarter, mOutput->getState().colorTransformMatrix);

    // The dirtyRegion should be set to the full display size
    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

/*
 * Output::setColorProfile
 */

using OutputSetColorProfileTest = OutputTest;

TEST_F(OutputSetColorProfileTest, setsStateAndDirtiesOutputIfChanged) {
    using ColorProfile = Output::ColorProfile;

    EXPECT_CALL(*mDisplayColorProfile,
                getTargetDataspace(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                   ui::Dataspace::UNKNOWN))
            .WillOnce(Return(ui::Dataspace::UNKNOWN));
    EXPECT_CALL(*mRenderSurface, setBufferDataspace(ui::Dataspace::DISPLAY_P3)).Times(1);

    mOutput->setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                          ui::RenderIntent::TONE_MAP_COLORIMETRIC,
                                          ui::Dataspace::UNKNOWN});

    EXPECT_EQ(ui::ColorMode::DISPLAY_P3, mOutput->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mOutput->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::TONE_MAP_COLORIMETRIC, mOutput->getState().renderIntent);
    EXPECT_EQ(ui::Dataspace::UNKNOWN, mOutput->getState().targetDataspace);

    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

TEST_F(OutputSetColorProfileTest, doesNothingIfNoChange) {
    using ColorProfile = Output::ColorProfile;

    EXPECT_CALL(*mDisplayColorProfile,
                getTargetDataspace(ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                   ui::Dataspace::UNKNOWN))
            .WillOnce(Return(ui::Dataspace::UNKNOWN));

    mOutput->editState().colorMode = ui::ColorMode::DISPLAY_P3;
    mOutput->editState().dataspace = ui::Dataspace::DISPLAY_P3;
    mOutput->editState().renderIntent = ui::RenderIntent::TONE_MAP_COLORIMETRIC;
    mOutput->editState().targetDataspace = ui::Dataspace::UNKNOWN;

    mOutput->setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                          ui::RenderIntent::TONE_MAP_COLORIMETRIC,
                                          ui::Dataspace::UNKNOWN});

    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region()));
}

/*
 * Output::setRenderSurface()
 */

TEST_F(OutputTest, setRenderSurfaceResetsBounds) {
    const ui::Size newDisplaySize{640, 480};

    mock::RenderSurface* renderSurface = new StrictMock<mock::RenderSurface>();
    EXPECT_CALL(*renderSurface, getSize()).WillOnce(ReturnRef(newDisplaySize));

    mOutput->setRenderSurface(std::unique_ptr<RenderSurface>(renderSurface));

    EXPECT_EQ(Rect(newDisplaySize), mOutput->getState().bounds);
}

/*
 * Output::getDirtyRegion()
 */

TEST_F(OutputTest, getDirtyRegionWithRepaintEverythingTrue) {
    const Rect viewport{100, 200};
    mOutput->editState().viewport = viewport;
    mOutput->editState().dirtyRegion.set(50, 300);

    {
        Region result = mOutput->getDirtyRegion(true);

        EXPECT_THAT(result, RegionEq(Region(viewport)));
    }
}

TEST_F(OutputTest, getDirtyRegionWithRepaintEverythingFalse) {
    const Rect viewport{100, 200};
    mOutput->editState().viewport = viewport;
    mOutput->editState().dirtyRegion.set(50, 300);

    {
        Region result = mOutput->getDirtyRegion(false);

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
    mOutput->setLayerStackFilter(layerStack1, true);

    // A layer with no layerStack does not belong to it, internal-only or not.
    EXPECT_FALSE(mOutput->belongsInOutput(std::nullopt, false));
    EXPECT_FALSE(mOutput->belongsInOutput(std::nullopt, true));

    // Any layer with layerStack1 belongs to it, internal-only or not.
    EXPECT_TRUE(mOutput->belongsInOutput(layerStack1, false));
    EXPECT_TRUE(mOutput->belongsInOutput(layerStack1, true));
    EXPECT_FALSE(mOutput->belongsInOutput(layerStack2, true));
    EXPECT_FALSE(mOutput->belongsInOutput(layerStack2, false));

    // If the output accepts layerStack21 but not internal-only layers...
    mOutput->setLayerStackFilter(layerStack1, false);

    // Only non-internal layers with layerStack1 belong to it.
    EXPECT_TRUE(mOutput->belongsInOutput(layerStack1, false));
    EXPECT_FALSE(mOutput->belongsInOutput(layerStack1, true));
    EXPECT_FALSE(mOutput->belongsInOutput(layerStack2, true));
    EXPECT_FALSE(mOutput->belongsInOutput(layerStack2, false));
}

TEST_F(OutputTest, belongsInOutputHandlesLayerWithNoCompositionState) {
    NonInjectedLayer layer;
    sp<LayerFE> layerFE(layer.layerFE);

    // If the layer has no composition state, it does not belong to any output.
    EXPECT_CALL(*layer.layerFE, getCompositionState).WillOnce(Return(nullptr));
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));
}

TEST_F(OutputTest, belongsInOutputFiltersLayersAsExpected) {
    NonInjectedLayer layer;
    sp<LayerFE> layerFE(layer.layerFE);

    const uint32_t layerStack1 = 123u;
    const uint32_t layerStack2 = 456u;

    // If the output accepts layerStack1 and internal-only layers....
    mOutput->setLayerStackFilter(layerStack1, true);

    // A layer with no layerStack does not belong to it, internal-only or not.
    layer.layerFEState.layerStackId = std::nullopt;
    layer.layerFEState.internalOnly = false;
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));

    layer.layerFEState.layerStackId = std::nullopt;
    layer.layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));

    // Any layer with layerStack1 belongs to it, internal-only or not.
    layer.layerFEState.layerStackId = layerStack1;
    layer.layerFEState.internalOnly = false;
    EXPECT_TRUE(mOutput->belongsInOutput(layerFE));

    layer.layerFEState.layerStackId = layerStack1;
    layer.layerFEState.internalOnly = true;
    EXPECT_TRUE(mOutput->belongsInOutput(layerFE));

    layer.layerFEState.layerStackId = layerStack2;
    layer.layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));

    layer.layerFEState.layerStackId = layerStack2;
    layer.layerFEState.internalOnly = false;
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));

    // If the output accepts layerStack1 but not internal-only layers...
    mOutput->setLayerStackFilter(layerStack1, false);

    // Only non-internal layers with layerStack1 belong to it.
    layer.layerFEState.layerStackId = layerStack1;
    layer.layerFEState.internalOnly = false;
    EXPECT_TRUE(mOutput->belongsInOutput(layerFE));

    layer.layerFEState.layerStackId = layerStack1;
    layer.layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));

    layer.layerFEState.layerStackId = layerStack2;
    layer.layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));

    layer.layerFEState.layerStackId = layerStack2;
    layer.layerFEState.internalOnly = false;
    EXPECT_FALSE(mOutput->belongsInOutput(layerFE));
}

/*
 * Output::getOutputLayerForLayer()
 */

TEST_F(OutputTest, getOutputLayerForLayerWorks) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    NonInjectedLayer layer3;

    injectOutputLayer(layer1);
    injectNullOutputLayer();
    injectOutputLayer(layer2);

    // If the input layer matches the first OutputLayer, it will be returned.
    EXPECT_CALL(*layer1.outputLayer, getLayerFE()).WillOnce(ReturnRef(*layer1.layerFE.get()));
    EXPECT_EQ(layer1.outputLayer, mOutput->getOutputLayerForLayer(layer1.layerFE));

    // If the input layer matches the second OutputLayer, it will be returned.
    EXPECT_CALL(*layer1.outputLayer, getLayerFE()).WillOnce(ReturnRef(*layer1.layerFE.get()));
    EXPECT_CALL(*layer2.outputLayer, getLayerFE()).WillOnce(ReturnRef(*layer2.layerFE.get()));
    EXPECT_EQ(layer2.outputLayer, mOutput->getOutputLayerForLayer(layer2.layerFE));

    // If the input layer does not match an output layer, null will be returned.
    EXPECT_CALL(*layer1.outputLayer, getLayerFE()).WillOnce(ReturnRef(*layer1.layerFE.get()));
    EXPECT_CALL(*layer2.outputLayer, getLayerFE()).WillOnce(ReturnRef(*layer2.layerFE.get()));
    EXPECT_EQ(nullptr, mOutput->getOutputLayerForLayer(layer3.layerFE));
}

/*
 * Output::setReleasedLayers()
 */

using OutputSetReleasedLayersTest = OutputTest;

TEST_F(OutputSetReleasedLayersTest, setReleasedLayersTakesGivenLayers) {
    sp<StrictMock<mock::LayerFE>> layer1FE{new StrictMock<mock::LayerFE>()};
    sp<StrictMock<mock::LayerFE>> layer2FE{new StrictMock<mock::LayerFE>()};
    sp<StrictMock<mock::LayerFE>> layer3FE{new StrictMock<mock::LayerFE>()};

    Output::ReleasedLayers layers;
    layers.push_back(layer1FE);
    layers.push_back(layer2FE);
    layers.push_back(layer3FE);

    mOutput->setReleasedLayers(std::move(layers));

    const auto& setLayers = mOutput->getReleasedLayersForTest();
    ASSERT_EQ(3u, setLayers.size());
    ASSERT_EQ(layer1FE.get(), setLayers[0].promote().get());
    ASSERT_EQ(layer2FE.get(), setLayers[1].promote().get());
    ASSERT_EQ(layer3FE.get(), setLayers[2].promote().get());
}

/*
 * Output::updateLayerStateFromFE()
 */

using OutputUpdateLayerStateFromFETest = OutputTest;

TEST_F(OutputUpdateLayerStateFromFETest, handlesNoOutputLayerCase) {
    CompositionRefreshArgs refreshArgs;

    mOutput->updateLayerStateFromFE(refreshArgs);
}

TEST_F(OutputUpdateLayerStateFromFETest, preparesContentStateForAllContainedLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    EXPECT_CALL(*layer1.layerFE.get(), prepareCompositionState(LayerFE::StateSubset::Content));
    EXPECT_CALL(*layer2.layerFE.get(), prepareCompositionState(LayerFE::StateSubset::Content));
    EXPECT_CALL(*layer3.layerFE.get(), prepareCompositionState(LayerFE::StateSubset::Content));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    CompositionRefreshArgs refreshArgs;
    refreshArgs.updatingGeometryThisFrame = false;

    mOutput->updateLayerStateFromFE(refreshArgs);
}

TEST_F(OutputUpdateLayerStateFromFETest, preparesGeometryAndContentStateForAllContainedLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    EXPECT_CALL(*layer1.layerFE, prepareCompositionState(LayerFE::StateSubset::GeometryAndContent));
    EXPECT_CALL(*layer2.layerFE, prepareCompositionState(LayerFE::StateSubset::GeometryAndContent));
    EXPECT_CALL(*layer3.layerFE, prepareCompositionState(LayerFE::StateSubset::GeometryAndContent));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    CompositionRefreshArgs refreshArgs;
    refreshArgs.updatingGeometryThisFrame = true;

    mOutput->updateLayerStateFromFE(refreshArgs);
}

/*
 * Output::updateAndWriteCompositionState()
 */

using OutputUpdateAndWriteCompositionStateTest = OutputTest;

TEST_F(OutputUpdateAndWriteCompositionStateTest, doesNothingIfLayers) {
    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, doesNothingIfOutputNotEnabled) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    mOutput->editState().isEnabled = false;

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    CompositionRefreshArgs args;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, updatesLayerContentForAllLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_180));
    EXPECT_CALL(*layer1.outputLayer, writeStateToHWC(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_180));
    EXPECT_CALL(*layer2.outputLayer, writeStateToHWC(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_180));
    EXPECT_CALL(*layer3.outputLayer, writeStateToHWC(false));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = false;
    args.internalDisplayRotationFlags = ui::Transform::ROT_180;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, updatesLayerGeometryAndContentForAllLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer, writeStateToHWC(true));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer, writeStateToHWC(true));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer, writeStateToHWC(true));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = true;
    args.devOptForceClientComposition = false;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, forcesClientCompositionForAllLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer, writeStateToHWC(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer, writeStateToHWC(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer, writeStateToHWC(false));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = true;
    mOutput->updateAndWriteCompositionState(args);
}

/*
 * Output::prepareFrame()
 */

struct OutputPrepareFrameTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
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
    StrictMock<OutputPartialMock> mOutput;
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
    mOutput->editState().isEnabled = true;
    mOutput->editState().usesClientComposition = false;
    mOutput->editState().usesDeviceComposition = true;

    EXPECT_CALL(*mRenderSurface, prepareFrame(true, false));

    mOutput->prepareFrame();

    EXPECT_TRUE(mOutput->getState().usesClientComposition);
    EXPECT_FALSE(mOutput->getState().usesDeviceComposition);
}

/*
 * Output::prepare()
 */

struct OutputPrepareTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD2(rebuildLayerStacks,
                     void(const compositionengine::CompositionRefreshArgs&,
                          compositionengine::LayerFESet&));
    };

    StrictMock<OutputPartialMock> mOutput;
    CompositionRefreshArgs mRefreshArgs;
    LayerFESet mGeomSnapshots;
};

TEST_F(OutputPrepareTest, justInvokesRebuildLayerStacks) {
    InSequence seq;
    EXPECT_CALL(mOutput, rebuildLayerStacks(Ref(mRefreshArgs), Ref(mGeomSnapshots)));

    mOutput.prepare(mRefreshArgs, mGeomSnapshots);
}

/*
 * Output::rebuildLayerStacks()
 */

struct OutputRebuildLayerStacksTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD2(collectVisibleLayers,
                     void(const compositionengine::CompositionRefreshArgs&,
                          compositionengine::Output::CoverageState&));
    };

    OutputRebuildLayerStacksTest() {
        mOutput.mState.isEnabled = true;
        mOutput.mState.transform = kIdentityTransform;
        mOutput.mState.bounds = kOutputBounds;

        mRefreshArgs.updatingOutputGeometryThisFrame = true;

        mCoverageAboveCoveredLayersToSet = Region(Rect(0, 0, 10, 10));

        EXPECT_CALL(mOutput, collectVisibleLayers(Ref(mRefreshArgs), _))
                .WillRepeatedly(Invoke(this, &OutputRebuildLayerStacksTest::setTestCoverageValues));
    }

    void setTestCoverageValues(const CompositionRefreshArgs&,
                               compositionengine::Output::CoverageState& state) {
        state.aboveCoveredLayers = mCoverageAboveCoveredLayersToSet;
        state.aboveOpaqueLayers = mCoverageAboveOpaqueLayersToSet;
        state.dirtyRegion = mCoverageDirtyRegionToSet;
    }

    static const ui::Transform kIdentityTransform;
    static const ui::Transform kRotate90Transform;
    static const Rect kOutputBounds;

    StrictMock<OutputPartialMock> mOutput;
    CompositionRefreshArgs mRefreshArgs;
    LayerFESet mGeomSnapshots;
    Region mCoverageAboveCoveredLayersToSet;
    Region mCoverageAboveOpaqueLayersToSet;
    Region mCoverageDirtyRegionToSet;
};

const ui::Transform OutputRebuildLayerStacksTest::kIdentityTransform{TR_IDENT, 1920, 1080};
const ui::Transform OutputRebuildLayerStacksTest::kRotate90Transform{TR_ROT_90, 1920, 1080};
const Rect OutputRebuildLayerStacksTest::kOutputBounds{0, 0, 1920, 1080};

TEST_F(OutputRebuildLayerStacksTest, doesNothingIfNotEnabled) {
    mOutput.mState.isEnabled = false;

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);
}

TEST_F(OutputRebuildLayerStacksTest, doesNothingIfNotUpdatingGeometryThisFrame) {
    mRefreshArgs.updatingOutputGeometryThisFrame = false;

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);
}

TEST_F(OutputRebuildLayerStacksTest, computesUndefinedRegionWithNoRotationAndFullCoverage) {
    mOutput.mState.transform = kIdentityTransform;

    mCoverageAboveOpaqueLayersToSet = Region(Rect(0, 0, 1920, 1080));

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);

    EXPECT_THAT(mOutput.mState.undefinedRegion, RegionEq(Region(Rect(0, 0, 0, 0))));
}

TEST_F(OutputRebuildLayerStacksTest, computesUndefinedRegionWithNoRotationAndPartialCoverage) {
    mOutput.mState.transform = kIdentityTransform;

    mCoverageAboveOpaqueLayersToSet = Region(Rect(0, 0, 960, 1080));

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);

    EXPECT_THAT(mOutput.mState.undefinedRegion, RegionEq(Region(Rect(960, 0, 1920, 1080))));
}

TEST_F(OutputRebuildLayerStacksTest, computesUndefinedRegionWith90RotationAndFullCoverage) {
    mOutput.mState.transform = kRotate90Transform;

    mCoverageAboveOpaqueLayersToSet = Region(Rect(0, 0, 1080, 1920));

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);

    EXPECT_THAT(mOutput.mState.undefinedRegion, RegionEq(Region(Rect(0, 0, 0, 0))));
}

TEST_F(OutputRebuildLayerStacksTest, computesUndefinedRegionWith90RotationAndPartialCoverage) {
    mOutput.mState.transform = kRotate90Transform;

    mCoverageAboveOpaqueLayersToSet = Region(Rect(0, 0, 1080, 960));

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);

    EXPECT_THAT(mOutput.mState.undefinedRegion, RegionEq(Region(Rect(0, 0, 960, 1080))));
}

TEST_F(OutputRebuildLayerStacksTest, addsToDirtyRegionWithNoRotation) {
    mOutput.mState.transform = kIdentityTransform;
    mOutput.mState.dirtyRegion = Region(Rect(960, 0, 1920, 1080));

    mCoverageDirtyRegionToSet = Region(Rect(0, 0, 960, 1080));

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);

    EXPECT_THAT(mOutput.mState.dirtyRegion, RegionEq(Region(Rect(0, 0, 1920, 1080))));
}

TEST_F(OutputRebuildLayerStacksTest, addsToDirtyRegionWith90Rotation) {
    mOutput.mState.transform = kRotate90Transform;
    mOutput.mState.dirtyRegion = Region(Rect(0, 960, 1080, 1920));

    mCoverageDirtyRegionToSet = Region(Rect(0, 0, 1080, 960));

    mOutput.rebuildLayerStacks(mRefreshArgs, mGeomSnapshots);

    EXPECT_THAT(mOutput.mState.dirtyRegion, RegionEq(Region(Rect(0, 0, 1080, 1920))));
}

/*
 * Output::collectVisibleLayers()
 */

struct OutputCollectVisibleLayersTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD2(ensureOutputLayerIfVisible,
                     void(sp<compositionengine::LayerFE>&,
                          compositionengine::Output::CoverageState&));
        MOCK_METHOD1(setReleasedLayers, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(finalizePendingOutputLayers, void());
    };

    struct Layer {
        Layer() {
            EXPECT_CALL(outputLayer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
            EXPECT_CALL(outputLayer, editState()).WillRepeatedly(ReturnRef(outputLayerState));
        }

        StrictMock<mock::OutputLayer> outputLayer;
        impl::OutputLayerCompositionState outputLayerState;
        sp<StrictMock<mock::LayerFE>> layerFE{new StrictMock<mock::LayerFE>()};
    };

    OutputCollectVisibleLayersTest() {
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(3u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0))
                .WillRepeatedly(Return(&mLayer1.outputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1))
                .WillRepeatedly(Return(&mLayer2.outputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(2))
                .WillRepeatedly(Return(&mLayer3.outputLayer));

        mRefreshArgs.layers.push_back(mLayer1.layerFE);
        mRefreshArgs.layers.push_back(mLayer2.layerFE);
        mRefreshArgs.layers.push_back(mLayer3.layerFE);
    }

    StrictMock<OutputPartialMock> mOutput;
    CompositionRefreshArgs mRefreshArgs;
    LayerFESet mGeomSnapshots;
    Output::CoverageState mCoverageState{mGeomSnapshots};
    Layer mLayer1;
    Layer mLayer2;
    Layer mLayer3;
};

TEST_F(OutputCollectVisibleLayersTest, doesMinimalWorkIfNoLayers) {
    mRefreshArgs.layers.clear();
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));

    EXPECT_CALL(mOutput, setReleasedLayers(Ref(mRefreshArgs)));
    EXPECT_CALL(mOutput, finalizePendingOutputLayers());

    mOutput.collectVisibleLayers(mRefreshArgs, mCoverageState);
}

TEST_F(OutputCollectVisibleLayersTest, processesCandidateLayersReversedAndSetsOutputLayerZ) {
    // Enforce a call order sequence for this test.
    InSequence seq;

    // Layer coverage is evaluated from front to back!
    EXPECT_CALL(mOutput, ensureOutputLayerIfVisible(Eq(mLayer3.layerFE), Ref(mCoverageState)));
    EXPECT_CALL(mOutput, ensureOutputLayerIfVisible(Eq(mLayer2.layerFE), Ref(mCoverageState)));
    EXPECT_CALL(mOutput, ensureOutputLayerIfVisible(Eq(mLayer1.layerFE), Ref(mCoverageState)));

    EXPECT_CALL(mOutput, setReleasedLayers(Ref(mRefreshArgs)));
    EXPECT_CALL(mOutput, finalizePendingOutputLayers());

    mOutput.collectVisibleLayers(mRefreshArgs, mCoverageState);

    // Ensure all output layers have been assigned a simple/flattened z-order.
    EXPECT_EQ(0u, mLayer1.outputLayerState.z);
    EXPECT_EQ(1u, mLayer2.outputLayerState.z);
    EXPECT_EQ(2u, mLayer3.outputLayerState.z);
}

/*
 * Output::ensureOutputLayerIfVisible()
 */

struct OutputEnsureOutputLayerIfVisibleTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_CONST_METHOD1(belongsInOutput, bool(const sp<compositionengine::LayerFE>&));
        MOCK_CONST_METHOD1(getOutputLayerOrderedByZByIndex, OutputLayer*(size_t));
        MOCK_METHOD2(ensureOutputLayer,
                     compositionengine::OutputLayer*(std::optional<size_t>, const sp<LayerFE>&));
    };

    OutputEnsureOutputLayerIfVisibleTest() {
        EXPECT_CALL(mOutput, belongsInOutput(sp<LayerFE>(mLayer.layerFE)))
                .WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
                .WillRepeatedly(Return(&mLayer.outputLayer));

        mOutput.mState.bounds = Rect(0, 0, 200, 300);
        mOutput.mState.viewport = Rect(0, 0, 200, 300);
        mOutput.mState.transform = ui::Transform(TR_IDENT, 200, 300);

        mLayer.layerFEState.isVisible = true;
        mLayer.layerFEState.isOpaque = true;
        mLayer.layerFEState.contentDirty = true;
        mLayer.layerFEState.geomLayerBounds = FloatRect{0, 0, 100, 200};
        mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);
        mLayer.layerFEState.transparentRegionHint = Region(Rect(0, 0, 100, 100));

        mLayer.outputLayerState.visibleRegion = Region(Rect(0, 0, 50, 200));
        mLayer.outputLayerState.coveredRegion = Region(Rect(50, 0, 100, 200));

        mGeomSnapshots.insert(mLayer.layerFE);
    }

    void ensureOutputLayerIfVisible() {
        sp<LayerFE> layerFE(mLayer.layerFE);
        mOutput.ensureOutputLayerIfVisible(layerFE, mCoverageState);
    }

    static const Region kEmptyRegion;
    static const Region kFullBoundsNoRotation;
    static const Region kRightHalfBoundsNoRotation;
    static const Region kLowerHalfBoundsNoRotation;
    static const Region kFullBounds90Rotation;

    StrictMock<OutputPartialMock> mOutput;
    LayerFESet mGeomSnapshots;
    Output::CoverageState mCoverageState{mGeomSnapshots};

    NonInjectedLayer mLayer;
};

const Region OutputEnsureOutputLayerIfVisibleTest::kEmptyRegion = Region(Rect(0, 0, 0, 0));
const Region OutputEnsureOutputLayerIfVisibleTest::kFullBoundsNoRotation =
        Region(Rect(0, 0, 100, 200));
const Region OutputEnsureOutputLayerIfVisibleTest::kRightHalfBoundsNoRotation =
        Region(Rect(0, 100, 100, 200));
const Region OutputEnsureOutputLayerIfVisibleTest::kLowerHalfBoundsNoRotation =
        Region(Rect(50, 0, 100, 200));
const Region OutputEnsureOutputLayerIfVisibleTest::kFullBounds90Rotation =
        Region(Rect(0, 0, 200, 100));

TEST_F(OutputEnsureOutputLayerIfVisibleTest, performsGeomLatchBeforeCheckingIfLayerBelongs) {
    EXPECT_CALL(mOutput, belongsInOutput(sp<LayerFE>(mLayer.layerFE))).WillOnce(Return(false));
    EXPECT_CALL(*mLayer.layerFE,
                prepareCompositionState(compositionengine::LayerFE::StateSubset::BasicGeometry));

    mGeomSnapshots.clear();

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       skipsLatchIfAlreadyLatchedBeforeCheckingIfLayerBelongs) {
    EXPECT_CALL(mOutput, belongsInOutput(sp<LayerFE>(mLayer.layerFE))).WillOnce(Return(false));

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesEarlyOutIfLayerHasNoCompositionState) {
    EXPECT_CALL(*mLayer.layerFE, getCompositionState()).WillOnce(Return(nullptr));

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesEarlyOutIfLayerNotVisible) {
    mLayer.layerFEState.isVisible = false;

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesEarlyOutIfLayerHasEmptyVisibleRegion) {
    mLayer.layerFEState.geomLayerBounds = FloatRect{0, 0, 0, 0};

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesNotSoEarlyOutifDrawRegionEmpty) {
    mOutput.mState.bounds = Rect(0, 0, 0, 0);

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyNotRotatedLayer) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueDirtyNotRotatedLayer) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForTransparentDirtyNotRotatedLayer) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kEmptyRegion));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kRightHalfBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForTransparentDirtyNotRotatedLayer) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kEmptyRegion));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kRightHalfBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueNonDirtyNotRotatedLayer) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = false;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueNonDirtyNotRotatedLayer) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = false;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kLowerHalfBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyRotated90Layer) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerBounds = FloatRect{0, 0, 200, 100};
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_ROT_90, 100, 200);
    mLayer.outputLayerState.visibleRegion = Region(Rect(0, 0, 100, 100));
    mLayer.outputLayerState.coveredRegion = Region(Rect(100, 0, 200, 100));

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueDirtyRotated90Layer) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerBounds = FloatRect{0, 0, 200, 100};
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_ROT_90, 100, 200);
    mLayer.outputLayerState.visibleRegion = Region(Rect(0, 0, 100, 100));
    mLayer.outputLayerState.coveredRegion = Region(Rect(100, 0, 200, 100));

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyNotRotatedLayerRotatedOutput) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    mOutput.mState.viewport = Rect(0, 0, 300, 200);
    mOutput.mState.transform = ui::Transform(TR_ROT_90, 200, 300);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBounds90Rotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueDirtyNotRotatedLayerRotatedOutput) {
    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    mOutput.mState.viewport = Rect(0, 0, 300, 200);
    mOutput.mState.transform = ui::Transform(TR_ROT_90, 200, 300);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBounds90Rotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyArbitraryTransformLayer) {
    ui::Transform arbitraryTransform;
    arbitraryTransform.set(1, 1, -1, 1);
    arbitraryTransform.set(0, 100);

    mLayer.layerFEState.isOpaque = true;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerBounds = FloatRect{0, 0, 100, 200};
    mLayer.layerFEState.geomLayerTransform = arbitraryTransform;

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    const Region kRegion = Region(Rect(0, 0, 300, 300));
    const Region kRegionClipped = Region(Rect(0, 0, 200, 300));

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kRegion));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kRegion));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kEmptyRegion));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kRegion));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion, RegionEq(kRegion));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion, RegionEq(kRegionClipped));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, coverageAccumulatesTest) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    mCoverageState.dirtyRegion = Region(Rect(0, 0, 500, 500));
    mCoverageState.aboveCoveredLayers = Region(Rect(50, 0, 150, 200));
    mCoverageState.aboveOpaqueLayers = Region(Rect(50, 0, 150, 200));

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    const Region kExpectedDirtyRegion = Region(Rect(0, 0, 500, 500));
    const Region kExpectedAboveCoveredRegion = Region(Rect(0, 0, 150, 200));
    const Region kExpectedAboveOpaqueRegion = Region(Rect(50, 0, 150, 200));
    const Region kExpectedLayerVisibleRegion = Region(Rect(0, 0, 50, 200));
    const Region kExpectedLayerCoveredRegion = Region(Rect(50, 0, 100, 200));
    const Region kExpectedLayerVisibleNonTransparentRegion = Region(Rect(0, 100, 50, 200));

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kExpectedDirtyRegion));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kExpectedAboveCoveredRegion));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kExpectedAboveOpaqueRegion));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kExpectedLayerVisibleRegion));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kExpectedLayerVisibleNonTransparentRegion));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kExpectedLayerCoveredRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion,
                RegionEq(kExpectedLayerVisibleRegion));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, coverageAccumulatesWithShadowsTest) {
    ui::Transform translate;
    translate.set(50, 50);
    mLayer.layerFEState.geomLayerTransform = translate;
    mLayer.layerFEState.shadowRadius = 10.0f;

    mCoverageState.dirtyRegion = Region(Rect(0, 0, 500, 500));
    // half of the layer including the casting shadow is covered and opaque
    mCoverageState.aboveCoveredLayers = Region(Rect(40, 40, 100, 260));
    mCoverageState.aboveOpaqueLayers = Region(Rect(40, 40, 100, 260));

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    const Region kExpectedDirtyRegion = Region(Rect(0, 0, 500, 500));
    const Region kExpectedAboveCoveredRegion = Region(Rect(40, 40, 160, 260));
    // add starting opaque region to the opaque half of the casting layer bounds
    const Region kExpectedAboveOpaqueRegion =
            Region(Rect(40, 40, 100, 260)).orSelf(Rect(100, 50, 150, 250));
    const Region kExpectedLayerVisibleRegion = Region(Rect(100, 40, 160, 260));
    const Region kExpectedoutputSpaceLayerVisibleRegion = Region(Rect(100, 50, 150, 250));
    const Region kExpectedLayerCoveredRegion = Region(Rect(40, 40, 100, 260));
    const Region kExpectedLayerVisibleNonTransparentRegion = Region(Rect(100, 40, 160, 260));
    const Region kExpectedLayerShadowRegion =
            Region(Rect(40, 40, 160, 260)).subtractSelf(Rect(50, 50, 150, 250));

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kExpectedDirtyRegion));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kExpectedAboveCoveredRegion));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kExpectedAboveOpaqueRegion));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kExpectedLayerVisibleRegion));
    EXPECT_THAT(mLayer.outputLayerState.visibleNonTransparentRegion,
                RegionEq(kExpectedLayerVisibleNonTransparentRegion));
    EXPECT_THAT(mLayer.outputLayerState.coveredRegion, RegionEq(kExpectedLayerCoveredRegion));
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceVisibleRegion,
                RegionEq(kExpectedoutputSpaceLayerVisibleRegion));
    EXPECT_THAT(mLayer.outputLayerState.shadowRegion, RegionEq(kExpectedLayerShadowRegion));
    EXPECT_FALSE(kExpectedLayerVisibleRegion.subtract(kExpectedLayerShadowRegion).isEmpty());
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, shadowRegionOnlyTest) {
    ui::Transform translate;
    translate.set(50, 50);
    mLayer.layerFEState.geomLayerTransform = translate;
    mLayer.layerFEState.shadowRadius = 10.0f;

    mCoverageState.dirtyRegion = Region(Rect(0, 0, 500, 500));
    // Casting layer is covered by an opaque region leaving only part of its shadow to be drawn
    mCoverageState.aboveCoveredLayers = Region(Rect(40, 40, 150, 260));
    mCoverageState.aboveOpaqueLayers = Region(Rect(40, 40, 150, 260));

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));

    ensureOutputLayerIfVisible();

    const Region kExpectedLayerVisibleRegion = Region(Rect(150, 40, 160, 260));
    const Region kExpectedLayerShadowRegion =
            Region(Rect(40, 40, 160, 260)).subtractSelf(Rect(50, 50, 150, 250));

    EXPECT_THAT(mLayer.outputLayerState.visibleRegion, RegionEq(kExpectedLayerVisibleRegion));
    EXPECT_THAT(mLayer.outputLayerState.shadowRegion, RegionEq(kExpectedLayerShadowRegion));
    EXPECT_TRUE(kExpectedLayerVisibleRegion.subtract(kExpectedLayerShadowRegion).isEmpty());
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesNotSoEarlyOutifLayerWithShadowIsCovered) {
    ui::Transform translate;
    translate.set(50, 50);
    mLayer.layerFEState.geomLayerTransform = translate;
    mLayer.layerFEState.shadowRadius = 10.0f;

    mCoverageState.dirtyRegion = Region(Rect(0, 0, 500, 500));
    // Casting layer and its shadows are covered by an opaque region
    mCoverageState.aboveCoveredLayers = Region(Rect(40, 40, 160, 260));
    mCoverageState.aboveOpaqueLayers = Region(Rect(40, 40, 160, 260));

    ensureOutputLayerIfVisible();
}

/*
 * Output::present()
 */

struct OutputPresentTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD1(updateColorProfile, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(updateAndWriteCompositionState,
                     void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(setColorTransform, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(beginFrame, void());
        MOCK_METHOD0(prepareFrame, void());
        MOCK_METHOD1(devOptRepaintFlash, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(finishFrame, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(postFramebuffer, void());
    };

    StrictMock<OutputPartialMock> mOutput;
};

TEST_F(OutputPresentTest, justInvokesChildFunctionsInSequence) {
    CompositionRefreshArgs args;

    InSequence seq;
    EXPECT_CALL(mOutput, updateColorProfile(Ref(args)));
    EXPECT_CALL(mOutput, updateAndWriteCompositionState(Ref(args)));
    EXPECT_CALL(mOutput, setColorTransform(Ref(args)));
    EXPECT_CALL(mOutput, beginFrame());
    EXPECT_CALL(mOutput, prepareFrame());
    EXPECT_CALL(mOutput, devOptRepaintFlash(Ref(args)));
    EXPECT_CALL(mOutput, finishFrame(Ref(args)));
    EXPECT_CALL(mOutput, postFramebuffer());

    mOutput.present(args);
}

/*
 * Output::updateColorProfile()
 */

struct OutputUpdateColorProfileTest : public testing::Test {
    using TestType = OutputUpdateColorProfileTest;

    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD1(setColorProfile, void(const ColorProfile&));
    };

    struct Layer {
        Layer() {
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(mLayerFE));
            EXPECT_CALL(mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        StrictMock<mock::LayerFE> mLayerFE;
        LayerFECompositionState mLayerFEState;
    };

    OutputUpdateColorProfileTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));

        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0))
                .WillRepeatedly(Return(&mLayer1.mOutputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1))
                .WillRepeatedly(Return(&mLayer2.mOutputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(2))
                .WillRepeatedly(Return(&mLayer3.mOutputLayer));
    }

    struct ExecuteState : public CallOrderStateMachineHelper<TestType, ExecuteState> {
        void execute() { getInstance()->mOutput.updateColorProfile(getInstance()->mRefreshArgs); }
    };

    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;

    Layer mLayer1;
    Layer mLayer2;
    Layer mLayer3;

    CompositionRefreshArgs mRefreshArgs;
};

// TODO(b/144522012): Refactor Output::updateColorProfile and the related code
// to make it easier to write unit tests.

TEST_F(OutputUpdateColorProfileTest, setsAColorProfileWhenUnmanaged) {
    // When the outputColorSetting is set to kUnmanaged, the implementation sets
    // a simple default color profile without looking at anything else.

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(3u));
    EXPECT_CALL(mOutput,
                setColorProfile(ColorProfileEq(
                        ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                                     ui::RenderIntent::COLORIMETRIC, ui::Dataspace::UNKNOWN})));

    mRefreshArgs.outputColorSetting = OutputColorSetting::kUnmanaged;
    mRefreshArgs.colorSpaceAgnosticDataspace = ui::Dataspace::UNKNOWN;

    mOutput.updateColorProfile(mRefreshArgs);
}

struct OutputUpdateColorProfileTest_GetBestColorModeResultBecomesSetProfile
      : public OutputUpdateColorProfileTest {
    OutputUpdateColorProfileTest_GetBestColorModeResultBecomesSetProfile() {
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;
        mRefreshArgs.colorSpaceAgnosticDataspace = ui::Dataspace::UNKNOWN;
    }

    struct ExpectBestColorModeCallResultUsedToSetColorProfileState
          : public CallOrderStateMachineHelper<
                    TestType, ExpectBestColorModeCallResultUsedToSetColorProfileState> {
        [[nodiscard]] auto expectBestColorModeCallResultUsedToSetColorProfile(
                ui::ColorMode colorMode, ui::Dataspace dataspace, ui::RenderIntent renderIntent) {
            EXPECT_CALL(*getInstance()->mDisplayColorProfile,
                        getBestColorMode(ui::Dataspace::V0_SRGB, ui::RenderIntent::ENHANCE, _, _,
                                         _))
                    .WillOnce(DoAll(SetArgPointee<2>(dataspace), SetArgPointee<3>(colorMode),
                                    SetArgPointee<4>(renderIntent)));
            EXPECT_CALL(getInstance()->mOutput,
                        setColorProfile(
                                ColorProfileEq(ColorProfile{colorMode, dataspace, renderIntent,
                                                            ui::Dataspace::UNKNOWN})));
            return nextState<ExecuteState>();
        }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() {
        return ExpectBestColorModeCallResultUsedToSetColorProfileState::make(this);
    }
};

TEST_F(OutputUpdateColorProfileTest_GetBestColorModeResultBecomesSetProfile,
       Native_Unknown_Colorimetric_Set) {
    verify().expectBestColorModeCallResultUsedToSetColorProfile(ui::ColorMode::NATIVE,
                                                                ui::Dataspace::UNKNOWN,
                                                                ui::RenderIntent::COLORIMETRIC)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_GetBestColorModeResultBecomesSetProfile,
       DisplayP3_DisplayP3_Enhance_Set) {
    verify().expectBestColorModeCallResultUsedToSetColorProfile(ui::ColorMode::DISPLAY_P3,
                                                                ui::Dataspace::DISPLAY_P3,
                                                                ui::RenderIntent::ENHANCE)
            .execute();
}

struct OutputUpdateColorProfileTest_ColorSpaceAgnosticeDataspaceAffectsSetColorProfile
      : public OutputUpdateColorProfileTest {
    OutputUpdateColorProfileTest_ColorSpaceAgnosticeDataspaceAffectsSetColorProfile() {
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
        EXPECT_CALL(*mDisplayColorProfile,
                    getBestColorMode(ui::Dataspace::V0_SRGB, ui::RenderIntent::ENHANCE, _, _, _))
                .WillRepeatedly(DoAll(SetArgPointee<2>(ui::Dataspace::UNKNOWN),
                                      SetArgPointee<3>(ui::ColorMode::NATIVE),
                                      SetArgPointee<4>(ui::RenderIntent::COLORIMETRIC)));
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;
    }

    struct IfColorSpaceAgnosticDataspaceSetToState
          : public CallOrderStateMachineHelper<TestType, IfColorSpaceAgnosticDataspaceSetToState> {
        [[nodiscard]] auto ifColorSpaceAgnosticDataspaceSetTo(ui::Dataspace dataspace) {
            getInstance()->mRefreshArgs.colorSpaceAgnosticDataspace = dataspace;
            return nextState<ThenExpectSetColorProfileCallUsesColorSpaceAgnosticDataspaceState>();
        }
    };

    struct ThenExpectSetColorProfileCallUsesColorSpaceAgnosticDataspaceState
          : public CallOrderStateMachineHelper<
                    TestType, ThenExpectSetColorProfileCallUsesColorSpaceAgnosticDataspaceState> {
        [[nodiscard]] auto thenExpectSetColorProfileCallUsesColorSpaceAgnosticDataspace(
                ui::Dataspace dataspace) {
            EXPECT_CALL(getInstance()->mOutput,
                        setColorProfile(ColorProfileEq(
                                ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                                             ui::RenderIntent::COLORIMETRIC, dataspace})));
            return nextState<ExecuteState>();
        }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return IfColorSpaceAgnosticDataspaceSetToState::make(this); }
};

TEST_F(OutputUpdateColorProfileTest_ColorSpaceAgnosticeDataspaceAffectsSetColorProfile, DisplayP3) {
    verify().ifColorSpaceAgnosticDataspaceSetTo(ui::Dataspace::DISPLAY_P3)
            .thenExpectSetColorProfileCallUsesColorSpaceAgnosticDataspace(ui::Dataspace::DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_ColorSpaceAgnosticeDataspaceAffectsSetColorProfile, V0_SRGB) {
    verify().ifColorSpaceAgnosticDataspaceSetTo(ui::Dataspace::V0_SRGB)
            .thenExpectSetColorProfileCallUsesColorSpaceAgnosticDataspace(ui::Dataspace::V0_SRGB)
            .execute();
}

struct OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference
      : public OutputUpdateColorProfileTest {
    // Internally the implementation looks through the dataspaces of all the
    // visible layers. The topmost one that also has an actual dataspace
    // preference set is used to drive subsequent choices.

    OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference() {
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;
        mRefreshArgs.colorSpaceAgnosticDataspace = ui::Dataspace::UNKNOWN;

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(3u));
        EXPECT_CALL(mOutput, setColorProfile(_)).WillRepeatedly(Return());
    }

    struct IfTopLayerDataspaceState
          : public CallOrderStateMachineHelper<TestType, IfTopLayerDataspaceState> {
        [[nodiscard]] auto ifTopLayerIs(ui::Dataspace dataspace) {
            getInstance()->mLayer3.mLayerFEState.dataspace = dataspace;
            return nextState<AndIfMiddleLayerDataspaceState>();
        }
        [[nodiscard]] auto ifTopLayerHasNoPreference() {
            return ifTopLayerIs(ui::Dataspace::UNKNOWN);
        }
    };

    struct AndIfMiddleLayerDataspaceState
          : public CallOrderStateMachineHelper<TestType, AndIfMiddleLayerDataspaceState> {
        [[nodiscard]] auto andIfMiddleLayerIs(ui::Dataspace dataspace) {
            getInstance()->mLayer2.mLayerFEState.dataspace = dataspace;
            return nextState<AndIfBottomLayerDataspaceState>();
        }
        [[nodiscard]] auto andIfMiddleLayerHasNoPreference() {
            return andIfMiddleLayerIs(ui::Dataspace::UNKNOWN);
        }
    };

    struct AndIfBottomLayerDataspaceState
          : public CallOrderStateMachineHelper<TestType, AndIfBottomLayerDataspaceState> {
        [[nodiscard]] auto andIfBottomLayerIs(ui::Dataspace dataspace) {
            getInstance()->mLayer1.mLayerFEState.dataspace = dataspace;
            return nextState<ThenExpectBestColorModeCallUsesState>();
        }
        [[nodiscard]] auto andIfBottomLayerHasNoPreference() {
            return andIfBottomLayerIs(ui::Dataspace::UNKNOWN);
        }
    };

    struct ThenExpectBestColorModeCallUsesState
          : public CallOrderStateMachineHelper<TestType, ThenExpectBestColorModeCallUsesState> {
        [[nodiscard]] auto thenExpectBestColorModeCallUses(ui::Dataspace dataspace) {
            EXPECT_CALL(*getInstance()->mDisplayColorProfile,
                        getBestColorMode(dataspace, _, _, _, _));
            return nextState<ExecuteState>();
        }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return IfTopLayerDataspaceState::make(this); }
};

TEST_F(OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference,
       noStrongLayerPrefenceUses_V0_SRGB) {
    // If none of the layers indicate a preference, then V0_SRGB is the
    // preferred choice (subject to additional checks).
    verify().ifTopLayerHasNoPreference()
            .andIfMiddleLayerHasNoPreference()
            .andIfBottomLayerHasNoPreference()
            .thenExpectBestColorModeCallUses(ui::Dataspace::V0_SRGB)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference,
       ifTopmostUses_DisplayP3_Then_DisplayP3_Chosen) {
    // If only the topmost layer has a preference, then that is what is chosen.
    verify().ifTopLayerIs(ui::Dataspace::DISPLAY_P3)
            .andIfMiddleLayerHasNoPreference()
            .andIfBottomLayerHasNoPreference()
            .thenExpectBestColorModeCallUses(ui::Dataspace::DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference,
       ifMiddleUses_DisplayP3_Then_DisplayP3_Chosen) {
    // If only the middle layer has a preference, that that is what is chosen.
    verify().ifTopLayerHasNoPreference()
            .andIfMiddleLayerIs(ui::Dataspace::DISPLAY_P3)
            .andIfBottomLayerHasNoPreference()
            .thenExpectBestColorModeCallUses(ui::Dataspace::DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference,
       ifBottomUses_DisplayP3_Then_DisplayP3_Chosen) {
    // If only the middle layer has a preference, that that is what is chosen.
    verify().ifTopLayerHasNoPreference()
            .andIfMiddleLayerHasNoPreference()
            .andIfBottomLayerIs(ui::Dataspace::DISPLAY_P3)
            .thenExpectBestColorModeCallUses(ui::Dataspace::DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference,
       ifTopUses_DisplayBT2020_AndBottomUses_DisplayP3_Then_DisplayBT2020_Chosen) {
    // If multiple layers have a preference, the topmost value is what is used.
    verify().ifTopLayerIs(ui::Dataspace::DISPLAY_BT2020)
            .andIfMiddleLayerHasNoPreference()
            .andIfBottomLayerIs(ui::Dataspace::DISPLAY_P3)
            .thenExpectBestColorModeCallUses(ui::Dataspace::DISPLAY_BT2020)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference,
       ifTopUses_DisplayP3_AndBottomUses_V0_SRGB_Then_DisplayP3_Chosen) {
    // If multiple layers have a preference, the topmost value is what is used.
    verify().ifTopLayerIs(ui::Dataspace::DISPLAY_P3)
            .andIfMiddleLayerHasNoPreference()
            .andIfBottomLayerIs(ui::Dataspace::DISPLAY_BT2020)
            .thenExpectBestColorModeCallUses(ui::Dataspace::DISPLAY_P3)
            .execute();
}

struct OutputUpdateColorProfileTest_ForceOutputColorOverrides
      : public OutputUpdateColorProfileTest {
    // If CompositionRefreshArgs::forceOutputColorMode is set to some specific
    // values, it overrides the layer dataspace choice.

    OutputUpdateColorProfileTest_ForceOutputColorOverrides() {
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;
        mRefreshArgs.colorSpaceAgnosticDataspace = ui::Dataspace::UNKNOWN;

        mLayer1.mLayerFEState.dataspace = ui::Dataspace::DISPLAY_BT2020;

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1u));
        EXPECT_CALL(mOutput, setColorProfile(_)).WillRepeatedly(Return());
    }

    struct IfForceOutputColorModeState
          : public CallOrderStateMachineHelper<TestType, IfForceOutputColorModeState> {
        [[nodiscard]] auto ifForceOutputColorMode(ui::ColorMode colorMode) {
            getInstance()->mRefreshArgs.forceOutputColorMode = colorMode;
            return nextState<ThenExpectBestColorModeCallUsesState>();
        }
        [[nodiscard]] auto ifNoOverride() { return ifForceOutputColorMode(ui::ColorMode::NATIVE); }
    };

    struct ThenExpectBestColorModeCallUsesState
          : public CallOrderStateMachineHelper<TestType, ThenExpectBestColorModeCallUsesState> {
        [[nodiscard]] auto thenExpectBestColorModeCallUses(ui::Dataspace dataspace) {
            EXPECT_CALL(*getInstance()->mDisplayColorProfile,
                        getBestColorMode(dataspace, _, _, _, _));
            return nextState<ExecuteState>();
        }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return IfForceOutputColorModeState::make(this); }
};

TEST_F(OutputUpdateColorProfileTest_ForceOutputColorOverrides, NoOverride_DoesNotOverride) {
    // By default the layer state is used to set the preferred dataspace
    verify().ifNoOverride()
            .thenExpectBestColorModeCallUses(ui::Dataspace::DISPLAY_BT2020)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_ForceOutputColorOverrides, SRGB_Override_USES_V0_SRGB) {
    // Setting ui::ColorMode::SRGB overrides it with ui::Dataspace::V0_SRGB
    verify().ifForceOutputColorMode(ui::ColorMode::SRGB)
            .thenExpectBestColorModeCallUses(ui::Dataspace::V0_SRGB)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_ForceOutputColorOverrides, DisplayP3_Override_Uses_DisplayP3) {
    // Setting ui::ColorMode::DISPLAY_P3 overrides it with ui::Dataspace::DISPLAY_P3
    verify().ifForceOutputColorMode(ui::ColorMode::DISPLAY_P3)
            .thenExpectBestColorModeCallUses(ui::Dataspace::DISPLAY_P3)
            .execute();
}

// HDR output requires all layers to be compatible with the chosen HDR
// dataspace, along with there being proper support.
struct OutputUpdateColorProfileTest_Hdr : public OutputUpdateColorProfileTest {
    OutputUpdateColorProfileTest_Hdr() {
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;
        mRefreshArgs.colorSpaceAgnosticDataspace = ui::Dataspace::UNKNOWN;
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
        EXPECT_CALL(mOutput, setColorProfile(_)).WillRepeatedly(Return());
    }

    static constexpr ui::Dataspace kNonHdrDataspace = ui::Dataspace::DISPLAY_P3;
    static constexpr ui::Dataspace BT2020_PQ = ui::Dataspace::BT2020_PQ;
    static constexpr ui::Dataspace BT2020_HLG = ui::Dataspace::BT2020_HLG;
    static constexpr ui::Dataspace DISPLAY_P3 = ui::Dataspace::DISPLAY_P3;

    struct IfTopLayerDataspaceState
          : public CallOrderStateMachineHelper<TestType, IfTopLayerDataspaceState> {
        [[nodiscard]] auto ifTopLayerIs(ui::Dataspace dataspace) {
            getInstance()->mLayer2.mLayerFEState.dataspace = dataspace;
            return nextState<AndTopLayerCompositionTypeState>();
        }
        [[nodiscard]] auto ifTopLayerIsNotHdr() { return ifTopLayerIs(kNonHdrDataspace); }
    };

    struct AndTopLayerCompositionTypeState
          : public CallOrderStateMachineHelper<TestType, AndTopLayerCompositionTypeState> {
        [[nodiscard]] auto andTopLayerIsREComposed(bool renderEngineComposed) {
            getInstance()->mLayer2.mLayerFEState.forceClientComposition = renderEngineComposed;
            return nextState<AndIfBottomLayerDataspaceState>();
        }
    };

    struct AndIfBottomLayerDataspaceState
          : public CallOrderStateMachineHelper<TestType, AndIfBottomLayerDataspaceState> {
        [[nodiscard]] auto andIfBottomLayerIs(ui::Dataspace dataspace) {
            getInstance()->mLayer1.mLayerFEState.dataspace = dataspace;
            return nextState<AndBottomLayerCompositionTypeState>();
        }
        [[nodiscard]] auto andIfBottomLayerIsNotHdr() {
            return andIfBottomLayerIs(kNonHdrDataspace);
        }
    };

    struct AndBottomLayerCompositionTypeState
          : public CallOrderStateMachineHelper<TestType, AndBottomLayerCompositionTypeState> {
        [[nodiscard]] auto andBottomLayerIsREComposed(bool renderEngineComposed) {
            getInstance()->mLayer1.mLayerFEState.forceClientComposition = renderEngineComposed;
            return nextState<AndIfHasLegacySupportState>();
        }
    };

    struct AndIfHasLegacySupportState
          : public CallOrderStateMachineHelper<TestType, AndIfHasLegacySupportState> {
        [[nodiscard]] auto andIfLegacySupportFor(ui::Dataspace dataspace, bool legacySupport) {
            EXPECT_CALL(*getInstance()->mDisplayColorProfile, hasLegacyHdrSupport(dataspace))
                    .WillOnce(Return(legacySupport));
            return nextState<ThenExpectBestColorModeCallUsesState>();
        }
    };

    struct ThenExpectBestColorModeCallUsesState
          : public CallOrderStateMachineHelper<TestType, ThenExpectBestColorModeCallUsesState> {
        [[nodiscard]] auto thenExpectBestColorModeCallUses(ui::Dataspace dataspace) {
            EXPECT_CALL(*getInstance()->mDisplayColorProfile,
                        getBestColorMode(dataspace, _, _, _, _));
            return nextState<ExecuteState>();
        }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return IfTopLayerDataspaceState::make(this); }
};

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_HW_On_PQ_HW_Uses_PQ) {
    // If all layers use BT2020_PQ, and there are no other special conditions,
    // BT2020_PQ is used.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(BT2020_PQ)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_HW_On_PQ_HW_IfPQHasLegacySupport_Uses_DisplayP3) {
    // BT2020_PQ is not used if there is only legacy support for it.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, true)
            .thenExpectBestColorModeCallUses(DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_HW_On_PQ_RE_Uses_PQ) {
    // BT2020_PQ is still used if the bottom layer is RenderEngine composed.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(true)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(BT2020_PQ)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_RE_On_PQ_HW_Uses_DisplayP3) {
    // BT2020_PQ is not used if the top layer is RenderEngine composed.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(true)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_HW_On_HLG_HW_Uses_PQ) {
    // If there is mixed HLG/PQ use, and the topmost layer is PQ, then PQ is used if there
    // are no other special conditions.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(BT2020_PQ)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_HW_On_HLG_HW_IfPQHasLegacySupport_Uses_DisplayP3) {
    // BT2020_PQ is not used if there is only legacy support for it.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, true)
            .thenExpectBestColorModeCallUses(DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_HW_On_HLG_RE_Uses_PQ) {
    // BT2020_PQ is used if the bottom HLG layer is RenderEngine composed.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(true)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(BT2020_PQ)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_RE_On_HLG_HW_Uses_DisplayP3) {
    // BT2020_PQ is not used if the top PQ layer is RenderEngine composed.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(true)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_HW_On_PQ_HW_Uses_PQ) {
    // If there is mixed HLG/PQ use, and the topmost layer is HLG, then PQ is
    // used if there are no other special conditions.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(BT2020_PQ)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_HW_On_PQ_HW_IfPQHasLegacySupport_Uses_DisplayP3) {
    // BT2020_PQ is not used if there is only legacy support for it.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, true)
            .thenExpectBestColorModeCallUses(DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_HW_On_PQ_RE_Uses_DisplayP3) {
    // BT2020_PQ is not used if the bottom PQ layer is RenderEngine composed.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(true)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_RE_On_PQ_HW_Uses_PQ) {
    // BT2020_PQ is still used if the top HLG layer is RenderEngine composed.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(true)
            .andIfBottomLayerIs(BT2020_PQ)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(BT2020_PQ)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_HW_On_HLG_HW_Uses_HLG) {
    // If all layers use HLG then HLG is used if there are no other special
    // conditions.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_HLG, false)
            .thenExpectBestColorModeCallUses(BT2020_HLG)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_HW_On_HLG_HW_IfPQHasLegacySupport_Uses_DisplayP3) {
    // BT2020_HLG is not used if there is legacy support for it.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_HLG, true)
            .thenExpectBestColorModeCallUses(DISPLAY_P3)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_HW_On_HLG_RE_Uses_HLG) {
    // BT2020_HLG is used even if the bottom layer is client composed.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(true)
            .andIfLegacySupportFor(BT2020_HLG, false)
            .thenExpectBestColorModeCallUses(BT2020_HLG)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_RE_On_HLG_HW_Uses_HLG) {
    // BT2020_HLG is used even if the top layer is client composed.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(true)
            .andIfBottomLayerIs(BT2020_HLG)
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_HLG, false)
            .thenExpectBestColorModeCallUses(BT2020_HLG)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, PQ_HW_On_NonHdr_HW_Uses_PQ) {
    // Even if there are non-HDR layers present, BT2020_PQ can still be used.
    verify().ifTopLayerIs(BT2020_PQ)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIsNotHdr()
            .andBottomLayerIsREComposed(false)
            .andIfLegacySupportFor(BT2020_PQ, false)
            .thenExpectBestColorModeCallUses(BT2020_PQ)
            .execute();
}

TEST_F(OutputUpdateColorProfileTest_Hdr, HLG_HW_On_NonHdr_RE_Uses_HLG) {
    // If all layers use HLG then HLG is used if there are no other special
    // conditions.
    verify().ifTopLayerIs(BT2020_HLG)
            .andTopLayerIsREComposed(false)
            .andIfBottomLayerIsNotHdr()
            .andBottomLayerIsREComposed(true)
            .andIfLegacySupportFor(BT2020_HLG, false)
            .thenExpectBestColorModeCallUses(BT2020_HLG)
            .execute();
}

struct OutputUpdateColorProfile_AffectsChosenRenderIntentTest
      : public OutputUpdateColorProfileTest {
    // The various values for CompositionRefreshArgs::outputColorSetting affect
    // the chosen renderIntent, along with whether the preferred dataspace is an
    // HDR dataspace or not.

    OutputUpdateColorProfile_AffectsChosenRenderIntentTest() {
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;
        mRefreshArgs.colorSpaceAgnosticDataspace = ui::Dataspace::UNKNOWN;
        mLayer1.mLayerFEState.dataspace = ui::Dataspace::BT2020_PQ;
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1u));
        EXPECT_CALL(mOutput, setColorProfile(_)).WillRepeatedly(Return());
        EXPECT_CALL(*mDisplayColorProfile, hasLegacyHdrSupport(ui::Dataspace::BT2020_PQ))
                .WillRepeatedly(Return(false));
    }

    // The tests here involve enough state and GMock setup that using a mini-DSL
    // makes the tests much more readable, and allows the test to focus more on
    // the intent than on some of the details.

    static constexpr ui::Dataspace kNonHdrDataspace = ui::Dataspace::DISPLAY_P3;
    static constexpr ui::Dataspace kHdrDataspace = ui::Dataspace::BT2020_PQ;

    struct IfDataspaceChosenState
          : public CallOrderStateMachineHelper<TestType, IfDataspaceChosenState> {
        [[nodiscard]] auto ifDataspaceChosenIs(ui::Dataspace dataspace) {
            getInstance()->mLayer1.mLayerFEState.dataspace = dataspace;
            return nextState<AndOutputColorSettingState>();
        }
        [[nodiscard]] auto ifDataspaceChosenIsNonHdr() {
            return ifDataspaceChosenIs(kNonHdrDataspace);
        }
        [[nodiscard]] auto ifDataspaceChosenIsHdr() { return ifDataspaceChosenIs(kHdrDataspace); }
    };

    struct AndOutputColorSettingState
          : public CallOrderStateMachineHelper<TestType, AndOutputColorSettingState> {
        [[nodiscard]] auto andOutputColorSettingIs(OutputColorSetting setting) {
            getInstance()->mRefreshArgs.outputColorSetting = setting;
            return nextState<ThenExpectBestColorModeCallUsesState>();
        }
    };

    struct ThenExpectBestColorModeCallUsesState
          : public CallOrderStateMachineHelper<TestType, ThenExpectBestColorModeCallUsesState> {
        [[nodiscard]] auto thenExpectBestColorModeCallUses(ui::RenderIntent intent) {
            EXPECT_CALL(*getInstance()->mDisplayColorProfile,
                        getBestColorMode(getInstance()->mLayer1.mLayerFEState.dataspace, intent, _,
                                         _, _));
            return nextState<ExecuteState>();
        }
    };

    // Tests call one of these two helper member functions to start using the
    // mini-DSL defined above.
    [[nodiscard]] auto verify() { return IfDataspaceChosenState::make(this); }
};

TEST_F(OutputUpdateColorProfile_AffectsChosenRenderIntentTest,
       Managed_NonHdr_Prefers_Colorimetric) {
    verify().ifDataspaceChosenIsNonHdr()
            .andOutputColorSettingIs(OutputColorSetting::kManaged)
            .thenExpectBestColorModeCallUses(ui::RenderIntent::COLORIMETRIC)
            .execute();
}

TEST_F(OutputUpdateColorProfile_AffectsChosenRenderIntentTest,
       Managed_Hdr_Prefers_ToneMapColorimetric) {
    verify().ifDataspaceChosenIsHdr()
            .andOutputColorSettingIs(OutputColorSetting::kManaged)
            .thenExpectBestColorModeCallUses(ui::RenderIntent::TONE_MAP_COLORIMETRIC)
            .execute();
}

TEST_F(OutputUpdateColorProfile_AffectsChosenRenderIntentTest, Enhanced_NonHdr_Prefers_Enhance) {
    verify().ifDataspaceChosenIsNonHdr()
            .andOutputColorSettingIs(OutputColorSetting::kEnhanced)
            .thenExpectBestColorModeCallUses(ui::RenderIntent::ENHANCE)
            .execute();
}

TEST_F(OutputUpdateColorProfile_AffectsChosenRenderIntentTest,
       Enhanced_Hdr_Prefers_ToneMapEnhance) {
    verify().ifDataspaceChosenIsHdr()
            .andOutputColorSettingIs(OutputColorSetting::kEnhanced)
            .thenExpectBestColorModeCallUses(ui::RenderIntent::TONE_MAP_ENHANCE)
            .execute();
}

TEST_F(OutputUpdateColorProfile_AffectsChosenRenderIntentTest, Vendor_NonHdr_Prefers_Vendor) {
    verify().ifDataspaceChosenIsNonHdr()
            .andOutputColorSettingIs(kVendorSpecifiedOutputColorSetting)
            .thenExpectBestColorModeCallUses(
                    static_cast<ui::RenderIntent>(kVendorSpecifiedOutputColorSetting))
            .execute();
}

TEST_F(OutputUpdateColorProfile_AffectsChosenRenderIntentTest, Vendor_Hdr_Prefers_Vendor) {
    verify().ifDataspaceChosenIsHdr()
            .andOutputColorSettingIs(kVendorSpecifiedOutputColorSetting)
            .thenExpectBestColorModeCallUses(
                    static_cast<ui::RenderIntent>(kVendorSpecifiedOutputColorSetting))
            .execute();
}

/*
 * Output::beginFrame()
 */

struct OutputBeginFrameTest : public ::testing::Test {
    using TestType = OutputBeginFrameTest;

    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_CONST_METHOD1(getDirtyRegion, Region(bool));
    };

    OutputBeginFrameTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    struct IfGetDirtyRegionExpectationState
          : public CallOrderStateMachineHelper<TestType, IfGetDirtyRegionExpectationState> {
        [[nodiscard]] auto ifGetDirtyRegionReturns(Region dirtyRegion) {
            EXPECT_CALL(getInstance()->mOutput, getDirtyRegion(false))
                    .WillOnce(Return(dirtyRegion));
            return nextState<AndIfGetOutputLayerCountExpectationState>();
        }
    };

    struct AndIfGetOutputLayerCountExpectationState
          : public CallOrderStateMachineHelper<TestType, AndIfGetOutputLayerCountExpectationState> {
        [[nodiscard]] auto andIfGetOutputLayerCountReturns(size_t layerCount) {
            EXPECT_CALL(getInstance()->mOutput, getOutputLayerCount()).WillOnce(Return(layerCount));
            return nextState<AndIfLastCompositionHadVisibleLayersState>();
        }
    };

    struct AndIfLastCompositionHadVisibleLayersState
          : public CallOrderStateMachineHelper<TestType,
                                               AndIfLastCompositionHadVisibleLayersState> {
        [[nodiscard]] auto andIfLastCompositionHadVisibleLayersIs(bool hadOutputLayers) {
            getInstance()->mOutput.mState.lastCompositionHadVisibleLayers = hadOutputLayers;
            return nextState<ThenExpectRenderSurfaceBeginFrameCallState>();
        }
    };

    struct ThenExpectRenderSurfaceBeginFrameCallState
          : public CallOrderStateMachineHelper<TestType,
                                               ThenExpectRenderSurfaceBeginFrameCallState> {
        [[nodiscard]] auto thenExpectRenderSurfaceBeginFrameCall(bool mustRecompose) {
            EXPECT_CALL(*getInstance()->mRenderSurface, beginFrame(mustRecompose));
            return nextState<ExecuteState>();
        }
    };

    struct ExecuteState : public CallOrderStateMachineHelper<TestType, ExecuteState> {
        [[nodiscard]] auto execute() {
            getInstance()->mOutput.beginFrame();
            return nextState<CheckPostconditionHadVisibleLayersState>();
        }
    };

    struct CheckPostconditionHadVisibleLayersState
          : public CallOrderStateMachineHelper<TestType, CheckPostconditionHadVisibleLayersState> {
        void checkPostconditionHadVisibleLayers(bool expected) {
            EXPECT_EQ(expected, getInstance()->mOutput.mState.lastCompositionHadVisibleLayers);
        }
    };

    // Tests call one of these two helper member functions to start using the
    // mini-DSL defined above.
    [[nodiscard]] auto verify() { return IfGetDirtyRegionExpectationState::make(this); }

    static const Region kEmptyRegion;
    static const Region kNotEmptyRegion;

    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
};

const Region OutputBeginFrameTest::kEmptyRegion{Rect{0, 0, 0, 0}};
const Region OutputBeginFrameTest::kNotEmptyRegion{Rect{0, 0, 1, 1}};

TEST_F(OutputBeginFrameTest, hasDirtyHasLayersHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kNotEmptyRegion)
            .andIfGetOutputLayerCountReturns(1u)
            .andIfLastCompositionHadVisibleLayersIs(true)
            .thenExpectRenderSurfaceBeginFrameCall(true)
            .execute()
            .checkPostconditionHadVisibleLayers(true);
}

TEST_F(OutputBeginFrameTest, hasDirtyNotHasLayersHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kNotEmptyRegion)
            .andIfGetOutputLayerCountReturns(0u)
            .andIfLastCompositionHadVisibleLayersIs(true)
            .thenExpectRenderSurfaceBeginFrameCall(true)
            .execute()
            .checkPostconditionHadVisibleLayers(false);
}

TEST_F(OutputBeginFrameTest, hasDirtyHasLayersNotHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kNotEmptyRegion)
            .andIfGetOutputLayerCountReturns(1u)
            .andIfLastCompositionHadVisibleLayersIs(false)
            .thenExpectRenderSurfaceBeginFrameCall(true)
            .execute()
            .checkPostconditionHadVisibleLayers(true);
}

TEST_F(OutputBeginFrameTest, hasDirtyNotHasLayersNotHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kNotEmptyRegion)
            .andIfGetOutputLayerCountReturns(0u)
            .andIfLastCompositionHadVisibleLayersIs(false)
            .thenExpectRenderSurfaceBeginFrameCall(false)
            .execute()
            .checkPostconditionHadVisibleLayers(false);
}

TEST_F(OutputBeginFrameTest, notHasDirtyHasLayersHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kEmptyRegion)
            .andIfGetOutputLayerCountReturns(1u)
            .andIfLastCompositionHadVisibleLayersIs(true)
            .thenExpectRenderSurfaceBeginFrameCall(false)
            .execute()
            .checkPostconditionHadVisibleLayers(true);
}

TEST_F(OutputBeginFrameTest, notHasDirtyNotHasLayersHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kEmptyRegion)
            .andIfGetOutputLayerCountReturns(0u)
            .andIfLastCompositionHadVisibleLayersIs(true)
            .thenExpectRenderSurfaceBeginFrameCall(false)
            .execute()
            .checkPostconditionHadVisibleLayers(true);
}

TEST_F(OutputBeginFrameTest, notHasDirtyHasLayersNotHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kEmptyRegion)
            .andIfGetOutputLayerCountReturns(1u)
            .andIfLastCompositionHadVisibleLayersIs(false)
            .thenExpectRenderSurfaceBeginFrameCall(false)
            .execute()
            .checkPostconditionHadVisibleLayers(false);
}

TEST_F(OutputBeginFrameTest, notHasDirtyNotHasLayersNotHadLayersLastFrame) {
    verify().ifGetDirtyRegionReturns(kEmptyRegion)
            .andIfGetOutputLayerCountReturns(0u)
            .andIfLastCompositionHadVisibleLayersIs(false)
            .thenExpectRenderSurfaceBeginFrameCall(false)
            .execute()
            .checkPostconditionHadVisibleLayers(false);
}

/*
 * Output::devOptRepaintFlash()
 */

struct OutputDevOptRepaintFlashTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_CONST_METHOD1(getDirtyRegion, Region(bool));
        MOCK_METHOD2(composeSurfaces,
                     std::optional<base::unique_fd>(
                             const Region&, const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(postFramebuffer, void());
        MOCK_METHOD0(prepareFrame, void());
    };

    OutputDevOptRepaintFlashTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    static const Region kEmptyRegion;
    static const Region kNotEmptyRegion;

    StrictMock<OutputPartialMock> mOutput;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    CompositionRefreshArgs mRefreshArgs;
};

const Region OutputDevOptRepaintFlashTest::kEmptyRegion{Rect{0, 0, 0, 0}};
const Region OutputDevOptRepaintFlashTest::kNotEmptyRegion{Rect{0, 0, 1, 1}};

TEST_F(OutputDevOptRepaintFlashTest, doesNothingIfFlashDelayNotSet) {
    mRefreshArgs.devOptFlashDirtyRegionsDelay = {};
    mRefreshArgs.repaintEverything = true;
    mOutput.mState.isEnabled = true;

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

TEST_F(OutputDevOptRepaintFlashTest, postsAndPreparesANewFrameIfNotEnabled) {
    mRefreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::microseconds(1);
    mRefreshArgs.repaintEverything = true;
    mOutput.mState.isEnabled = false;

    InSequence seq;
    EXPECT_CALL(mOutput, postFramebuffer());
    EXPECT_CALL(mOutput, prepareFrame());

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

TEST_F(OutputDevOptRepaintFlashTest, postsAndPreparesANewFrameIfNotDirty) {
    mRefreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::microseconds(1);
    mRefreshArgs.repaintEverything = true;
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, getDirtyRegion(true)).WillOnce(Return(kEmptyRegion));
    EXPECT_CALL(mOutput, postFramebuffer());
    EXPECT_CALL(mOutput, prepareFrame());

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

TEST_F(OutputDevOptRepaintFlashTest, alsoComposesSurfacesAndQueuesABufferIfDirty) {
    mRefreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::microseconds(1);
    mRefreshArgs.repaintEverything = false;
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, getDirtyRegion(false)).WillOnce(Return(kNotEmptyRegion));
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(kNotEmptyRegion), Ref(mRefreshArgs)));
    EXPECT_CALL(*mRenderSurface, queueBuffer(_));
    EXPECT_CALL(mOutput, postFramebuffer());
    EXPECT_CALL(mOutput, prepareFrame());

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

/*
 * Output::finishFrame()
 */

struct OutputFinishFrameTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD2(composeSurfaces,
                     std::optional<base::unique_fd>(
                             const Region&, const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(postFramebuffer, void());
    };

    OutputFinishFrameTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    StrictMock<OutputPartialMock> mOutput;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    CompositionRefreshArgs mRefreshArgs;
};

TEST_F(OutputFinishFrameTest, ifNotEnabledDoesNothing) {
    mOutput.mState.isEnabled = false;

    mOutput.finishFrame(mRefreshArgs);
}

TEST_F(OutputFinishFrameTest, takesEarlyOutifComposeSurfacesReturnsNoFence) {
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION), _));

    mOutput.finishFrame(mRefreshArgs);
}

TEST_F(OutputFinishFrameTest, queuesBufferIfComposeSurfacesReturnsAFence) {
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION), _))
            .WillOnce(Return(ByMove(base::unique_fd())));
    EXPECT_CALL(*mRenderSurface, queueBuffer(_));

    mOutput.finishFrame(mRefreshArgs);
}

/*
 * Output::postFramebuffer()
 */

struct OutputPostFramebufferTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD0(presentAndGetFrameFences, compositionengine::Output::FrameFences());
    };

    struct Layer {
        Layer() {
            EXPECT_CALL(outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(layerFE));
            EXPECT_CALL(outputLayer, getHwcLayer()).WillRepeatedly(Return(&hwc2Layer));
        }

        StrictMock<mock::OutputLayer> outputLayer;
        StrictMock<mock::LayerFE> layerFE;
        StrictMock<HWC2::mock::Layer> hwc2Layer;
    };

    OutputPostFramebufferTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(3u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
                .WillRepeatedly(Return(&mLayer1.outputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1u))
                .WillRepeatedly(Return(&mLayer2.outputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(2u))
                .WillRepeatedly(Return(&mLayer3.outputLayer));
    }

    StrictMock<OutputPartialMock> mOutput;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();

    Layer mLayer1;
    Layer mLayer2;
    Layer mLayer3;
};

TEST_F(OutputPostFramebufferTest, ifNotEnabledDoesNothing) {
    mOutput.mState.isEnabled = false;

    mOutput.postFramebuffer();
}

TEST_F(OutputPostFramebufferTest, ifEnabledMustFlipThenPresentThenSendPresentCompleted) {
    mOutput.mState.isEnabled = true;

    compositionengine::Output::FrameFences frameFences;

    // This should happen even if there are no output layers.
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));

    // For this test in particular we want to make sure the call expectations
    // setup below are satisfied in the specific order.
    InSequence seq;

    EXPECT_CALL(*mRenderSurface, flip());
    EXPECT_CALL(mOutput, presentAndGetFrameFences()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    mOutput.postFramebuffer();
}

TEST_F(OutputPostFramebufferTest, releaseFencesAreSentToLayerFE) {
    // Simulate getting release fences from each layer, and ensure they are passed to the
    // front-end layer interface for each layer correctly.

    mOutput.mState.isEnabled = true;

    // Create three unique fence instances
    sp<Fence> layer1Fence = new Fence();
    sp<Fence> layer2Fence = new Fence();
    sp<Fence> layer3Fence = new Fence();

    Output::FrameFences frameFences;
    frameFences.layerFences.emplace(&mLayer1.hwc2Layer, layer1Fence);
    frameFences.layerFences.emplace(&mLayer2.hwc2Layer, layer2Fence);
    frameFences.layerFences.emplace(&mLayer3.hwc2Layer, layer3Fence);

    EXPECT_CALL(*mRenderSurface, flip());
    EXPECT_CALL(mOutput, presentAndGetFrameFences()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Compare the pointers values of each fence to make sure the correct ones
    // are passed. This happens to work with the current implementation, but
    // would not survive certain calls like Fence::merge() which would return a
    // new instance.
    EXPECT_CALL(mLayer1.layerFE,
                onLayerDisplayed(Property(&sp<Fence>::get, Eq(layer1Fence.get()))));
    EXPECT_CALL(mLayer2.layerFE,
                onLayerDisplayed(Property(&sp<Fence>::get, Eq(layer2Fence.get()))));
    EXPECT_CALL(mLayer3.layerFE,
                onLayerDisplayed(Property(&sp<Fence>::get, Eq(layer3Fence.get()))));

    mOutput.postFramebuffer();
}

TEST_F(OutputPostFramebufferTest, releaseFencesIncludeClientTargetAcquireFence) {
    mOutput.mState.isEnabled = true;
    mOutput.mState.usesClientComposition = true;

    sp<Fence> clientTargetAcquireFence = new Fence();
    sp<Fence> layer1Fence = new Fence();
    sp<Fence> layer2Fence = new Fence();
    sp<Fence> layer3Fence = new Fence();
    Output::FrameFences frameFences;
    frameFences.clientTargetAcquireFence = clientTargetAcquireFence;
    frameFences.layerFences.emplace(&mLayer1.hwc2Layer, layer1Fence);
    frameFences.layerFences.emplace(&mLayer2.hwc2Layer, layer2Fence);
    frameFences.layerFences.emplace(&mLayer3.hwc2Layer, layer3Fence);

    EXPECT_CALL(*mRenderSurface, flip());
    EXPECT_CALL(mOutput, presentAndGetFrameFences()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Fence::merge is called, and since none of the fences are actually valid,
    // Fence::NO_FENCE is returned and passed to each onLayerDisplayed() call.
    // This is the best we can do without creating a real kernel fence object.
    EXPECT_CALL(mLayer1.layerFE, onLayerDisplayed(Fence::NO_FENCE));
    EXPECT_CALL(mLayer2.layerFE, onLayerDisplayed(Fence::NO_FENCE));
    EXPECT_CALL(mLayer3.layerFE, onLayerDisplayed(Fence::NO_FENCE));

    mOutput.postFramebuffer();
}

TEST_F(OutputPostFramebufferTest, releasedLayersSentPresentFence) {
    mOutput.mState.isEnabled = true;
    mOutput.mState.usesClientComposition = true;

    // This should happen even if there are no (current) output layers.
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));

    // Load up the released layers with some mock instances
    sp<StrictMock<mock::LayerFE>> releasedLayer1{new StrictMock<mock::LayerFE>()};
    sp<StrictMock<mock::LayerFE>> releasedLayer2{new StrictMock<mock::LayerFE>()};
    sp<StrictMock<mock::LayerFE>> releasedLayer3{new StrictMock<mock::LayerFE>()};
    Output::ReleasedLayers layers;
    layers.push_back(releasedLayer1);
    layers.push_back(releasedLayer2);
    layers.push_back(releasedLayer3);
    mOutput.setReleasedLayers(std::move(layers));

    // Set up a fake present fence
    sp<Fence> presentFence = new Fence();
    Output::FrameFences frameFences;
    frameFences.presentFence = presentFence;

    EXPECT_CALL(*mRenderSurface, flip());
    EXPECT_CALL(mOutput, presentAndGetFrameFences()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Each released layer should be given the presentFence.
    EXPECT_CALL(*releasedLayer1,
                onLayerDisplayed(Property(&sp<Fence>::get, Eq(presentFence.get()))));
    EXPECT_CALL(*releasedLayer2,
                onLayerDisplayed(Property(&sp<Fence>::get, Eq(presentFence.get()))));
    EXPECT_CALL(*releasedLayer3,
                onLayerDisplayed(Property(&sp<Fence>::get, Eq(presentFence.get()))));

    mOutput.postFramebuffer();

    // After the call the list of released layers should have been cleared.
    EXPECT_TRUE(mOutput.getReleasedLayersForTest().empty());
}

/*
 * Output::composeSurfaces()
 */

struct OutputComposeSurfacesTest : public testing::Test {
    using TestType = OutputComposeSurfacesTest;

    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_CONST_METHOD0(getSkipColorTransform, bool());
        MOCK_METHOD3(generateClientCompositionRequests,
                     std::vector<LayerFE::LayerSettings>(bool, Region&, ui::Dataspace));
        MOCK_METHOD2(appendRegionFlashRequests,
                     void(const Region&, std::vector<LayerFE::LayerSettings>&));
        MOCK_METHOD1(setExpensiveRenderingExpected, void(bool));
    };

    OutputComposeSurfacesTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
        mOutput.cacheClientCompositionRequests(MAX_CLIENT_COMPOSITION_CACHE_SIZE);

        mOutput.mState.frame = kDefaultOutputFrame;
        mOutput.mState.viewport = kDefaultOutputViewport;
        mOutput.mState.sourceClip = kDefaultOutputSourceClip;
        mOutput.mState.destinationClip = kDefaultOutputDestinationClip;
        mOutput.mState.transform = ui::Transform{kDefaultOutputOrientation};
        mOutput.mState.orientation = kDefaultOutputOrientation;
        mOutput.mState.dataspace = kDefaultOutputDataspace;
        mOutput.mState.colorTransformMatrix = kDefaultColorTransformMat;
        mOutput.mState.isSecure = false;
        mOutput.mState.needsFiltering = false;
        mOutput.mState.usesClientComposition = true;
        mOutput.mState.usesDeviceComposition = false;
        mOutput.mState.reusedClientComposition = false;
        mOutput.mState.flipClientTarget = false;

        EXPECT_CALL(mOutput, getCompositionEngine()).WillRepeatedly(ReturnRef(mCompositionEngine));
        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
        EXPECT_CALL(mCompositionEngine, getTimeStats())
                .WillRepeatedly(ReturnRef(*mTimeStats.get()));
        EXPECT_CALL(*mDisplayColorProfile, getHdrCapabilities())
                .WillRepeatedly(ReturnRef(kHdrCapabilities));
    }

    struct ExecuteState : public CallOrderStateMachineHelper<TestType, ExecuteState> {
        auto execute() {
            getInstance()->mReadyFence =
                    getInstance()->mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
            return nextState<FenceCheckState>();
        }
    };

    struct FenceCheckState : public CallOrderStateMachineHelper<TestType, FenceCheckState> {
        void expectNoFenceWasReturned() { EXPECT_FALSE(getInstance()->mReadyFence); }

        void expectAFenceWasReturned() { EXPECT_TRUE(getInstance()->mReadyFence); }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return ExecuteState::make(this); }

    static constexpr uint32_t kDefaultOutputOrientation = TR_IDENT;
    static constexpr ui::Dataspace kDefaultOutputDataspace = ui::Dataspace::UNKNOWN;
    static constexpr ui::Dataspace kExpensiveOutputDataspace = ui::Dataspace::DISPLAY_P3;
    static constexpr float kDefaultMaxLuminance = 0.9f;
    static constexpr float kDefaultAvgLuminance = 0.7f;
    static constexpr float kDefaultMinLuminance = 0.1f;

    static const Rect kDefaultOutputFrame;
    static const Rect kDefaultOutputViewport;
    static const Rect kDefaultOutputSourceClip;
    static const Rect kDefaultOutputDestinationClip;
    static const mat4 kDefaultColorTransformMat;

    static const Region kDebugRegion;
    static const compositionengine::CompositionRefreshArgs kDefaultRefreshArgs;
    static const HdrCapabilities kHdrCapabilities;

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    // TODO: make this is a proper mock.
    std::shared_ptr<TimeStats> mTimeStats = std::make_shared<android::impl::TimeStats>();
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
    sp<GraphicBuffer> mOutputBuffer = new GraphicBuffer();

    std::optional<base::unique_fd> mReadyFence;
};

const Rect OutputComposeSurfacesTest::kDefaultOutputFrame{1001, 1002, 1003, 1004};
const Rect OutputComposeSurfacesTest::kDefaultOutputViewport{1005, 1006, 1007, 1008};
const Rect OutputComposeSurfacesTest::kDefaultOutputSourceClip{1009, 1010, 1011, 1012};
const Rect OutputComposeSurfacesTest::kDefaultOutputDestinationClip{1013, 1014, 1015, 1016};
const mat4 OutputComposeSurfacesTest::kDefaultColorTransformMat{mat4() * 0.5f};
const compositionengine::CompositionRefreshArgs OutputComposeSurfacesTest::kDefaultRefreshArgs;
const Region OutputComposeSurfacesTest::kDebugRegion{Rect{100, 101, 102, 103}};
const HdrCapabilities OutputComposeSurfacesTest::
        kHdrCapabilities{{},
                         OutputComposeSurfacesTest::kDefaultMaxLuminance,
                         OutputComposeSurfacesTest::kDefaultAvgLuminance,
                         OutputComposeSurfacesTest::kDefaultMinLuminance};

TEST_F(OutputComposeSurfacesTest, doesNothingButSignalNoExpensiveRenderingIfNoClientComposition) {
    mOutput.mState.usesClientComposition = false;

    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));

    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(false));

    verify().execute().expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest,
       dequeuesABufferIfNoClientCompositionButFlipClientTargetRequested) {
    mOutput.mState.usesClientComposition = false;
    mOutput.mState.flipClientTarget = true;

    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillOnce(Return(mOutputBuffer));
    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(false));

    verify().execute().expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest, doesMinimalWorkIfDequeueBufferFailsForClientComposition) {
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillOnce(Return(nullptr));

    verify().execute().expectNoFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest,
       doesMinimalWorkIfDequeueBufferFailsForNoClientCompositionButFlipClientTargetRequested) {
    mOutput.mState.usesClientComposition = false;
    mOutput.mState.flipClientTarget = true;

    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillOnce(Return(nullptr));

    verify().execute().expectNoFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest, handlesZeroCompositionRequests) {
    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, IsEmpty(), _, true, _, _))
            .WillRepeatedly(Return(NO_ERROR));

    verify().execute().expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest, buildsAndRendersRequestList) {
    LayerFE::LayerSettings r1;
    LayerFE::LayerSettings r2;

    r1.geometry.boundaries = FloatRect{1, 2, 3, 4};
    r2.geometry.boundaries = FloatRect{5, 6, 7, 8};

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(
                    Invoke([&](const Region&,
                               std::vector<LayerFE::LayerSettings>& clientCompositionLayers) {
                        clientCompositionLayers.emplace_back(r2);
                    }));

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(Pointee(r1), Pointee(r2)), _, true, _, _))
            .WillRepeatedly(Return(NO_ERROR));

    verify().execute().expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest, renderDuplicateClientCompositionRequestsWithoutCache) {
    mOutput.cacheClientCompositionRequests(0);
    LayerFE::LayerSettings r1;
    LayerFE::LayerSettings r2;

    r1.geometry.boundaries = FloatRect{1, 2, 3, 4};
    r2.geometry.boundaries = FloatRect{5, 6, 7, 8};

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1, r2}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(Pointee(r1), Pointee(r2)), _, true, _, _))
            .Times(2)
            .WillOnce(Return(NO_ERROR));

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);
}

TEST_F(OutputComposeSurfacesTest, skipDuplicateClientCompositionRequests) {
    mOutput.cacheClientCompositionRequests(3);
    LayerFE::LayerSettings r1;
    LayerFE::LayerSettings r2;

    r1.geometry.boundaries = FloatRect{1, 2, 3, 4};
    r2.geometry.boundaries = FloatRect{5, 6, 7, 8};

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1, r2}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(Pointee(r1), Pointee(r2)), _, true, _, _))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(false));

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);

    // We do not expect another call to draw layers.
    verify().execute().expectAFenceWasReturned();
    EXPECT_TRUE(mOutput.mState.reusedClientComposition);
}

TEST_F(OutputComposeSurfacesTest, clientCompositionIfBufferChanges) {
    LayerFE::LayerSettings r1;
    LayerFE::LayerSettings r2;

    r1.geometry.boundaries = FloatRect{1, 2, 3, 4};
    r2.geometry.boundaries = FloatRect{5, 6, 7, 8};

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1, r2}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    sp<GraphicBuffer> otherOutputBuffer = new GraphicBuffer();
    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_))
            .WillOnce(Return(mOutputBuffer))
            .WillOnce(Return(otherOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(Pointee(r1), Pointee(r2)), _, true, _, _))
            .WillRepeatedly(Return(NO_ERROR));

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);
}

TEST_F(OutputComposeSurfacesTest, clientCompositionIfRequestChanges) {
    LayerFE::LayerSettings r1;
    LayerFE::LayerSettings r2;
    LayerFE::LayerSettings r3;

    r1.geometry.boundaries = FloatRect{1, 2, 3, 4};
    r2.geometry.boundaries = FloatRect{5, 6, 7, 8};
    r3.geometry.boundaries = FloatRect{5, 6, 7, 9};

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>{r1, r2}))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>{r1, r3}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(Pointee(r1), Pointee(r2)), _, true, _, _))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(Pointee(r1), Pointee(r3)), _, true, _, _))
            .WillOnce(Return(NO_ERROR));

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);
}

struct OutputComposeSurfacesTest_UsesExpectedDisplaySettings : public OutputComposeSurfacesTest {
    OutputComposeSurfacesTest_UsesExpectedDisplaySettings() {
        EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
        EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
        EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
                .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{}));
        EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
                .WillRepeatedly(Return());
        EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    }

    struct MixedCompositionState
          : public CallOrderStateMachineHelper<TestType, MixedCompositionState> {
        auto ifMixedCompositionIs(bool used) {
            getInstance()->mOutput.mState.usesDeviceComposition = used;
            return nextState<OutputUsesHdrState>();
        }
    };

    struct OutputUsesHdrState : public CallOrderStateMachineHelper<TestType, OutputUsesHdrState> {
        auto andIfUsesHdr(bool used) {
            EXPECT_CALL(*getInstance()->mDisplayColorProfile, hasWideColorGamut())
                    .WillOnce(Return(used));
            return nextState<SkipColorTransformState>();
        }
    };

    struct SkipColorTransformState
          : public CallOrderStateMachineHelper<TestType, SkipColorTransformState> {
        auto andIfSkipColorTransform(bool skip) {
            // May be called zero or one times.
            EXPECT_CALL(getInstance()->mOutput, getSkipColorTransform())
                    .WillRepeatedly(Return(skip));
            return nextState<ExpectDisplaySettingsState>();
        }
    };

    struct ExpectDisplaySettingsState
          : public CallOrderStateMachineHelper<TestType, ExpectDisplaySettingsState> {
        auto thenExpectDisplaySettingsUsed(renderengine::DisplaySettings settings) {
            EXPECT_CALL(getInstance()->mRenderEngine, drawLayers(settings, _, _, true, _, _))
                    .WillOnce(Return(NO_ERROR));
            return nextState<ExecuteState>();
        }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return MixedCompositionState::make(this); }
};

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forHdrMixedComposition) {
    verify().ifMixedCompositionIs(true)
            .andIfUsesHdr(true)
            .andIfSkipColorTransform(false)
            .thenExpectDisplaySettingsUsed({kDefaultOutputDestinationClip, kDefaultOutputSourceClip,
                                            kDefaultMaxLuminance, kDefaultOutputDataspace, mat4(),
                                            Region::INVALID_REGION, kDefaultOutputOrientation})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forNonHdrMixedComposition) {
    verify().ifMixedCompositionIs(true)
            .andIfUsesHdr(false)
            .andIfSkipColorTransform(false)
            .thenExpectDisplaySettingsUsed({kDefaultOutputDestinationClip, kDefaultOutputSourceClip,
                                            kDefaultMaxLuminance, kDefaultOutputDataspace, mat4(),
                                            Region::INVALID_REGION, kDefaultOutputOrientation})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forHdrOnlyClientComposition) {
    verify().ifMixedCompositionIs(false)
            .andIfUsesHdr(true)
            .andIfSkipColorTransform(false)
            .thenExpectDisplaySettingsUsed({kDefaultOutputDestinationClip, kDefaultOutputSourceClip,
                                            kDefaultMaxLuminance, kDefaultOutputDataspace,
                                            kDefaultColorTransformMat, Region::INVALID_REGION,
                                            kDefaultOutputOrientation})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forNonHdrOnlyClientComposition) {
    verify().ifMixedCompositionIs(false)
            .andIfUsesHdr(false)
            .andIfSkipColorTransform(false)
            .thenExpectDisplaySettingsUsed({kDefaultOutputDestinationClip, kDefaultOutputSourceClip,
                                            kDefaultMaxLuminance, kDefaultOutputDataspace,
                                            kDefaultColorTransformMat, Region::INVALID_REGION,
                                            kDefaultOutputOrientation})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings,
       usesExpectedDisplaySettingsForHdrOnlyClientCompositionWithSkipClientTransform) {
    verify().ifMixedCompositionIs(false)
            .andIfUsesHdr(true)
            .andIfSkipColorTransform(true)
            .thenExpectDisplaySettingsUsed({kDefaultOutputDestinationClip, kDefaultOutputSourceClip,
                                            kDefaultMaxLuminance, kDefaultOutputDataspace, mat4(),
                                            Region::INVALID_REGION, kDefaultOutputOrientation})
            .execute()
            .expectAFenceWasReturned();
}

struct OutputComposeSurfacesTest_HandlesProtectedContent : public OutputComposeSurfacesTest {
    struct Layer {
        Layer() {
            EXPECT_CALL(mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(mLayerFE));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        StrictMock<mock::LayerFE> mLayerFE;
        LayerFECompositionState mLayerFEState;
    };

    OutputComposeSurfacesTest_HandlesProtectedContent() {
        mLayer1.mLayerFEState.hasProtectedContent = false;
        mLayer2.mLayerFEState.hasProtectedContent = false;

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
                .WillRepeatedly(Return(&mLayer1.mOutputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1u))
                .WillRepeatedly(Return(&mLayer2.mOutputLayer));

        EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));

        EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));

        EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, _))
                .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{}));
        EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
                .WillRepeatedly(Return());
        EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
        EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, true, _, _))
                .WillRepeatedly(Return(NO_ERROR));
    }

    Layer mLayer1;
    Layer mLayer2;
};

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifDisplayIsNotSecure) {
    mOutput.mState.isSecure = false;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(true));
    EXPECT_CALL(mRenderEngine, useProtectedContext(false)).WillOnce(Return(true));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifRenderEngineDoesNotSupportIt) {
    mOutput.mState.isSecure = true;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifNoProtectedContentLayers) {
    mOutput.mState.isSecure = true;
    mLayer2.mLayerFEState.hasProtectedContent = false;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(true)).WillOnce(Return(false));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(true));
    EXPECT_CALL(mRenderEngine, useProtectedContext(false));
    EXPECT_CALL(*mRenderSurface, setProtected(false));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifNotEnabled) {
    mOutput.mState.isSecure = true;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));

    // For this test, we also check the call order of key functions.
    InSequence seq;

    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(false));
    EXPECT_CALL(mRenderEngine, useProtectedContext(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(true));
    EXPECT_CALL(*mRenderSurface, setProtected(true));
    // Must happen after setting the protected content state.
    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, true, _, _)).WillOnce(Return(NO_ERROR));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifAlreadyEnabledEverywhere) {
    mOutput.mState.isSecure = true;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(true));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifFailsToEnableInRenderEngine) {
    mOutput.mState.isSecure = true;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(false)).WillOnce(Return(false));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(false));
    EXPECT_CALL(mRenderEngine, useProtectedContext(true));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifAlreadyEnabledInRenderEngine) {
    mOutput.mState.isSecure = true;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(false));
    EXPECT_CALL(*mRenderSurface, setProtected(true));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifAlreadyEnabledInRenderSurface) {
    mOutput.mState.isSecure = true;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, isProtected).WillOnce(Return(false));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(true));
    EXPECT_CALL(mRenderEngine, useProtectedContext(true));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

struct OutputComposeSurfacesTest_SetsExpensiveRendering : public OutputComposeSurfacesTest {
    OutputComposeSurfacesTest_SetsExpensiveRendering() {
        EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
        EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
        EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
        EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
        EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
                .WillRepeatedly(Return());
        EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    }
};

TEST_F(OutputComposeSurfacesTest_SetsExpensiveRendering, IfExepensiveOutputDataspaceIsUsed) {
    mOutput.mState.dataspace = kExpensiveOutputDataspace;

    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kExpensiveOutputDataspace))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>{}));

    // For this test, we also check the call order of key functions.
    InSequence seq;

    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(true));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, true, _, _)).WillOnce(Return(NO_ERROR));

    mOutput.composeSurfaces(kDebugRegion, kDefaultRefreshArgs);
}

struct OutputComposeSurfacesTest_SetsExpensiveRendering_ForBlur
      : public OutputComposeSurfacesTest_SetsExpensiveRendering {
    OutputComposeSurfacesTest_SetsExpensiveRendering_ForBlur() {
        mLayer.layerFEState.backgroundBlurRadius = 10;
        mOutput.editState().isEnabled = true;

        EXPECT_CALL(mLayer.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
        EXPECT_CALL(mLayer.outputLayer, writeStateToHWC(false));
        EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, kDefaultOutputDataspace))
                .WillOnce(Return(std::vector<LayerFE::LayerSettings>{}));
        EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, true, _, _)).WillOnce(Return(NO_ERROR));
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
                .WillRepeatedly(Return(&mLayer.outputLayer));
    }

    NonInjectedLayer mLayer;
    compositionengine::CompositionRefreshArgs mRefreshArgs;
};

TEST_F(OutputComposeSurfacesTest_SetsExpensiveRendering_ForBlur, IfBlursAreExpensive) {
    mRefreshArgs.blursAreExpensive = true;
    mOutput.updateAndWriteCompositionState(mRefreshArgs);

    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(true));
    mOutput.composeSurfaces(kDebugRegion, mRefreshArgs);
}

TEST_F(OutputComposeSurfacesTest_SetsExpensiveRendering_ForBlur, IfBlursAreNotExpensive) {
    mRefreshArgs.blursAreExpensive = false;
    mOutput.updateAndWriteCompositionState(mRefreshArgs);

    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(true)).Times(0);
    mOutput.composeSurfaces(kDebugRegion, mRefreshArgs);
}

/*
 * Output::generateClientCompositionRequests()
 */

struct GenerateClientCompositionRequestsTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // compositionengine::Output overrides
        std::vector<LayerFE::LayerSettings> generateClientCompositionRequests(
                bool supportsProtectedContent, Region& clearRegion,
                ui::Dataspace dataspace) override {
            return impl::Output::generateClientCompositionRequests(supportsProtectedContent,
                                                                   clearRegion, dataspace);
        }
    };

    struct Layer {
        Layer() {
            EXPECT_CALL(mOutputLayer, getState()).WillRepeatedly(ReturnRef(mOutputLayerState));
            EXPECT_CALL(mOutputLayer, editState()).WillRepeatedly(ReturnRef(mOutputLayerState));
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(mLayerFE));
            EXPECT_CALL(mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        StrictMock<mock::LayerFE> mLayerFE;
        LayerFECompositionState mLayerFEState;
        impl::OutputLayerCompositionState mOutputLayerState;
        LayerFE::LayerSettings mLayerSettings;
    };

    GenerateClientCompositionRequestsTest() {
        mOutput.mState.needsFiltering = false;

        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
};

struct GenerateClientCompositionRequestsTest_ThreeLayers
      : public GenerateClientCompositionRequestsTest {
    GenerateClientCompositionRequestsTest_ThreeLayers() {
        mOutput.mState.frame = kDisplayFrame;
        mOutput.mState.viewport = kDisplayViewport;
        mOutput.mState.sourceClip = kDisplaySourceClip;
        mOutput.mState.destinationClip = kDisplayDestinationClip;
        mOutput.mState.transform = ui::Transform{kDisplayOrientation};
        mOutput.mState.orientation = kDisplayOrientation;
        mOutput.mState.needsFiltering = false;
        mOutput.mState.isSecure = false;

        for (size_t i = 0; i < mLayers.size(); i++) {
            mLayers[i].mOutputLayerState.clearClientTarget = false;
            mLayers[i].mOutputLayerState.visibleRegion = Region(kDisplayFrame);
            mLayers[i].mLayerFEState.isOpaque = true;
            mLayers[i].mLayerSettings.geometry.boundaries =
                    FloatRect{static_cast<float>(i + 1), 0.f, 0.f, 0.f};
            mLayers[i].mLayerSettings.source.solidColor = {1.0f, 1.0f, 1.0f};
            mLayers[i].mLayerSettings.alpha = 1.0f;
            mLayers[i].mLayerSettings.disableBlending = false;

            EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(i))
                    .WillRepeatedly(Return(&mLayers[i].mOutputLayer));
            EXPECT_CALL(mLayers[i].mOutputLayer, requiresClientComposition())
                    .WillRepeatedly(Return(true));
            EXPECT_CALL(mLayers[i].mOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
        }

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(mLayers.size()));
    }

    static constexpr uint32_t kDisplayOrientation = TR_IDENT;
    static constexpr ui::Dataspace kDisplayDataspace = ui::Dataspace::UNKNOWN;

    static const Rect kDisplayFrame;
    static const Rect kDisplayViewport;
    static const Rect kDisplaySourceClip;
    static const Rect kDisplayDestinationClip;

    std::array<Layer, 3> mLayers;
};

const Rect GenerateClientCompositionRequestsTest_ThreeLayers::kDisplayFrame(0, 0, 100, 200);
const Rect GenerateClientCompositionRequestsTest_ThreeLayers::kDisplayViewport(0, 0, 101, 201);
const Rect GenerateClientCompositionRequestsTest_ThreeLayers::kDisplaySourceClip(0, 0, 102, 202);
const Rect GenerateClientCompositionRequestsTest_ThreeLayers::kDisplayDestinationClip(0, 0, 103,
                                                                                      203);

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, handlesNoClientCompostionLayers) {
    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[2].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));

    Region accumClearRegion(Rect(10, 11, 12, 13));
    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    EXPECT_EQ(0u, requests.size());
    EXPECT_THAT(accumClearRegion, RegionEq(Region(Rect(10, 11, 12, 13))));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, requiresVisibleRegionAfterViewportClip) {
    mLayers[0].mOutputLayerState.visibleRegion = Region(Rect(10, 10, 10, 10));
    mLayers[1].mOutputLayerState.visibleRegion = Region(Rect(4000, 0, 4010, 10));
    mLayers[2].mOutputLayerState.visibleRegion = Region(Rect(-10, -10, 0, 0));

    Region accumClearRegion(Rect(10, 11, 12, 13));
    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    EXPECT_EQ(0u, requests.size());
    EXPECT_THAT(accumClearRegion, RegionEq(Region(Rect(10, 11, 12, 13))));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, gathersClientCompositionRequests) {
    LayerFE::LayerSettings mShadowSettings;
    mShadowSettings.source.solidColor = {0.1f, 0.1f, 0.1f};

    EXPECT_CALL(mLayers[0].mLayerFE, prepareClientCompositionList(_))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[1].mLayerFE, prepareClientCompositionList(_))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({mLayers[1].mLayerSettings})));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(_))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>(
                    {mShadowSettings, mLayers[2].mLayerSettings})));

    Region accumClearRegion(Rect(10, 11, 12, 13));
    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    ASSERT_EQ(3u, requests.size());
    EXPECT_EQ(mLayers[1].mLayerSettings, requests[0]);
    EXPECT_EQ(mShadowSettings, requests[1]);
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[2]);

    EXPECT_THAT(accumClearRegion, RegionEq(Region(Rect(10, 11, 12, 13))));

    // Check that a timestamp was set for the layers that generated requests
    EXPECT_TRUE(0 == mLayers[0].mOutputLayerState.clientCompositionTimestamp);
    EXPECT_TRUE(0 != mLayers[1].mOutputLayerState.clientCompositionTimestamp);
    EXPECT_TRUE(0 != mLayers[2].mOutputLayerState.clientCompositionTimestamp);
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       onlyClientComposesClientComposedLayersIfNoClearingNeeded) {
    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[2].mOutputLayer, requiresClientComposition()).WillOnce(Return(true));

    mLayers[0].mOutputLayerState.clearClientTarget = false;
    mLayers[1].mOutputLayerState.clearClientTarget = false;
    mLayers[2].mOutputLayerState.clearClientTarget = false;

    mLayers[0].mLayerFEState.isOpaque = true;
    mLayers[1].mLayerFEState.isOpaque = true;
    mLayers[2].mLayerFEState.isOpaque = true;

    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(_))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({mLayers[2].mLayerSettings})));

    Region accumClearRegion(Rect(10, 11, 12, 13));
    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    ASSERT_EQ(1u, requests.size());
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[0]);

    EXPECT_THAT(accumClearRegion, RegionEq(Region(Rect(10, 11, 12, 13))));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       onlyClientComposesClientComposedLayersIfOthersAreNotOpaque) {
    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[2].mOutputLayer, requiresClientComposition()).WillOnce(Return(true));

    mLayers[0].mOutputLayerState.clearClientTarget = true;
    mLayers[1].mOutputLayerState.clearClientTarget = true;
    mLayers[2].mOutputLayerState.clearClientTarget = true;

    mLayers[0].mLayerFEState.isOpaque = false;
    mLayers[1].mLayerFEState.isOpaque = false;
    mLayers[2].mLayerFEState.isOpaque = false;

    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(_))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({mLayers[2].mLayerSettings})));

    Region accumClearRegion(Rect(10, 11, 12, 13));
    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    ASSERT_EQ(1u, requests.size());
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[0]);

    EXPECT_THAT(accumClearRegion, RegionEq(Region(Rect(10, 11, 12, 13))));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, clearsHWCLayersIfOpaqueAndNotFirst) {
    // If client composition is performed with some layers set to use device
    // composition, device layers after the first layer (device or client) will
    // clear the frame buffer if they are opaque and if that layer has a flag
    // set to do so. The first layer is skipped as the frame buffer is already
    // expected to be clear.

    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[2].mOutputLayer, requiresClientComposition()).WillOnce(Return(true));

    mLayers[0].mOutputLayerState.clearClientTarget = true;
    mLayers[1].mOutputLayerState.clearClientTarget = true;
    mLayers[2].mOutputLayerState.clearClientTarget = true;

    mLayers[0].mLayerFEState.isOpaque = true;
    mLayers[1].mLayerFEState.isOpaque = true;
    mLayers[2].mLayerFEState.isOpaque = true;
    Region accumClearRegion(Rect(10, 11, 12, 13));
    Region dummyRegion;

    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false,       /* identity transform */
            false,       /* needs filtering */
            false,       /* secure */
            false,       /* supports protected content */
            dummyRegion, /* clear region */
            kDisplayViewport,
            kDisplayDataspace,
            false /* realContentIsVisible */,
            true /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    LayerFE::LayerSettings mBlackoutSettings = mLayers[1].mLayerSettings;
    mBlackoutSettings.source.buffer.buffer = nullptr;
    mBlackoutSettings.source.solidColor = {0.1f, 0.1f, 0.1f};
    mBlackoutSettings.alpha = 0.f;
    mBlackoutSettings.disableBlending = true;

    EXPECT_CALL(mLayers[1].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({mBlackoutSettings})));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({mLayers[2].mLayerSettings})));

    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    ASSERT_EQ(2u, requests.size());

    // The second layer is expected to be rendered as alpha=0 black with no blending
    EXPECT_EQ(mBlackoutSettings, requests[0]);

    EXPECT_EQ(mLayers[2].mLayerSettings, requests[1]);

    EXPECT_THAT(accumClearRegion, RegionEq(Region(Rect(10, 11, 12, 13))));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       clippedVisibleRegionUsedToGenerateRequest) {
    mLayers[0].mOutputLayerState.visibleRegion = Region(Rect(10, 10, 20, 20));
    mLayers[1].mOutputLayerState.visibleRegion = Region(Rect(-10, -10, 30, 30));
    mLayers[2].mOutputLayerState.visibleRegion = Region(Rect(-10, 0, 40, 4000));

    Region accumClearRegion(Rect(10, 11, 12, 13));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(Rect(10, 10, 20, 20)),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(Rect(0, 0, 30, 30)),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(Rect(0, 0, 40, 201)),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(mLayers[0].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[1].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                      accumClearRegion, kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       perLayerNeedsFilteringUsedToGenerateRequests) {
    mOutput.mState.needsFiltering = false;
    EXPECT_CALL(mLayers[0].mOutputLayer, needsFiltering()).WillRepeatedly(Return(true));

    Region accumClearRegion(Rect(10, 11, 12, 13));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(mLayers[0].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[1].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                      accumClearRegion, kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       wholeOutputNeedsFilteringUsedToGenerateRequests) {
    mOutput.mState.needsFiltering = true;
    EXPECT_CALL(mLayers[0].mOutputLayer, needsFiltering()).WillRepeatedly(Return(true));

    Region accumClearRegion(Rect(10, 11, 12, 13));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,

    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(mLayers[0].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[1].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                      accumClearRegion, kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       wholeOutputSecurityUsedToGenerateRequests) {
    mOutput.mState.isSecure = true;

    Region accumClearRegion(Rect(10, 11, 12, 13));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            true,  /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            true,  /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            true,  /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(mLayers[0].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[1].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                      accumClearRegion, kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       protectedContentSupportUsedToGenerateRequests) {
    Region accumClearRegion(Rect(10, 11, 12, 13));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            true,  /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            true,  /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* identity transform */
            false, /* needs filtering */
            false, /* secure */
            true,  /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(mLayers[0].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[1].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>()));

    static_cast<void>(mOutput.generateClientCompositionRequests(true /* supportsProtectedContent */,
                                                                accumClearRegion,
                                                                kDisplayDataspace));
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, handlesBackgroundBlurRequests) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    // Layer requesting blur, or below, should request client composition.
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer, writeStateToHWC(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer, writeStateToHWC(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer, writeStateToHWC(false));

    layer2.layerFEState.backgroundBlurRadius = 10;

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = false;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(GenerateClientCompositionRequestsTest, handlesLandscapeModeSplitScreenRequests) {
    // In split-screen landscape mode, the screen is rotated 90 degrees, with
    // one layer on the left covering the left side of the output, and one layer
    // on the right covering that side of the output.

    const Rect kPortraitFrame(0, 0, 1000, 2000);
    const Rect kPortraitViewport(0, 0, 2000, 1000);
    const Rect kPortraitSourceClip(0, 0, 1000, 2000);
    const Rect kPortraitDestinationClip(0, 0, 1000, 2000);
    const uint32_t kPortraitOrientation = TR_ROT_90;
    constexpr ui::Dataspace kOutputDataspace = ui::Dataspace::DISPLAY_P3;

    mOutput.mState.frame = kPortraitFrame;
    mOutput.mState.viewport = kPortraitViewport;
    mOutput.mState.sourceClip = kPortraitSourceClip;
    mOutput.mState.destinationClip = kPortraitDestinationClip;
    mOutput.mState.transform = ui::Transform{kPortraitOrientation};
    mOutput.mState.orientation = kPortraitOrientation;
    mOutput.mState.needsFiltering = false;
    mOutput.mState.isSecure = true;

    Layer leftLayer;
    Layer rightLayer;

    leftLayer.mOutputLayerState.clearClientTarget = false;
    leftLayer.mOutputLayerState.visibleRegion = Region(Rect(0, 0, 1000, 1000));
    leftLayer.mLayerFEState.isOpaque = true;
    leftLayer.mLayerSettings.source.solidColor = {1.f, 0.f, 0.f};

    rightLayer.mOutputLayerState.clearClientTarget = false;
    rightLayer.mOutputLayerState.visibleRegion = Region(Rect(1000, 0, 2000, 1000));
    rightLayer.mLayerFEState.isOpaque = true;
    rightLayer.mLayerSettings.source.solidColor = {0.f, 1.f, 0.f};

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
    EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
            .WillRepeatedly(Return(&leftLayer.mOutputLayer));
    EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1u))
            .WillRepeatedly(Return(&rightLayer.mOutputLayer));

    Region accumClearRegion(Rect(10, 11, 12, 13));

    compositionengine::LayerFE::ClientCompositionTargetSettings leftLayerSettings{
            Region(Rect(0, 0, 1000, 1000)),
            false, /* identity transform */
            false, /* needs filtering */
            true,  /* secure */
            true,  /* supports protected content */
            accumClearRegion,
            kPortraitViewport,
            kOutputDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(leftLayer.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(leftLayer.mOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(leftLayer.mLayerFE, prepareClientCompositionList(Eq(ByRef(leftLayerSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({leftLayer.mLayerSettings})));

    compositionengine::LayerFE::ClientCompositionTargetSettings rightLayerSettings{
            Region(Rect(1000, 0, 2000, 1000)),
            false, /* identity transform */
            false, /* needs filtering */
            true,  /* secure */
            true,  /* supports protected content */
            accumClearRegion,
            kPortraitViewport,
            kOutputDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(rightLayer.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(rightLayer.mOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(rightLayer.mLayerFE, prepareClientCompositionList(Eq(ByRef(rightLayerSettings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({rightLayer.mLayerSettings})));

    constexpr bool supportsProtectedContent = true;
    auto requests = mOutput.generateClientCompositionRequests(supportsProtectedContent,
                                                              accumClearRegion, kOutputDataspace);
    ASSERT_EQ(2u, requests.size());
    EXPECT_EQ(leftLayer.mLayerSettings, requests[0]);
    EXPECT_EQ(rightLayer.mLayerSettings, requests[1]);
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       shadowRegionOnlyVisibleSkipsContentComposition) {
    const Rect kContentWithShadow(40, 40, 70, 90);
    const Rect kContent(50, 50, 60, 80);
    const Region kShadowRegion = Region(kContentWithShadow).subtract(kContent);
    const Region kPartialShadowRegion = Region(kContentWithShadow).subtract(Rect(40, 40, 60, 80));

    Region accumClearRegion(Rect(10, 11, 12, 13));
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2Settings{
            Region(Rect(60, 40, 70, 80)).merge(Rect(40, 80, 70, 90)), /* visible region */
            false,                                                    /* identity transform */
            false,                                                    /* needs filtering */
            false,                                                    /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            false /* realContentIsVisible */,
            false /* clearContent */,
    };

    LayerFE::LayerSettings mShadowSettings;
    mShadowSettings.source.solidColor = {0.1f, 0.1f, 0.1f};

    mLayers[2].mOutputLayerState.visibleRegion = kPartialShadowRegion;
    mLayers[2].mOutputLayerState.shadowRegion = kShadowRegion;

    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2Settings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>({mShadowSettings})));

    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    ASSERT_EQ(1u, requests.size());

    EXPECT_EQ(mShadowSettings, requests[0]);
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       shadowRegionWithContentVisibleRequestsContentAndShadowComposition) {
    const Rect kContentWithShadow(40, 40, 70, 90);
    const Rect kContent(50, 50, 60, 80);
    const Region kShadowRegion = Region(kContentWithShadow).subtract(kContent);
    const Region kPartialContentWithPartialShadowRegion =
            Region(kContentWithShadow).subtract(Rect(40, 40, 50, 80));

    LayerFE::LayerSettings mShadowSettings;
    mShadowSettings.source.solidColor = {0.1f, 0.1f, 0.1f};

    mLayers[2].mOutputLayerState.visibleRegion = kPartialContentWithPartialShadowRegion;
    mLayers[2].mOutputLayerState.shadowRegion = kShadowRegion;

    Region accumClearRegion(Rect(10, 11, 12, 13));
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2Settings{
            Region(Rect(50, 40, 70, 80)).merge(Rect(40, 80, 70, 90)), /* visible region */
            false,                                                    /* identity transform */
            false,                                                    /* needs filtering */
            false,                                                    /* secure */
            false, /* supports protected content */
            accumClearRegion,
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
    };

    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[2].mLayerFE, prepareClientCompositionList(Eq(ByRef(layer2Settings))))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>(
                    {mShadowSettings, mLayers[2].mLayerSettings})));

    auto requests = mOutput.generateClientCompositionRequests(false /* supportsProtectedContent */,
                                                              accumClearRegion, kDisplayDataspace);
    ASSERT_EQ(2u, requests.size());

    EXPECT_EQ(mShadowSettings, requests[0]);
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[1]);
}

} // namespace
} // namespace android::compositionengine
