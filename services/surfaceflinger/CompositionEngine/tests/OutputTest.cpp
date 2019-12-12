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
#include <compositionengine/mock/Layer.h>
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
using testing::DoAll;
using testing::Eq;
using testing::InSequence;
using testing::Mock;
using testing::Property;
using testing::Ref;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;
using testing::StrictMock;

constexpr auto TR_IDENT = 0u;
constexpr auto TR_ROT_90 = HAL_TRANSFORM_ROT_90;

const mat4 kIdentity;
const mat4 kNonIdentityHalf = mat4() * 0.5;
const mat4 kNonIdentityQuarter = mat4() * 0.25;

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
    MOCK_METHOD3(ensureOutputLayer,
                 compositionengine::OutputLayer*(std::optional<size_t>,
                                                 const std::shared_ptr<compositionengine::Layer>&,
                                                 const sp<LayerFE>&));
    MOCK_METHOD0(finalizePendingOutputLayers, void());
    MOCK_METHOD0(clearOutputLayers, void());
    MOCK_CONST_METHOD1(dumpState, void(std::string&));
    MOCK_CONST_METHOD0(getCompositionEngine, const CompositionEngine&());
    MOCK_METHOD2(injectOutputLayerForTest,
                 compositionengine::OutputLayer*(const std::shared_ptr<compositionengine::Layer>&,
                                                 const sp<LayerFE>&));
    MOCK_METHOD1(injectOutputLayerForTest, void(std::unique_ptr<OutputLayer>));

    impl::OutputCompositionState mState;
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

    static const Rect kDefaultDisplaySize;

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    std::shared_ptr<Output> mOutput = createOutput(mCompositionEngine);
};

// Extension of the base test useful for checking interactions with the LayerFE
// functions to latch composition state.
struct OutputLatchFEStateTest : public OutputTest {
    OutputLatchFEStateTest() {
        EXPECT_CALL(*mOutputLayer1, getLayer()).WillRepeatedly(ReturnRef(mLayer1));
        EXPECT_CALL(*mOutputLayer2, getLayer()).WillRepeatedly(ReturnRef(mLayer2));
        EXPECT_CALL(*mOutputLayer3, getLayer()).WillRepeatedly(ReturnRef(mLayer3));

        EXPECT_CALL(*mOutputLayer1, getLayerFE()).WillRepeatedly(ReturnRef(mLayer1FE));
        EXPECT_CALL(*mOutputLayer2, getLayerFE()).WillRepeatedly(ReturnRef(mLayer2FE));
        EXPECT_CALL(*mOutputLayer3, getLayerFE()).WillRepeatedly(ReturnRef(mLayer3FE));

        EXPECT_CALL(mLayer1, editFEState()).WillRepeatedly(ReturnRef(mLayer1FEState));
        EXPECT_CALL(mLayer2, editFEState()).WillRepeatedly(ReturnRef(mLayer2FEState));
        EXPECT_CALL(mLayer3, editFEState()).WillRepeatedly(ReturnRef(mLayer3FEState));
    }

    void injectLayer(std::unique_ptr<mock::OutputLayer> layer) {
        mOutput->injectOutputLayerForTest(std::unique_ptr<OutputLayer>(layer.release()));
    }

    std::unique_ptr<mock::OutputLayer> mOutputLayer1{new StrictMock<mock::OutputLayer>};
    std::unique_ptr<mock::OutputLayer> mOutputLayer2{new StrictMock<mock::OutputLayer>};
    std::unique_ptr<mock::OutputLayer> mOutputLayer3{new StrictMock<mock::OutputLayer>};

    StrictMock<mock::Layer> mLayer1;
    StrictMock<mock::Layer> mLayer2;
    StrictMock<mock::Layer> mLayer3;

    StrictMock<mock::LayerFE> mLayer1FE;
    StrictMock<mock::LayerFE> mLayer2FE;
    StrictMock<mock::LayerFE> mLayer3FE;

    LayerFECompositionState mLayer1FEState;
    LayerFECompositionState mLayer2FEState;
    LayerFECompositionState mLayer3FEState;
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
    const Rect scissor{9, 10, 11, 12};
    const bool needsFiltering = true;

    mOutput->setProjection(transform, orientation, frame, viewport, scissor, needsFiltering);

    EXPECT_THAT(mOutput->getState().transform, transform);
    EXPECT_EQ(orientation, mOutput->getState().orientation);
    EXPECT_EQ(frame, mOutput->getState().frame);
    EXPECT_EQ(viewport, mOutput->getState().viewport);
    EXPECT_EQ(scissor, mOutput->getState().scissor);
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

TEST_F(OutputTest, belongsInOutputFiltersLayersAsExpected) {
    StrictMock<mock::Layer> layer;
    LayerFECompositionState layerFEState;

    EXPECT_CALL(layer, getFEState()).WillRepeatedly(ReturnRef(layerFEState));

    const uint32_t layerStack1 = 123u;
    const uint32_t layerStack2 = 456u;

    // If the output accepts layerStack1 and internal-only layers....
    mOutput->setLayerStackFilter(layerStack1, true);

    // A null layer pointer does not belong to the output
    EXPECT_FALSE(mOutput->belongsInOutput(nullptr));

    // A layer with no layerStack does not belong to it, internal-only or not.
    layerFEState.layerStackId = std::nullopt;
    layerFEState.internalOnly = false;
    EXPECT_FALSE(mOutput->belongsInOutput(&layer));

    layerFEState.layerStackId = std::nullopt;
    layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(&layer));

    // Any layer with layerStack1 belongs to it, internal-only or not.
    layerFEState.layerStackId = layerStack1;
    layerFEState.internalOnly = false;
    EXPECT_TRUE(mOutput->belongsInOutput(&layer));

    layerFEState.layerStackId = layerStack1;
    layerFEState.internalOnly = true;
    EXPECT_TRUE(mOutput->belongsInOutput(&layer));

    layerFEState.layerStackId = layerStack2;
    layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(&layer));

    layerFEState.layerStackId = layerStack2;
    layerFEState.internalOnly = false;
    EXPECT_FALSE(mOutput->belongsInOutput(&layer));

    // If the output accepts layerStack1 but not internal-only layers...
    mOutput->setLayerStackFilter(layerStack1, false);

    // A null layer pointer does not belong to the output
    EXPECT_FALSE(mOutput->belongsInOutput(nullptr));

    // Only non-internal layers with layerStack1 belong to it.
    layerFEState.layerStackId = layerStack1;
    layerFEState.internalOnly = false;
    EXPECT_TRUE(mOutput->belongsInOutput(&layer));

    layerFEState.layerStackId = layerStack1;
    layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(&layer));

    layerFEState.layerStackId = layerStack2;
    layerFEState.internalOnly = true;
    EXPECT_FALSE(mOutput->belongsInOutput(&layer));

    layerFEState.layerStackId = layerStack2;
    layerFEState.internalOnly = false;
    EXPECT_FALSE(mOutput->belongsInOutput(&layer));
}

/*
 * Output::getOutputLayerForLayer()
 */

TEST_F(OutputTest, getOutputLayerForLayerWorks) {
    mock::OutputLayer* outputLayer1 = new StrictMock<mock::OutputLayer>();
    mock::OutputLayer* outputLayer2 = new StrictMock<mock::OutputLayer>();

    mOutput->injectOutputLayerForTest(std::unique_ptr<OutputLayer>(outputLayer1));
    mOutput->injectOutputLayerForTest(nullptr);
    mOutput->injectOutputLayerForTest(std::unique_ptr<OutputLayer>(outputLayer2));

    StrictMock<mock::Layer> layer;
    StrictMock<mock::Layer> otherLayer;

    // If the input layer matches the first OutputLayer, it will be returned.
    EXPECT_CALL(*outputLayer1, getLayer()).WillOnce(ReturnRef(layer));
    EXPECT_EQ(outputLayer1, mOutput->getOutputLayerForLayer(&layer));

    // If the input layer matches the second OutputLayer, it will be returned.
    EXPECT_CALL(*outputLayer1, getLayer()).WillOnce(ReturnRef(otherLayer));
    EXPECT_CALL(*outputLayer2, getLayer()).WillOnce(ReturnRef(layer));
    EXPECT_EQ(outputLayer2, mOutput->getOutputLayerForLayer(&layer));

    // If the input layer does not match an output layer, null will be returned.
    EXPECT_CALL(*outputLayer1, getLayer()).WillOnce(ReturnRef(otherLayer));
    EXPECT_CALL(*outputLayer2, getLayer()).WillOnce(ReturnRef(otherLayer));
    EXPECT_EQ(nullptr, mOutput->getOutputLayerForLayer(&layer));
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

using OutputUpdateLayerStateFromFETest = OutputLatchFEStateTest;

TEST_F(OutputUpdateLayerStateFromFETest, handlesNoOutputLayerCase) {
    CompositionRefreshArgs refreshArgs;

    mOutput->updateLayerStateFromFE(refreshArgs);
}

TEST_F(OutputUpdateLayerStateFromFETest, latchesContentStateForAllContainedLayers) {
    EXPECT_CALL(mLayer1FE,
                latchCompositionState(Ref(mLayer1FEState), LayerFE::StateSubset::Content));
    EXPECT_CALL(mLayer2FE,
                latchCompositionState(Ref(mLayer2FEState), LayerFE::StateSubset::Content));
    EXPECT_CALL(mLayer3FE,
                latchCompositionState(Ref(mLayer3FEState), LayerFE::StateSubset::Content));

    // Note: Must be performed after any expectations on these mocks
    injectLayer(std::move(mOutputLayer1));
    injectLayer(std::move(mOutputLayer2));
    injectLayer(std::move(mOutputLayer3));

    CompositionRefreshArgs refreshArgs;
    refreshArgs.updatingGeometryThisFrame = false;

    mOutput->updateLayerStateFromFE(refreshArgs);
}

TEST_F(OutputUpdateLayerStateFromFETest, latchesGeometryAndContentStateForAllContainedLayers) {
    EXPECT_CALL(mLayer1FE,
                latchCompositionState(Ref(mLayer1FEState),
                                      LayerFE::StateSubset::GeometryAndContent));
    EXPECT_CALL(mLayer2FE,
                latchCompositionState(Ref(mLayer2FEState),
                                      LayerFE::StateSubset::GeometryAndContent));
    EXPECT_CALL(mLayer3FE,
                latchCompositionState(Ref(mLayer3FEState),
                                      LayerFE::StateSubset::GeometryAndContent));

    // Note: Must be performed after any expectations on these mocks
    injectLayer(std::move(mOutputLayer1));
    injectLayer(std::move(mOutputLayer2));
    injectLayer(std::move(mOutputLayer3));

    CompositionRefreshArgs refreshArgs;
    refreshArgs.updatingGeometryThisFrame = true;

    mOutput->updateLayerStateFromFE(refreshArgs);
}

/*
 * Output::updateAndWriteCompositionState()
 */

using OutputUpdateAndWriteCompositionStateTest = OutputLatchFEStateTest;

TEST_F(OutputUpdateAndWriteCompositionStateTest, doesNothingIfLayers) {
    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, doesNothingIfOutputNotEnabled) {
    mOutput->editState().isEnabled = false;

    injectLayer(std::move(mOutputLayer1));
    injectLayer(std::move(mOutputLayer2));
    injectLayer(std::move(mOutputLayer3));

    CompositionRefreshArgs args;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, updatesLayerContentForAllLayers) {
    EXPECT_CALL(*mOutputLayer1, updateCompositionState(false, false));
    EXPECT_CALL(*mOutputLayer1, writeStateToHWC(false));
    EXPECT_CALL(*mOutputLayer2, updateCompositionState(false, false));
    EXPECT_CALL(*mOutputLayer2, writeStateToHWC(false));
    EXPECT_CALL(*mOutputLayer3, updateCompositionState(false, false));
    EXPECT_CALL(*mOutputLayer3, writeStateToHWC(false));

    injectLayer(std::move(mOutputLayer1));
    injectLayer(std::move(mOutputLayer2));
    injectLayer(std::move(mOutputLayer3));

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = false;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, updatesLayerGeometryAndContentForAllLayers) {
    EXPECT_CALL(*mOutputLayer1, updateCompositionState(true, false));
    EXPECT_CALL(*mOutputLayer1, writeStateToHWC(true));
    EXPECT_CALL(*mOutputLayer2, updateCompositionState(true, false));
    EXPECT_CALL(*mOutputLayer2, writeStateToHWC(true));
    EXPECT_CALL(*mOutputLayer3, updateCompositionState(true, false));
    EXPECT_CALL(*mOutputLayer3, writeStateToHWC(true));

    injectLayer(std::move(mOutputLayer1));
    injectLayer(std::move(mOutputLayer2));
    injectLayer(std::move(mOutputLayer3));

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = true;
    args.devOptForceClientComposition = false;
    mOutput->updateAndWriteCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, forcesClientCompositionForAllLayers) {
    EXPECT_CALL(*mOutputLayer1, updateCompositionState(false, true));
    EXPECT_CALL(*mOutputLayer1, writeStateToHWC(false));
    EXPECT_CALL(*mOutputLayer2, updateCompositionState(false, true));
    EXPECT_CALL(*mOutputLayer2, writeStateToHWC(false));
    EXPECT_CALL(*mOutputLayer3, updateCompositionState(false, true));
    EXPECT_CALL(*mOutputLayer3, writeStateToHWC(false));

    injectLayer(std::move(mOutputLayer1));
    injectLayer(std::move(mOutputLayer2));
    injectLayer(std::move(mOutputLayer3));

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
                     void(std::shared_ptr<compositionengine::Layer>,
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
        std::shared_ptr<StrictMock<mock::Layer>> layer{new StrictMock<mock::Layer>()};
        impl::OutputLayerCompositionState outputLayerState;
    };

    OutputCollectVisibleLayersTest() {
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(3));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0))
                .WillRepeatedly(Return(&mLayer1.outputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1))
                .WillRepeatedly(Return(&mLayer2.outputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(2))
                .WillRepeatedly(Return(&mLayer3.outputLayer));

        mRefreshArgs.layers.push_back(mLayer1.layer);
        mRefreshArgs.layers.push_back(mLayer2.layer);
        mRefreshArgs.layers.push_back(mLayer3.layer);
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
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0));

    EXPECT_CALL(mOutput, setReleasedLayers(Ref(mRefreshArgs)));
    EXPECT_CALL(mOutput, finalizePendingOutputLayers());

    mOutput.collectVisibleLayers(mRefreshArgs, mCoverageState);
}

TEST_F(OutputCollectVisibleLayersTest, processesCandidateLayersReversedAndSetsOutputLayerZ) {
    // Enforce a call order sequence for this test.
    InSequence seq;

    // Layer coverage is evaluated from front to back!
    EXPECT_CALL(mOutput, ensureOutputLayerIfVisible(Eq(mLayer3.layer), Ref(mCoverageState)));
    EXPECT_CALL(mOutput, ensureOutputLayerIfVisible(Eq(mLayer2.layer), Ref(mCoverageState)));
    EXPECT_CALL(mOutput, ensureOutputLayerIfVisible(Eq(mLayer1.layer), Ref(mCoverageState)));

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
        MOCK_CONST_METHOD1(belongsInOutput, bool(const compositionengine::Layer*));
        MOCK_CONST_METHOD1(getOutputLayerOrderedByZByIndex, OutputLayer*(size_t));
        MOCK_METHOD3(ensureOutputLayer,
                     compositionengine::OutputLayer*(
                             std::optional<size_t>,
                             const std::shared_ptr<compositionengine::Layer>&, const sp<LayerFE>&));
    };

    OutputEnsureOutputLayerIfVisibleTest() {
        EXPECT_CALL(*mLayer, getLayerFE()).WillRepeatedly(Return(mLayerFE));
        EXPECT_CALL(*mLayer, getFEState()).WillRepeatedly(ReturnRef(mLayerFEState));
        EXPECT_CALL(*mLayer, editFEState()).WillRepeatedly(ReturnRef(mLayerFEState));

        EXPECT_CALL(mOutput, belongsInOutput(mLayer.get())).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
                .WillRepeatedly(Return(&mOutputLayer));

        EXPECT_CALL(mOutputLayer, getState()).WillRepeatedly(ReturnRef(mOutputLayerState));
        EXPECT_CALL(mOutputLayer, editState()).WillRepeatedly(ReturnRef(mOutputLayerState));
        EXPECT_CALL(mOutputLayer, getLayer()).WillRepeatedly(ReturnRef(*mLayer.get()));

        mOutput.mState.bounds = Rect(0, 0, 200, 300);
        mOutput.mState.viewport = Rect(0, 0, 200, 300);
        mOutput.mState.transform = ui::Transform(TR_IDENT, 200, 300);

        mLayerFEState.isVisible = true;
        mLayerFEState.isOpaque = true;
        mLayerFEState.contentDirty = true;
        mLayerFEState.geomLayerBounds = FloatRect{0, 0, 100, 200};
        mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);
        mLayerFEState.transparentRegionHint = Region(Rect(0, 0, 100, 100));

        mOutputLayerState.visibleRegion = Region(Rect(0, 0, 50, 200));
        mOutputLayerState.coveredRegion = Region(Rect(50, 0, 100, 200));

        mGeomSnapshots.insert(mLayerFE);
    }

    static const Region kEmptyRegion;
    static const Region kFullBoundsNoRotation;
    static const Region kRightHalfBoundsNoRotation;
    static const Region kLowerHalfBoundsNoRotation;
    static const Region kFullBounds90Rotation;

    StrictMock<OutputPartialMock> mOutput;
    LayerFESet mGeomSnapshots;
    Output::CoverageState mCoverageState{mGeomSnapshots};

    std::shared_ptr<mock::Layer> mLayer{new StrictMock<mock::Layer>()};
    sp<StrictMock<mock::LayerFE>> mLayerFE{new StrictMock<mock::LayerFE>()};
    LayerFECompositionState mLayerFEState;
    mock::OutputLayer mOutputLayer;
    impl::OutputLayerCompositionState mOutputLayerState;
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

TEST_F(OutputEnsureOutputLayerIfVisibleTest, doesNothingIfNoLayerFE) {
    EXPECT_CALL(*mLayer, getLayerFE).WillOnce(Return(sp<LayerFE>()));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, performsGeomLatchBeforeCheckingIfLayerBelongs) {
    EXPECT_CALL(mOutput, belongsInOutput(mLayer.get())).WillOnce(Return(false));
    EXPECT_CALL(*mLayerFE.get(),
                latchCompositionState(Ref(mLayerFEState),
                                      compositionengine::LayerFE::StateSubset::BasicGeometry));

    mGeomSnapshots.clear();

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       skipsLatchIfAlreadyLatchedBeforeCheckingIfLayerBelongs) {
    EXPECT_CALL(mOutput, belongsInOutput(mLayer.get())).WillOnce(Return(false));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesEarlyOutIfLayerNotVisible) {
    mLayerFEState.isVisible = false;

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesEarlyOutIfLayerHasEmptyVisibleRegion) {
    mLayerFEState.geomLayerBounds = FloatRect{0, 0, 0, 0};

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, takesNotSoEarlyOutifDrawRegionEmpty) {
    mOutput.mState.bounds = Rect(0, 0, 0, 0);

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyNotRotatedLayer) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueDirtyNotRotatedLayer) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForTransparentDirtyNotRotatedLayer) {
    mLayerFEState.isOpaque = false;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kEmptyRegion));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion,
                RegionEq(kRightHalfBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForTransparentDirtyNotRotatedLayer) {
    mLayerFEState.isOpaque = false;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kEmptyRegion));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion,
                RegionEq(kRightHalfBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueNonDirtyNotRotatedLayer) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = false;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueNonDirtyNotRotatedLayer) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = false;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kLowerHalfBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyRotated90Layer) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerBounds = FloatRect{0, 0, 200, 100};
    mLayerFEState.geomLayerTransform = ui::Transform(TR_ROT_90, 100, 200);
    mOutputLayerState.visibleRegion = Region(Rect(0, 0, 100, 100));
    mOutputLayerState.coveredRegion = Region(Rect(100, 0, 200, 100));

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueDirtyRotated90Layer) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerBounds = FloatRect{0, 0, 200, 100};
    mLayerFEState.geomLayerTransform = ui::Transform(TR_ROT_90, 100, 200);
    mOutputLayerState.visibleRegion = Region(Rect(0, 0, 100, 100));
    mOutputLayerState.coveredRegion = Region(Rect(100, 0, 200, 100));

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBoundsNoRotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyNotRotatedLayerRotatedOutput) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    mOutput.mState.viewport = Rect(0, 0, 300, 200);
    mOutput.mState.transform = ui::Transform(TR_ROT_90, 200, 300);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBounds90Rotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesUpdatingOutputLayerForOpaqueDirtyNotRotatedLayerRotatedOutput) {
    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    mOutput.mState.viewport = Rect(0, 0, 300, 200);
    mOutput.mState.transform = ui::Transform(TR_ROT_90, 200, 300);

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kFullBoundsNoRotation));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kFullBoundsNoRotation));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kFullBounds90Rotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       handlesCreatingOutputLayerForOpaqueDirtyArbitraryTransformLayer) {
    ui::Transform arbitraryTransform;
    arbitraryTransform.set(1, 1, -1, 1);
    arbitraryTransform.set(0, 100);

    mLayerFEState.isOpaque = true;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerBounds = FloatRect{0, 0, 100, 200};
    mLayerFEState.geomLayerTransform = arbitraryTransform;

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    const Region kRegion = Region(Rect(0, 0, 300, 300));
    const Region kRegionClipped = Region(Rect(0, 0, 200, 300));

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kRegion));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kRegion));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kEmptyRegion));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kRegion));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion, RegionEq(kRegion));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kEmptyRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kRegionClipped));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, coverageAccumulatesTest) {
    mLayerFEState.isOpaque = false;
    mLayerFEState.contentDirty = true;
    mLayerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);

    mCoverageState.dirtyRegion = Region(Rect(0, 0, 500, 500));
    mCoverageState.aboveCoveredLayers = Region(Rect(50, 0, 150, 200));
    mCoverageState.aboveOpaqueLayers = Region(Rect(50, 0, 150, 200));

    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(0u), Eq(mLayer), Eq(mLayerFE)))
            .WillOnce(Return(&mOutputLayer));

    mOutput.ensureOutputLayerIfVisible(mLayer, mCoverageState);

    const Region kExpectedDirtyRegion = Region(Rect(0, 0, 500, 500));
    const Region kExpectedAboveCoveredRegion = Region(Rect(0, 0, 150, 200));
    const Region kExpectedAboveOpaqueRegion = Region(Rect(50, 0, 150, 200));
    const Region kExpectedLayerVisibleRegion = Region(Rect(0, 0, 50, 200));
    const Region kExpectedLayerCoveredRegion = Region(Rect(50, 0, 100, 200));
    const Region kExpectedLayerVisibleNonTransparentRegion = Region(Rect(0, 100, 50, 200));

    EXPECT_THAT(mCoverageState.dirtyRegion, RegionEq(kExpectedDirtyRegion));
    EXPECT_THAT(mCoverageState.aboveCoveredLayers, RegionEq(kExpectedAboveCoveredRegion));
    EXPECT_THAT(mCoverageState.aboveOpaqueLayers, RegionEq(kExpectedAboveOpaqueRegion));

    EXPECT_THAT(mOutputLayerState.visibleRegion, RegionEq(kExpectedLayerVisibleRegion));
    EXPECT_THAT(mOutputLayerState.visibleNonTransparentRegion,
                RegionEq(kExpectedLayerVisibleNonTransparentRegion));
    EXPECT_THAT(mOutputLayerState.coveredRegion, RegionEq(kExpectedLayerCoveredRegion));
    EXPECT_THAT(mOutputLayerState.outputSpaceVisibleRegion, RegionEq(kExpectedLayerVisibleRegion));
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
            EXPECT_CALL(mOutputLayer, getLayer()).WillRepeatedly(ReturnRef(mLayer));
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(mLayerFE));
            EXPECT_CALL(mLayer, getFEState()).WillRepeatedly(ReturnRef(mLayerFEState));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        StrictMock<mock::Layer> mLayer;
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

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(3));
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
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0));
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
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0));
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

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(3));
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

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1));
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
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2));
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
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1));
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
        MOCK_METHOD1(composeSurfaces, std::optional<base::unique_fd>(const Region&));
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
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(kNotEmptyRegion)));
    EXPECT_CALL(*mRenderSurface, queueBuffer(_));
    EXPECT_CALL(mOutput, postFramebuffer());
    EXPECT_CALL(mOutput, prepareFrame());

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

// TODO(b/144060211) - Add coverage

/*
 * Output::finishFrame()
 */

struct OutputFinishFrameTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD1(composeSurfaces, std::optional<base::unique_fd>(const Region&));
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
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION)));

    mOutput.finishFrame(mRefreshArgs);
}

TEST_F(OutputFinishFrameTest, queuesBufferIfComposeSurfacesReturnsAFence) {
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION)))
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
    static constexpr uint32_t kDefaultOutputOrientation = TR_IDENT;
    static constexpr ui::Dataspace kDefaultOutputDataspace = ui::Dataspace::DISPLAY_P3;

    static const Rect kDefaultOutputFrame;
    static const Rect kDefaultOutputViewport;
    static const Rect kDefaultOutputScissor;
    static const mat4 kDefaultColorTransformMat;

    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_CONST_METHOD0(getSkipColorTransform, bool());
        MOCK_METHOD3(generateClientCompositionRequests,
                     std::vector<renderengine::LayerSettings>(bool, Region&, ui::Dataspace));
        MOCK_METHOD2(appendRegionFlashRequests,
                     void(const Region&, std::vector<renderengine::LayerSettings>&));
        MOCK_METHOD1(setExpensiveRenderingExpected, void(bool));
    };

    OutputComposeSurfacesTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));

        mOutput.editState().frame = kDefaultOutputFrame;
        mOutput.editState().viewport = kDefaultOutputViewport;
        mOutput.editState().scissor = kDefaultOutputScissor;
        mOutput.editState().transform = ui::Transform{kDefaultOutputOrientation};
        mOutput.editState().orientation = kDefaultOutputOrientation;
        mOutput.editState().dataspace = kDefaultOutputDataspace;
        mOutput.editState().colorTransformMatrix = kDefaultColorTransformMat;
        mOutput.editState().isSecure = true;
        mOutput.editState().needsFiltering = false;
        mOutput.editState().usesClientComposition = true;
        mOutput.editState().usesDeviceComposition = false;

        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
                .WillRepeatedly(Return(&mOutputLayer1));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1u))
                .WillRepeatedly(Return(&mOutputLayer2));
        EXPECT_CALL(mOutput, getCompositionEngine()).WillRepeatedly(ReturnRef(mCompositionEngine));
        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
        EXPECT_CALL(mCompositionEngine, getTimeStats())
                .WillRepeatedly(ReturnRef(*mTimeStats.get()));
    }

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    // TODO: make this is a proper mock.
    std::shared_ptr<TimeStats> mTimeStats = std::make_shared<android::impl::TimeStats>();
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<mock::OutputLayer> mOutputLayer1;
    StrictMock<mock::OutputLayer> mOutputLayer2;
    StrictMock<OutputPartialMock> mOutput;
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
    std::optional<base::unique_fd> readyFence = mOutput.composeSurfaces(debugRegion);
    EXPECT_TRUE(readyFence);
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
    EXPECT_CALL(mOutput, generateClientCompositionRequests(false, _, _)).Times(1);
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _)).Times(1);
    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(true)).Times(1);
    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(false)).Times(1);

    std::optional<base::unique_fd> readyFence = mOutput.composeSurfaces(kDebugRegion);
    EXPECT_TRUE(readyFence);
}

/*
 * Output::generateClientCompositionRequests()
 */

struct GenerateClientCompositionRequestsTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // compositionengine::Output overrides
        std::vector<renderengine::LayerSettings> generateClientCompositionRequests(
                bool supportsProtectedContent, Region& clearRegion,
                ui::Dataspace dataspace) override {
            return impl::Output::generateClientCompositionRequests(supportsProtectedContent,
                                                                   clearRegion, dataspace);
        }
    };

    GenerateClientCompositionRequestsTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
};

// TODO(b/121291683): Add more unit test coverage for generateClientCompositionRequests

TEST_F(GenerateClientCompositionRequestsTest, worksForLandscapeModeSplitScreen) {
    // In split-screen landscape mode, the screen is rotated 90 degrees, with
    // one layer on the left covering the left side of the output, and one layer
    // on the right covering that side of the output.

    StrictMock<mock::OutputLayer> leftOutputLayer;
    StrictMock<mock::OutputLayer> rightOutputLayer;

    StrictMock<mock::Layer> leftLayer;
    StrictMock<mock::LayerFE> leftLayerFE;
    StrictMock<mock::Layer> rightLayer;
    StrictMock<mock::LayerFE> rightLayerFE;

    impl::OutputLayerCompositionState leftOutputLayerState;
    leftOutputLayerState.clearClientTarget = false;
    leftOutputLayerState.visibleRegion = Region{Rect{0, 0, 1000, 1000}};

    LayerFECompositionState leftLayerFEState;
    leftLayerFEState.isOpaque = true;

    const half3 leftLayerColor{1.f, 0.f, 0.f};
    renderengine::LayerSettings leftLayerRESettings;
    leftLayerRESettings.source.solidColor = leftLayerColor;

    impl::OutputLayerCompositionState rightOutputLayerState;
    rightOutputLayerState.clearClientTarget = false;
    rightOutputLayerState.visibleRegion = Region{Rect{1000, 0, 2000, 1000}};

    LayerFECompositionState rightLayerFEState;
    rightLayerFEState.isOpaque = true;

    const half3 rightLayerColor{0.f, 1.f, 0.f};
    renderengine::LayerSettings rightLayerRESettings;
    rightLayerRESettings.source.solidColor = rightLayerColor;

    EXPECT_CALL(leftOutputLayer, getState()).WillRepeatedly(ReturnRef(leftOutputLayerState));
    EXPECT_CALL(leftOutputLayer, getLayer()).WillRepeatedly(ReturnRef(leftLayer));
    EXPECT_CALL(leftOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(leftLayerFE));
    EXPECT_CALL(leftOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(leftOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(leftLayer, getFEState()).WillRepeatedly(ReturnRef(leftLayerFEState));
    EXPECT_CALL(leftLayerFE, prepareClientComposition(_)).WillOnce(Return(leftLayerRESettings));
    EXPECT_CALL(leftLayerFE, prepareShadowClientComposition(_, _, _))
            .WillOnce(Return(std::optional<renderengine::LayerSettings>()));
    EXPECT_CALL(leftOutputLayer, editState()).WillRepeatedly(ReturnRef(leftOutputLayerState));

    EXPECT_CALL(rightOutputLayer, getState()).WillRepeatedly(ReturnRef(rightOutputLayerState));
    EXPECT_CALL(rightOutputLayer, getLayer()).WillRepeatedly(ReturnRef(rightLayer));
    EXPECT_CALL(rightOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(rightLayerFE));
    EXPECT_CALL(rightOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(rightOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(rightLayer, getFEState()).WillRepeatedly(ReturnRef(rightLayerFEState));
    EXPECT_CALL(rightLayerFE, prepareClientComposition(_)).WillOnce(Return(rightLayerRESettings));
    EXPECT_CALL(rightLayerFE, prepareShadowClientComposition(_, _, _))
            .WillOnce(Return(std::optional<renderengine::LayerSettings>()));
    EXPECT_CALL(rightOutputLayer, editState()).WillRepeatedly(ReturnRef(rightOutputLayerState));

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
    EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
            .WillRepeatedly(Return(&leftOutputLayer));
    EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1u))
            .WillRepeatedly(Return(&rightOutputLayer));

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
    auto requests = mOutput.generateClientCompositionRequests(supportsProtectedContent, clearRegion,
                                                              mOutput.getState().targetDataspace);

    ASSERT_EQ(2u, requests.size());
    EXPECT_EQ(leftLayerColor, requests[0].source.solidColor);
    EXPECT_EQ(rightLayerColor, requests[1].source.solidColor);
}

TEST_F(GenerateClientCompositionRequestsTest, ignoresLayersThatDoNotIntersectWithViewport) {
    // Layers whose visible region does not intersect with the viewport will be
    // skipped when generating client composition request state.

    StrictMock<mock::OutputLayer> outputLayer;
    StrictMock<mock::Layer> layer;
    StrictMock<mock::LayerFE> layerFE;

    impl::OutputLayerCompositionState outputLayerState;
    outputLayerState.clearClientTarget = false;
    outputLayerState.visibleRegion = Region{Rect{3000, 0, 4000, 1000}};

    LayerFECompositionState layerFEState;
    layerFEState.isOpaque = true;

    EXPECT_CALL(outputLayer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
    EXPECT_CALL(outputLayer, getLayer()).WillRepeatedly(ReturnRef(layer));
    EXPECT_CALL(outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(layerFE));
    EXPECT_CALL(outputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(outputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(layer, getFEState()).WillRepeatedly(ReturnRef(layerFEState));
    EXPECT_CALL(layerFE, prepareClientComposition(_)).Times(0);
    EXPECT_CALL(outputLayer, editState()).WillRepeatedly(ReturnRef(outputLayerState));

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1u));
    EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u)).WillRepeatedly(Return(&outputLayer));

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
    auto requests = mOutput.generateClientCompositionRequests(supportsProtectedContent, clearRegion,
                                                              mOutput.getState().targetDataspace);

    EXPECT_EQ(0u, requests.size());
}

TEST_F(GenerateClientCompositionRequestsTest, clearsDeviceLayesAfterFirst) {
    // If client composition is performed with some layers set to use device
    // composition, device layers after the first layer (device or client) will
    // clear the frame buffer if they are opaque and if that layer has a flag
    // set to do so. The first layer is skipped as the frame buffer is already
    // expected to be clear.

    StrictMock<mock::OutputLayer> leftOutputLayer;
    StrictMock<mock::OutputLayer> rightOutputLayer;

    StrictMock<mock::Layer> leftLayer;
    StrictMock<mock::LayerFE> leftLayerFE;
    StrictMock<mock::Layer> rightLayer;
    StrictMock<mock::LayerFE> rightLayerFE;

    impl::OutputLayerCompositionState leftOutputLayerState;
    leftOutputLayerState.clearClientTarget = true;
    leftOutputLayerState.visibleRegion = Region{Rect{0, 0, 1000, 1000}};

    LayerFECompositionState leftLayerFEState;
    leftLayerFEState.isOpaque = true;

    impl::OutputLayerCompositionState rightOutputLayerState;
    rightOutputLayerState.clearClientTarget = true;
    rightOutputLayerState.visibleRegion = Region{Rect{1000, 0, 2000, 1000}};

    LayerFECompositionState rightLayerFEState;
    rightLayerFEState.isOpaque = true;

    const half3 rightLayerColor{0.f, 1.f, 0.f};
    renderengine::LayerSettings rightLayerRESettings;
    rightLayerRESettings.geometry.boundaries = FloatRect{456, 0, 0, 0};
    rightLayerRESettings.source.solidColor = rightLayerColor;

    EXPECT_CALL(leftOutputLayer, getState()).WillRepeatedly(ReturnRef(leftOutputLayerState));
    EXPECT_CALL(leftOutputLayer, getLayer()).WillRepeatedly(ReturnRef(leftLayer));
    EXPECT_CALL(leftOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(leftLayerFE));
    EXPECT_CALL(leftOutputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(leftOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(leftLayer, getFEState()).WillRepeatedly(ReturnRef(leftLayerFEState));
    EXPECT_CALL(leftOutputLayer, editState()).WillRepeatedly(ReturnRef(leftOutputLayerState));

    EXPECT_CALL(rightOutputLayer, getState()).WillRepeatedly(ReturnRef(rightOutputLayerState));
    EXPECT_CALL(rightOutputLayer, getLayer()).WillRepeatedly(ReturnRef(rightLayer));
    EXPECT_CALL(rightOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(rightLayerFE));
    EXPECT_CALL(rightOutputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(rightOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(rightLayer, getFEState()).WillRepeatedly(ReturnRef(rightLayerFEState));
    EXPECT_CALL(rightLayerFE, prepareClientComposition(_)).WillOnce(Return(rightLayerRESettings));
    EXPECT_CALL(rightOutputLayer, editState()).WillRepeatedly(ReturnRef(rightOutputLayerState));

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
    EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
            .WillRepeatedly(Return(&leftOutputLayer));
    EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1u))
            .WillRepeatedly(Return(&rightOutputLayer));

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
    auto requests = mOutput.generateClientCompositionRequests(supportsProtectedContent, clearRegion,
                                                              mOutput.getState().targetDataspace);

    const half3 clearColor{0.f, 0.f, 0.f};

    ASSERT_EQ(1u, requests.size());
    EXPECT_EQ(456.f, requests[0].geometry.boundaries.left);
    EXPECT_EQ(clearColor, requests[0].source.solidColor);
}

} // namespace
} // namespace android::compositionengine
