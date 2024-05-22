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

#include <android-base/stringprintf.h>
#include <com_android_graphics_surfaceflinger_flags.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/impl/Output.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/OutputLayer.h>
#include <compositionengine/mock/RenderSurface.h>
#include <ftl/future.h>
#include <gtest/gtest.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/impl/ExternalTexture.h>
#include <renderengine/mock/FakeExternalTexture.h>
#include <renderengine/mock/RenderEngine.h>
#include <ui/Rect.h>
#include <ui/Region.h>

#include <cmath>
#include <cstdint>
#include <variant>

#include <common/FlagManager.h>
#include <common/test/FlagUtils.h>
#include "CallOrderStateMachineHelper.h"
#include "MockHWC2.h"
#include "RegionMatcher.h"

namespace android::compositionengine {
namespace {

using namespace com::android::graphics::surfaceflinger;

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
using testing::NiceMock;
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

using CompositionStrategyPredictionState = android::compositionengine::impl::
        OutputCompositionState::CompositionStrategyPredictionState;

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
        EXPECT_CALL(*layerFE, getSequence()).WillRepeatedly(Return(0));
        EXPECT_CALL(*layerFE, getDebugName()).WillRepeatedly(Return("InjectedLayer"));
    }

    mock::OutputLayer* outputLayer = {new StrictMock<mock::OutputLayer>};
    sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
    LayerFECompositionState layerFEState;
    impl::OutputLayerCompositionState outputLayerState;
};

struct NonInjectedLayer {
    NonInjectedLayer() {
        EXPECT_CALL(outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE.get()));
        EXPECT_CALL(outputLayer, getState()).WillRepeatedly(ReturnRef(outputLayerState));
        EXPECT_CALL(outputLayer, editState()).WillRepeatedly(ReturnRef(outputLayerState));

        EXPECT_CALL(*layerFE, getCompositionState()).WillRepeatedly(Return(&layerFEState));
        EXPECT_CALL(*layerFE, getSequence()).WillRepeatedly(Return(0));
        EXPECT_CALL(*layerFE, getDebugName()).WillRepeatedly(Return("NonInjectedLayer"));
    }

    mock::OutputLayer outputLayer;
    sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
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

        mOutput->editState().displaySpace.setBounds(
                ui::Size(kDefaultDisplaySize.getWidth(), kDefaultDisplaySize.getHeight()));
        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
    }

    void injectOutputLayer(InjectedLayer& layer) {
        mOutput->injectOutputLayerForTest(std::unique_ptr<OutputLayer>(layer.outputLayer));
    }

    void injectNullOutputLayer() {
        mOutput->injectOutputLayerForTest(std::unique_ptr<OutputLayer>(nullptr));
    }

    static const Rect kDefaultDisplaySize;

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    std::shared_ptr<Output> mOutput = createOutput(mCompositionEngine);
};

const Rect OutputTest::kDefaultDisplaySize{100, 200};

using ColorProfile = compositionengine::Output::ColorProfile;

void dumpColorProfile(ColorProfile profile, std::string& result, const char* name) {
    android::base::StringAppendF(&result, "%s (%s[%d] %s[%d] %s[%d]) ", name,
                                 toString(profile.mode).c_str(), profile.mode,
                                 toString(profile.dataspace).c_str(), profile.dataspace,
                                 toString(profile.renderIntent).c_str(), profile.renderIntent);
}

// Checks for a ColorProfile match
MATCHER_P(ColorProfileEq, expected, "") {
    std::string buf;
    buf.append("ColorProfiles are not equal\n");
    dumpColorProfile(expected, buf, "expected value");
    dumpColorProfile(arg, buf, "actual value");
    *result_listener << buf;

    return (expected.mode == arg.mode) && (expected.dataspace == arg.dataspace) &&
            (expected.renderIntent == arg.renderIntent);
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
 * Output::setTreat170mAsSrgb()
 */

TEST_F(OutputTest, setTreat170mAsSrgb) {
    EXPECT_FALSE(mOutput->getState().treat170mAsSrgb);

    mOutput->setTreat170mAsSrgb(true);
    EXPECT_TRUE(mOutput->getState().treat170mAsSrgb);

    mOutput->setTreat170mAsSrgb(false);
    EXPECT_FALSE(mOutput->getState().treat170mAsSrgb);
}

/*
 * Output::setLayerCachingEnabled()
 */

TEST_F(OutputTest, setLayerCachingEnabled_enablesCaching) {
    const auto kSize = ui::Size(1, 1);
    EXPECT_CALL(*mRenderSurface, getSize()).WillRepeatedly(ReturnRef(kSize));
    mOutput->setLayerCachingEnabled(false);
    mOutput->setLayerCachingEnabled(true);

    EXPECT_TRUE(mOutput->plannerEnabled());
}

TEST_F(OutputTest, setLayerCachingEnabled_disablesCaching) {
    const auto kSize = ui::Size(1, 1);
    EXPECT_CALL(*mRenderSurface, getSize()).WillRepeatedly(ReturnRef(kSize));
    mOutput->setLayerCachingEnabled(true);
    mOutput->setLayerCachingEnabled(false);

    EXPECT_FALSE(mOutput->plannerEnabled());
}

TEST_F(OutputTest, setLayerCachingEnabled_disablesCachingAndResetsOverrideInfo) {
    renderengine::mock::RenderEngine renderEngine;
    const auto kSize = ui::Size(1, 1);
    EXPECT_CALL(*mRenderSurface, getSize()).WillRepeatedly(ReturnRef(kSize));
    mOutput->setLayerCachingEnabled(true);

    // Inject some layers
    InjectedLayer layer;
    layer.outputLayerState.overrideInfo.buffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), renderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    injectOutputLayer(layer);
    // inject a null layer to check for null exceptions
    injectNullOutputLayer();

    EXPECT_NE(nullptr, layer.outputLayerState.overrideInfo.buffer);
    mOutput->setLayerCachingEnabled(false);
    EXPECT_EQ(nullptr, layer.outputLayerState.overrideInfo.buffer);
}

/*
 * Output::setProjection()
 */

TEST_F(OutputTest, setProjectionWorks) {
    const Rect displayRect{0, 0, 1000, 2000};
    mOutput->editState().displaySpace.setBounds(
            ui::Size(displayRect.getWidth(), displayRect.getHeight()));
    mOutput->editState().framebufferSpace.setBounds(
            ui::Size(displayRect.getWidth(), displayRect.getHeight()));

    const ui::Rotation orientation = ui::ROTATION_90;
    const Rect frame{50, 60, 100, 100};
    const Rect viewport{10, 20, 30, 40};

    mOutput->setProjection(orientation, viewport, frame);

    EXPECT_EQ(orientation, mOutput->getState().displaySpace.getOrientation());
    EXPECT_EQ(frame, mOutput->getState().orientedDisplaySpace.getContent());
    EXPECT_EQ(viewport, mOutput->getState().layerStackSpace.getContent());

    const auto state = mOutput->getState();
    EXPECT_EQ(ui::ROTATION_0, state.layerStackSpace.getOrientation());
    EXPECT_EQ(viewport, state.layerStackSpace.getContent());
    EXPECT_EQ(Rect(0, 0, 20, 20), state.layerStackSpace.getBoundsAsRect());

    EXPECT_EQ(ui::ROTATION_0, state.orientedDisplaySpace.getOrientation());
    EXPECT_EQ(frame, state.orientedDisplaySpace.getContent());
    EXPECT_EQ(Rect(0, 0, 2000, 1000), state.orientedDisplaySpace.getBoundsAsRect());

    EXPECT_EQ(displayRect, state.displaySpace.getBoundsAsRect());
    EXPECT_EQ(Rect(900, 50, 940, 100), state.displaySpace.getContent());
    EXPECT_EQ(orientation, state.displaySpace.getOrientation());

    EXPECT_EQ(displayRect, state.framebufferSpace.getBoundsAsRect());
    EXPECT_EQ(Rect(900, 50, 940, 100), state.framebufferSpace.getContent());
    EXPECT_EQ(orientation, state.framebufferSpace.getOrientation());

    EXPECT_EQ(state.displaySpace.getContent(),
              state.transform.transform(state.layerStackSpace.getContent()));

    EXPECT_EQ(ui::Transform::ROT_90, mOutput->getTransformHint());
}

TEST_F(OutputTest, setProjectionWithSmallFramebufferWorks) {
    const Rect displayRect{0, 0, 1000, 2000};
    const Rect framebufferRect{0, 0, 500, 1000};
    mOutput->editState().displaySpace.setBounds(
            ui::Size(displayRect.getWidth(), displayRect.getHeight()));
    mOutput->editState().framebufferSpace.setBounds(
            ui::Size(framebufferRect.getWidth(), framebufferRect.getHeight()));

    const ui::Rotation orientation = ui::ROTATION_90;
    const Rect frame{50, 60, 100, 100};
    const Rect viewport{10, 20, 30, 40};

    mOutput->setProjection(orientation, viewport, frame);

    EXPECT_EQ(orientation, mOutput->getState().displaySpace.getOrientation());
    EXPECT_EQ(frame, mOutput->getState().orientedDisplaySpace.getContent());
    EXPECT_EQ(viewport, mOutput->getState().layerStackSpace.getContent());

    const auto state = mOutput->getState();
    EXPECT_EQ(ui::ROTATION_0, state.layerStackSpace.getOrientation());
    EXPECT_EQ(viewport, state.layerStackSpace.getContent());
    EXPECT_EQ(Rect(0, 0, 20, 20), state.layerStackSpace.getBoundsAsRect());

    EXPECT_EQ(ui::ROTATION_0, state.orientedDisplaySpace.getOrientation());
    EXPECT_EQ(frame, state.orientedDisplaySpace.getContent());
    EXPECT_EQ(Rect(0, 0, 2000, 1000), state.orientedDisplaySpace.getBoundsAsRect());

    EXPECT_EQ(displayRect, state.displaySpace.getBoundsAsRect());
    EXPECT_EQ(Rect(900, 50, 940, 100), state.displaySpace.getContent());
    EXPECT_EQ(orientation, state.displaySpace.getOrientation());

    EXPECT_EQ(framebufferRect, state.framebufferSpace.getBoundsAsRect());
    EXPECT_EQ(Rect(450, 25, 470, 50), state.framebufferSpace.getContent());
    EXPECT_EQ(orientation, state.framebufferSpace.getOrientation());

    EXPECT_EQ(state.displaySpace.getContent(),
              state.transform.transform(state.layerStackSpace.getContent()));
}

/*
 * Output::setDisplaySize()
 */

TEST_F(OutputTest, setDisplaySpaceSizeUpdatesOutputStateAndDirtiesEntireOutput) {
    mOutput->editState().layerStackSpace.setContent(Rect(0, 0, 2000, 1000));
    mOutput->editState().layerStackSpace.setBounds(ui::Size(2000, 1000));
    mOutput->editState().orientedDisplaySpace.setContent(Rect(0, 0, 1800, 900));
    mOutput->editState().orientedDisplaySpace.setBounds(ui::Size(2000, 1000));
    mOutput->editState().framebufferSpace.setContent(Rect(0, 0, 900, 1800));
    mOutput->editState().framebufferSpace.setBounds(ui::Size(1000, 2000));
    mOutput->editState().framebufferSpace.setOrientation(ui::ROTATION_90);
    mOutput->editState().displaySpace.setContent(Rect(0, 0, 900, 1800));
    mOutput->editState().displaySpace.setBounds(ui::Size(1000, 2000));
    mOutput->editState().displaySpace.setOrientation(ui::ROTATION_90);

    const ui::Size newDisplaySize{500, 1000};

    EXPECT_CALL(*mRenderSurface, setDisplaySize(newDisplaySize)).Times(1);

    mOutput->setDisplaySize(newDisplaySize);

    const auto state = mOutput->getState();

    const Rect displayRect(newDisplaySize);
    EXPECT_EQ(ui::ROTATION_0, state.layerStackSpace.getOrientation());
    EXPECT_EQ(Rect(0, 0, 2000, 1000), state.layerStackSpace.getContent());
    EXPECT_EQ(Rect(0, 0, 2000, 1000), state.layerStackSpace.getBoundsAsRect());

    EXPECT_EQ(ui::ROTATION_0, state.orientedDisplaySpace.getOrientation());
    EXPECT_EQ(Rect(0, 0, 1000, 500), state.orientedDisplaySpace.getBoundsAsRect());

    EXPECT_EQ(displayRect, state.displaySpace.getBoundsAsRect());
    EXPECT_EQ(ui::ROTATION_90, state.displaySpace.getOrientation());

    EXPECT_EQ(displayRect, state.framebufferSpace.getBoundsAsRect());
    EXPECT_EQ(ui::ROTATION_90, state.framebufferSpace.getOrientation());

    EXPECT_EQ(state.displaySpace.getContent(),
              state.transform.transform(state.layerStackSpace.getContent()));

    EXPECT_THAT(state.dirtyRegion, RegionEq(Region(displayRect)));
}

/*
 * Output::setLayerFilter()
 */

TEST_F(OutputTest, setLayerFilterSetsFilterAndDirtiesEntireOutput) {
    constexpr ui::LayerFilter kFilter{ui::LayerStack{123u}, true};
    mOutput->setLayerFilter(kFilter);

    const auto& state = mOutput->getState();
    EXPECT_EQ(kFilter.layerStack, state.layerFilter.layerStack);
    EXPECT_TRUE(state.layerFilter.toInternalDisplay);

    EXPECT_THAT(state.dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
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

    EXPECT_CALL(*mRenderSurface, setBufferDataspace(ui::Dataspace::DISPLAY_P3)).Times(1);

    mOutput->setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                          ui::RenderIntent::TONE_MAP_COLORIMETRIC});

    EXPECT_EQ(ui::ColorMode::DISPLAY_P3, mOutput->getState().colorMode);
    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mOutput->getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::TONE_MAP_COLORIMETRIC, mOutput->getState().renderIntent);

    EXPECT_THAT(mOutput->getState().dirtyRegion, RegionEq(Region(kDefaultDisplaySize)));
}

TEST_F(OutputSetColorProfileTest, doesNothingIfNoChange) {
    using ColorProfile = Output::ColorProfile;

    mOutput->editState().colorMode = ui::ColorMode::DISPLAY_P3;
    mOutput->editState().dataspace = ui::Dataspace::DISPLAY_P3;
    mOutput->editState().renderIntent = ui::RenderIntent::TONE_MAP_COLORIMETRIC;

    mOutput->setColorProfile(ColorProfile{ui::ColorMode::DISPLAY_P3, ui::Dataspace::DISPLAY_P3,
                                          ui::RenderIntent::TONE_MAP_COLORIMETRIC});

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

    EXPECT_EQ(Rect(newDisplaySize), mOutput->getState().framebufferSpace.getBoundsAsRect());
}

/**
 * Output::setDisplayBrightness()
 */

TEST_F(OutputTest, setNextBrightness) {
    constexpr float kDisplayBrightness = 0.5f;
    mOutput->setNextBrightness(kDisplayBrightness);
    ASSERT_TRUE(mOutput->getState().displayBrightness.has_value());
    EXPECT_EQ(kDisplayBrightness, mOutput->getState().displayBrightness);
}

/*
 * Output::getDirtyRegion()
 */

TEST_F(OutputTest, getDirtyRegion) {
    const Rect viewport{100, 200};
    mOutput->editState().layerStackSpace.setContent(viewport);
    mOutput->editState().dirtyRegion.set(50, 300);

    // The dirty region should be clipped to the display bounds.
    EXPECT_THAT(mOutput->getDirtyRegion(), RegionEq(Region(Rect(50, 200))));
}

/*
 * Output::includesLayer()
 */

TEST_F(OutputTest, layerFiltering) {
    const ui::LayerStack layerStack1{123u};
    const ui::LayerStack layerStack2{456u};

    // If the output is associated to layerStack1 and to an internal display...
    mOutput->setLayerFilter({layerStack1, true});

    // It excludes layers with no layer stack, internal-only or not.
    EXPECT_FALSE(mOutput->includesLayer({ui::INVALID_LAYER_STACK, false}));
    EXPECT_FALSE(mOutput->includesLayer({ui::INVALID_LAYER_STACK, true}));

    // It includes layers on layerStack1, internal-only or not.
    EXPECT_TRUE(mOutput->includesLayer({layerStack1, false}));
    EXPECT_TRUE(mOutput->includesLayer({layerStack1, true}));
    EXPECT_FALSE(mOutput->includesLayer({layerStack2, true}));
    EXPECT_FALSE(mOutput->includesLayer({layerStack2, false}));

    // If the output is associated to layerStack1 but not to an internal display...
    mOutput->setLayerFilter({layerStack1, false});

    // It includes layers on layerStack1, unless they are internal-only.
    EXPECT_TRUE(mOutput->includesLayer({layerStack1, false}));
    EXPECT_FALSE(mOutput->includesLayer({layerStack1, true}));
    EXPECT_FALSE(mOutput->includesLayer({layerStack2, true}));
    EXPECT_FALSE(mOutput->includesLayer({layerStack2, false}));
}

TEST_F(OutputTest, layerFilteringWithoutCompositionState) {
    NonInjectedLayer layer;
    sp<LayerFE> layerFE(layer.layerFE);

    // Layers without composition state are excluded.
    EXPECT_CALL(*layer.layerFE, getCompositionState).WillOnce(Return(nullptr));
    EXPECT_FALSE(mOutput->includesLayer(layerFE));
}

TEST_F(OutputTest, layerFilteringWithCompositionState) {
    NonInjectedLayer layer;
    sp<LayerFE> layerFE(layer.layerFE);

    const ui::LayerStack layerStack1{123u};
    const ui::LayerStack layerStack2{456u};

    // If the output is associated to layerStack1 and to an internal display...
    mOutput->setLayerFilter({layerStack1, true});

    // It excludes layers with no layer stack, internal-only or not.
    layer.layerFEState.outputFilter = {ui::INVALID_LAYER_STACK, false};
    EXPECT_FALSE(mOutput->includesLayer(layerFE));

    layer.layerFEState.outputFilter = {ui::INVALID_LAYER_STACK, true};
    EXPECT_FALSE(mOutput->includesLayer(layerFE));

    // It includes layers on layerStack1, internal-only or not.
    layer.layerFEState.outputFilter = {layerStack1, false};
    EXPECT_TRUE(mOutput->includesLayer(layerFE));

    layer.layerFEState.outputFilter = {layerStack1, true};
    EXPECT_TRUE(mOutput->includesLayer(layerFE));

    layer.layerFEState.outputFilter = {layerStack2, true};
    EXPECT_FALSE(mOutput->includesLayer(layerFE));

    layer.layerFEState.outputFilter = {layerStack2, false};
    EXPECT_FALSE(mOutput->includesLayer(layerFE));

    // If the output is associated to layerStack1 but not to an internal display...
    mOutput->setLayerFilter({layerStack1, false});

    // It includes layers on layerStack1, unless they are internal-only.
    layer.layerFEState.outputFilter = {layerStack1, false};
    EXPECT_TRUE(mOutput->includesLayer(layerFE));

    layer.layerFEState.outputFilter = {layerStack1, true};
    EXPECT_FALSE(mOutput->includesLayer(layerFE));

    layer.layerFEState.outputFilter = {layerStack2, true};
    EXPECT_FALSE(mOutput->includesLayer(layerFE));

    layer.layerFEState.outputFilter = {layerStack2, false};
    EXPECT_FALSE(mOutput->includesLayer(layerFE));
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
    sp<StrictMock<mock::LayerFE>> layer1FE = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> layer2FE = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> layer3FE = sp<StrictMock<mock::LayerFE>>::make();

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
 * Output::updateAndWriteCompositionState()
 */

using OutputUpdateAndWriteCompositionStateTest = OutputTest;

TEST_F(OutputUpdateAndWriteCompositionStateTest, doesNothingIfLayers) {
    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
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
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, updatesLayerContentForAllLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    uint32_t z = 0;
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_180));
    EXPECT_CALL(*layer1.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_180));
    EXPECT_CALL(*layer2.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer2.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_180));
    EXPECT_CALL(*layer3.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer3.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = false;
    args.internalDisplayRotationFlags = ui::Transform::ROT_180;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, updatesLayerGeometryAndContentForAllLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    uint32_t z = 0;
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer,
                writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer,
                writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer2.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer,
                writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer3.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = true;
    args.devOptForceClientComposition = false;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, forcesClientCompositionForAllLayers) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    uint32_t z = 0;
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer2.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer3.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = true;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, peekThroughLayerChangesOrder) {
    renderengine::mock::RenderEngine renderEngine;
    InjectedLayer layer0;
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    InSequence seq;
    EXPECT_CALL(*layer0.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(true, false, ui::Transform::ROT_0));

    uint32_t z = 0;
    EXPECT_CALL(*layer0.outputLayer,
                writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer0.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    // After calling planComposition (which clears overrideInfo), this test sets
    // layer3 to be the peekThroughLayer for layer1 and layer2. As a result, it
    // comes first, setting isPeekingThrough to true and zIsOverridden to true
    // for it and the following layers.
    EXPECT_CALL(*layer3.outputLayer,
                writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ true, /*isPeekingThrough*/
                                true));
    EXPECT_CALL(*layer3.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer1.outputLayer,
                writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ true, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer,
                writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ true, z++,
                                /*zIsOverridden*/ true, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer2.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    injectOutputLayer(layer0);
    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = true;
    args.devOptForceClientComposition = false;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();

    std::shared_ptr<renderengine::ExternalTexture> buffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), renderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    layer1.outputLayerState.overrideInfo.buffer = buffer;
    layer2.outputLayerState.overrideInfo.buffer = buffer;
    layer1.outputLayerState.overrideInfo.peekThroughLayer = layer3.outputLayer;
    layer2.outputLayerState.overrideInfo.peekThroughLayer = layer3.outputLayer;

    mOutput->writeCompositionState(args);
}

/*
 * Output::prepareFrame()
 */

struct OutputPrepareFrameTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD1(chooseCompositionStrategy,
                     bool(std::optional<android::HWComposer::DeviceRequestedChanges>*));
        MOCK_METHOD0(resetCompositionStrategy, void());
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

    EXPECT_CALL(mOutput, chooseCompositionStrategy(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mOutput, resetCompositionStrategy()).Times(1);
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
    EXPECT_CALL(*mRenderSurface, prepareFrame(false, true));

    mOutput.prepareFrame();
    EXPECT_EQ(mOutput.getState().strategyPrediction, CompositionStrategyPredictionState::DISABLED);
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
    EXPECT_EQ(mOutput->getState().strategyPrediction, CompositionStrategyPredictionState::DISABLED);
}

struct OutputPrepareFrameAsyncTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD1(chooseCompositionStrategy,
                     bool(std::optional<android::HWComposer::DeviceRequestedChanges>*));
        MOCK_METHOD0(updateProtectedContentState, void());
        MOCK_METHOD2(dequeueRenderBuffer,
                     bool(base::unique_fd*, std::shared_ptr<renderengine::ExternalTexture>*));
        MOCK_METHOD1(
                chooseCompositionStrategyAsync,
                std::future<bool>(std::optional<android::HWComposer::DeviceRequestedChanges>*));
        MOCK_METHOD3(composeSurfaces,
                     std::optional<base::unique_fd>(const Region&,
                                                    std::shared_ptr<renderengine::ExternalTexture>,
                                                    base::unique_fd&));
        MOCK_METHOD0(resetCompositionStrategy, void());
    };

    OutputPrepareFrameAsyncTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
    CompositionRefreshArgs mRefreshArgs;
};

TEST_F(OutputPrepareFrameAsyncTest, delegatesToChooseCompositionStrategyAndRenderSurface) {
    mOutput.editState().isEnabled = true;
    mOutput.editState().usesClientComposition = false;
    mOutput.editState().usesDeviceComposition = true;
    mOutput.editState().previousDeviceRequestedChanges =
            std::make_optional<android::HWComposer::DeviceRequestedChanges>({});
    std::promise<bool> p;
    p.set_value(true);

    EXPECT_CALL(mOutput, resetCompositionStrategy()).Times(1);
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*mRenderSurface, prepareFrame(false, true)).Times(1);
    EXPECT_CALL(mOutput, chooseCompositionStrategyAsync(_))
            .WillOnce(DoAll(SetArgPointee<0>(mOutput.editState().previousDeviceRequestedChanges),
                            Return(ByMove(p.get_future()))));
    EXPECT_CALL(mOutput, composeSurfaces(_, _, _));

    impl::GpuCompositionResult result = mOutput.prepareFrameAsync();
    EXPECT_EQ(mOutput.getState().strategyPrediction, CompositionStrategyPredictionState::SUCCESS);
    EXPECT_FALSE(result.bufferAvailable());
}

TEST_F(OutputPrepareFrameAsyncTest, skipCompositionOnDequeueFailure) {
    mOutput.editState().isEnabled = true;
    mOutput.editState().usesClientComposition = false;
    mOutput.editState().usesDeviceComposition = true;
    mOutput.editState().previousDeviceRequestedChanges =
            std::make_optional<android::HWComposer::DeviceRequestedChanges>({});
    std::promise<bool> p;
    p.set_value(true);

    EXPECT_CALL(mOutput, resetCompositionStrategy()).Times(2);
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _)).WillOnce(Return(false));
    EXPECT_CALL(*mRenderSurface, prepareFrame(false, true)).Times(2);
    EXPECT_CALL(mOutput, chooseCompositionStrategyAsync(_))
            .WillOnce(DoAll(SetArgPointee<0>(mOutput.editState().previousDeviceRequestedChanges),
                            Return(ByMove(p.get_future()))));

    impl::GpuCompositionResult result = mOutput.prepareFrameAsync();
    EXPECT_EQ(mOutput.getState().strategyPrediction, CompositionStrategyPredictionState::FAIL);
    EXPECT_FALSE(result.bufferAvailable());
}

// Tests that in the event of hwc error when choosing composition strategy, we would fall back
// client composition
TEST_F(OutputPrepareFrameAsyncTest, chooseCompositionStrategyFailureCallsPrepareFrame) {
    mOutput.editState().isEnabled = true;
    mOutput.editState().usesClientComposition = false;
    mOutput.editState().usesDeviceComposition = true;
    mOutput.editState().previousDeviceRequestedChanges =
            std::make_optional<android::HWComposer::DeviceRequestedChanges>({});
    std::promise<bool> p;
    p.set_value(false);
    std::shared_ptr<renderengine::ExternalTexture> tex =
            std::make_shared<renderengine::mock::FakeExternalTexture>(1, 1,
                                                                      HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                                      2);
    EXPECT_CALL(mOutput, resetCompositionStrategy()).Times(2);
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _))
            .WillOnce(DoAll(SetArgPointee<1>(tex), Return(true)));
    EXPECT_CALL(*mRenderSurface, prepareFrame(false, true)).Times(2);
    EXPECT_CALL(mOutput, chooseCompositionStrategyAsync(_)).WillOnce([&] {
        return p.get_future();
    });
    EXPECT_CALL(mOutput, composeSurfaces(_, _, _));

    impl::GpuCompositionResult result = mOutput.prepareFrameAsync();
    EXPECT_EQ(mOutput.getState().strategyPrediction, CompositionStrategyPredictionState::FAIL);
    EXPECT_TRUE(result.bufferAvailable());
}

TEST_F(OutputPrepareFrameAsyncTest, predictionMiss) {
    mOutput.editState().isEnabled = true;
    mOutput.editState().usesClientComposition = false;
    mOutput.editState().usesDeviceComposition = true;
    mOutput.editState().previousDeviceRequestedChanges =
            std::make_optional<android::HWComposer::DeviceRequestedChanges>({});
    auto newDeviceRequestedChanges =
            std::make_optional<android::HWComposer::DeviceRequestedChanges>({});
    newDeviceRequestedChanges->displayRequests = static_cast<hal::DisplayRequest>(0);
    std::promise<bool> p;
    p.set_value(false);
    std::shared_ptr<renderengine::ExternalTexture> tex =
            std::make_shared<renderengine::mock::FakeExternalTexture>(1, 1,
                                                                      HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                                      2);

    EXPECT_CALL(mOutput, resetCompositionStrategy()).Times(2);
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _))
            .WillOnce(DoAll(SetArgPointee<1>(tex), Return(true)));
    EXPECT_CALL(*mRenderSurface, prepareFrame(false, true)).Times(2);
    EXPECT_CALL(mOutput, chooseCompositionStrategyAsync(_)).WillOnce([&] {
        return p.get_future();
    });
    EXPECT_CALL(mOutput, composeSurfaces(_, _, _));

    impl::GpuCompositionResult result = mOutput.prepareFrameAsync();
    EXPECT_EQ(mOutput.getState().strategyPrediction, CompositionStrategyPredictionState::FAIL);
    EXPECT_TRUE(result.bufferAvailable());
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

    OutputPrepareTest() {
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0))
                .WillRepeatedly(Return(&mLayer1.outputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1))
                .WillRepeatedly(Return(&mLayer2.outputLayer));

        mRefreshArgs.layers.push_back(mLayer1.layerFE);
        mRefreshArgs.layers.push_back(mLayer2.layerFE);
    }

    struct Layer {
        StrictMock<mock::OutputLayer> outputLayer;
        sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
    };

    StrictMock<OutputPartialMock> mOutput;
    CompositionRefreshArgs mRefreshArgs;
    LayerFESet mGeomSnapshots;
    Layer mLayer1;
    Layer mLayer2;
};

TEST_F(OutputPrepareTest, callsUncacheBuffersOnEachOutputLayerAndThenRebuildsLayerStacks) {
    InSequence seq;

    mRefreshArgs.bufferIdsToUncache = {1, 3, 5};

    EXPECT_CALL(mOutput, rebuildLayerStacks(Ref(mRefreshArgs), Ref(mGeomSnapshots)));
    EXPECT_CALL(mLayer1.outputLayer, uncacheBuffers(Ref(mRefreshArgs.bufferIdsToUncache)));
    EXPECT_CALL(mLayer2.outputLayer, uncacheBuffers(Ref(mRefreshArgs.bufferIdsToUncache)));

    mOutput.prepare(mRefreshArgs, mGeomSnapshots);
}

TEST_F(OutputPrepareTest, skipsUncacheBuffersIfEmptyAndThenRebuildsLayerStacks) {
    InSequence seq;

    mRefreshArgs.bufferIdsToUncache = {};

    EXPECT_CALL(mOutput, rebuildLayerStacks(Ref(mRefreshArgs), Ref(mGeomSnapshots)));
    EXPECT_CALL(mLayer1.outputLayer, uncacheBuffers(_)).Times(0);
    EXPECT_CALL(mLayer2.outputLayer, uncacheBuffers(_)).Times(0);

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
        mOutput.mState.displaySpace.setBounds(
                ui::Size(kOutputBounds.getWidth(), kOutputBounds.getHeight()));

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
        sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
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
}

/*
 * Output::ensureOutputLayerIfVisible()
 */

struct OutputEnsureOutputLayerIfVisibleTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD(bool, includesLayer, (const sp<compositionengine::LayerFE>&),
                    (const, override));
        MOCK_CONST_METHOD1(getOutputLayerOrderedByZByIndex, OutputLayer*(size_t));
        MOCK_METHOD2(ensureOutputLayer,
                     compositionengine::OutputLayer*(std::optional<size_t>, const sp<LayerFE>&));
    };

    OutputEnsureOutputLayerIfVisibleTest() {
        EXPECT_CALL(mOutput, includesLayer(sp<LayerFE>(mLayer.layerFE)))
                .WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(1u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0u))
                .WillRepeatedly(Return(&mLayer.outputLayer));

        mOutput.mState.displaySpace.setBounds(ui::Size(200, 300));
        mOutput.mState.layerStackSpace.setContent(Rect(0, 0, 200, 300));
        mOutput.mState.transform = ui::Transform(TR_IDENT, 200, 300);

        mLayer.layerFEState.isVisible = true;
        mLayer.layerFEState.isOpaque = true;
        mLayer.layerFEState.contentDirty = true;
        mLayer.layerFEState.geomLayerBounds = FloatRect{0, 0, 100, 200};
        mLayer.layerFEState.geomLayerTransform = ui::Transform(TR_IDENT, 100, 200);
        mLayer.layerFEState.transparentRegionHint = kTransparentRegionHint;

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
    static const Region kTransparentRegionHint;
    static const Region kTransparentRegionHintTwo;
    static const Region kTransparentRegionHintTwo90Rotation;
    static const Region kTransparentRegionHintNegative;
    static const Region kTransparentRegionHintNegativeIntersectsBounds;

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
const Region OutputEnsureOutputLayerIfVisibleTest::kTransparentRegionHint =
        Region(Rect(0, 0, 100, 100));
const Region OutputEnsureOutputLayerIfVisibleTest::kTransparentRegionHintTwo =
        Region(Rect(25, 20, 50, 75));
const Region OutputEnsureOutputLayerIfVisibleTest::kTransparentRegionHintTwo90Rotation =
        Region(Rect(125, 25, 180, 50));
const Region OutputEnsureOutputLayerIfVisibleTest::kTransparentRegionHintNegative =
        Region(Rect(INT32_MIN, INT32_MIN, INT32_MIN + 100, INT32_MIN + 200));
const Region OutputEnsureOutputLayerIfVisibleTest::kTransparentRegionHintNegativeIntersectsBounds =
        Region(Rect(INT32_MIN, INT32_MIN, 100, 100));

TEST_F(OutputEnsureOutputLayerIfVisibleTest, performsGeomLatchBeforeCheckingIfLayerIncluded) {
    EXPECT_CALL(mOutput, includesLayer(sp<LayerFE>(mLayer.layerFE))).WillOnce(Return(false));
    mGeomSnapshots.clear();

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest,
       skipsLatchIfAlreadyLatchedBeforeCheckingIfLayerIncluded) {
    EXPECT_CALL(mOutput, includesLayer(sp<LayerFE>(mLayer.layerFE))).WillOnce(Return(false));

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
    mOutput.mState.displaySpace.setBounds(ui::Size(0, 0));

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

    mOutput.mState.layerStackSpace.setContent(Rect(0, 0, 300, 200));
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

    mOutput.mState.layerStackSpace.setContent(Rect(0, 0, 300, 200));
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
    mLayer.layerFEState.shadowSettings.length = 10.0f;

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
    mLayer.layerFEState.shadowSettings.length = 10.0f;

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
    mLayer.layerFEState.shadowSettings.length = 10.0f;

    mCoverageState.dirtyRegion = Region(Rect(0, 0, 500, 500));
    // Casting layer and its shadows are covered by an opaque region
    mCoverageState.aboveCoveredLayers = Region(Rect(40, 40, 160, 260));
    mCoverageState.aboveOpaqueLayers = Region(Rect(40, 40, 160, 260));

    ensureOutputLayerIfVisible();
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, displayDecorSetsBlockingFromTransparentRegion) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.compositionType =
            aidl::android::hardware::graphics::composer3::Composition::DISPLAY_DECORATION;

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));
    ensureOutputLayerIfVisible();

    EXPECT_THAT(mLayer.outputLayerState.outputSpaceBlockingRegionHint,
                RegionEq(kTransparentRegionHint));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, normalLayersDoNotSetBlockingRegion) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));
    ensureOutputLayerIfVisible();

    EXPECT_THAT(mLayer.outputLayerState.outputSpaceBlockingRegionHint, RegionEq(Region()));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, blockingRegionIsInOutputSpace) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.compositionType =
            aidl::android::hardware::graphics::composer3::Composition::DISPLAY_DECORATION;
    mLayer.layerFEState.transparentRegionHint = kTransparentRegionHintTwo;

    mOutput.mState.layerStackSpace.setContent(Rect(0, 0, 300, 200));
    mOutput.mState.transform = ui::Transform(TR_ROT_90, 200, 300);

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));
    ensureOutputLayerIfVisible();

    EXPECT_THAT(mLayer.outputLayerState.outputSpaceBlockingRegionHint,
                RegionEq(kTransparentRegionHintTwo90Rotation));
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, transparentRegionExcludesOutputLayer) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerBounds = kFullBoundsNoRotation.bounds().toFloatRect();
    mLayer.layerFEState.transparentRegionHint = kFullBoundsNoRotation;

    EXPECT_CALL(mOutput, ensureOutputLayer(_, _)).Times(0);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, transparentRegionIgnoredWhenOutsideBounds) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.geomLayerBounds = kFullBoundsNoRotation.bounds().toFloatRect();
    mLayer.layerFEState.transparentRegionHint = kTransparentRegionHintNegative;

    EXPECT_CALL(mOutput, ensureOutputLayer(_, _)).Times(0);
}

TEST_F(OutputEnsureOutputLayerIfVisibleTest, transparentRegionClipsWhenOutsideBounds) {
    mLayer.layerFEState.isOpaque = false;
    mLayer.layerFEState.contentDirty = true;
    mLayer.layerFEState.compositionType =
            aidl::android::hardware::graphics::composer3::Composition::DISPLAY_DECORATION;
    mLayer.layerFEState.transparentRegionHint = kTransparentRegionHintNegativeIntersectsBounds;

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));
    EXPECT_CALL(mOutput, ensureOutputLayer(Eq(std::nullopt), Eq(mLayer.layerFE)))
            .WillOnce(Return(&mLayer.outputLayer));
    ensureOutputLayerIfVisible();

    // Check that the blocking region clips an out-of-bounds transparent region.
    EXPECT_THAT(mLayer.outputLayerState.outputSpaceBlockingRegionHint,
                RegionEq(kTransparentRegionHint));
}

/*
 * Output::present()
 */

struct OutputPresentTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD1(updateColorProfile, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(updateCompositionState,
                     void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(planComposition, void());
        MOCK_METHOD1(writeCompositionState, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(setColorTransform, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(beginFrame, void());
        MOCK_METHOD0(prepareFrame, void());
        MOCK_METHOD0(prepareFrameAsync, GpuCompositionResult());
        MOCK_METHOD1(devOptRepaintFlash, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(finishFrame, void(GpuCompositionResult&&));
        MOCK_METHOD(void, presentFrameAndReleaseLayers, (bool flushEvenWhenDisabled), (override));
        MOCK_METHOD1(renderCachedSets, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(canPredictCompositionStrategy, bool(const CompositionRefreshArgs&));
        MOCK_METHOD(void, setHintSessionRequiresRenderEngine, (bool requiresRenderEngine),
                    (override));
        MOCK_METHOD(bool, isPowerHintSessionEnabled, (), (override));
        MOCK_METHOD(bool, isPowerHintSessionGpuReportingEnabled, (), (override));
    };

    OutputPresentTest() {
        EXPECT_CALL(mOutput, isPowerHintSessionEnabled()).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput, isPowerHintSessionGpuReportingEnabled()).WillRepeatedly(Return(true));
    }

    StrictMock<OutputPartialMock> mOutput;
};

TEST_F(OutputPresentTest, justInvokesChildFunctionsInSequence) {
    CompositionRefreshArgs args;

    InSequence seq;
    EXPECT_CALL(mOutput, updateColorProfile(Ref(args)));
    EXPECT_CALL(mOutput, updateCompositionState(Ref(args)));
    EXPECT_CALL(mOutput, planComposition());
    EXPECT_CALL(mOutput, writeCompositionState(Ref(args)));
    EXPECT_CALL(mOutput, setColorTransform(Ref(args)));
    EXPECT_CALL(mOutput, beginFrame());
    EXPECT_CALL(mOutput, setHintSessionRequiresRenderEngine(false));
    EXPECT_CALL(mOutput, canPredictCompositionStrategy(Ref(args))).WillOnce(Return(false));
    EXPECT_CALL(mOutput, prepareFrame());
    EXPECT_CALL(mOutput, devOptRepaintFlash(Ref(args)));
    EXPECT_CALL(mOutput, finishFrame(_));
    EXPECT_CALL(mOutput, presentFrameAndReleaseLayers(false));
    EXPECT_CALL(mOutput, renderCachedSets(Ref(args)));

    mOutput.present(args);
}

TEST_F(OutputPresentTest, predictingCompositionStrategyInvokesPrepareFrameAsync) {
    CompositionRefreshArgs args;

    InSequence seq;
    EXPECT_CALL(mOutput, updateColorProfile(Ref(args)));
    EXPECT_CALL(mOutput, updateCompositionState(Ref(args)));
    EXPECT_CALL(mOutput, planComposition());
    EXPECT_CALL(mOutput, writeCompositionState(Ref(args)));
    EXPECT_CALL(mOutput, setColorTransform(Ref(args)));
    EXPECT_CALL(mOutput, beginFrame());
    EXPECT_CALL(mOutput, setHintSessionRequiresRenderEngine(false));
    EXPECT_CALL(mOutput, canPredictCompositionStrategy(Ref(args))).WillOnce(Return(true));
    EXPECT_CALL(mOutput, prepareFrameAsync());
    EXPECT_CALL(mOutput, devOptRepaintFlash(Ref(args)));
    EXPECT_CALL(mOutput, finishFrame(_));
    EXPECT_CALL(mOutput, presentFrameAndReleaseLayers(false));
    EXPECT_CALL(mOutput, renderCachedSets(Ref(args)));

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
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*mLayerFE));
            EXPECT_CALL(*mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        sp<StrictMock<mock::LayerFE>> mLayerFE = sp<StrictMock<mock::LayerFE>>::make();
        LayerFECompositionState mLayerFEState;
    };

    OutputUpdateColorProfileTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
        mOutput.editState().isEnabled = true;

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
                setColorProfile(
                        ColorProfileEq(ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                                                    ui::RenderIntent::COLORIMETRIC})));

    mRefreshArgs.outputColorSetting = OutputColorSetting::kUnmanaged;

    mOutput.updateColorProfile(mRefreshArgs);
}

struct OutputUpdateColorProfileTest_GetBestColorModeResultBecomesSetProfile
      : public OutputUpdateColorProfileTest {
    OutputUpdateColorProfileTest_GetBestColorModeResultBecomesSetProfile() {
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(0u));
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;
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
                                ColorProfileEq(ColorProfile{colorMode, dataspace, renderIntent})));
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

struct OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference
      : public OutputUpdateColorProfileTest {
    // Internally the implementation looks through the dataspaces of all the
    // visible layers. The topmost one that also has an actual dataspace
    // preference set is used to drive subsequent choices.

    OutputUpdateColorProfileTest_TopmostLayerPreferenceSetsOutputPreference() {
        mRefreshArgs.outputColorSetting = OutputColorSetting::kEnhanced;

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
        MOCK_METHOD(Region, getDirtyRegion, (), (const));
    };

    OutputBeginFrameTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    struct IfGetDirtyRegionExpectationState
          : public CallOrderStateMachineHelper<TestType, IfGetDirtyRegionExpectationState> {
        [[nodiscard]] auto ifGetDirtyRegionReturns(Region dirtyRegion) {
            EXPECT_CALL(getInstance()->mOutput, getDirtyRegion()).WillOnce(Return(dirtyRegion));
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
        MOCK_METHOD(Region, getDirtyRegion, (), (const));
        MOCK_METHOD3(composeSurfaces,
                     std::optional<base::unique_fd>(const Region&,
                                                    std::shared_ptr<renderengine::ExternalTexture>,
                                                    base::unique_fd&));
        MOCK_METHOD(void, presentFrameAndReleaseLayers, (bool flushEvenWhenDisabled));
        MOCK_METHOD0(prepareFrame, void());
        MOCK_METHOD0(updateProtectedContentState, void());
        MOCK_METHOD2(dequeueRenderBuffer,
                     bool(base::unique_fd*, std::shared_ptr<renderengine::ExternalTexture>*));
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
    mOutput.mState.isEnabled = true;

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

TEST_F(OutputDevOptRepaintFlashTest, postsAndPreparesANewFrameIfNotEnabled) {
    mRefreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::microseconds(1);
    mOutput.mState.isEnabled = false;

    InSequence seq;
    constexpr bool kFlushEvenWhenDisabled = false;
    EXPECT_CALL(mOutput, presentFrameAndReleaseLayers(kFlushEvenWhenDisabled));
    EXPECT_CALL(mOutput, prepareFrame());

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

TEST_F(OutputDevOptRepaintFlashTest, postsAndPreparesANewFrameIfEnabled) {
    mRefreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::microseconds(1);
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, getDirtyRegion()).WillOnce(Return(kEmptyRegion));
    constexpr bool kFlushEvenWhenDisabled = false;
    EXPECT_CALL(mOutput, presentFrameAndReleaseLayers(kFlushEvenWhenDisabled));
    EXPECT_CALL(mOutput, prepareFrame());

    mOutput.devOptRepaintFlash(mRefreshArgs);
}

TEST_F(OutputDevOptRepaintFlashTest, alsoComposesSurfacesAndQueuesABufferIfDirty) {
    mRefreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::microseconds(1);
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, getDirtyRegion()).WillOnce(Return(kNotEmptyRegion));
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _));
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(kNotEmptyRegion), _, _));
    EXPECT_CALL(*mRenderSurface, queueBuffer(_, 1.f));
    constexpr bool kFlushEvenWhenDisabled = false;
    EXPECT_CALL(mOutput, presentFrameAndReleaseLayers(kFlushEvenWhenDisabled));
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
        MOCK_METHOD3(composeSurfaces,
                     std::optional<base::unique_fd>(const Region&,
                                                    std::shared_ptr<renderengine::ExternalTexture>,
                                                    base::unique_fd&));
        MOCK_METHOD(void, presentFrameAndReleaseLayers, (bool flushEvenWhenDisabled), (override));
        MOCK_METHOD0(updateProtectedContentState, void());
        MOCK_METHOD2(dequeueRenderBuffer,
                     bool(base::unique_fd*, std::shared_ptr<renderengine::ExternalTexture>*));
        MOCK_METHOD(void, setHintSessionGpuFence, (std::unique_ptr<FenceTime> && gpuFence),
                    (override));
        MOCK_METHOD(bool, isPowerHintSessionEnabled, (), (override));
        MOCK_METHOD(bool, isPowerHintSessionGpuReportingEnabled, (), (override));
    };

    OutputFinishFrameTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
        EXPECT_CALL(mOutput, getCompositionEngine()).WillRepeatedly(ReturnRef(mCompositionEngine));
        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
        EXPECT_CALL(mOutput, isPowerHintSessionEnabled()).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput, isPowerHintSessionGpuReportingEnabled()).WillRepeatedly(Return(true));
    }

    StrictMock<OutputPartialMock> mOutput;
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
};

TEST_F(OutputFinishFrameTest, ifNotEnabledDoesNothing) {
    mOutput.mState.isEnabled = false;

    impl::GpuCompositionResult result;
    mOutput.finishFrame(std::move(result));
}

TEST_F(OutputFinishFrameTest, takesEarlyOutifComposeSurfacesReturnsNoFence) {
    mOutput.mState.isEnabled = true;
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _)).WillOnce(Return(true));
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION), _, _));

    impl::GpuCompositionResult result;
    mOutput.finishFrame(std::move(result));
}

TEST_F(OutputFinishFrameTest, queuesBufferIfComposeSurfacesReturnsAFenceWithAdpfGpuOff) {
    EXPECT_CALL(mOutput, isPowerHintSessionGpuReportingEnabled()).WillOnce(Return(false));
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _)).WillOnce(Return(true));
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION), _, _))
            .WillOnce(Return(ByMove(base::unique_fd())));
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_));
    EXPECT_CALL(*mRenderSurface, queueBuffer(_, 1.f));

    impl::GpuCompositionResult result;
    mOutput.finishFrame(std::move(result));
}

TEST_F(OutputFinishFrameTest, queuesBufferIfComposeSurfacesReturnsAFence) {
    mOutput.mState.isEnabled = true;

    InSequence seq;
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _)).WillOnce(Return(true));
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION), _, _))
            .WillOnce(Return(ByMove(base::unique_fd())));
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_)).Times(0);
    EXPECT_CALL(*mRenderSurface, queueBuffer(_, 1.f));

    impl::GpuCompositionResult result;
    mOutput.finishFrame(std::move(result));
}

TEST_F(OutputFinishFrameTest, queuesBufferWithHdrSdrRatio) {
    SET_FLAG_FOR_TEST(flags::fp16_client_target, true);
    mOutput.mState.isEnabled = true;

    InSequence seq;
    auto texture = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(1u, 1u, PIXEL_FORMAT_RGBA_FP16,
                                                             GRALLOC_USAGE_SW_WRITE_OFTEN |
                                                                     GRALLOC_USAGE_SW_READ_OFTEN),
                                     mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    mOutput.mState.displayBrightnessNits = 400.f;
    mOutput.mState.sdrWhitePointNits = 200.f;
    mOutput.mState.dataspace = ui::Dataspace::V0_SCRGB;
    EXPECT_CALL(mOutput, updateProtectedContentState());
    EXPECT_CALL(mOutput, dequeueRenderBuffer(_, _))
            .WillOnce(DoAll(SetArgPointee<1>(texture), Return(true)));
    EXPECT_CALL(mOutput, composeSurfaces(RegionEq(Region::INVALID_REGION), _, _))
            .WillOnce(Return(ByMove(base::unique_fd())));
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_)).Times(0);
    EXPECT_CALL(*mRenderSurface, queueBuffer(_, 2.f));

    impl::GpuCompositionResult result;
    mOutput.finishFrame(std::move(result));
}

TEST_F(OutputFinishFrameTest, predictionSucceeded) {
    mOutput.mState.isEnabled = true;
    mOutput.mState.strategyPrediction = CompositionStrategyPredictionState::SUCCESS;
    InSequence seq;
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_)).Times(0);
    EXPECT_CALL(*mRenderSurface, queueBuffer(_, 1.f));

    impl::GpuCompositionResult result;
    mOutput.finishFrame(std::move(result));
}

TEST_F(OutputFinishFrameTest, predictionFailedAndBufferIsReused) {
    mOutput.mState.isEnabled = true;
    mOutput.mState.strategyPrediction = CompositionStrategyPredictionState::FAIL;

    InSequence seq;

    impl::GpuCompositionResult result;
    result.buffer =
            std::make_shared<renderengine::mock::FakeExternalTexture>(1, 1,
                                                                      HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                                      2);

    EXPECT_CALL(mOutput,
                composeSurfaces(RegionEq(Region::INVALID_REGION), result.buffer,
                                Eq(ByRef(result.fence))))
            .WillOnce(Return(ByMove(base::unique_fd())));
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_)).Times(0);
    EXPECT_CALL(*mRenderSurface, queueBuffer(_, 1.f));
    mOutput.finishFrame(std::move(result));
}

/*
 * Output::presentFrameAndReleaseLayers()
 */

struct OutputPostFramebufferTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD(compositionengine::Output::FrameFences, presentFrame, ());
        MOCK_METHOD(void, executeCommands, ());
    };

    struct Layer {
        Layer() {
            EXPECT_CALL(outputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*layerFE));
            EXPECT_CALL(outputLayer, getHwcLayer()).WillRepeatedly(Return(&hwc2Layer));
        }

        StrictMock<mock::OutputLayer> outputLayer;
        sp<StrictMock<mock::LayerFE>> layerFE = sp<StrictMock<mock::LayerFE>>::make();
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
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::flush_buffer_slots_to_uncache,
                      true);
    mOutput.mState.isEnabled = false;
    EXPECT_CALL(mOutput, executeCommands()).Times(0);
    EXPECT_CALL(mOutput, presentFrame()).Times(0);

    constexpr bool kFlushEvenWhenDisabled = false;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, ifNotEnabledExecutesCommandsIfFlush) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::flush_buffer_slots_to_uncache,
                      true);
    mOutput.mState.isEnabled = false;
    EXPECT_CALL(mOutput, executeCommands());
    EXPECT_CALL(mOutput, presentFrame()).Times(0);

    constexpr bool kFlushEvenWhenDisabled = true;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, ifEnabledDoNotExecuteCommands) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::flush_buffer_slots_to_uncache,
                      true);
    mOutput.mState.isEnabled = true;

    compositionengine::Output::FrameFences frameFences;

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));

    // This should only be called for disabled outputs. This test's goal is to verify this line;
    // the other expectations help satisfy the StrictMocks.
    EXPECT_CALL(mOutput, executeCommands()).Times(0);

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    constexpr bool kFlushEvenWhenDisabled = true;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, ifEnabledDoNotExecuteCommands2) {
    // Same test as ifEnabledDoNotExecuteCommands, but with this variable set to false.
    constexpr bool kFlushEvenWhenDisabled = false;

    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::flush_buffer_slots_to_uncache,
                      true);
    mOutput.mState.isEnabled = true;

    compositionengine::Output::FrameFences frameFences;

    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));

    // This should only be called for disabled outputs. This test's goal is to verify this line;
    // the other expectations help satisfy the StrictMocks.
    EXPECT_CALL(mOutput, executeCommands()).Times(0);

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, ifEnabledMustFlipThenPresentThenSendPresentCompleted) {
    mOutput.mState.isEnabled = true;

    compositionengine::Output::FrameFences frameFences;

    // This should happen even if there are no output layers.
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));

    // For this test in particular we want to make sure the call expectations
    // setup below are satisfied in the specific order.
    InSequence seq;

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    constexpr bool kFlushEvenWhenDisabled = true;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, releaseFencesAreSentToLayerFE) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::ce_fence_promise, false);
    ASSERT_FALSE(FlagManager::getInstance().ce_fence_promise());
    // Simulate getting release fences from each layer, and ensure they are passed to the
    // front-end layer interface for each layer correctly.

    mOutput.mState.isEnabled = true;

    // Create three unique fence instances
    sp<Fence> layer1Fence = sp<Fence>::make();
    sp<Fence> layer2Fence = sp<Fence>::make();
    sp<Fence> layer3Fence = sp<Fence>::make();

    Output::FrameFences frameFences;
    frameFences.layerFences.emplace(&mLayer1.hwc2Layer, layer1Fence);
    frameFences.layerFences.emplace(&mLayer2.hwc2Layer, layer2Fence);
    frameFences.layerFences.emplace(&mLayer3.hwc2Layer, layer3Fence);

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Compare the pointers values of each fence to make sure the correct ones
    // are passed. This happens to work with the current implementation, but
    // would not survive certain calls like Fence::merge() which would return a
    // new instance.
    EXPECT_CALL(*mLayer1.layerFE, onLayerDisplayed(_, _))
            .WillOnce([&layer1Fence](ftl::SharedFuture<FenceResult> futureFenceResult,
                                     ui::LayerStack) {
                EXPECT_EQ(FenceResult(layer1Fence), futureFenceResult.get());
            });
    EXPECT_CALL(*mLayer2.layerFE, onLayerDisplayed(_, _))
            .WillOnce([&layer2Fence](ftl::SharedFuture<FenceResult> futureFenceResult,
                                     ui::LayerStack) {
                EXPECT_EQ(FenceResult(layer2Fence), futureFenceResult.get());
            });
    EXPECT_CALL(*mLayer3.layerFE, onLayerDisplayed(_, _))
            .WillOnce([&layer3Fence](ftl::SharedFuture<FenceResult> futureFenceResult,
                                     ui::LayerStack) {
                EXPECT_EQ(FenceResult(layer3Fence), futureFenceResult.get());
            });

    constexpr bool kFlushEvenWhenDisabled = false;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, releaseFencesAreSetInLayerFE) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::ce_fence_promise, true);
    ASSERT_TRUE(FlagManager::getInstance().ce_fence_promise());
    // Simulate getting release fences from each layer, and ensure they are passed to the
    // front-end layer interface for each layer correctly.

    mOutput.mState.isEnabled = true;

    // Create three unique fence instances
    sp<Fence> layer1Fence = sp<Fence>::make();
    sp<Fence> layer2Fence = sp<Fence>::make();
    sp<Fence> layer3Fence = sp<Fence>::make();

    Output::FrameFences frameFences;
    frameFences.layerFences.emplace(&mLayer1.hwc2Layer, layer1Fence);
    frameFences.layerFences.emplace(&mLayer2.hwc2Layer, layer2Fence);
    frameFences.layerFences.emplace(&mLayer3.hwc2Layer, layer3Fence);

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Compare the pointers values of each fence to make sure the correct ones
    // are passed. This happens to work with the current implementation, but
    // would not survive certain calls like Fence::merge() which would return a
    // new instance.
    EXPECT_CALL(*mLayer1.layerFE, setReleaseFence(_))
            .WillOnce([&layer1Fence](FenceResult releaseFence) {
                EXPECT_EQ(FenceResult(layer1Fence), releaseFence);
            });
    EXPECT_CALL(*mLayer2.layerFE, setReleaseFence(_))
            .WillOnce([&layer2Fence](FenceResult releaseFence) {
                EXPECT_EQ(FenceResult(layer2Fence), releaseFence);
            });
    EXPECT_CALL(*mLayer3.layerFE, setReleaseFence(_))
            .WillOnce([&layer3Fence](FenceResult releaseFence) {
                EXPECT_EQ(FenceResult(layer3Fence), releaseFence);
            });

    constexpr bool kFlushEvenWhenDisabled = false;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, releaseFencesIncludeClientTargetAcquireFence) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::ce_fence_promise, false);
    ASSERT_FALSE(FlagManager::getInstance().ce_fence_promise());

    mOutput.mState.isEnabled = true;
    mOutput.mState.usesClientComposition = true;

    Output::FrameFences frameFences;
    frameFences.clientTargetAcquireFence = sp<Fence>::make();
    frameFences.layerFences.emplace(&mLayer1.hwc2Layer, sp<Fence>::make());
    frameFences.layerFences.emplace(&mLayer2.hwc2Layer, sp<Fence>::make());
    frameFences.layerFences.emplace(&mLayer3.hwc2Layer, sp<Fence>::make());

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Fence::merge is called, and since none of the fences are actually valid,
    // Fence::NO_FENCE is returned and passed to each onLayerDisplayed() call.
    // This is the best we can do without creating a real kernel fence object.
    EXPECT_CALL(*mLayer1.layerFE, onLayerDisplayed).WillOnce(Return());
    EXPECT_CALL(*mLayer2.layerFE, onLayerDisplayed).WillOnce(Return());
    EXPECT_CALL(*mLayer3.layerFE, onLayerDisplayed).WillOnce(Return());

    constexpr bool kFlushEvenWhenDisabled = false;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, setReleaseFencesIncludeClientTargetAcquireFence) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::ce_fence_promise, true);
    ASSERT_TRUE(FlagManager::getInstance().ce_fence_promise());

    mOutput.mState.isEnabled = true;
    mOutput.mState.usesClientComposition = true;

    Output::FrameFences frameFences;
    frameFences.clientTargetAcquireFence = sp<Fence>::make();
    frameFences.layerFences.emplace(&mLayer1.hwc2Layer, sp<Fence>::make());
    frameFences.layerFences.emplace(&mLayer2.hwc2Layer, sp<Fence>::make());
    frameFences.layerFences.emplace(&mLayer3.hwc2Layer, sp<Fence>::make());

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Fence::merge is called, and since none of the fences are actually valid,
    // Fence::NO_FENCE is returned and passed to each setReleaseFence() call.
    // This is the best we can do without creating a real kernel fence object.
    EXPECT_CALL(*mLayer1.layerFE, setReleaseFence).WillOnce(Return());
    EXPECT_CALL(*mLayer2.layerFE, setReleaseFence).WillOnce(Return());
    EXPECT_CALL(*mLayer3.layerFE, setReleaseFence).WillOnce(Return());
    constexpr bool kFlushEvenWhenDisabled = false;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);
}

TEST_F(OutputPostFramebufferTest, releasedLayersSentPresentFence) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::ce_fence_promise, false);
    ASSERT_FALSE(FlagManager::getInstance().ce_fence_promise());

    mOutput.mState.isEnabled = true;
    mOutput.mState.usesClientComposition = true;

    // This should happen even if there are no (current) output layers.
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));

    // Load up the released layers with some mock instances
    sp<StrictMock<mock::LayerFE>> releasedLayer1 = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> releasedLayer2 = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> releasedLayer3 = sp<StrictMock<mock::LayerFE>>::make();
    Output::ReleasedLayers layers;
    layers.push_back(releasedLayer1);
    layers.push_back(releasedLayer2);
    layers.push_back(releasedLayer3);
    mOutput.setReleasedLayers(std::move(layers));

    // Set up a fake present fence
    sp<Fence> presentFence = sp<Fence>::make();
    Output::FrameFences frameFences;
    frameFences.presentFence = presentFence;

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Each released layer should be given the presentFence.
    EXPECT_CALL(*releasedLayer1, onLayerDisplayed(_, _))
            .WillOnce([&presentFence](ftl::SharedFuture<FenceResult> futureFenceResult,
                                      ui::LayerStack) {
                EXPECT_EQ(FenceResult(presentFence), futureFenceResult.get());
            });
    EXPECT_CALL(*releasedLayer2, onLayerDisplayed(_, _))
            .WillOnce([&presentFence](ftl::SharedFuture<FenceResult> futureFenceResult,
                                      ui::LayerStack) {
                EXPECT_EQ(FenceResult(presentFence), futureFenceResult.get());
            });
    EXPECT_CALL(*releasedLayer3, onLayerDisplayed(_, _))
            .WillOnce([&presentFence](ftl::SharedFuture<FenceResult> futureFenceResult,
                                      ui::LayerStack) {
                EXPECT_EQ(FenceResult(presentFence), futureFenceResult.get());
            });

    constexpr bool kFlushEvenWhenDisabled = false;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);

    // After the call the list of released layers should have been cleared.
    EXPECT_TRUE(mOutput.getReleasedLayersForTest().empty());
}

TEST_F(OutputPostFramebufferTest, setReleasedLayersSentPresentFence) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::ce_fence_promise, true);
    ASSERT_TRUE(FlagManager::getInstance().ce_fence_promise());

    mOutput.mState.isEnabled = true;
    mOutput.mState.usesClientComposition = true;

    // This should happen even if there are no (current) output layers.
    EXPECT_CALL(mOutput, getOutputLayerCount()).WillOnce(Return(0u));

    // Load up the released layers with some mock instances
    sp<StrictMock<mock::LayerFE>> releasedLayer1 = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> releasedLayer2 = sp<StrictMock<mock::LayerFE>>::make();
    sp<StrictMock<mock::LayerFE>> releasedLayer3 = sp<StrictMock<mock::LayerFE>>::make();
    Output::ReleasedLayers layers;
    layers.push_back(releasedLayer1);
    layers.push_back(releasedLayer2);
    layers.push_back(releasedLayer3);
    mOutput.setReleasedLayers(std::move(layers));

    // Set up a fake present fence
    sp<Fence> presentFence = sp<Fence>::make();
    Output::FrameFences frameFences;
    frameFences.presentFence = presentFence;

    EXPECT_CALL(mOutput, presentFrame()).WillOnce(Return(frameFences));
    EXPECT_CALL(*mRenderSurface, onPresentDisplayCompleted());

    // Each released layer should be given the presentFence.
    EXPECT_CALL(*releasedLayer1, setReleaseFence(_))
            .WillOnce([&presentFence](FenceResult fenceResult) {
                EXPECT_EQ(FenceResult(presentFence), fenceResult);
            });
    EXPECT_CALL(*releasedLayer2, setReleaseFence(_))
            .WillOnce([&presentFence](FenceResult fenceResult) {
                EXPECT_EQ(FenceResult(presentFence), fenceResult);
            });
    EXPECT_CALL(*releasedLayer3, setReleaseFence(_))
            .WillOnce([&presentFence](FenceResult fenceResult) {
                EXPECT_EQ(FenceResult(presentFence), fenceResult);
            });

    constexpr bool kFlushEvenWhenDisabled = false;
    mOutput.presentFrameAndReleaseLayers(kFlushEvenWhenDisabled);

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
                     std::vector<LayerFE::LayerSettings>(bool, ui::Dataspace,
                                                         std::vector<LayerFE*>&));
        MOCK_METHOD2(appendRegionFlashRequests,
                     void(const Region&, std::vector<LayerFE::LayerSettings>&));
        MOCK_METHOD1(setExpensiveRenderingExpected, void(bool));
        MOCK_METHOD(void, setHintSessionGpuStart, (TimePoint startTime), (override));
        MOCK_METHOD(void, setHintSessionGpuFence, (std::unique_ptr<FenceTime> && gpuFence),
                    (override));
        MOCK_METHOD(void, setHintSessionRequiresRenderEngine, (bool), (override));
        MOCK_METHOD(bool, isPowerHintSessionEnabled, (), (override));
        MOCK_METHOD(bool, isPowerHintSessionGpuReportingEnabled, (), (override));
    };

    OutputComposeSurfacesTest() {
        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
        mOutput.cacheClientCompositionRequests(MAX_CLIENT_COMPOSITION_CACHE_SIZE);

        mOutput.mState.orientedDisplaySpace.setContent(kDefaultOutputFrame);
        mOutput.mState.layerStackSpace.setContent(kDefaultOutputViewport);
        mOutput.mState.framebufferSpace.setContent(kDefaultOutputDestinationClip);
        mOutput.mState.displaySpace.setContent(kDefaultOutputDestinationClip);
        mOutput.mState.displaySpace.setOrientation(kDefaultOutputOrientation);
        mOutput.mState.transform = ui::Transform{kDefaultOutputOrientationFlags};
        mOutput.mState.dataspace = kDefaultOutputDataspace;
        mOutput.mState.colorTransformMatrix = kDefaultColorTransformMat;
        mOutput.mState.isSecure = false;
        mOutput.mState.needsFiltering = false;
        mOutput.mState.usesClientComposition = true;
        mOutput.mState.usesDeviceComposition = false;
        mOutput.mState.reusedClientComposition = false;
        mOutput.mState.flipClientTarget = false;
        mOutput.mState.clientTargetBrightness = kClientTargetBrightness;

        EXPECT_CALL(mOutput, getCompositionEngine()).WillRepeatedly(ReturnRef(mCompositionEngine));
        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
        EXPECT_CALL(mCompositionEngine, getTimeStats()).WillRepeatedly(Return(mTimeStats.get()));
        EXPECT_CALL(*mDisplayColorProfile, getHdrCapabilities())
                .WillRepeatedly(ReturnRef(kHdrCapabilities));
        EXPECT_CALL(mOutput, isPowerHintSessionEnabled()).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput, isPowerHintSessionGpuReportingEnabled()).WillRepeatedly(Return(true));
    }

    struct ExecuteState : public CallOrderStateMachineHelper<TestType, ExecuteState> {
        auto execute() {
            base::unique_fd fence;
            std::shared_ptr<renderengine::ExternalTexture> externalTexture;
            const bool success =
                    getInstance()->mOutput.dequeueRenderBuffer(&fence, &externalTexture);
            if (success) {
                getInstance()->mReadyFence =
                        getInstance()->mOutput.composeSurfaces(kDebugRegion, externalTexture,
                                                               fence);
            }
            return nextState<FenceCheckState>();
        }
    };

    struct FenceCheckState : public CallOrderStateMachineHelper<TestType, FenceCheckState> {
        void expectNoFenceWasReturned() { EXPECT_FALSE(getInstance()->mReadyFence); }

        void expectAFenceWasReturned() { EXPECT_TRUE(getInstance()->mReadyFence); }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return ExecuteState::make(this); }

    static constexpr ui::Rotation kDefaultOutputOrientation = ui::ROTATION_0;
    static constexpr uint32_t kDefaultOutputOrientationFlags =
            ui::Transform::toRotationFlags(kDefaultOutputOrientation);
    static constexpr ui::Dataspace kDefaultOutputDataspace = ui::Dataspace::UNKNOWN;
    static constexpr ui::Dataspace kExpensiveOutputDataspace = ui::Dataspace::DISPLAY_P3;
    static constexpr float kDefaultMaxLuminance = 0.9f;
    static constexpr float kDefaultAvgLuminance = 0.7f;
    static constexpr float kDefaultMinLuminance = 0.1f;
    static constexpr float kDisplayLuminance = 400.f;
    static constexpr float kWhitePointLuminance = 300.f;
    static constexpr float kClientTargetLuminanceNits = 200.f;
    static constexpr float kClientTargetBrightness = 0.5f;

    static const Rect kDefaultOutputFrame;
    static const Rect kDefaultOutputViewport;
    static const Rect kDefaultOutputDestinationClip;
    static const mat4 kDefaultColorTransformMat;

    static const Region kDebugRegion;
    static const HdrCapabilities kHdrCapabilities;

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    // TODO: make this is a proper mock.
    std::shared_ptr<TimeStats> mTimeStats = std::make_shared<android::impl::TimeStats>();
    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
    std::shared_ptr<renderengine::ExternalTexture> mOutputBuffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);

    std::optional<base::unique_fd> mReadyFence;
};

const Rect OutputComposeSurfacesTest::kDefaultOutputFrame{1001, 1002, 1003, 1004};
const Rect OutputComposeSurfacesTest::kDefaultOutputViewport{1005, 1006, 1007, 1008};
const Rect OutputComposeSurfacesTest::kDefaultOutputDestinationClip{1013, 1014, 1015, 1016};
const mat4 OutputComposeSurfacesTest::kDefaultColorTransformMat{mat4() * 0.5f};
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
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, IsEmpty(), _, _))
            .WillRepeatedly([&](const renderengine::DisplaySettings&,
                                const std::vector<renderengine::LayerSettings>&,
                                const std::shared_ptr<renderengine::ExternalTexture>&,
                                base::unique_fd&&) -> ftl::Future<FenceResult> {
                return ftl::yield<FenceResult>(Fence::NO_FENCE);
            });
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
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(
                    Invoke([&](const Region&,
                               std::vector<LayerFE::LayerSettings>& clientCompositionLayers) {
                        clientCompositionLayers.emplace_back(r2);
                    }));

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r2), _, _))
            .WillRepeatedly([&](const renderengine::DisplaySettings&,
                                const std::vector<renderengine::LayerSettings>&,
                                const std::shared_ptr<renderengine::ExternalTexture>&,
                                base::unique_fd&&) -> ftl::Future<FenceResult> {
                return ftl::yield<FenceResult>(Fence::NO_FENCE);
            });

    verify().execute().expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest,
       buildsAndRendersRequestListAndCachesFramebufferForInternalLayers) {
    LayerFE::LayerSettings r1;
    LayerFE::LayerSettings r2;

    r1.geometry.boundaries = FloatRect{1, 2, 3, 4};
    r2.geometry.boundaries = FloatRect{5, 6, 7, 8};
    mOutput.setLayerFilter({ui::LayerStack{1234u}, true});

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(
                    Invoke([&](const Region&,
                               std::vector<LayerFE::LayerSettings>& clientCompositionLayers) {
                        clientCompositionLayers.emplace_back(r2);
                    }));

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r2), _, _))
            .WillRepeatedly([&](const renderengine::DisplaySettings&,
                                const std::vector<renderengine::LayerSettings>&,
                                const std::shared_ptr<renderengine::ExternalTexture>&,
                                base::unique_fd&&) -> ftl::Future<FenceResult> {
                return ftl::yield<FenceResult>(Fence::NO_FENCE);
            });

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
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1, r2}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r2), _, _))
            .Times(2)
            .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))))
            .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))));

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
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1, r2}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r2), _, _))
            .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))));
    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(false));

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);

    // We do not expect another call to draw layers.
    EXPECT_CALL(mOutput, setHintSessionRequiresRenderEngine(_)).Times(0);
    EXPECT_CALL(mOutput, setHintSessionGpuStart(_)).Times(0);
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_)).Times(0);
    verify().execute().expectAFenceWasReturned();
    EXPECT_TRUE(mOutput.mState.reusedClientComposition);
}

TEST_F(OutputComposeSurfacesTest, clientCompositionIfBufferChangesWithAdpfGpuOff) {
    EXPECT_CALL(mOutput, isPowerHintSessionGpuReportingEnabled()).WillOnce(Return(false));
    LayerFE::LayerSettings r1;
    LayerFE::LayerSettings r2;

    r1.geometry.boundaries = FloatRect{1, 2, 3, 4};
    r2.geometry.boundaries = FloatRect{5, 6, 7, 8};

    EXPECT_CALL(mOutput, getSkipColorTransform()).WillRepeatedly(Return(false));
    EXPECT_CALL(*mDisplayColorProfile, hasWideColorGamut()).WillRepeatedly(Return(true));
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
    EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1, r2}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    const auto otherOutputBuffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_))
            .WillOnce(Return(mOutputBuffer))
            .WillOnce(Return(otherOutputBuffer));
    base::unique_fd fd(open("/dev/null", O_RDONLY));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r2), _, _))
            .WillRepeatedly([&](const renderengine::DisplaySettings&,
                                const std::vector<renderengine::LayerSettings>&,
                                const std::shared_ptr<renderengine::ExternalTexture>&,
                                base::unique_fd&&) -> ftl::Future<FenceResult> {
                return ftl::yield<FenceResult>(sp<Fence>::make(std::move(fd)));
            });

    EXPECT_CALL(mOutput, setHintSessionRequiresRenderEngine(true));
    EXPECT_CALL(mOutput, setHintSessionGpuStart(_)).Times(0);
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_)).Times(0);
    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);
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
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillRepeatedly(Return(std::vector<LayerFE::LayerSettings>{r1, r2}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    const auto otherOutputBuffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_))
            .WillOnce(Return(mOutputBuffer))
            .WillOnce(Return(otherOutputBuffer));
    base::unique_fd fd(open("/dev/null", O_RDONLY));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r2), _, _))
            .WillRepeatedly([&](const renderengine::DisplaySettings&,
                                const std::vector<renderengine::LayerSettings>&,
                                const std::shared_ptr<renderengine::ExternalTexture>&,
                                base::unique_fd&&) -> ftl::Future<FenceResult> {
                return ftl::yield<FenceResult>(sp<Fence>::make(std::move(fd)));
            });

    EXPECT_CALL(mOutput, setHintSessionRequiresRenderEngine(true));
    EXPECT_CALL(mOutput, setHintSessionGpuStart(_));
    EXPECT_CALL(mOutput, setHintSessionGpuFence(_));
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
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kDefaultOutputDataspace, _))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>{r1, r2}))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>{r1, r3}));
    EXPECT_CALL(mOutput, appendRegionFlashRequests(RegionEq(kDebugRegion), _))
            .WillRepeatedly(Return());

    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r2), _, _))
            .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))));
    EXPECT_CALL(mRenderEngine, drawLayers(_, ElementsAre(r1, r3), _, _))
            .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))));

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);

    verify().execute().expectAFenceWasReturned();
    EXPECT_FALSE(mOutput.mState.reusedClientComposition);
}

struct OutputComposeSurfacesTest_UsesExpectedDisplaySettings : public OutputComposeSurfacesTest {
    OutputComposeSurfacesTest_UsesExpectedDisplaySettings() {
        EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(false));
        EXPECT_CALL(mRenderEngine, isProtected()).WillRepeatedly(Return(false));
        EXPECT_CALL(mOutput, generateClientCompositionRequests(_, _, _))
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
            return nextState<OutputWithDisplayBrightnessNits>();
        }
    };

    struct OutputWithDisplayBrightnessNits
          : public CallOrderStateMachineHelper<TestType, OutputWithDisplayBrightnessNits> {
        auto withDisplayBrightnessNits(float nits) {
            getInstance()->mOutput.mState.displayBrightnessNits = nits;
            return nextState<OutputWithSdrWhitePointNits>();
        }
    };

    struct OutputWithSdrWhitePointNits
          : public CallOrderStateMachineHelper<TestType, OutputWithSdrWhitePointNits> {
        auto withSdrWhitePointNits(float nits) {
            getInstance()->mOutput.mState.sdrWhitePointNits = nits;
            return nextState<OutputWithDimmingStage>();
        }
    };

    struct OutputWithDimmingStage
          : public CallOrderStateMachineHelper<TestType, OutputWithDimmingStage> {
        auto withDimmingStage(
                aidl::android::hardware::graphics::composer3::DimmingStage dimmingStage) {
            getInstance()->mOutput.mState.clientTargetDimmingStage = dimmingStage;
            return nextState<OutputWithRenderIntent>();
        }
    };

    struct OutputWithRenderIntent
          : public CallOrderStateMachineHelper<TestType, OutputWithRenderIntent> {
        auto withRenderIntent(
                aidl::android::hardware::graphics::composer3::RenderIntent renderIntent) {
            getInstance()->mOutput.mState.renderIntent =
                    static_cast<ui::RenderIntent>(renderIntent);
            return nextState<SkipColorTransformState>();
        }
    };

    struct SkipColorTransformState
          : public CallOrderStateMachineHelper<TestType, SkipColorTransformState> {
        auto andIfSkipColorTransform(bool skip) {
            // May be called zero or one times.
            EXPECT_CALL(getInstance()->mOutput, getSkipColorTransform())
                    .WillRepeatedly(Return(skip));
            return nextState<PixelFormatState>();
        }
    };

    struct PixelFormatState : public CallOrderStateMachineHelper<TestType, PixelFormatState> {
        auto withPixelFormat(std::optional<PixelFormat> format) {
            // May be called zero or one times.
            if (format) {
                auto outputBuffer = std::make_shared<
                        renderengine::impl::
                                ExternalTexture>(sp<GraphicBuffer>::
                                                         make(1u, 1u, *format,
                                                              GRALLOC_USAGE_SW_WRITE_OFTEN |
                                                                      GRALLOC_USAGE_SW_READ_OFTEN),
                                                 getInstance()->mRenderEngine,
                                                 renderengine::impl::ExternalTexture::Usage::
                                                                 READABLE |
                                                         renderengine::impl::ExternalTexture::
                                                                 Usage::WRITEABLE);
                EXPECT_CALL(*getInstance()->mRenderSurface, dequeueBuffer(_))
                        .WillRepeatedly(Return(outputBuffer));
            }
            return nextState<DataspaceState>();
        }
    };

    struct DataspaceState : public CallOrderStateMachineHelper<TestType, DataspaceState> {
        auto withDataspace(ui::Dataspace dataspace) {
            getInstance()->mOutput.mState.dataspace = dataspace;
            return nextState<ExpectDisplaySettingsState>();
        }
    };

    struct ExpectDisplaySettingsState
          : public CallOrderStateMachineHelper<TestType, ExpectDisplaySettingsState> {
        auto thenExpectDisplaySettingsUsed(renderengine::DisplaySettings settings) {
            EXPECT_CALL(getInstance()->mRenderEngine, drawLayers(settings, _, _, _))
                    .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))));
            return nextState<ExecuteState>();
        }
    };

    // Call this member function to start using the mini-DSL defined above.
    [[nodiscard]] auto verify() { return MixedCompositionState::make(this); }
};

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forHdrMixedComposition) {
    verify().ifMixedCompositionIs(true)
            .andIfUsesHdr(true)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(false)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = true,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings,
       forHdrMixedCompositionWithDisplayBrightness) {
    verify().ifMixedCompositionIs(true)
            .andIfUsesHdr(true)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(false)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = true,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings,
       forHdrMixedCompositionWithDimmingStage) {
    verify().ifMixedCompositionIs(true)
            .andIfUsesHdr(true)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(
                    aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(false)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = true,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings,
       forHdrMixedCompositionWithRenderIntent) {
    verify().ifMixedCompositionIs(true)
            .andIfUsesHdr(true)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(aidl::android::hardware::graphics::composer3::RenderIntent::ENHANCE)
            .andIfSkipColorTransform(false)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = true,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent =
                             aidl::android::hardware::graphics::composer3::RenderIntent::ENHANCE})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forNonHdrMixedComposition) {
    verify().ifMixedCompositionIs(true)
            .andIfUsesHdr(false)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(false)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = true,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forHdrOnlyClientComposition) {
    verify().ifMixedCompositionIs(false)
            .andIfUsesHdr(true)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(false)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = false,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings, forNonHdrOnlyClientComposition) {
    verify().ifMixedCompositionIs(false)
            .andIfUsesHdr(false)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(false)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = false,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings,
       usesExpectedDisplaySettingsForHdrOnlyClientCompositionWithSkipClientTransform) {
    verify().ifMixedCompositionIs(false)
            .andIfUsesHdr(true)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(true)
            .withPixelFormat(std::nullopt)
            .withDataspace(kDefaultOutputDataspace)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = kDefaultOutputDataspace,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = true,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

TEST_F(OutputComposeSurfacesTest_UsesExpectedDisplaySettings,
       usesExpectedDisplaySettingsWithFp16Buffer) {
    SET_FLAG_FOR_TEST(flags::fp16_client_target, true);
    verify().ifMixedCompositionIs(false)
            .andIfUsesHdr(true)
            .withDisplayBrightnessNits(kDisplayLuminance)
            .withSdrWhitePointNits(kWhitePointLuminance)
            .withDimmingStage(aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR)
            .withRenderIntent(
                    aidl::android::hardware::graphics::composer3::RenderIntent::COLORIMETRIC)
            .andIfSkipColorTransform(true)
            .withPixelFormat(PIXEL_FORMAT_RGBA_FP16)
            .withDataspace(ui::Dataspace::V0_SCRGB)
            .thenExpectDisplaySettingsUsed(
                    {.physicalDisplay = kDefaultOutputDestinationClip,
                     .clip = kDefaultOutputViewport,
                     .maxLuminance = kDefaultMaxLuminance,
                     .currentLuminanceNits = kDisplayLuminance,
                     .outputDataspace = ui::Dataspace::V0_SCRGB,
                     .colorTransform = kDefaultColorTransformMat,
                     .deviceHandlesColorTransform = true,
                     .orientation = kDefaultOutputOrientationFlags,
                     .targetLuminanceNits = kClientTargetLuminanceNits * 0.75f,
                     .dimmingStage =
                             aidl::android::hardware::graphics::composer3::DimmingStage::LINEAR,
                     .renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::
                             COLORIMETRIC})
            .execute()
            .expectAFenceWasReturned();
}

struct OutputComposeSurfacesTest_HandlesProtectedContent : public OutputComposeSurfacesTest {
    struct Layer {
        Layer() {
            EXPECT_CALL(*mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*mLayerFE));
            EXPECT_CALL(mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        sp<StrictMock<mock::LayerFE>> mLayerFE = sp<StrictMock<mock::LayerFE>>::make();
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
        EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _))
                .WillRepeatedly([&](const renderengine::DisplaySettings&,
                                    const std::vector<renderengine::LayerSettings>&,
                                    const std::shared_ptr<renderengine::ExternalTexture>&,
                                    base::unique_fd&&) -> ftl::Future<FenceResult> {
                    return ftl::yield<FenceResult>(Fence::NO_FENCE);
                });
    }

    Layer mLayer1;
    Layer mLayer2;
};

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifNoProtectedContentLayers) {
    SET_FLAG_FOR_TEST(flags::protected_if_client, true);
    if (FlagManager::getInstance().display_protected()) {
        mOutput.mState.isProtected = true;
    } else {
        mOutput.mState.isSecure = true;
    }
    mLayer2.mLayerFEState.hasProtectedContent = false;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(true));
    EXPECT_CALL(*mRenderSurface, setProtected(false));

    base::unique_fd fd;
    std::shared_ptr<renderengine::ExternalTexture> tex;
    mOutput.updateProtectedContentState();
    mOutput.dequeueRenderBuffer(&fd, &tex);
    mOutput.composeSurfaces(kDebugRegion, tex, fd);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifNotEnabled) {
    SET_FLAG_FOR_TEST(flags::protected_if_client, true);
    if (FlagManager::getInstance().display_protected()) {
        mOutput.mState.isProtected = true;
    } else {
        mOutput.mState.isSecure = true;
    }
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));

    // For this test, we also check the call order of key functions.
    InSequence seq;

    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(false));
    EXPECT_CALL(*mRenderSurface, setProtected(true));
    // Must happen after setting the protected content state.
    EXPECT_CALL(*mRenderSurface, dequeueBuffer(_)).WillRepeatedly(Return(mOutputBuffer));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _))
            .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))));

    base::unique_fd fd;
    std::shared_ptr<renderengine::ExternalTexture> tex;
    mOutput.updateProtectedContentState();
    mOutput.dequeueRenderBuffer(&fd, &tex);
    mOutput.composeSurfaces(kDebugRegion, tex, fd);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifAlreadyEnabledEverywhere) {
    SET_FLAG_FOR_TEST(flags::protected_if_client, true);
    if (FlagManager::getInstance().display_protected()) {
        mOutput.mState.isProtected = true;
    } else {
        mOutput.mState.isSecure = true;
    }
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(true));

    base::unique_fd fd;
    std::shared_ptr<renderengine::ExternalTexture> tex;
    mOutput.updateProtectedContentState();
    mOutput.dequeueRenderBuffer(&fd, &tex);
    mOutput.composeSurfaces(kDebugRegion, tex, fd);
}

TEST_F(OutputComposeSurfacesTest_HandlesProtectedContent, ifAlreadyEnabledInRenderSurface) {
    SET_FLAG_FOR_TEST(flags::protected_if_client, true);
    if (FlagManager::getInstance().display_protected()) {
        mOutput.mState.isProtected = true;
    } else {
        mOutput.mState.isSecure = true;
    }
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(true));

    base::unique_fd fd;
    std::shared_ptr<renderengine::ExternalTexture> tex;
    mOutput.updateProtectedContentState();
    mOutput.dequeueRenderBuffer(&fd, &tex);
    mOutput.composeSurfaces(kDebugRegion, tex, fd);
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

    LayerFE::LayerSettings layerSettings;
    EXPECT_CALL(mOutput, generateClientCompositionRequests(_, kExpensiveOutputDataspace, _))
            .WillOnce(Return(std::vector<LayerFE::LayerSettings>{layerSettings}));

    // For this test, we also check the call order of key functions.
    InSequence seq;

    EXPECT_CALL(mOutput, setExpensiveRenderingExpected(true));
    EXPECT_CALL(mRenderEngine, drawLayers(_, _, _, _))
            .WillOnce(Return(ByMove(ftl::yield<FenceResult>(Fence::NO_FENCE))));

    base::unique_fd fd;
    std::shared_ptr<renderengine::ExternalTexture> tex;
    mOutput.updateProtectedContentState();
    mOutput.dequeueRenderBuffer(&fd, &tex);
    mOutput.composeSurfaces(kDebugRegion, tex, fd);
}

/*
 * Output::generateClientCompositionRequests()
 */

struct GenerateClientCompositionRequestsTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // compositionengine::Output overrides
        std::vector<LayerFE::LayerSettings> generateClientCompositionRequestsHelper(
                bool supportsProtectedContent, ui::Dataspace dataspace) {
            std::vector<LayerFE*> ignore;
            return impl::Output::generateClientCompositionRequests(supportsProtectedContent,
                                                                   dataspace, ignore);
        }
    };

    struct Layer {
        Layer() {
            EXPECT_CALL(mOutputLayer, getOverrideCompositionSettings())
                    .WillRepeatedly(Return(std::nullopt));
            EXPECT_CALL(mOutputLayer, getState()).WillRepeatedly(ReturnRef(mOutputLayerState));
            EXPECT_CALL(mOutputLayer, editState()).WillRepeatedly(ReturnRef(mOutputLayerState));
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*mLayerFE));
            EXPECT_CALL(*mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        sp<StrictMock<mock::LayerFE>> mLayerFE = sp<StrictMock<mock::LayerFE>>::make();
        LayerFECompositionState mLayerFEState;
        impl::OutputLayerCompositionState mOutputLayerState;
        LayerFE::LayerSettings mLayerSettings;
    };

    GenerateClientCompositionRequestsTest() {
        mOutput.mState.needsFiltering = false;
        mOutput.mState.isProtected = true;

        mOutput.setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
    }

    static constexpr float kLayerWhitePointNits = 200.f;

    mock::DisplayColorProfile* mDisplayColorProfile = new StrictMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
};

struct GenerateClientCompositionRequestsTest_ThreeLayers
      : public GenerateClientCompositionRequestsTest {
    GenerateClientCompositionRequestsTest_ThreeLayers() {
        mOutput.mState.orientedDisplaySpace.setContent(kDisplayFrame);
        mOutput.mState.layerStackSpace.setContent(kDisplayViewport);
        mOutput.mState.displaySpace.setContent(kDisplayDestinationClip);
        mOutput.mState.transform =
                ui::Transform{ui::Transform::toRotationFlags(kDisplayOrientation)};
        mOutput.mState.displaySpace.setOrientation(kDisplayOrientation);
        mOutput.mState.needsFiltering = false;
        mOutput.mState.isSecure = false;
        mOutput.mState.isProtected = true;

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

    static constexpr ui::Rotation kDisplayOrientation = ui::ROTATION_0;
    static constexpr ui::Dataspace kDisplayDataspace = ui::Dataspace::UNKNOWN;
    static constexpr float kLayerWhitePointNits = 200.f;

    static const Rect kDisplayFrame;
    static const Rect kDisplayViewport;
    static const Rect kDisplayDestinationClip;

    std::array<Layer, 3> mLayers;
};

const Rect GenerateClientCompositionRequestsTest_ThreeLayers::kDisplayFrame(0, 0, 100, 200);
const Rect GenerateClientCompositionRequestsTest_ThreeLayers::kDisplayViewport(0, 0, 101, 201);
const Rect GenerateClientCompositionRequestsTest_ThreeLayers::kDisplayDestinationClip(0, 0, 103,
                                                                                      203);

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, handlesNoClientCompostionLayers) {
    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[2].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    EXPECT_EQ(0u, requests.size());
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, requiresVisibleRegionAfterViewportClip) {
    mLayers[0].mOutputLayerState.visibleRegion = Region(Rect(10, 10, 10, 10));
    mLayers[1].mOutputLayerState.visibleRegion = Region(Rect(4000, 0, 4010, 10));
    mLayers[2].mOutputLayerState.visibleRegion = Region(Rect(-10, -10, 0, 0));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    EXPECT_EQ(0u, requests.size());
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, gathersClientCompositionRequests) {
    EXPECT_CALL(*mLayers[0].mLayerFE, prepareClientComposition(_))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(_))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[1].mLayerSettings)));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(_))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[2].mLayerSettings)));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    ASSERT_EQ(2u, requests.size());
    EXPECT_EQ(mLayers[1].mLayerSettings, requests[0]);
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[1]);

    // Check that a timestamp was set for the layers that generated requests
    EXPECT_TRUE(0 == mLayers[0].mOutputLayerState.clientCompositionTimestamp);
    EXPECT_TRUE(0 != mLayers[1].mOutputLayerState.clientCompositionTimestamp);
    EXPECT_TRUE(0 != mLayers[2].mOutputLayerState.clientCompositionTimestamp);
}

MATCHER_P(ClientCompositionTargetSettingsBlurSettingsEq, expectedBlurSetting, "") {
    *result_listener << "ClientCompositionTargetSettings' BlurSettings aren't equal \n";
    *result_listener << "expected " << expectedBlurSetting << "\n";
    *result_listener << "actual " << arg.blurSetting << "\n";

    return expectedBlurSetting == arg.blurSetting;
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers, overridesBlur) {
    mLayers[2].mOutputLayerState.overrideInfo.disableBackgroundBlur = true;

    EXPECT_CALL(*mLayers[0].mLayerFE, prepareClientComposition(_))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(_))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[1].mLayerSettings)));
    EXPECT_CALL(*mLayers[2].mLayerFE,
                prepareClientComposition(ClientCompositionTargetSettingsBlurSettingsEq(
                        LayerFE::ClientCompositionTargetSettings::BlurSetting::BlurRegionsOnly)))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[2].mLayerSettings)));
    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    ASSERT_EQ(2u, requests.size());
    EXPECT_EQ(mLayers[1].mLayerSettings, requests[0]);
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[1]);

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

    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(_))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[2].mLayerSettings)));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    ASSERT_EQ(1u, requests.size());
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[0]);
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

    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(_))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[2].mLayerSettings)));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    ASSERT_EQ(1u, requests.size());
    EXPECT_EQ(mLayers[2].mLayerSettings, requests[0]);
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

    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            false /* realContentIsVisible */,
            true /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    LayerFE::LayerSettings mBlackoutSettings = mLayers[1].mLayerSettings;
    mBlackoutSettings.source.buffer.buffer = nullptr;
    mBlackoutSettings.source.solidColor = {0.1f, 0.1f, 0.1f};
    mBlackoutSettings.alpha = 0.f;
    mBlackoutSettings.disableBlending = true;

    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mBlackoutSettings)));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[2].mLayerSettings)));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    ASSERT_EQ(2u, requests.size());

    // The second layer is expected to be rendered as alpha=0 black with no blending
    EXPECT_EQ(mBlackoutSettings, requests[0]);

    EXPECT_EQ(mLayers[2].mLayerSettings, requests[1]);
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       clippedVisibleRegionUsedToGenerateRequest) {
    mLayers[0].mOutputLayerState.visibleRegion = Region(Rect(10, 10, 20, 20));
    mLayers[1].mOutputLayerState.visibleRegion = Region(Rect(-10, -10, 30, 30));
    mLayers[2].mOutputLayerState.visibleRegion = Region(Rect(-10, 0, 40, 4000));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(Rect(10, 10, 20, 20)),
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(Rect(0, 0, 30, 30)),
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(Rect(0, 0, 40, 201)),
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(*mLayers[0].mLayerFE, prepareClientComposition(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       perLayerNeedsFilteringUsedToGenerateRequests) {
    mOutput.mState.needsFiltering = false;
    EXPECT_CALL(mLayers[0].mOutputLayer, needsFiltering()).WillRepeatedly(Return(true));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(*mLayers[0].mLayerFE, prepareClientComposition(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       wholeOutputNeedsFilteringUsedToGenerateRequests) {
    mOutput.mState.needsFiltering = true;
    EXPECT_CALL(mLayers[0].mOutputLayer, needsFiltering()).WillRepeatedly(Return(true));

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            true,  /* needs filtering */
            false, /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(*mLayers[0].mLayerFE, prepareClientComposition(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       wholeOutputSecurityUsedToGenerateRequests) {
    mOutput.mState.isSecure = true;

    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            true,  /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            true,  /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            true,  /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(*mLayers[0].mLayerFE, prepareClientComposition(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace));
}

TEST_F(GenerateClientCompositionRequestsTest_ThreeLayers,
       protectedContentSupportUsedToGenerateRequests) {
    compositionengine::LayerFE::ClientCompositionTargetSettings layer0TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            false, /* secure */
            true,  /* isProtected */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer1TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            false, /* secure */
            true,  /* isProtected */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };
    compositionengine::LayerFE::ClientCompositionTargetSettings layer2TargetSettings{
            Region(kDisplayFrame),
            false, /* needs filtering */
            false, /* secure */
            true,  /* isProtected */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(*mLayers[0].mLayerFE, prepareClientComposition(Eq(ByRef(layer0TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[1].mLayerFE, prepareClientComposition(Eq(ByRef(layer1TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2TargetSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>()));

    static_cast<void>(
            mOutput.generateClientCompositionRequestsHelper(true /* supportsProtectedContent */,
                                                            kDisplayDataspace));
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, noBackgroundBlurWhenOpaque) {
    InjectedLayer layer1;
    InjectedLayer layer2;

    uint32_t z = 0;
    // Layer requesting blur, or below, should request client composition, unless opaque.
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer2.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    layer2.layerFEState.backgroundBlurRadius = 10;
    layer2.layerFEState.isOpaque = true;

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = false;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, handlesBackgroundBlurRequests) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    uint32_t z = 0;
    // Layer requesting blur, or below, should request client composition.
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer2.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer3.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    layer2.layerFEState.backgroundBlurRadius = 10;
    layer2.layerFEState.isOpaque = false;

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = false;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
}

TEST_F(OutputUpdateAndWriteCompositionStateTest, handlesBlurRegionRequests) {
    InjectedLayer layer1;
    InjectedLayer layer2;
    InjectedLayer layer3;

    uint32_t z = 0;
    // Layer requesting blur, or below, should request client composition.
    EXPECT_CALL(*layer1.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer1.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer1.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer2.outputLayer, updateCompositionState(false, true, ui::Transform::ROT_0));
    EXPECT_CALL(*layer2.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer2.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    EXPECT_CALL(*layer3.outputLayer, updateCompositionState(false, false, ui::Transform::ROT_0));
    EXPECT_CALL(*layer3.outputLayer,
                writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, z++,
                                /*zIsOverridden*/ false, /*isPeekingThrough*/ false));
    EXPECT_CALL(*layer3.outputLayer, requiresClientComposition()).WillRepeatedly(Return(false));

    BlurRegion region;
    layer2.layerFEState.blurRegions.push_back(region);
    layer2.layerFEState.isOpaque = false;

    injectOutputLayer(layer1);
    injectOutputLayer(layer2);
    injectOutputLayer(layer3);

    mOutput->editState().isEnabled = true;

    CompositionRefreshArgs args;
    args.updatingGeometryThisFrame = false;
    args.devOptForceClientComposition = false;
    mOutput->updateCompositionState(args);
    mOutput->planComposition();
    mOutput->writeCompositionState(args);
}

TEST_F(GenerateClientCompositionRequestsTest, handlesLandscapeModeSplitScreenRequests) {
    // In split-screen landscape mode, the screen is rotated 90 degrees, with
    // one layer on the left covering the left side of the output, and one layer
    // on the right covering that side of the output.

    const Rect kPortraitFrame(0, 0, 1000, 2000);
    const Rect kPortraitViewport(0, 0, 2000, 1000);
    const Rect kPortraitDestinationClip(0, 0, 1000, 2000);
    const ui::Rotation kPortraitOrientation = ui::ROTATION_90;
    constexpr ui::Dataspace kOutputDataspace = ui::Dataspace::DISPLAY_P3;

    mOutput.mState.orientedDisplaySpace.setContent(kPortraitFrame);
    mOutput.mState.layerStackSpace.setContent(kPortraitViewport);
    mOutput.mState.displaySpace.setContent(kPortraitDestinationClip);
    mOutput.mState.transform = ui::Transform{ui::Transform::toRotationFlags(kPortraitOrientation)};
    mOutput.mState.displaySpace.setOrientation(kPortraitOrientation);
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

    compositionengine::LayerFE::ClientCompositionTargetSettings leftLayerSettings{
            Region(Rect(0, 0, 1000, 1000)),
            false, /* needs filtering */
            true,  /* secure */
            true,  /* isProtected */
            kPortraitViewport,
            kOutputDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(leftLayer.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(leftLayer.mOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(*leftLayer.mLayerFE, prepareClientComposition(Eq(ByRef(leftLayerSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(leftLayer.mLayerSettings)));

    compositionengine::LayerFE::ClientCompositionTargetSettings rightLayerSettings{
            Region(Rect(1000, 0, 2000, 1000)),
            false, /* needs filtering */
            true,  /* secure */
            true,  /* isProtected */
            kPortraitViewport,
            kOutputDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(rightLayer.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(rightLayer.mOutputLayer, needsFiltering()).WillRepeatedly(Return(false));
    EXPECT_CALL(*rightLayer.mLayerFE, prepareClientComposition(Eq(ByRef(rightLayerSettings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(rightLayer.mLayerSettings)));

    constexpr bool supportsProtectedContent = true;
    auto requests = mOutput.generateClientCompositionRequestsHelper(supportsProtectedContent,
                                                                    kOutputDataspace);
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

    compositionengine::LayerFE::ClientCompositionTargetSettings layer2Settings{
            Region(Rect(60, 40, 70, 80)).merge(Rect(40, 80, 70, 90)), /* visible region */
            false,                                                    /* needs filtering */
            false,                                                    /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            false /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    LayerFE::LayerSettings mShadowSettings;
    mShadowSettings.source.solidColor = {0.1f, 0.1f, 0.1f};

    mLayers[2].mOutputLayerState.visibleRegion = kPartialShadowRegion;
    mLayers[2].mOutputLayerState.shadowRegion = kShadowRegion;

    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2Settings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mShadowSettings)));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
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

    mLayers[2].mOutputLayerState.visibleRegion = kPartialContentWithPartialShadowRegion;
    mLayers[2].mOutputLayerState.shadowRegion = kShadowRegion;

    compositionengine::LayerFE::ClientCompositionTargetSettings layer2Settings{
            Region(Rect(50, 40, 70, 80)).merge(Rect(40, 80, 70, 90)), /* visible region */
            false,                                                    /* needs filtering */
            false,                                                    /* secure */
            false, /* supports protected content */
            kDisplayViewport,
            kDisplayDataspace,
            true /* realContentIsVisible */,
            false /* clearContent */,
            compositionengine::LayerFE::ClientCompositionTargetSettings::BlurSetting::Enabled,
            kLayerWhitePointNits,
            false /* treat170mAsSrgb */,
    };

    EXPECT_CALL(mLayers[0].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(mLayers[1].mOutputLayer, requiresClientComposition()).WillOnce(Return(false));
    EXPECT_CALL(*mLayers[2].mLayerFE, prepareClientComposition(Eq(ByRef(layer2Settings))))
            .WillOnce(Return(std::optional<LayerFE::LayerSettings>(mLayers[2].mLayerSettings)));

    auto requests =
            mOutput.generateClientCompositionRequestsHelper(false /* supportsProtectedContent */,
                                                            kDisplayDataspace);
    ASSERT_EQ(1u, requests.size());

    EXPECT_EQ(mLayers[2].mLayerSettings, requests[0]);
}

struct OutputPresentFrameAndReleaseLayersAsyncTest : public ::testing::Test {
    // Piggy-back on OutputPrepareFrameAsyncTest's version to avoid some boilerplate.
    struct OutputPartialMock : public OutputPrepareFrameAsyncTest::OutputPartialMock {
        // Set up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_METHOD(void, presentFrameAndReleaseLayers, (bool flushEvenWhenDisabled));
        MOCK_METHOD(ftl::Future<std::monostate>, presentFrameAndReleaseLayersAsync,
                    (bool flushEvenWhenDisabled));
    };
    OutputPresentFrameAndReleaseLayersAsyncTest() {
        mOutput->setDisplayColorProfileForTest(
                std::unique_ptr<DisplayColorProfile>(mDisplayColorProfile));
        mOutput->setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
        mOutput->setCompositionEnabled(true);
        mRefreshArgs.outputs = {mOutput};
    }

    mock::DisplayColorProfile* mDisplayColorProfile = new NiceMock<mock::DisplayColorProfile>();
    mock::RenderSurface* mRenderSurface = new NiceMock<mock::RenderSurface>();
    std::shared_ptr<OutputPartialMock> mOutput{std::make_shared<NiceMock<OutputPartialMock>>()};
    CompositionRefreshArgs mRefreshArgs;
};

TEST_F(OutputPresentFrameAndReleaseLayersAsyncTest, notCalledWhenNotRequested) {
    EXPECT_CALL(*mOutput, presentFrameAndReleaseLayersAsync(_)).Times(0);
    EXPECT_CALL(*mOutput, presentFrameAndReleaseLayers(_)).Times(1);

    mOutput->present(mRefreshArgs);
}

TEST_F(OutputPresentFrameAndReleaseLayersAsyncTest, calledWhenRequested) {
    EXPECT_CALL(*mOutput, presentFrameAndReleaseLayersAsync(false))
            .WillOnce(Return(ftl::yield<std::monostate>({})));
    EXPECT_CALL(*mOutput, presentFrameAndReleaseLayers(_)).Times(0);

    mOutput->offloadPresentNextFrame();
    mOutput->present(mRefreshArgs);
}

TEST_F(OutputPresentFrameAndReleaseLayersAsyncTest, calledForOneFrame) {
    ::testing::InSequence inseq;
    constexpr bool kFlushEvenWhenDisabled = false;
    EXPECT_CALL(*mOutput, presentFrameAndReleaseLayersAsync(kFlushEvenWhenDisabled))
            .WillOnce(Return(ftl::yield<std::monostate>({})));
    EXPECT_CALL(*mOutput, presentFrameAndReleaseLayers(kFlushEvenWhenDisabled)).Times(1);

    mOutput->offloadPresentNextFrame();
    mOutput->present(mRefreshArgs);
    mOutput->present(mRefreshArgs);
}

/*
 * Output::updateProtectedContentState()
 */

struct OutputUpdateProtectedContentStateTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test to use
        // mock implementations.
        MOCK_CONST_METHOD0(getCompositionEngine, const CompositionEngine&());
    };

    OutputUpdateProtectedContentStateTest() {
        mOutput.setRenderSurfaceForTest(std::unique_ptr<RenderSurface>(mRenderSurface));
        EXPECT_CALL(mOutput, getCompositionEngine()).WillRepeatedly(ReturnRef(mCompositionEngine));
        EXPECT_CALL(mCompositionEngine, getRenderEngine()).WillRepeatedly(ReturnRef(mRenderEngine));
        EXPECT_CALL(mOutput, getOutputLayerCount()).WillRepeatedly(Return(2u));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(0))
                .WillRepeatedly(Return(&mLayer1.mOutputLayer));
        EXPECT_CALL(mOutput, getOutputLayerOrderedByZByIndex(1))
                .WillRepeatedly(Return(&mLayer2.mOutputLayer));
    }

    struct Layer {
        Layer() {
            EXPECT_CALL(*mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
            EXPECT_CALL(mOutputLayer, getLayerFE()).WillRepeatedly(ReturnRef(*mLayerFE));
        }

        StrictMock<mock::OutputLayer> mOutputLayer;
        sp<StrictMock<mock::LayerFE>> mLayerFE = sp<StrictMock<mock::LayerFE>>::make();
        LayerFECompositionState mLayerFEState;
    };

    mock::RenderSurface* mRenderSurface = new StrictMock<mock::RenderSurface>();
    StrictMock<OutputPartialMock> mOutput;
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    Layer mLayer1;
    Layer mLayer2;
};

TEST_F(OutputUpdateProtectedContentStateTest, ifProtectedContentLayerComposeByHWC) {
    SET_FLAG_FOR_TEST(flags::protected_if_client, true);
    if (FlagManager::getInstance().display_protected()) {
        mOutput.mState.isProtected = true;
    } else {
        mOutput.mState.isSecure = true;
    }
    mLayer1.mLayerFEState.hasProtectedContent = false;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(false));
    EXPECT_CALL(mLayer1.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(mLayer2.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(false));
    mOutput.updateProtectedContentState();
}

TEST_F(OutputUpdateProtectedContentStateTest, ifProtectedContentLayerComposeByClient) {
    SET_FLAG_FOR_TEST(flags::protected_if_client, true);
    if (FlagManager::getInstance().display_protected()) {
        mOutput.mState.isProtected = true;
    } else {
        mOutput.mState.isSecure = true;
    }
    mLayer1.mLayerFEState.hasProtectedContent = false;
    mLayer2.mLayerFEState.hasProtectedContent = true;
    EXPECT_CALL(mRenderEngine, supportsProtectedContent()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mRenderSurface, isProtected).WillOnce(Return(false));
    EXPECT_CALL(*mRenderSurface, setProtected(true));
    EXPECT_CALL(mLayer1.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    EXPECT_CALL(mLayer2.mOutputLayer, requiresClientComposition()).WillRepeatedly(Return(true));
    mOutput.updateProtectedContentState();
}

struct OutputPresentFrameAndReleaseLayersTest : public testing::Test {
    struct OutputPartialMock : public OutputPartialMockBase {
        // Sets up the helper functions called by the function under test (and functions we can
        // ignore) to use mock implementations.
        MOCK_METHOD1(updateColorProfile, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(updateCompositionState,
                     void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(planComposition, void());
        MOCK_METHOD1(writeCompositionState, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(setColorTransform, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD0(beginFrame, void());
        MOCK_METHOD0(prepareFrame, void());
        MOCK_METHOD0(prepareFrameAsync, GpuCompositionResult());
        MOCK_METHOD1(devOptRepaintFlash, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(finishFrame, void(GpuCompositionResult&&));
        MOCK_METHOD(void, presentFrameAndReleaseLayers, (bool flushEvenWhenDisabled), (override));
        MOCK_METHOD1(renderCachedSets, void(const compositionengine::CompositionRefreshArgs&));
        MOCK_METHOD1(canPredictCompositionStrategy, bool(const CompositionRefreshArgs&));
        MOCK_METHOD(void, setHintSessionRequiresRenderEngine, (bool requiresRenderEngine),
                    (override));
        MOCK_METHOD(bool, isPowerHintSessionEnabled, (), (override));
        MOCK_METHOD(bool, isPowerHintSessionGpuReportingEnabled, (), (override));
    };

    OutputPresentFrameAndReleaseLayersTest() {
        EXPECT_CALL(mOutput, isPowerHintSessionEnabled()).WillRepeatedly(Return(true));
        EXPECT_CALL(mOutput, isPowerHintSessionGpuReportingEnabled()).WillRepeatedly(Return(true));
    }

    NiceMock<OutputPartialMock> mOutput;
};

TEST_F(OutputPresentFrameAndReleaseLayersTest, noBuffersToUncache) {
    CompositionRefreshArgs args;
    ASSERT_TRUE(args.bufferIdsToUncache.empty());
    mOutput.editState().isEnabled = false;

    constexpr bool kFlushEvenWhenDisabled = false;
    EXPECT_CALL(mOutput, presentFrameAndReleaseLayers(kFlushEvenWhenDisabled));

    mOutput.present(args);
}

TEST_F(OutputPresentFrameAndReleaseLayersTest, buffersToUncache) {
    CompositionRefreshArgs args;
    args.bufferIdsToUncache.push_back(1);
    mOutput.editState().isEnabled = false;

    constexpr bool kFlushEvenWhenDisabled = true;
    EXPECT_CALL(mOutput, presentFrameAndReleaseLayers(kFlushEvenWhenDisabled));

    mOutput.present(args);
}

} // namespace
} // namespace android::compositionengine
