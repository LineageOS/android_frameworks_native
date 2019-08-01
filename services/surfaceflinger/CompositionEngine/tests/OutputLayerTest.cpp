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

#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/Layer.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/Output.h>
#include <gtest/gtest.h>

#include "FloatRectMatcher.h"
#include "MockHWC2.h"
#include "MockHWComposer.h"
#include "RectMatcher.h"
#include "RegionMatcher.h"

namespace android::compositionengine {
namespace {

using testing::_;
using testing::Return;
using testing::ReturnRef;
using testing::StrictMock;

constexpr DisplayId DEFAULT_DISPLAY_ID = DisplayId{42};

constexpr auto TR_IDENT = 0u;
constexpr auto TR_FLP_H = HAL_TRANSFORM_FLIP_H;
constexpr auto TR_FLP_V = HAL_TRANSFORM_FLIP_V;
constexpr auto TR_ROT_90 = HAL_TRANSFORM_ROT_90;
constexpr auto TR_ROT_180 = TR_FLP_H | TR_FLP_V;
constexpr auto TR_ROT_270 = TR_ROT_90 | TR_ROT_180;

const std::string kOutputName{"Test Output"};

MATCHER_P(ColorEq, expected, "") {
    *result_listener << "Colors are not equal\n";
    *result_listener << "expected " << expected.r << " " << expected.g << " " << expected.b << " "
                     << expected.a << "\n";
    *result_listener << "actual " << arg.r << " " << arg.g << " " << arg.b << " " << arg.a << "\n";

    return expected.r == arg.r && expected.g == arg.g && expected.b == arg.b && expected.a == arg.a;
}

struct OutputLayerTest : public testing::Test {
    OutputLayerTest() {
        EXPECT_CALL(*mLayerFE, getDebugName()).WillRepeatedly(Return("Test LayerFE"));
        EXPECT_CALL(mOutput, getName()).WillRepeatedly(ReturnRef(kOutputName));

        EXPECT_CALL(*mLayer, getState()).WillRepeatedly(ReturnRef(mLayerState));
        EXPECT_CALL(mOutput, getState()).WillRepeatedly(ReturnRef(mOutputState));
    }

    compositionengine::mock::Output mOutput;
    std::shared_ptr<compositionengine::mock::Layer> mLayer{
            new StrictMock<compositionengine::mock::Layer>()};
    sp<compositionengine::mock::LayerFE> mLayerFE{
            new StrictMock<compositionengine::mock::LayerFE>()};
    impl::OutputLayer mOutputLayer{mOutput, mLayer, mLayerFE};

    impl::LayerCompositionState mLayerState;
    impl::OutputCompositionState mOutputState;
};

/*
 * Basic construction
 */

TEST_F(OutputLayerTest, canInstantiateOutputLayer) {}

/*
 * OutputLayer::initialize()
 */

TEST_F(OutputLayerTest, initializingOutputLayerWithoutHwcDoesNothingInteresting) {
    StrictMock<compositionengine::mock::CompositionEngine> compositionEngine;

    mOutputLayer.initialize(compositionEngine, std::nullopt);

    EXPECT_FALSE(mOutputLayer.getState().hwc);
}

TEST_F(OutputLayerTest, initializingOutputLayerWithHwcDisplayCreatesHwcLayer) {
    StrictMock<compositionengine::mock::CompositionEngine> compositionEngine;
    StrictMock<android::mock::HWComposer> hwc;
    StrictMock<HWC2::mock::Layer> hwcLayer;

    EXPECT_CALL(compositionEngine, getHwComposer()).WillOnce(ReturnRef(hwc));
    EXPECT_CALL(hwc, createLayer(DEFAULT_DISPLAY_ID)).WillOnce(Return(&hwcLayer));

    mOutputLayer.initialize(compositionEngine, DEFAULT_DISPLAY_ID);

    const auto& outputLayerState = mOutputLayer.getState();
    ASSERT_TRUE(outputLayerState.hwc);

    const auto& hwcState = *outputLayerState.hwc;
    EXPECT_EQ(&hwcLayer, hwcState.hwcLayer.get());

    EXPECT_CALL(hwc, destroyLayer(DEFAULT_DISPLAY_ID, &hwcLayer));
    mOutputLayer.editState().hwc.reset();
}

/*
 * OutputLayer::calculateOutputSourceCrop()
 */

struct OutputLayerSourceCropTest : public OutputLayerTest {
    OutputLayerSourceCropTest() {
        // Set reasonable default values for a simple case. Each test will
        // set one specific value to something different.
        mLayerState.frontEnd.geomUsesSourceCrop = true;
        mLayerState.frontEnd.geomContentCrop = Rect{0, 0, 1920, 1080};
        mLayerState.frontEnd.geomActiveTransparentRegion = Region{};
        mLayerState.frontEnd.geomLayerBounds = FloatRect{0.f, 0.f, 1920.f, 1080.f};
        mLayerState.frontEnd.geomLayerTransform = ui::Transform{TR_IDENT};
        mLayerState.frontEnd.geomBufferSize = Rect{0, 0, 1920, 1080};
        mLayerState.frontEnd.geomBufferTransform = TR_IDENT;

        mOutputState.viewport = Rect{0, 0, 1920, 1080};
    }

    FloatRect calculateOutputSourceCrop() {
        mLayerState.frontEnd.geomInverseLayerTransform =
                mLayerState.frontEnd.geomLayerTransform.inverse();

        return mOutputLayer.calculateOutputSourceCrop();
    }
};

TEST_F(OutputLayerSourceCropTest, computesEmptyIfSourceCropNotUsed) {
    mLayerState.frontEnd.geomUsesSourceCrop = false;

    const FloatRect expected{};
    EXPECT_THAT(calculateOutputSourceCrop(), FloatRectEq(expected));
}

TEST_F(OutputLayerSourceCropTest, correctForSimpleDefaultCase) {
    const FloatRect expected{0.f, 0.f, 1920.f, 1080.f};
    EXPECT_THAT(calculateOutputSourceCrop(), FloatRectEq(expected));
}

TEST_F(OutputLayerSourceCropTest, handlesBoundsOutsideViewport) {
    mLayerState.frontEnd.geomLayerBounds = FloatRect{-2000.f, -2000.f, 2000.f, 2000.f};

    const FloatRect expected{0.f, 0.f, 1920.f, 1080.f};
    EXPECT_THAT(calculateOutputSourceCrop(), FloatRectEq(expected));
}

TEST_F(OutputLayerSourceCropTest, handlesBoundsOutsideViewportRotated) {
    mLayerState.frontEnd.geomLayerBounds = FloatRect{-2000.f, -2000.f, 2000.f, 2000.f};
    mLayerState.frontEnd.geomLayerTransform.set(HAL_TRANSFORM_ROT_90, 1920, 1080);

    const FloatRect expected{0.f, 0.f, 1080.f, 1080.f};
    EXPECT_THAT(calculateOutputSourceCrop(), FloatRectEq(expected));
}

TEST_F(OutputLayerSourceCropTest, calculateOutputSourceCropWorksWithATransformedBuffer) {
    struct Entry {
        uint32_t bufferInvDisplay;
        uint32_t buffer;
        uint32_t display;
        FloatRect expected;
    };
    // Not an exhaustive list of cases, but hopefully enough.
    const std::array<Entry, 12> testData = {
            // clang-format off
            //             inv      buffer      display     expected
            /*  0 */ Entry{false,   TR_IDENT,   TR_IDENT,   FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /*  1 */ Entry{false,   TR_IDENT,   TR_ROT_90,  FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /*  2 */ Entry{false,   TR_IDENT,   TR_ROT_180, FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /*  3 */ Entry{false,   TR_IDENT,   TR_ROT_270, FloatRect{0.f, 0.f, 1920.f, 1080.f}},

            /*  4 */ Entry{true,    TR_IDENT,   TR_IDENT,   FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /*  5 */ Entry{true,    TR_IDENT,   TR_ROT_90,  FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /*  6 */ Entry{true,    TR_IDENT,   TR_ROT_180, FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /*  7 */ Entry{true,    TR_IDENT,   TR_ROT_270, FloatRect{0.f, 0.f, 1920.f, 1080.f}},

            /*  8 */ Entry{false,   TR_IDENT,   TR_IDENT,   FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /*  9 */ Entry{false,   TR_ROT_90,  TR_ROT_90,  FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /* 10 */ Entry{false,   TR_ROT_180, TR_ROT_180, FloatRect{0.f, 0.f, 1920.f, 1080.f}},
            /* 11 */ Entry{false,   TR_ROT_270, TR_ROT_270, FloatRect{0.f, 0.f, 1920.f, 1080.f}},

            // clang-format on
    };

    for (size_t i = 0; i < testData.size(); i++) {
        const auto& entry = testData[i];

        mLayerState.frontEnd.geomBufferUsesDisplayInverseTransform = entry.bufferInvDisplay;
        mLayerState.frontEnd.geomBufferTransform = entry.buffer;
        mOutputState.orientation = entry.display;

        EXPECT_THAT(calculateOutputSourceCrop(), FloatRectEq(entry.expected)) << "entry " << i;
    }
}

TEST_F(OutputLayerSourceCropTest, geomContentCropAffectsCrop) {
    mLayerState.frontEnd.geomContentCrop = Rect{0, 0, 960, 540};

    const FloatRect expected{0.f, 0.f, 960.f, 540.f};
    EXPECT_THAT(calculateOutputSourceCrop(), FloatRectEq(expected));
}

TEST_F(OutputLayerSourceCropTest, viewportAffectsCrop) {
    mOutputState.viewport = Rect{0, 0, 960, 540};

    const FloatRect expected{0.f, 0.f, 960.f, 540.f};
    EXPECT_THAT(calculateOutputSourceCrop(), FloatRectEq(expected));
}

/*
 * OutputLayer::calculateOutputDisplayFrame()
 */

struct OutputLayerDisplayFrameTest : public OutputLayerTest {
    OutputLayerDisplayFrameTest() {
        // Set reasonable default values for a simple case. Each test will
        // set one specific value to something different.

        mLayerState.frontEnd.geomActiveTransparentRegion = Region{};
        mLayerState.frontEnd.geomLayerTransform = ui::Transform{TR_IDENT};
        mLayerState.frontEnd.geomBufferSize = Rect{0, 0, 1920, 1080};
        mLayerState.frontEnd.geomBufferUsesDisplayInverseTransform = false;
        mLayerState.frontEnd.geomCrop = Rect{0, 0, 1920, 1080};
        mLayerState.frontEnd.geomLayerBounds = FloatRect{0.f, 0.f, 1920.f, 1080.f};

        mOutputState.viewport = Rect{0, 0, 1920, 1080};
        mOutputState.transform = ui::Transform{TR_IDENT};
    }

    Rect calculateOutputDisplayFrame() {
        mLayerState.frontEnd.geomInverseLayerTransform =
                mLayerState.frontEnd.geomLayerTransform.inverse();

        return mOutputLayer.calculateOutputDisplayFrame();
    }
};

TEST_F(OutputLayerDisplayFrameTest, correctForSimpleDefaultCase) {
    const Rect expected{0, 0, 1920, 1080};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

TEST_F(OutputLayerDisplayFrameTest, fullActiveTransparentRegionReturnsEmptyFrame) {
    mLayerState.frontEnd.geomActiveTransparentRegion = Region{Rect{0, 0, 1920, 1080}};
    const Rect expected{0, 0, 0, 0};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

TEST_F(OutputLayerDisplayFrameTest, cropAffectsDisplayFrame) {
    mLayerState.frontEnd.geomCrop = Rect{100, 200, 300, 500};
    const Rect expected{100, 200, 300, 500};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

TEST_F(OutputLayerDisplayFrameTest, cropAffectsDisplayFrameRotated) {
    mLayerState.frontEnd.geomCrop = Rect{100, 200, 300, 500};
    mLayerState.frontEnd.geomLayerTransform.set(HAL_TRANSFORM_ROT_90, 1920, 1080);
    const Rect expected{1420, 100, 1720, 300};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

TEST_F(OutputLayerDisplayFrameTest, emptyGeomCropIsNotUsedToComputeFrame) {
    mLayerState.frontEnd.geomCrop = Rect{};
    const Rect expected{0, 0, 1920, 1080};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

TEST_F(OutputLayerDisplayFrameTest, geomLayerBoundsAffectsFrame) {
    mLayerState.frontEnd.geomLayerBounds = FloatRect{0.f, 0.f, 960.f, 540.f};
    const Rect expected{0, 0, 960, 540};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

TEST_F(OutputLayerDisplayFrameTest, viewportAffectsFrame) {
    mOutputState.viewport = Rect{0, 0, 960, 540};
    const Rect expected{0, 0, 960, 540};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

TEST_F(OutputLayerDisplayFrameTest, outputTransformAffectsDisplayFrame) {
    mOutputState.transform = ui::Transform{HAL_TRANSFORM_ROT_90};
    const Rect expected{-1080, 0, 0, 1920};
    EXPECT_THAT(calculateOutputDisplayFrame(), RectEq(expected));
}

/*
 * OutputLayer::calculateOutputRelativeBufferTransform()
 */

TEST_F(OutputLayerTest, calculateOutputRelativeBufferTransformTestsNeeded) {
    mLayerState.frontEnd.geomBufferUsesDisplayInverseTransform = false;

    struct Entry {
        uint32_t layer;
        uint32_t buffer;
        uint32_t display;
        uint32_t expected;
    };
    // Not an exhaustive list of cases, but hopefully enough.
    const std::array<Entry, 24> testData = {
            // clang-format off
            //             layer       buffer      display     expected
            /*  0 */ Entry{TR_IDENT,   TR_IDENT,   TR_IDENT,   TR_IDENT},
            /*  1 */ Entry{TR_IDENT,   TR_IDENT,   TR_ROT_90,  TR_ROT_90},
            /*  2 */ Entry{TR_IDENT,   TR_IDENT,   TR_ROT_180, TR_ROT_180},
            /*  3 */ Entry{TR_IDENT,   TR_IDENT,   TR_ROT_270, TR_ROT_270},

            /*  4 */ Entry{TR_IDENT,   TR_FLP_H,   TR_IDENT,   TR_FLP_H ^ TR_IDENT},
            /*  5 */ Entry{TR_IDENT,   TR_FLP_H,   TR_ROT_90,  TR_FLP_H ^ TR_ROT_90},
            /*  6 */ Entry{TR_IDENT,   TR_FLP_H,   TR_ROT_180, TR_FLP_H ^ TR_ROT_180},
            /*  7 */ Entry{TR_IDENT,   TR_FLP_H,   TR_ROT_270, TR_FLP_H ^ TR_ROT_270},

            /*  8 */ Entry{TR_IDENT,   TR_FLP_V,   TR_IDENT,   TR_FLP_V},
            /*  9 */ Entry{TR_IDENT,   TR_ROT_90,  TR_ROT_90,  TR_ROT_180},
            /* 10 */ Entry{TR_IDENT,   TR_ROT_180, TR_ROT_180, TR_IDENT},
            /* 11 */ Entry{TR_IDENT,   TR_ROT_270, TR_ROT_270, TR_ROT_180},

            /* 12 */ Entry{TR_ROT_90,  TR_IDENT,   TR_IDENT,   TR_IDENT ^ TR_ROT_90},
            /* 13 */ Entry{TR_ROT_90,  TR_FLP_H,   TR_ROT_90,  TR_FLP_H ^ TR_ROT_180},
            /* 14 */ Entry{TR_ROT_90,  TR_IDENT,   TR_ROT_180, TR_IDENT ^ TR_ROT_270},
            /* 15 */ Entry{TR_ROT_90,  TR_FLP_H,   TR_ROT_270, TR_FLP_H ^ TR_IDENT},

            /* 16 */ Entry{TR_ROT_180, TR_FLP_H,   TR_IDENT,   TR_FLP_H ^ TR_ROT_180},
            /* 17 */ Entry{TR_ROT_180, TR_IDENT,   TR_ROT_90,  TR_IDENT ^ TR_ROT_270},
            /* 18 */ Entry{TR_ROT_180, TR_FLP_H,   TR_ROT_180, TR_FLP_H ^ TR_IDENT},
            /* 19 */ Entry{TR_ROT_180, TR_IDENT,   TR_ROT_270, TR_IDENT ^ TR_ROT_90},

            /* 20 */ Entry{TR_ROT_270, TR_IDENT,   TR_IDENT,   TR_IDENT ^ TR_ROT_270},
            /* 21 */ Entry{TR_ROT_270, TR_FLP_H,   TR_ROT_90,  TR_FLP_H ^ TR_IDENT},
            /* 22 */ Entry{TR_ROT_270, TR_FLP_H,   TR_ROT_180, TR_FLP_H ^ TR_ROT_90},
            /* 23 */ Entry{TR_ROT_270, TR_IDENT,   TR_ROT_270, TR_IDENT ^ TR_ROT_180},
            // clang-format on
    };

    for (size_t i = 0; i < testData.size(); i++) {
        const auto& entry = testData[i];

        mLayerState.frontEnd.geomLayerTransform.set(entry.layer, 1920, 1080);
        mLayerState.frontEnd.geomBufferTransform = entry.buffer;
        mOutputState.orientation = entry.display;

        auto actual = mOutputLayer.calculateOutputRelativeBufferTransform();
        EXPECT_EQ(entry.expected, actual) << "entry " << i;
    }
}

TEST_F(OutputLayerTest,
       calculateOutputRelativeBufferTransformTestWithOfBufferUsesDisplayInverseTransform) {
    mLayerState.frontEnd.geomBufferUsesDisplayInverseTransform = true;

    struct Entry {
        uint32_t layer;
        uint32_t buffer;
        uint32_t display;
        uint32_t expected;
    };
    // Not an exhaustive list of cases, but hopefully enough.
    const std::array<Entry, 24> testData = {
            // clang-format off
            //             layer       buffer      display     expected
            /*  0 */ Entry{TR_IDENT,   TR_IDENT,   TR_IDENT,   TR_IDENT},
            /*  1 */ Entry{TR_IDENT,   TR_IDENT,   TR_ROT_90,  TR_IDENT},
            /*  2 */ Entry{TR_IDENT,   TR_IDENT,   TR_ROT_180, TR_IDENT},
            /*  3 */ Entry{TR_IDENT,   TR_IDENT,   TR_ROT_270, TR_IDENT},

            /*  4 */ Entry{TR_IDENT,   TR_FLP_H,   TR_IDENT,   TR_FLP_H},
            /*  5 */ Entry{TR_IDENT,   TR_FLP_H,   TR_ROT_90,  TR_FLP_H},
            /*  6 */ Entry{TR_IDENT,   TR_FLP_H,   TR_ROT_180, TR_FLP_H},
            /*  7 */ Entry{TR_IDENT,   TR_FLP_H,   TR_ROT_270, TR_FLP_H},

            /*  8 */ Entry{TR_IDENT,   TR_FLP_V,   TR_IDENT,   TR_FLP_V},
            /*  9 */ Entry{TR_IDENT,   TR_ROT_90,  TR_ROT_90,  TR_ROT_90},
            /* 10 */ Entry{TR_IDENT,   TR_ROT_180, TR_ROT_180, TR_ROT_180},
            /* 11 */ Entry{TR_IDENT,   TR_ROT_270, TR_ROT_270, TR_ROT_270},

            /* 12 */ Entry{TR_ROT_90,  TR_IDENT,   TR_IDENT,   TR_IDENT},
            /* 13 */ Entry{TR_ROT_90,  TR_FLP_H,   TR_ROT_90,  TR_FLP_H},
            /* 14 */ Entry{TR_ROT_90,  TR_IDENT,   TR_ROT_180, TR_IDENT},
            /* 15 */ Entry{TR_ROT_90,  TR_FLP_H,   TR_ROT_270, TR_FLP_H},

            /* 16 */ Entry{TR_ROT_180, TR_FLP_H,   TR_IDENT,   TR_FLP_H},
            /* 17 */ Entry{TR_ROT_180, TR_IDENT,   TR_ROT_90,  TR_IDENT},
            /* 18 */ Entry{TR_ROT_180, TR_FLP_H,   TR_ROT_180, TR_FLP_H},
            /* 19 */ Entry{TR_ROT_180, TR_IDENT,   TR_ROT_270, TR_IDENT},

            /* 20 */ Entry{TR_ROT_270, TR_IDENT,   TR_IDENT,   TR_IDENT},
            /* 21 */ Entry{TR_ROT_270, TR_FLP_H,   TR_ROT_90,  TR_FLP_H},
            /* 22 */ Entry{TR_ROT_270, TR_FLP_H,   TR_ROT_180, TR_FLP_H},
            /* 23 */ Entry{TR_ROT_270, TR_IDENT,   TR_ROT_270, TR_IDENT},
            // clang-format on
    };

    for (size_t i = 0; i < testData.size(); i++) {
        const auto& entry = testData[i];

        mLayerState.frontEnd.geomLayerTransform = ui::Transform{entry.layer};
        mLayerState.frontEnd.geomBufferTransform = entry.buffer;
        mOutputState.orientation = entry.display;

        auto actual = mOutputLayer.calculateOutputRelativeBufferTransform();
        EXPECT_EQ(entry.expected, actual) << "entry " << i;
    }
}

/*
 * OutputLayer::updateCompositionState()
 */

struct OutputLayerPartialMockForUpdateCompositionState : public impl::OutputLayer {
    OutputLayerPartialMockForUpdateCompositionState(const compositionengine::Output& output,
                                                    std::shared_ptr<compositionengine::Layer> layer,
                                                    sp<compositionengine::LayerFE> layerFE)
          : impl::OutputLayer(output, layer, layerFE) {}
    // Mock everything called by updateCompositionState to simplify testing it.
    MOCK_CONST_METHOD0(calculateOutputSourceCrop, FloatRect());
    MOCK_CONST_METHOD0(calculateOutputDisplayFrame, Rect());
    MOCK_CONST_METHOD0(calculateOutputRelativeBufferTransform, uint32_t());
};

struct OutputLayerUpdateCompositionStateTest : public OutputLayerTest {
public:
    OutputLayerUpdateCompositionStateTest() {
        EXPECT_CALL(*mLayer, getState()).WillRepeatedly(ReturnRef(mLayerState));
        EXPECT_CALL(mOutput, getState()).WillRepeatedly(ReturnRef(mOutputState));
        EXPECT_CALL(mOutput, getDisplayColorProfile())
                .WillRepeatedly(Return(&mDisplayColorProfile));
        EXPECT_CALL(mDisplayColorProfile, isDataspaceSupported(_)).WillRepeatedly(Return(true));
    }

    ~OutputLayerUpdateCompositionStateTest() = default;

    void setupGeometryChildCallValues() {
        EXPECT_CALL(mOutputLayer, calculateOutputSourceCrop()).WillOnce(Return(kSourceCrop));
        EXPECT_CALL(mOutputLayer, calculateOutputDisplayFrame()).WillOnce(Return(kDisplayFrame));
        EXPECT_CALL(mOutputLayer, calculateOutputRelativeBufferTransform())
                .WillOnce(Return(mBufferTransform));
    }

    void validateComputedGeometryState() {
        const auto& state = mOutputLayer.getState();
        EXPECT_EQ(kSourceCrop, state.sourceCrop);
        EXPECT_EQ(kDisplayFrame, state.displayFrame);
        EXPECT_EQ(static_cast<Hwc2::Transform>(mBufferTransform), state.bufferTransform);
    }

    const FloatRect kSourceCrop{1.f, 2.f, 3.f, 4.f};
    const Rect kDisplayFrame{11, 12, 13, 14};
    uint32_t mBufferTransform{21};

    using OutputLayer = OutputLayerPartialMockForUpdateCompositionState;
    StrictMock<OutputLayer> mOutputLayer{mOutput, mLayer, mLayerFE};
    StrictMock<mock::DisplayColorProfile> mDisplayColorProfile;
};

TEST_F(OutputLayerUpdateCompositionStateTest, setsStateNormally) {
    mLayerState.frontEnd.isSecure = true;
    mOutputState.isSecure = true;

    setupGeometryChildCallValues();

    mOutputLayer.updateCompositionState(true);

    validateComputedGeometryState();

    EXPECT_EQ(false, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest,
       alsoSetsForceCompositionIfSecureLayerOnNonsecureOutput) {
    mLayerState.frontEnd.isSecure = true;
    mOutputState.isSecure = false;

    setupGeometryChildCallValues();

    mOutputLayer.updateCompositionState(true);

    validateComputedGeometryState();

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest,
       alsoSetsForceCompositionIfUnsupportedBufferTransform) {
    mLayerState.frontEnd.isSecure = true;
    mOutputState.isSecure = true;

    mBufferTransform = ui::Transform::ROT_INVALID;

    setupGeometryChildCallValues();

    mOutputLayer.updateCompositionState(true);

    validateComputedGeometryState();

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest, setsOutputLayerColorspaceCorrectly) {
    mLayerState.frontEnd.dataspace = ui::Dataspace::DISPLAY_P3;
    mOutputState.targetDataspace = ui::Dataspace::V0_SCRGB;

    // If the layer is not colorspace agnostic, the output layer dataspace
    // should use the layers requested colorspace.
    mLayerState.frontEnd.isColorspaceAgnostic = false;

    mOutputLayer.updateCompositionState(false);

    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mOutputLayer.getState().dataspace);

    // If the layer is colorspace agnostic, the output layer dataspace
    // should use the colorspace chosen for the whole output.
    mLayerState.frontEnd.isColorspaceAgnostic = true;

    mOutputLayer.updateCompositionState(false);

    EXPECT_EQ(ui::Dataspace::V0_SCRGB, mOutputLayer.getState().dataspace);
}

TEST_F(OutputLayerUpdateCompositionStateTest, doesNotRecomputeGeometryIfNotRequested) {
    mOutputLayer.updateCompositionState(false);

    EXPECT_EQ(false, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest, clientCompositionForcedFromFrontEndFlagAtAnyTime) {
    mLayerState.frontEnd.forceClientComposition = true;

    mOutputLayer.updateCompositionState(false);

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest,
       clientCompositionForcedFromUnsupportedDataspaceAtAnyTime) {
    EXPECT_CALL(mDisplayColorProfile, isDataspaceSupported(_)).WillRepeatedly(Return(false));

    mOutputLayer.updateCompositionState(false);

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

/*
 * OutputLayer::writeStateToHWC()
 */

struct OutputLayerWriteStateToHWCTest : public OutputLayerTest {
    static constexpr HWC2::Error kError = HWC2::Error::Unsupported;
    static constexpr FloatRect kSourceCrop{11.f, 12.f, 13.f, 14.f};
    static constexpr uint32_t kZOrder = 21u;
    static constexpr Hwc2::Transform kBufferTransform = static_cast<Hwc2::Transform>(31);
    static constexpr Hwc2::IComposerClient::BlendMode kBlendMode =
            static_cast<Hwc2::IComposerClient::BlendMode>(41);
    static constexpr float kAlpha = 51.f;
    static constexpr uint32_t kType = 61u;
    static constexpr uint32_t kAppId = 62u;
    static constexpr ui::Dataspace kDataspace = static_cast<ui::Dataspace>(71);
    static constexpr int kSupportedPerFrameMetadata = 101;
    static constexpr int kExpectedHwcSlot = 0;

    static const half4 kColor;
    static const Rect kDisplayFrame;
    static const Region kVisibleRegion;
    static const mat4 kColorTransform;
    static const Region kSurfaceDamage;
    static const HdrMetadata kHdrMetadata;
    static native_handle_t* kSidebandStreamHandle;
    static const sp<GraphicBuffer> kBuffer;
    static const sp<Fence> kFence;

    OutputLayerWriteStateToHWCTest() {
        auto& outputLayerState = mOutputLayer.editState();
        outputLayerState.hwc = impl::OutputLayerCompositionState::Hwc(mHwcLayer);

        outputLayerState.displayFrame = kDisplayFrame;
        outputLayerState.sourceCrop = kSourceCrop;
        outputLayerState.z = kZOrder;
        outputLayerState.bufferTransform = static_cast<Hwc2::Transform>(kBufferTransform);
        outputLayerState.visibleRegion = kVisibleRegion;
        outputLayerState.dataspace = kDataspace;

        mLayerState.frontEnd.blendMode = kBlendMode;
        mLayerState.frontEnd.alpha = kAlpha;
        mLayerState.frontEnd.type = kType;
        mLayerState.frontEnd.appId = kAppId;
        mLayerState.frontEnd.colorTransform = kColorTransform;
        mLayerState.frontEnd.color = kColor;
        mLayerState.frontEnd.surfaceDamage = kSurfaceDamage;
        mLayerState.frontEnd.hdrMetadata = kHdrMetadata;
        mLayerState.frontEnd.sidebandStream = NativeHandle::create(kSidebandStreamHandle, false);
        mLayerState.frontEnd.buffer = kBuffer;
        mLayerState.frontEnd.bufferSlot = BufferQueue::INVALID_BUFFER_SLOT;
        mLayerState.frontEnd.acquireFence = kFence;

        EXPECT_CALL(mOutput, getDisplayColorProfile())
                .WillRepeatedly(Return(&mDisplayColorProfile));
        EXPECT_CALL(mDisplayColorProfile, getSupportedPerFrameMetadata())
                .WillRepeatedly(Return(kSupportedPerFrameMetadata));
    }

    // Some tests may need to simulate unsupported HWC calls
    enum class SimulateUnsupported { None, ColorTransform };

    void expectGeometryCommonCalls() {
        EXPECT_CALL(*mHwcLayer, setDisplayFrame(kDisplayFrame)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setSourceCrop(kSourceCrop)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setZOrder(kZOrder)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setTransform(static_cast<HWC2::Transform>(kBufferTransform)))
                .WillOnce(Return(kError));

        EXPECT_CALL(*mHwcLayer, setBlendMode(static_cast<HWC2::BlendMode>(kBlendMode)))
                .WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setPlaneAlpha(kAlpha)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setInfo(kType, kAppId)).WillOnce(Return(kError));
    }

    void expectPerFrameCommonCalls(SimulateUnsupported unsupported = SimulateUnsupported::None) {
        EXPECT_CALL(*mHwcLayer, setVisibleRegion(RegionEq(kVisibleRegion)))
                .WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setDataspace(kDataspace)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setColorTransform(kColorTransform))
                .WillOnce(Return(unsupported == SimulateUnsupported::ColorTransform
                                         ? HWC2::Error::Unsupported
                                         : HWC2::Error::None));
        EXPECT_CALL(*mHwcLayer, setSurfaceDamage(RegionEq(kSurfaceDamage)))
                .WillOnce(Return(kError));
    }

    void expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition compositionType) {
        EXPECT_CALL(*mHwcLayer, setCompositionType(static_cast<HWC2::Composition>(compositionType)))
                .WillOnce(Return(kError));
    }

    void expectNoSetCompositionTypeCall() {
        EXPECT_CALL(*mHwcLayer, setCompositionType(_)).Times(0);
    }

    void expectSetColorCall() {
        hwc_color_t color = {static_cast<uint8_t>(std::round(kColor.r * 255)),
                             static_cast<uint8_t>(std::round(kColor.g * 255)),
                             static_cast<uint8_t>(std::round(kColor.b * 255)), 255};

        EXPECT_CALL(*mHwcLayer, setColor(ColorEq(color))).WillOnce(Return(kError));
    }

    void expectSetSidebandHandleCall() {
        EXPECT_CALL(*mHwcLayer, setSidebandStream(kSidebandStreamHandle));
    }

    void expectSetHdrMetadataAndBufferCalls() {
        EXPECT_CALL(*mHwcLayer, setPerFrameMetadata(kSupportedPerFrameMetadata, kHdrMetadata));
        EXPECT_CALL(*mHwcLayer, setBuffer(kExpectedHwcSlot, kBuffer, kFence));
    }

    std::shared_ptr<HWC2::mock::Layer> mHwcLayer{std::make_shared<StrictMock<HWC2::mock::Layer>>()};
    StrictMock<mock::DisplayColorProfile> mDisplayColorProfile;
};

const half4 OutputLayerWriteStateToHWCTest::kColor{81.f / 255.f, 82.f / 255.f, 83.f / 255.f,
                                                   84.f / 255.f};
const Rect OutputLayerWriteStateToHWCTest::kDisplayFrame{1001, 1002, 1003, 10044};
const Region OutputLayerWriteStateToHWCTest::kVisibleRegion{Rect{1005, 1006, 1007, 1008}};
const mat4 OutputLayerWriteStateToHWCTest::kColorTransform{
        1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016,
        1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024,
};
const Region OutputLayerWriteStateToHWCTest::kSurfaceDamage{Rect{1025, 1026, 1027, 1028}};
const HdrMetadata OutputLayerWriteStateToHWCTest::kHdrMetadata{{/* LightFlattenable */}, 1029};
native_handle_t* OutputLayerWriteStateToHWCTest::kSidebandStreamHandle =
        reinterpret_cast<native_handle_t*>(1031);
const sp<GraphicBuffer> OutputLayerWriteStateToHWCTest::kBuffer;
const sp<Fence> OutputLayerWriteStateToHWCTest::kFence;

TEST_F(OutputLayerWriteStateToHWCTest, doesNothingIfNoHWCState) {
    mOutputLayer.editState().hwc.reset();

    mOutputLayer.writeStateToHWC(true);
}

TEST_F(OutputLayerWriteStateToHWCTest, doesNothingIfNoHWCLayer) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc(nullptr);

    mOutputLayer.writeStateToHWC(true);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetAllState) {
    expectGeometryCommonCalls();
    expectPerFrameCommonCalls();

    expectNoSetCompositionTypeCall();

    mOutputLayer.writeStateToHWC(true);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForSolidColor) {
    mLayerState.frontEnd.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls();
    expectSetColorCall();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::SOLID_COLOR);

    mOutputLayer.writeStateToHWC(false);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForSideband) {
    mLayerState.frontEnd.compositionType = Hwc2::IComposerClient::Composition::SIDEBAND;

    expectPerFrameCommonCalls();
    expectSetSidebandHandleCall();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::SIDEBAND);

    mOutputLayer.writeStateToHWC(false);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForCursor) {
    mLayerState.frontEnd.compositionType = Hwc2::IComposerClient::Composition::CURSOR;

    expectPerFrameCommonCalls();
    expectSetHdrMetadataAndBufferCalls();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::CURSOR);

    mOutputLayer.writeStateToHWC(false);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForDevice) {
    mLayerState.frontEnd.compositionType = Hwc2::IComposerClient::Composition::DEVICE;

    expectPerFrameCommonCalls();
    expectSetHdrMetadataAndBufferCalls();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::DEVICE);

    mOutputLayer.writeStateToHWC(false);
}

TEST_F(OutputLayerWriteStateToHWCTest, compositionTypeIsNotSetIfUnchanged) {
    (*mOutputLayer.editState().hwc).hwcCompositionType =
            Hwc2::IComposerClient::Composition::SOLID_COLOR;

    mLayerState.frontEnd.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls();
    expectSetColorCall();
    expectNoSetCompositionTypeCall();

    mOutputLayer.writeStateToHWC(false);
}

TEST_F(OutputLayerWriteStateToHWCTest, compositionTypeIsSetToClientIfColorTransformNotSupported) {
    mLayerState.frontEnd.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls(SimulateUnsupported::ColorTransform);
    expectSetColorCall();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::CLIENT);

    mOutputLayer.writeStateToHWC(false);
}

TEST_F(OutputLayerWriteStateToHWCTest, compositionTypeIsSetToClientIfClientCompositionForced) {
    mOutputLayer.editState().forceClientComposition = true;

    mLayerState.frontEnd.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls();
    expectSetColorCall();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::CLIENT);

    mOutputLayer.writeStateToHWC(false);
}

/*
 * OutputLayer::getHwcLayer()
 */

TEST_F(OutputLayerTest, getHwcLayerHandlesNoHwcState) {
    mOutputLayer.editState().hwc.reset();

    EXPECT_TRUE(mOutputLayer.getHwcLayer() == nullptr);
}

TEST_F(OutputLayerTest, getHwcLayerHandlesNoHwcLayer) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc{nullptr};

    EXPECT_TRUE(mOutputLayer.getHwcLayer() == nullptr);
}

TEST_F(OutputLayerTest, getHwcLayerReturnsHwcLayer) {
    auto hwcLayer = std::make_shared<StrictMock<HWC2::mock::Layer>>();
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc{hwcLayer};

    EXPECT_EQ(hwcLayer.get(), mOutputLayer.getHwcLayer());
}

/*
 * OutputLayer::requiresClientComposition()
 */

TEST_F(OutputLayerTest, requiresClientCompositionReturnsTrueIfNoHWC2State) {
    mOutputLayer.editState().hwc.reset();

    EXPECT_TRUE(mOutputLayer.requiresClientComposition());
}

TEST_F(OutputLayerTest, requiresClientCompositionReturnsTrueIfSetToClientComposition) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc{nullptr};
    mOutputLayer.editState().hwc->hwcCompositionType = Hwc2::IComposerClient::Composition::CLIENT;

    EXPECT_TRUE(mOutputLayer.requiresClientComposition());
}

TEST_F(OutputLayerTest, requiresClientCompositionReturnsFalseIfSetToDeviceComposition) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc{nullptr};
    mOutputLayer.editState().hwc->hwcCompositionType = Hwc2::IComposerClient::Composition::DEVICE;

    EXPECT_FALSE(mOutputLayer.requiresClientComposition());
}

/*
 * OutputLayer::applyDeviceCompositionTypeChange()
 */

TEST_F(OutputLayerTest, applyDeviceCompositionTypeChangeSetsNewType) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc{nullptr};
    mOutputLayer.editState().hwc->hwcCompositionType = Hwc2::IComposerClient::Composition::DEVICE;

    mOutputLayer.applyDeviceCompositionTypeChange(Hwc2::IComposerClient::Composition::CLIENT);

    ASSERT_TRUE(mOutputLayer.getState().hwc);
    EXPECT_EQ(Hwc2::IComposerClient::Composition::CLIENT,
              mOutputLayer.getState().hwc->hwcCompositionType);
}

/*
 * OutputLayer::prepareForDeviceLayerRequests()
 */

TEST_F(OutputLayerTest, prepareForDeviceLayerRequestsResetsRequestState) {
    mOutputLayer.editState().clearClientTarget = true;

    mOutputLayer.prepareForDeviceLayerRequests();

    EXPECT_FALSE(mOutputLayer.getState().clearClientTarget);
}

/*
 * OutputLayer::applyDeviceLayerRequest()
 */

TEST_F(OutputLayerTest, applyDeviceLayerRequestHandlesClearClientTarget) {
    mOutputLayer.editState().clearClientTarget = false;

    mOutputLayer.applyDeviceLayerRequest(Hwc2::IComposerClient::LayerRequest::CLEAR_CLIENT_TARGET);

    EXPECT_TRUE(mOutputLayer.getState().clearClientTarget);
}

TEST_F(OutputLayerTest, applyDeviceLayerRequestHandlesUnknownRequest) {
    mOutputLayer.editState().clearClientTarget = false;

    mOutputLayer.applyDeviceLayerRequest(static_cast<Hwc2::IComposerClient::LayerRequest>(0));

    EXPECT_FALSE(mOutputLayer.getState().clearClientTarget);
}

} // namespace
} // namespace android::compositionengine
