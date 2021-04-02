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
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/DisplayColorProfile.h>
#include <compositionengine/mock/LayerFE.h>
#include <compositionengine/mock/Output.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include "MockHWC2.h"
#include "MockHWComposer.h"
#include "RegionMatcher.h"
#include "renderengine/mock/RenderEngine.h"

namespace android::compositionengine {
namespace {

namespace hal = android::hardware::graphics::composer::hal;

using testing::_;
using testing::InSequence;
using testing::Return;
using testing::ReturnRef;
using testing::StrictMock;

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

ui::Rotation toRotation(uint32_t rotationFlag) {
    switch (rotationFlag) {
        case ui::Transform::RotationFlags::ROT_0:
            return ui::ROTATION_0;
        case ui::Transform::RotationFlags::ROT_90:
            return ui::ROTATION_90;
        case ui::Transform::RotationFlags::ROT_180:
            return ui::ROTATION_180;
        case ui::Transform::RotationFlags::ROT_270:
            return ui::ROTATION_270;
        default:
            LOG_FATAL("Unexpected rotation flag %d", rotationFlag);
            return ui::Rotation(-1);
    }
}

struct OutputLayerTest : public testing::Test {
    struct OutputLayer final : public impl::OutputLayer {
        OutputLayer(const compositionengine::Output& output, sp<compositionengine::LayerFE> layerFE)
              : mOutput(output), mLayerFE(layerFE) {}
        ~OutputLayer() override = default;

        // compositionengine::OutputLayer overrides
        const compositionengine::Output& getOutput() const override { return mOutput; }
        compositionengine::LayerFE& getLayerFE() const override { return *mLayerFE; }
        const impl::OutputLayerCompositionState& getState() const override { return mState; }
        impl::OutputLayerCompositionState& editState() override { return mState; }

        // compositionengine::impl::OutputLayer overrides
        void dumpState(std::string& out) const override { mState.dump(out); }

        const compositionengine::Output& mOutput;
        sp<compositionengine::LayerFE> mLayerFE;
        impl::OutputLayerCompositionState mState;
    };

    OutputLayerTest() {
        EXPECT_CALL(*mLayerFE, getDebugName()).WillRepeatedly(Return("Test LayerFE"));
        EXPECT_CALL(mOutput, getName()).WillRepeatedly(ReturnRef(kOutputName));

        EXPECT_CALL(*mLayerFE, getCompositionState()).WillRepeatedly(Return(&mLayerFEState));
        EXPECT_CALL(mOutput, getState()).WillRepeatedly(ReturnRef(mOutputState));
    }

    compositionengine::mock::Output mOutput;
    sp<compositionengine::mock::LayerFE> mLayerFE{
            new StrictMock<compositionengine::mock::LayerFE>()};
    OutputLayer mOutputLayer{mOutput, mLayerFE};

    LayerFECompositionState mLayerFEState;
    impl::OutputCompositionState mOutputState;
};

/*
 * Basic construction
 */

TEST_F(OutputLayerTest, canInstantiateOutputLayer) {}

/*
 * OutputLayer::setHwcLayer()
 */

TEST_F(OutputLayerTest, settingNullHwcLayerSetsEmptyHwcState) {
    StrictMock<compositionengine::mock::CompositionEngine> compositionEngine;

    mOutputLayer.setHwcLayer(nullptr);

    EXPECT_FALSE(mOutputLayer.getState().hwc);
}

TEST_F(OutputLayerTest, settingHwcLayerSetsHwcState) {
    auto hwcLayer = std::make_shared<StrictMock<HWC2::mock::Layer>>();

    mOutputLayer.setHwcLayer(hwcLayer);

    const auto& outputLayerState = mOutputLayer.getState();
    ASSERT_TRUE(outputLayerState.hwc);

    const auto& hwcState = *outputLayerState.hwc;
    EXPECT_EQ(hwcLayer, hwcState.hwcLayer);
}

/*
 * OutputLayer::calculateOutputSourceCrop()
 */

struct OutputLayerSourceCropTest : public OutputLayerTest {
    OutputLayerSourceCropTest() {
        // Set reasonable default values for a simple case. Each test will
        // set one specific value to something different.
        mLayerFEState.geomUsesSourceCrop = true;
        mLayerFEState.geomContentCrop = Rect{0, 0, 1920, 1080};
        mLayerFEState.transparentRegionHint = Region{};
        mLayerFEState.geomLayerBounds = FloatRect{0.f, 0.f, 1920.f, 1080.f};
        mLayerFEState.geomLayerTransform = ui::Transform{TR_IDENT};
        mLayerFEState.geomBufferSize = Rect{0, 0, 1920, 1080};
        mLayerFEState.geomBufferTransform = TR_IDENT;

        mOutputState.layerStackSpace.content = Rect{0, 0, 1920, 1080};
    }

    FloatRect calculateOutputSourceCrop() {
        mLayerFEState.geomInverseLayerTransform = mLayerFEState.geomLayerTransform.inverse();

        return mOutputLayer.calculateOutputSourceCrop();
    }
};

TEST_F(OutputLayerSourceCropTest, computesEmptyIfSourceCropNotUsed) {
    mLayerFEState.geomUsesSourceCrop = false;

    const FloatRect expected{};
    EXPECT_THAT(calculateOutputSourceCrop(), expected);
}

TEST_F(OutputLayerSourceCropTest, correctForSimpleDefaultCase) {
    const FloatRect expected{0.f, 0.f, 1920.f, 1080.f};
    EXPECT_THAT(calculateOutputSourceCrop(), expected);
}

TEST_F(OutputLayerSourceCropTest, handlesBoundsOutsideViewport) {
    mLayerFEState.geomLayerBounds = FloatRect{-2000.f, -2000.f, 2000.f, 2000.f};

    const FloatRect expected{0.f, 0.f, 1920.f, 1080.f};
    EXPECT_THAT(calculateOutputSourceCrop(), expected);
}

TEST_F(OutputLayerSourceCropTest, handlesBoundsOutsideViewportRotated) {
    mLayerFEState.geomLayerBounds = FloatRect{-2000.f, -2000.f, 2000.f, 2000.f};
    mLayerFEState.geomLayerTransform.set(HAL_TRANSFORM_ROT_90, 1920, 1080);

    const FloatRect expected{0.f, 0.f, 1080.f, 1080.f};
    EXPECT_THAT(calculateOutputSourceCrop(), expected);
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

        mLayerFEState.geomBufferUsesDisplayInverseTransform = entry.bufferInvDisplay;
        mLayerFEState.geomBufferTransform = entry.buffer;
        mOutputState.displaySpace.orientation = toRotation(entry.display);

        EXPECT_THAT(calculateOutputSourceCrop(), entry.expected) << "entry " << i;
    }
}

TEST_F(OutputLayerSourceCropTest, geomContentCropAffectsCrop) {
    mLayerFEState.geomContentCrop = Rect{0, 0, 960, 540};

    const FloatRect expected{0.f, 0.f, 960.f, 540.f};
    EXPECT_THAT(calculateOutputSourceCrop(), expected);
}

TEST_F(OutputLayerSourceCropTest, viewportAffectsCrop) {
    mOutputState.layerStackSpace.content = Rect{0, 0, 960, 540};

    const FloatRect expected{0.f, 0.f, 960.f, 540.f};
    EXPECT_THAT(calculateOutputSourceCrop(), expected);
}

/*
 * OutputLayer::calculateOutputDisplayFrame()
 */

struct OutputLayerDisplayFrameTest : public OutputLayerTest {
    OutputLayerDisplayFrameTest() {
        // Set reasonable default values for a simple case. Each test will
        // set one specific value to something different.

        mLayerFEState.transparentRegionHint = Region{};
        mLayerFEState.geomLayerTransform = ui::Transform{TR_IDENT};
        mLayerFEState.geomBufferSize = Rect{0, 0, 1920, 1080};
        mLayerFEState.geomBufferUsesDisplayInverseTransform = false;
        mLayerFEState.geomCrop = Rect{0, 0, 1920, 1080};
        mLayerFEState.geomLayerBounds = FloatRect{0.f, 0.f, 1920.f, 1080.f};

        mOutputState.layerStackSpace.content = Rect{0, 0, 1920, 1080};
        mOutputState.transform = ui::Transform{TR_IDENT};
    }

    Rect calculateOutputDisplayFrame() {
        mLayerFEState.geomInverseLayerTransform = mLayerFEState.geomLayerTransform.inverse();

        return mOutputLayer.calculateOutputDisplayFrame();
    }
};

TEST_F(OutputLayerDisplayFrameTest, correctForSimpleDefaultCase) {
    const Rect expected{0, 0, 1920, 1080};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

TEST_F(OutputLayerDisplayFrameTest, fullActiveTransparentRegionReturnsEmptyFrame) {
    mLayerFEState.transparentRegionHint = Region{Rect{0, 0, 1920, 1080}};
    const Rect expected{0, 0, 0, 0};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

TEST_F(OutputLayerDisplayFrameTest, cropAffectsDisplayFrame) {
    mLayerFEState.geomCrop = Rect{100, 200, 300, 500};
    const Rect expected{100, 200, 300, 500};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

TEST_F(OutputLayerDisplayFrameTest, cropAffectsDisplayFrameRotated) {
    mLayerFEState.geomCrop = Rect{100, 200, 300, 500};
    mLayerFEState.geomLayerTransform.set(HAL_TRANSFORM_ROT_90, 1920, 1080);
    const Rect expected{1420, 100, 1720, 300};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

TEST_F(OutputLayerDisplayFrameTest, emptyGeomCropIsNotUsedToComputeFrame) {
    mLayerFEState.geomCrop = Rect{};
    const Rect expected{0, 0, 1920, 1080};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

TEST_F(OutputLayerDisplayFrameTest, geomLayerBoundsAffectsFrame) {
    mLayerFEState.geomLayerBounds = FloatRect{0.f, 0.f, 960.f, 540.f};
    const Rect expected{0, 0, 960, 540};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

TEST_F(OutputLayerDisplayFrameTest, viewportAffectsFrame) {
    mOutputState.layerStackSpace.content = Rect{0, 0, 960, 540};
    const Rect expected{0, 0, 960, 540};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

TEST_F(OutputLayerDisplayFrameTest, outputTransformAffectsDisplayFrame) {
    mOutputState.transform = ui::Transform{HAL_TRANSFORM_ROT_90};
    const Rect expected{-1080, 0, 0, 1920};
    EXPECT_THAT(calculateOutputDisplayFrame(), expected);
}

/*
 * OutputLayer::calculateOutputRelativeBufferTransform()
 */

TEST_F(OutputLayerTest, calculateOutputRelativeBufferTransformTestsNeeded) {
    mLayerFEState.geomBufferUsesDisplayInverseTransform = false;

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

        mLayerFEState.geomLayerTransform.set(entry.layer, 1920, 1080);
        mLayerFEState.geomBufferTransform = entry.buffer;
        mOutputState.displaySpace.orientation = toRotation(entry.display);
        mOutputState.transform = ui::Transform{entry.display};

        const auto actual = mOutputLayer.calculateOutputRelativeBufferTransform(entry.display);
        EXPECT_EQ(entry.expected, actual) << "entry " << i;
    }
}

TEST_F(OutputLayerTest,
       calculateOutputRelativeBufferTransformTestWithOfBufferUsesDisplayInverseTransform) {
    mLayerFEState.geomBufferUsesDisplayInverseTransform = true;

    struct Entry {
        uint32_t layer; /* shouldn't affect the result, so we just use arbitrary values */
        uint32_t buffer;
        uint32_t display;
        uint32_t internal;
        uint32_t expected;
    };
    const std::array<Entry, 64> testData = {
            // clang-format off
            //    layer       buffer      display     internal    expected
            Entry{TR_IDENT,   TR_IDENT,   TR_IDENT,   TR_IDENT,   TR_IDENT},
            Entry{TR_IDENT,   TR_IDENT,   TR_IDENT,   TR_ROT_90,  TR_ROT_270},
            Entry{TR_IDENT,   TR_IDENT,   TR_IDENT,   TR_ROT_180, TR_ROT_180},
            Entry{TR_IDENT,   TR_IDENT,   TR_IDENT,   TR_ROT_270, TR_ROT_90},

            Entry{TR_IDENT,   TR_IDENT,   TR_ROT_90,  TR_IDENT,   TR_ROT_90},
            Entry{TR_ROT_90,  TR_IDENT,   TR_ROT_90,  TR_ROT_90,  TR_IDENT},
            Entry{TR_ROT_180, TR_IDENT,   TR_ROT_90,  TR_ROT_180, TR_ROT_270},
            Entry{TR_ROT_90,  TR_IDENT,   TR_ROT_90,  TR_ROT_270, TR_ROT_180},

            Entry{TR_ROT_180, TR_IDENT,   TR_ROT_180, TR_IDENT,   TR_ROT_180},
            Entry{TR_ROT_90,  TR_IDENT,   TR_ROT_180, TR_ROT_90,  TR_ROT_90},
            Entry{TR_ROT_180, TR_IDENT,   TR_ROT_180, TR_ROT_180, TR_IDENT},
            Entry{TR_ROT_270, TR_IDENT,   TR_ROT_180, TR_ROT_270, TR_ROT_270},

            Entry{TR_ROT_270, TR_IDENT,   TR_ROT_270, TR_IDENT,   TR_ROT_270},
            Entry{TR_ROT_270, TR_IDENT,   TR_ROT_270, TR_ROT_90,  TR_ROT_180},
            Entry{TR_ROT_180, TR_IDENT,   TR_ROT_270, TR_ROT_180, TR_ROT_90},
            Entry{TR_IDENT,   TR_IDENT,   TR_ROT_270, TR_ROT_270, TR_IDENT},

            //    layer       buffer      display     internal    expected
            Entry{TR_IDENT,   TR_ROT_90,  TR_IDENT,   TR_IDENT,   TR_ROT_90},
            Entry{TR_ROT_90,  TR_ROT_90,  TR_IDENT,   TR_ROT_90,  TR_IDENT},
            Entry{TR_ROT_180, TR_ROT_90,  TR_IDENT,   TR_ROT_180, TR_ROT_270},
            Entry{TR_ROT_270, TR_ROT_90,  TR_IDENT,   TR_ROT_270, TR_ROT_180},

            Entry{TR_ROT_90,  TR_ROT_90,  TR_ROT_90,  TR_IDENT,   TR_ROT_180},
            Entry{TR_ROT_90,  TR_ROT_90,  TR_ROT_90,  TR_ROT_90,  TR_ROT_90},
            Entry{TR_ROT_90,  TR_ROT_90,  TR_ROT_90,  TR_ROT_180, TR_IDENT},
            Entry{TR_ROT_270, TR_ROT_90,  TR_ROT_90,  TR_ROT_270, TR_ROT_270},

            Entry{TR_IDENT,   TR_ROT_90,  TR_ROT_180, TR_IDENT,   TR_ROT_270},
            Entry{TR_ROT_90,  TR_ROT_90,  TR_ROT_180, TR_ROT_90,  TR_ROT_180},
            Entry{TR_ROT_180, TR_ROT_90,  TR_ROT_180, TR_ROT_180, TR_ROT_90},
            Entry{TR_ROT_90,  TR_ROT_90,  TR_ROT_180, TR_ROT_270, TR_IDENT},

            Entry{TR_IDENT,   TR_ROT_90,  TR_ROT_270, TR_IDENT,   TR_IDENT},
            Entry{TR_ROT_270, TR_ROT_90,  TR_ROT_270, TR_ROT_90,  TR_ROT_270},
            Entry{TR_ROT_180, TR_ROT_90,  TR_ROT_270, TR_ROT_180, TR_ROT_180},
            Entry{TR_ROT_270, TR_ROT_90,  TR_ROT_270, TR_ROT_270, TR_ROT_90},

            //    layer       buffer      display     internal    expected
            Entry{TR_IDENT,   TR_ROT_180, TR_IDENT,   TR_IDENT,   TR_ROT_180},
            Entry{TR_IDENT,   TR_ROT_180, TR_IDENT,   TR_ROT_90,  TR_ROT_90},
            Entry{TR_ROT_180, TR_ROT_180, TR_IDENT,   TR_ROT_180, TR_IDENT},
            Entry{TR_ROT_270, TR_ROT_180, TR_IDENT,   TR_ROT_270, TR_ROT_270},

            Entry{TR_IDENT,   TR_ROT_180, TR_ROT_90,  TR_IDENT,   TR_ROT_270},
            Entry{TR_ROT_90,  TR_ROT_180, TR_ROT_90,  TR_ROT_90,  TR_ROT_180},
            Entry{TR_ROT_180, TR_ROT_180, TR_ROT_90,  TR_ROT_180, TR_ROT_90},
            Entry{TR_ROT_180, TR_ROT_180, TR_ROT_90,  TR_ROT_270, TR_IDENT},

            Entry{TR_IDENT,   TR_ROT_180, TR_ROT_180, TR_IDENT,   TR_IDENT},
            Entry{TR_ROT_180, TR_ROT_180, TR_ROT_180, TR_ROT_90,  TR_ROT_270},
            Entry{TR_ROT_180, TR_ROT_180, TR_ROT_180, TR_ROT_180, TR_ROT_180},
            Entry{TR_ROT_270, TR_ROT_180, TR_ROT_180, TR_ROT_270, TR_ROT_90},

            Entry{TR_ROT_270, TR_ROT_180, TR_ROT_270, TR_IDENT,   TR_ROT_90},
            Entry{TR_ROT_180, TR_ROT_180, TR_ROT_270, TR_ROT_90,  TR_IDENT},
            Entry{TR_ROT_180, TR_ROT_180, TR_ROT_270, TR_ROT_180, TR_ROT_270},
            Entry{TR_ROT_270, TR_ROT_180, TR_ROT_270, TR_ROT_270, TR_ROT_180},

            //    layer       buffer      display     internal    expected
            Entry{TR_IDENT,   TR_ROT_270, TR_IDENT,   TR_IDENT,   TR_ROT_270},
            Entry{TR_ROT_90,  TR_ROT_270, TR_IDENT,   TR_ROT_90,  TR_ROT_180},
            Entry{TR_ROT_270, TR_ROT_270, TR_IDENT,   TR_ROT_180, TR_ROT_90},
            Entry{TR_IDENT,   TR_ROT_270, TR_IDENT,   TR_ROT_270, TR_IDENT},

            Entry{TR_ROT_270, TR_ROT_270, TR_ROT_90,  TR_IDENT,   TR_IDENT},
            Entry{TR_ROT_90,  TR_ROT_270, TR_ROT_90,  TR_ROT_90,  TR_ROT_270},
            Entry{TR_ROT_180, TR_ROT_270, TR_ROT_90,  TR_ROT_180, TR_ROT_180},
            Entry{TR_ROT_90,  TR_ROT_270, TR_ROT_90,  TR_ROT_270, TR_ROT_90},

            Entry{TR_IDENT,   TR_ROT_270, TR_ROT_180, TR_IDENT,   TR_ROT_90},
            Entry{TR_ROT_270, TR_ROT_270, TR_ROT_180, TR_ROT_90,  TR_IDENT},
            Entry{TR_ROT_180, TR_ROT_270, TR_ROT_180, TR_ROT_180, TR_ROT_270},
            Entry{TR_ROT_270, TR_ROT_270, TR_ROT_180, TR_ROT_270, TR_ROT_180},

            Entry{TR_IDENT,   TR_ROT_270, TR_ROT_270, TR_IDENT,   TR_ROT_180},
            Entry{TR_ROT_90,  TR_ROT_270, TR_ROT_270, TR_ROT_90,  TR_ROT_90},
            Entry{TR_ROT_270, TR_ROT_270, TR_ROT_270, TR_ROT_180, TR_IDENT},
            Entry{TR_ROT_270, TR_ROT_270, TR_ROT_270, TR_ROT_270, TR_ROT_270},
            // clang-format on
    };

    for (size_t i = 0; i < testData.size(); i++) {
        const auto& entry = testData[i];

        mLayerFEState.geomLayerTransform.set(entry.layer, 1920, 1080);
        mLayerFEState.geomBufferTransform = entry.buffer;
        mOutputState.displaySpace.orientation = toRotation(entry.display);
        mOutputState.transform = ui::Transform{entry.display};

        const auto actual = mOutputLayer.calculateOutputRelativeBufferTransform(entry.internal);
        EXPECT_EQ(entry.expected, actual) << "entry " << i;
    }
}

/*
 * OutputLayer::updateCompositionState()
 */

struct OutputLayerPartialMockForUpdateCompositionState : public impl::OutputLayer {
    OutputLayerPartialMockForUpdateCompositionState(const compositionengine::Output& output,
                                                    sp<compositionengine::LayerFE> layerFE)
          : mOutput(output), mLayerFE(layerFE) {}
    // Mock everything called by updateCompositionState to simplify testing it.
    MOCK_CONST_METHOD0(calculateOutputSourceCrop, FloatRect());
    MOCK_CONST_METHOD0(calculateOutputDisplayFrame, Rect());
    MOCK_CONST_METHOD1(calculateOutputRelativeBufferTransform, uint32_t(uint32_t));

    // compositionengine::OutputLayer overrides
    const compositionengine::Output& getOutput() const override { return mOutput; }
    compositionengine::LayerFE& getLayerFE() const override { return *mLayerFE; }
    const impl::OutputLayerCompositionState& getState() const override { return mState; }
    impl::OutputLayerCompositionState& editState() override { return mState; }

    // These need implementations though are not expected to be called.
    MOCK_CONST_METHOD1(dumpState, void(std::string&));

    const compositionengine::Output& mOutput;
    sp<compositionengine::LayerFE> mLayerFE;
    impl::OutputLayerCompositionState mState;
};

struct OutputLayerUpdateCompositionStateTest : public OutputLayerTest {
public:
    OutputLayerUpdateCompositionStateTest() {
        EXPECT_CALL(mOutput, getState()).WillRepeatedly(ReturnRef(mOutputState));
        EXPECT_CALL(mOutput, getDisplayColorProfile())
                .WillRepeatedly(Return(&mDisplayColorProfile));
        EXPECT_CALL(mDisplayColorProfile, isDataspaceSupported(_)).WillRepeatedly(Return(true));
    }

    ~OutputLayerUpdateCompositionStateTest() = default;

    void setupGeometryChildCallValues(ui::Transform::RotationFlags internalDisplayRotationFlags) {
        EXPECT_CALL(mOutputLayer, calculateOutputSourceCrop()).WillOnce(Return(kSourceCrop));
        EXPECT_CALL(mOutputLayer, calculateOutputDisplayFrame()).WillOnce(Return(kDisplayFrame));
        EXPECT_CALL(mOutputLayer,
                    calculateOutputRelativeBufferTransform(internalDisplayRotationFlags))
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
    StrictMock<OutputLayer> mOutputLayer{mOutput, mLayerFE};
    StrictMock<mock::DisplayColorProfile> mDisplayColorProfile;
};

TEST_F(OutputLayerUpdateCompositionStateTest, doesNothingIfNoFECompositionState) {
    EXPECT_CALL(*mLayerFE, getCompositionState()).WillOnce(Return(nullptr));

    mOutputLayer.updateCompositionState(true, false, ui::Transform::RotationFlags::ROT_90);
}

TEST_F(OutputLayerUpdateCompositionStateTest, setsStateNormally) {
    mLayerFEState.isSecure = true;
    mOutputState.isSecure = true;
    mOutputLayer.editState().forceClientComposition = true;

    setupGeometryChildCallValues(ui::Transform::RotationFlags::ROT_90);

    mOutputLayer.updateCompositionState(true, false, ui::Transform::RotationFlags::ROT_90);

    validateComputedGeometryState();

    EXPECT_EQ(false, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest,
       alsoSetsForceCompositionIfSecureLayerOnNonsecureOutput) {
    mLayerFEState.isSecure = true;
    mOutputState.isSecure = false;

    setupGeometryChildCallValues(ui::Transform::RotationFlags::ROT_0);

    mOutputLayer.updateCompositionState(true, false, ui::Transform::RotationFlags::ROT_0);

    validateComputedGeometryState();

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest,
       alsoSetsForceCompositionIfUnsupportedBufferTransform) {
    mLayerFEState.isSecure = true;
    mOutputState.isSecure = true;

    mBufferTransform = ui::Transform::ROT_INVALID;

    setupGeometryChildCallValues(ui::Transform::RotationFlags::ROT_0);

    mOutputLayer.updateCompositionState(true, false, ui::Transform::RotationFlags::ROT_0);

    validateComputedGeometryState();

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest, setsOutputLayerColorspaceCorrectly) {
    mLayerFEState.dataspace = ui::Dataspace::DISPLAY_P3;
    mOutputState.targetDataspace = ui::Dataspace::V0_SCRGB;

    // If the layer is not colorspace agnostic, the output layer dataspace
    // should use the layers requested colorspace.
    mLayerFEState.isColorspaceAgnostic = false;

    mOutputLayer.updateCompositionState(false, false, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(ui::Dataspace::DISPLAY_P3, mOutputLayer.getState().dataspace);

    // If the layer is colorspace agnostic, the output layer dataspace
    // should use the colorspace chosen for the whole output.
    mLayerFEState.isColorspaceAgnostic = true;

    mOutputLayer.updateCompositionState(false, false, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(ui::Dataspace::V0_SCRGB, mOutputLayer.getState().dataspace);
}

TEST_F(OutputLayerUpdateCompositionStateTest, doesNotRecomputeGeometryIfNotRequested) {
    mOutputLayer.editState().forceClientComposition = false;

    mOutputLayer.updateCompositionState(false, false, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(false, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest,
       doesNotClearForceClientCompositionIfNotDoingGeometry) {
    mOutputLayer.editState().forceClientComposition = true;

    mOutputLayer.updateCompositionState(false, false, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest, clientCompositionForcedFromFrontEndFlagAtAnyTime) {
    mLayerFEState.forceClientComposition = true;
    mOutputLayer.editState().forceClientComposition = false;

    mOutputLayer.updateCompositionState(false, false, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest,
       clientCompositionForcedFromUnsupportedDataspaceAtAnyTime) {
    mOutputLayer.editState().forceClientComposition = false;
    EXPECT_CALL(mDisplayColorProfile, isDataspaceSupported(_)).WillRepeatedly(Return(false));

    mOutputLayer.updateCompositionState(false, false, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

TEST_F(OutputLayerUpdateCompositionStateTest, clientCompositionForcedFromArgumentFlag) {
    mLayerFEState.forceClientComposition = false;
    mOutputLayer.editState().forceClientComposition = false;

    mOutputLayer.updateCompositionState(false, true, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);

    mOutputLayer.editState().forceClientComposition = false;

    setupGeometryChildCallValues(ui::Transform::RotationFlags::ROT_0);

    mOutputLayer.updateCompositionState(true, true, ui::Transform::RotationFlags::ROT_0);

    EXPECT_EQ(true, mOutputLayer.getState().forceClientComposition);
}

/*
 * OutputLayer::writeStateToHWC()
 */

struct OutputLayerWriteStateToHWCTest : public OutputLayerTest {
    static constexpr hal::Error kError = hal::Error::UNSUPPORTED;
    static constexpr FloatRect kSourceCrop{11.f, 12.f, 13.f, 14.f};
    static constexpr Hwc2::Transform kBufferTransform = static_cast<Hwc2::Transform>(31);
    static constexpr Hwc2::Transform kOverrideBufferTransform = static_cast<Hwc2::Transform>(0);
    static constexpr Hwc2::IComposerClient::BlendMode kBlendMode =
            static_cast<Hwc2::IComposerClient::BlendMode>(41);
    static constexpr Hwc2::IComposerClient::BlendMode kOverrideBlendMode =
            Hwc2::IComposerClient::BlendMode::PREMULTIPLIED;
    static constexpr float kAlpha = 51.f;
    static constexpr float kOverrideAlpha = 1.f;
    static constexpr ui::Dataspace kDataspace = static_cast<ui::Dataspace>(71);
    static constexpr ui::Dataspace kOverrideDataspace = static_cast<ui::Dataspace>(72);
    static constexpr int kSupportedPerFrameMetadata = 101;
    static constexpr int kExpectedHwcSlot = 0;
    static constexpr bool kLayerGenericMetadata1Mandatory = true;
    static constexpr bool kLayerGenericMetadata2Mandatory = true;

    static const half4 kColor;
    static const Rect kDisplayFrame;
    static const Rect kOverrideDisplayFrame;
    static const Region kOutputSpaceVisibleRegion;
    static const Region kOverrideVisibleRegion;
    static const mat4 kColorTransform;
    static const Region kSurfaceDamage;
    static const Region kOverrideSurfaceDamage;
    static const HdrMetadata kHdrMetadata;
    static native_handle_t* kSidebandStreamHandle;
    static const sp<GraphicBuffer> kBuffer;
    std::shared_ptr<renderengine::ExternalTexture> kOverrideBuffer;
    static const sp<Fence> kFence;
    static const sp<Fence> kOverrideFence;
    static const std::string kLayerGenericMetadata1Key;
    static const std::vector<uint8_t> kLayerGenericMetadata1Value;
    static const std::string kLayerGenericMetadata2Key;
    static const std::vector<uint8_t> kLayerGenericMetadata2Value;

    OutputLayerWriteStateToHWCTest() {
        kOverrideBuffer = std::make_shared<
                renderengine::ExternalTexture>(new GraphicBuffer(), mRenderEngine,
                                               renderengine::ExternalTexture::Usage::READABLE |
                                                       renderengine::ExternalTexture::Usage::
                                                               WRITEABLE);
        auto& outputLayerState = mOutputLayer.editState();
        outputLayerState.hwc = impl::OutputLayerCompositionState::Hwc(mHwcLayer);

        outputLayerState.displayFrame = kDisplayFrame;
        outputLayerState.sourceCrop = kSourceCrop;
        outputLayerState.bufferTransform = static_cast<Hwc2::Transform>(kBufferTransform);
        outputLayerState.outputSpaceVisibleRegion = kOutputSpaceVisibleRegion;
        outputLayerState.dataspace = kDataspace;

        mLayerFEState.blendMode = kBlendMode;
        mLayerFEState.alpha = kAlpha;
        mLayerFEState.colorTransform = kColorTransform;
        mLayerFEState.color = kColor;
        mLayerFEState.surfaceDamage = kSurfaceDamage;
        mLayerFEState.hdrMetadata = kHdrMetadata;
        mLayerFEState.sidebandStream = NativeHandle::create(kSidebandStreamHandle, false);
        mLayerFEState.buffer = kBuffer;
        mLayerFEState.bufferSlot = BufferQueue::INVALID_BUFFER_SLOT;
        mLayerFEState.acquireFence = kFence;

        EXPECT_CALL(mOutput, getDisplayColorProfile())
                .WillRepeatedly(Return(&mDisplayColorProfile));
        EXPECT_CALL(mDisplayColorProfile, getSupportedPerFrameMetadata())
                .WillRepeatedly(Return(kSupportedPerFrameMetadata));
    }

    // Some tests may need to simulate unsupported HWC calls
    enum class SimulateUnsupported { None, ColorTransform };

    void includeGenericLayerMetadataInState() {
        mLayerFEState.metadata[kLayerGenericMetadata1Key] = {kLayerGenericMetadata1Mandatory,
                                                             kLayerGenericMetadata1Value};
        mLayerFEState.metadata[kLayerGenericMetadata2Key] = {kLayerGenericMetadata2Mandatory,
                                                             kLayerGenericMetadata2Value};
    }

    void includeOverrideInfo() {
        auto& overrideInfo = mOutputLayer.editState().overrideInfo;

        overrideInfo.buffer = kOverrideBuffer;
        overrideInfo.acquireFence = kOverrideFence;
        overrideInfo.displayFrame = kOverrideDisplayFrame;
        overrideInfo.dataspace = kOverrideDataspace;
        overrideInfo.damageRegion = kOverrideSurfaceDamage;
        overrideInfo.visibleRegion = kOverrideVisibleRegion;
    }

    void expectGeometryCommonCalls(Rect displayFrame = kDisplayFrame,
                                   FloatRect sourceCrop = kSourceCrop,
                                   Hwc2::Transform bufferTransform = kBufferTransform,
                                   Hwc2::IComposerClient::BlendMode blendMode = kBlendMode,
                                   float alpha = kAlpha) {
        EXPECT_CALL(*mHwcLayer, setDisplayFrame(displayFrame)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setSourceCrop(sourceCrop)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setZOrder(_)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setTransform(bufferTransform)).WillOnce(Return(kError));

        EXPECT_CALL(*mHwcLayer, setBlendMode(blendMode)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setPlaneAlpha(alpha)).WillOnce(Return(kError));
    }

    void expectPerFrameCommonCalls(SimulateUnsupported unsupported = SimulateUnsupported::None,
                                   ui::Dataspace dataspace = kDataspace,
                                   const Region& visibleRegion = kOutputSpaceVisibleRegion,
                                   const Region& surfaceDamage = kSurfaceDamage) {
        EXPECT_CALL(*mHwcLayer, setVisibleRegion(RegionEq(visibleRegion))).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setDataspace(dataspace)).WillOnce(Return(kError));
        EXPECT_CALL(*mHwcLayer, setColorTransform(kColorTransform))
                .WillOnce(Return(unsupported == SimulateUnsupported::ColorTransform
                                         ? hal::Error::UNSUPPORTED
                                         : hal::Error::NONE));
        EXPECT_CALL(*mHwcLayer, setSurfaceDamage(RegionEq(surfaceDamage))).WillOnce(Return(kError));
    }

    void expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition compositionType) {
        EXPECT_CALL(*mHwcLayer, setCompositionType(compositionType)).WillOnce(Return(kError));
    }

    void expectNoSetCompositionTypeCall() {
        EXPECT_CALL(*mHwcLayer, setCompositionType(_)).Times(0);
    }

    void expectSetColorCall() {
        const hal::Color color = {static_cast<uint8_t>(std::round(kColor.r * 255)),
                                  static_cast<uint8_t>(std::round(kColor.g * 255)),
                                  static_cast<uint8_t>(std::round(kColor.b * 255)), 255};

        EXPECT_CALL(*mHwcLayer, setColor(ColorEq(color))).WillOnce(Return(kError));
    }

    void expectSetSidebandHandleCall() {
        EXPECT_CALL(*mHwcLayer, setSidebandStream(kSidebandStreamHandle));
    }

    void expectSetHdrMetadataAndBufferCalls(sp<GraphicBuffer> buffer = kBuffer,
                                            sp<Fence> fence = kFence) {
        EXPECT_CALL(*mHwcLayer, setPerFrameMetadata(kSupportedPerFrameMetadata, kHdrMetadata));
        EXPECT_CALL(*mHwcLayer, setBuffer(kExpectedHwcSlot, buffer, fence));
    }

    void expectGenericLayerMetadataCalls() {
        // Note: Can be in any order.
        EXPECT_CALL(*mHwcLayer,
                    setLayerGenericMetadata(kLayerGenericMetadata1Key,
                                            kLayerGenericMetadata1Mandatory,
                                            kLayerGenericMetadata1Value));
        EXPECT_CALL(*mHwcLayer,
                    setLayerGenericMetadata(kLayerGenericMetadata2Key,
                                            kLayerGenericMetadata2Mandatory,
                                            kLayerGenericMetadata2Value));
    }

    std::shared_ptr<HWC2::mock::Layer> mHwcLayer{std::make_shared<StrictMock<HWC2::mock::Layer>>()};
    StrictMock<mock::DisplayColorProfile> mDisplayColorProfile;
    renderengine::mock::RenderEngine mRenderEngine;
};

const half4 OutputLayerWriteStateToHWCTest::kColor{81.f / 255.f, 82.f / 255.f, 83.f / 255.f,
                                                   84.f / 255.f};
const Rect OutputLayerWriteStateToHWCTest::kDisplayFrame{1001, 1002, 1003, 10044};
const Rect OutputLayerWriteStateToHWCTest::kOverrideDisplayFrame{1002, 1003, 1004, 20044};
const Region OutputLayerWriteStateToHWCTest::kOutputSpaceVisibleRegion{
        Rect{1005, 1006, 1007, 1008}};
const Region OutputLayerWriteStateToHWCTest::kOverrideVisibleRegion{Rect{1006, 1007, 1008, 1009}};
const mat4 OutputLayerWriteStateToHWCTest::kColorTransform{
        1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016,
        1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024,
};
const Region OutputLayerWriteStateToHWCTest::kSurfaceDamage{Rect{1025, 1026, 1027, 1028}};
const Region OutputLayerWriteStateToHWCTest::kOverrideSurfaceDamage{Rect{1026, 1027, 1028, 1029}};
const HdrMetadata OutputLayerWriteStateToHWCTest::kHdrMetadata{{/* LightFlattenable */}, 1029};
native_handle_t* OutputLayerWriteStateToHWCTest::kSidebandStreamHandle =
        reinterpret_cast<native_handle_t*>(1031);
const sp<GraphicBuffer> OutputLayerWriteStateToHWCTest::kBuffer;
const sp<Fence> OutputLayerWriteStateToHWCTest::kFence;
const sp<Fence> OutputLayerWriteStateToHWCTest::kOverrideFence = new Fence();
const std::string OutputLayerWriteStateToHWCTest::kLayerGenericMetadata1Key =
        "com.example.metadata.1";
const std::vector<uint8_t> OutputLayerWriteStateToHWCTest::kLayerGenericMetadata1Value{{1, 2, 3}};
const std::string OutputLayerWriteStateToHWCTest::kLayerGenericMetadata2Key =
        "com.example.metadata.2";
const std::vector<uint8_t> OutputLayerWriteStateToHWCTest::kLayerGenericMetadata2Value{
        {4, 5, 6, 7}};

TEST_F(OutputLayerWriteStateToHWCTest, doesNothingIfNoFECompositionState) {
    EXPECT_CALL(*mLayerFE, getCompositionState()).WillOnce(Return(nullptr));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, doesNothingIfNoHWCState) {
    mOutputLayer.editState().hwc.reset();

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, doesNothingIfNoHWCLayer) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc(nullptr);

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetAllState) {
    expectGeometryCommonCalls();
    expectPerFrameCommonCalls();

    expectNoSetCompositionTypeCall();
    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerTest, displayInstallOrientationBufferTransformSetTo90) {
    mLayerFEState.geomBufferUsesDisplayInverseTransform = false;
    mLayerFEState.geomLayerTransform = ui::Transform{TR_IDENT};
    // This test simulates a scenario where displayInstallOrientation is set to
    // ROT_90. This only has an effect on the transform; orientation stays 0 (see
    // DisplayDevice::setProjection).
    mOutputState.displaySpace.orientation = ui::ROTATION_0;
    mOutputState.transform = ui::Transform{TR_ROT_90};
    // Buffers are pre-rotated based on the transform hint (ROT_90); their
    // geomBufferTransform is set to the inverse transform.
    mLayerFEState.geomBufferTransform = TR_ROT_270;

    EXPECT_EQ(TR_IDENT, mOutputLayer.calculateOutputRelativeBufferTransform(ui::Transform::ROT_90));
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForSolidColor) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls();
    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    // Setting the composition type should happen before setting the color. We
    // check this in this test only by setting up an testing::InSeqeuence
    // instance before setting up the two expectations.
    InSequence s;
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::SOLID_COLOR);
    expectSetColorCall();

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForSideband) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::SIDEBAND;

    expectPerFrameCommonCalls();
    expectSetSidebandHandleCall();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::SIDEBAND);

    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForCursor) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::CURSOR;

    expectPerFrameCommonCalls();
    expectSetHdrMetadataAndBufferCalls();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::CURSOR);

    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, canSetPerFrameStateForDevice) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::DEVICE;

    expectPerFrameCommonCalls();
    expectSetHdrMetadataAndBufferCalls();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::DEVICE);

    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, compositionTypeIsNotSetIfUnchanged) {
    (*mOutputLayer.editState().hwc).hwcCompositionType =
            Hwc2::IComposerClient::Composition::SOLID_COLOR;

    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls();
    expectSetColorCall();
    expectNoSetCompositionTypeCall();

    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, compositionTypeIsSetToClientIfColorTransformNotSupported) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls(SimulateUnsupported::ColorTransform);
    expectSetColorCall();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::CLIENT);

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, compositionTypeIsSetToClientIfClientCompositionForced) {
    mOutputLayer.editState().forceClientComposition = true;

    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::SOLID_COLOR;

    expectPerFrameCommonCalls();
    expectSetColorCall();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::CLIENT);

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, allStateIncludesMetadataIfPresent) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::DEVICE;
    includeGenericLayerMetadataInState();

    expectGeometryCommonCalls();
    expectPerFrameCommonCalls();
    expectSetHdrMetadataAndBufferCalls();
    expectGenericLayerMetadataCalls();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::DEVICE);

    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, perFrameStateDoesNotIncludeMetadataIfPresent) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::DEVICE;
    includeGenericLayerMetadataInState();

    expectPerFrameCommonCalls();
    expectSetHdrMetadataAndBufferCalls();
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::DEVICE);

    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ false, /*skipLayer*/ false, 0);
}

TEST_F(OutputLayerWriteStateToHWCTest, includesOverrideInfoIfPresent) {
    mLayerFEState.compositionType = Hwc2::IComposerClient::Composition::DEVICE;
    includeOverrideInfo();

    expectGeometryCommonCalls(kOverrideDisplayFrame, kOverrideDisplayFrame.toFloatRect(),
                              kOverrideBufferTransform, kOverrideBlendMode, kOverrideAlpha);
    expectPerFrameCommonCalls(SimulateUnsupported::None, kOverrideDataspace, kOverrideVisibleRegion,
                              kOverrideSurfaceDamage);
    expectSetHdrMetadataAndBufferCalls(kOverrideBuffer->getBuffer(), kOverrideFence);
    expectSetCompositionTypeCall(Hwc2::IComposerClient::Composition::DEVICE);

    EXPECT_CALL(*mLayerFE, hasRoundedCorners()).WillOnce(Return(false));

    mOutputLayer.writeStateToHWC(/*includeGeometry*/ true, /*skipLayer*/ false, 0);
}

/*
 * OutputLayer::writeCursorPositionToHWC()
 */

struct OutputLayerWriteCursorPositionToHWCTest : public OutputLayerTest {
    static constexpr int kDefaultTransform = TR_IDENT;
    static constexpr hal::Error kDefaultError = hal::Error::UNSUPPORTED;

    static const Rect kDefaultDisplayViewport;
    static const Rect kDefaultCursorFrame;

    OutputLayerWriteCursorPositionToHWCTest() {
        auto& outputLayerState = mOutputLayer.editState();
        outputLayerState.hwc = impl::OutputLayerCompositionState::Hwc(mHwcLayer);

        mLayerFEState.cursorFrame = kDefaultCursorFrame;

        mOutputState.layerStackSpace.content = kDefaultDisplayViewport;
        mOutputState.transform = ui::Transform{kDefaultTransform};
    }

    std::shared_ptr<HWC2::mock::Layer> mHwcLayer{std::make_shared<StrictMock<HWC2::mock::Layer>>()};
};

const Rect OutputLayerWriteCursorPositionToHWCTest::kDefaultDisplayViewport{0, 0, 1920, 1080};
const Rect OutputLayerWriteCursorPositionToHWCTest::kDefaultCursorFrame{1, 2, 3, 4};

TEST_F(OutputLayerWriteCursorPositionToHWCTest, doesNothingIfNoFECompositionState) {
    EXPECT_CALL(*mLayerFE, getCompositionState()).WillOnce(Return(nullptr));

    mOutputLayer.writeCursorPositionToHWC();
}

TEST_F(OutputLayerWriteCursorPositionToHWCTest, writeCursorPositionToHWCHandlesNoHwcState) {
    mOutputLayer.editState().hwc.reset();

    mOutputLayer.writeCursorPositionToHWC();
}

TEST_F(OutputLayerWriteCursorPositionToHWCTest, writeCursorPositionToHWCWritesStateToHWC) {
    EXPECT_CALL(*mHwcLayer, setCursorPosition(1, 2)).WillOnce(Return(kDefaultError));

    mOutputLayer.writeCursorPositionToHWC();
}

TEST_F(OutputLayerWriteCursorPositionToHWCTest, writeCursorPositionToHWCIntersectedWithViewport) {
    mLayerFEState.cursorFrame = Rect{3000, 3000, 3016, 3016};

    EXPECT_CALL(*mHwcLayer, setCursorPosition(1920, 1080)).WillOnce(Return(kDefaultError));

    mOutputLayer.writeCursorPositionToHWC();
}

TEST_F(OutputLayerWriteCursorPositionToHWCTest, writeCursorPositionToHWCRotatedByTransform) {
    mOutputState.transform = ui::Transform{TR_ROT_90};

    EXPECT_CALL(*mHwcLayer, setCursorPosition(-4, 1)).WillOnce(Return(kDefaultError));

    mOutputLayer.writeCursorPositionToHWC();
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
 * OutputLayer::isHardwareCursor()
 */

TEST_F(OutputLayerTest, isHardwareCursorReturnsFalseIfNoHWC2State) {
    mOutputLayer.editState().hwc.reset();

    EXPECT_FALSE(mOutputLayer.isHardwareCursor());
}

TEST_F(OutputLayerTest, isHardwareCursorReturnsTrueIfSetToCursorComposition) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc{nullptr};
    mOutputLayer.editState().hwc->hwcCompositionType = Hwc2::IComposerClient::Composition::CURSOR;

    EXPECT_TRUE(mOutputLayer.isHardwareCursor());
}

TEST_F(OutputLayerTest, isHardwareCursorReturnsFalseIfSetToDeviceComposition) {
    mOutputLayer.editState().hwc = impl::OutputLayerCompositionState::Hwc{nullptr};
    mOutputLayer.editState().hwc->hwcCompositionType = Hwc2::IComposerClient::Composition::DEVICE;

    EXPECT_FALSE(mOutputLayer.isHardwareCursor());
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

/*
 * OutputLayer::needsFiltering()
 */

TEST_F(OutputLayerTest, needsFilteringReturnsFalseIfDisplaySizeSameAsSourceSize) {
    mOutputLayer.editState().displayFrame = Rect(100, 100, 200, 200);
    mOutputLayer.editState().sourceCrop = FloatRect{0.f, 0.f, 100.f, 100.f};

    EXPECT_FALSE(mOutputLayer.needsFiltering());
}

TEST_F(OutputLayerTest, needsFilteringReturnsTrueIfDisplaySizeDifferentFromSourceSize) {
    mOutputLayer.editState().displayFrame = Rect(100, 100, 200, 200);
    mOutputLayer.editState().sourceCrop = FloatRect{0.f, 0.f, 100.1f, 100.1f};

    EXPECT_TRUE(mOutputLayer.needsFiltering());
}

} // namespace
} // namespace android::compositionengine
