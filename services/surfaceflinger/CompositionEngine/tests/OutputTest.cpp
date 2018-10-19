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

#include <compositionengine/impl/Output.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <gtest/gtest.h>
#include <ui/Rect.h>
#include <ui/Region.h>

#include "RegionMatcher.h"
#include "TransformMatcher.h"

namespace android::compositionengine {
namespace {

using testing::ReturnRef;
using testing::StrictMock;

class OutputTest : public testing::Test {
public:
    ~OutputTest() override = default;

    StrictMock<mock::CompositionEngine> mCompositionEngine;
    impl::Output mOutput{mCompositionEngine};
};

/* ------------------------------------------------------------------------
 * Basic construction
 */

TEST_F(OutputTest, canInstantiateOutput) {}

/* ------------------------------------------------------------------------
 * Output::setCompositionEnabled()
 */

TEST_F(OutputTest, setCompositionEnabledDoesNothingIfAlreadyEnabled) {
    const Rect displaySize{100, 200};
    mOutput.editState().bounds = displaySize;
    mOutput.editState().isEnabled = true;

    mOutput.setCompositionEnabled(true);

    EXPECT_TRUE(mOutput.getState().isEnabled);
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region()));
}

TEST_F(OutputTest, setCompositionEnabledSetsEnabledAndDirtiesEntireOutput) {
    const Rect displaySize{100, 200};
    mOutput.editState().bounds = displaySize;
    mOutput.editState().isEnabled = false;

    mOutput.setCompositionEnabled(true);

    EXPECT_TRUE(mOutput.getState().isEnabled);
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(displaySize)));
}

TEST_F(OutputTest, setCompositionEnabledSetsDisabledAndDirtiesEntireOutput) {
    const Rect displaySize{100, 200};
    mOutput.editState().bounds = displaySize;
    mOutput.editState().isEnabled = true;

    mOutput.setCompositionEnabled(false);

    EXPECT_FALSE(mOutput.getState().isEnabled);
    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(displaySize)));
}

/* ------------------------------------------------------------------------
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

/* ------------------------------------------------------------------------
 * Output::setBounds()
 */

TEST_F(OutputTest, setBoundsSetsSizeAndDirtiesEntireOutput) {
    const Rect displaySize{100, 200};
    mOutput.setBounds(displaySize);

    EXPECT_EQ(displaySize, mOutput.getState().bounds);

    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(displaySize)));
}

/* ------------------------------------------------------------------------
 * Output::setLayerStackFilter()
 */

TEST_F(OutputTest, setLayerStackFilterSetsFilterAndDirtiesEntireOutput) {
    const Rect displaySize{100, 200};
    mOutput.editState().bounds = displaySize;

    const uint32_t layerStack = 123u;
    mOutput.setLayerStackFilter(true, layerStack);

    EXPECT_TRUE(mOutput.getState().singleLayerStack);
    EXPECT_EQ(layerStack, mOutput.getState().singleLayerStackId);

    EXPECT_THAT(mOutput.getState().dirtyRegion, RegionEq(Region(displaySize)));
}

/* ------------------------------------------------------------------------
 * Output::setColorTransform
 */

TEST_F(OutputTest, setColorTransformSetsTransform) {
    // Identity matrix sets an identity state value
    const mat4 identity;

    mOutput.setColorTransform(identity);

    EXPECT_EQ(HAL_COLOR_TRANSFORM_IDENTITY, mOutput.getState().colorTransform);

    // Non-identity matrix sets a non-identity state value
    const mat4 nonIdentity = mat4() * 2;

    mOutput.setColorTransform(nonIdentity);

    EXPECT_EQ(HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX, mOutput.getState().colorTransform);
}

/* ------------------------------------------------------------------------
 * Output::setColorMode
 */

TEST_F(OutputTest, setColorModeSetsModeUnlessNoChange) {
    mOutput.setColorMode(ui::ColorMode::BT2100_PQ, ui::Dataspace::SRGB,
                         ui::RenderIntent::TONE_MAP_COLORIMETRIC);

    EXPECT_EQ(ui::ColorMode::BT2100_PQ, mOutput.getState().colorMode);
    EXPECT_EQ(ui::Dataspace::SRGB, mOutput.getState().dataspace);
    EXPECT_EQ(ui::RenderIntent::TONE_MAP_COLORIMETRIC, mOutput.getState().renderIntent);
}

/* ------------------------------------------------------------------------
 * Output::getPhysicalSpaceDirtyRegion()
 */

TEST_F(OutputTest, getPhysicalSpaceDirtyRegionWithRepaintEverythingTrue) {
    const Rect displaySize{100, 200};
    mOutput.editState().bounds = displaySize;
    mOutput.editState().dirtyRegion.set(50, 300);

    {
        Region result = mOutput.getPhysicalSpaceDirtyRegion(true);

        EXPECT_THAT(result, RegionEq(Region(displaySize)));
    }

    // For repaint everything == true, the returned value does not depend on the display
    // rotation.
    mOutput.editState().transform.set(ui::Transform::ROT_90, 0, 0);

    {
        Region result = mOutput.getPhysicalSpaceDirtyRegion(true);

        EXPECT_THAT(result, RegionEq(Region(displaySize)));
    }
}

TEST_F(OutputTest, getPhysicalSpaceDirtyRegionWithRepaintEverythingFalse) {
    const Rect displaySize{100, 200};
    mOutput.editState().bounds = displaySize;
    mOutput.editState().dirtyRegion.set(50, 300);

    {
        Region result = mOutput.getPhysicalSpaceDirtyRegion(false);

        // The dirtyRegion should be clipped to the display bounds.
        EXPECT_THAT(result, RegionEq(Region(Rect(50, 200))));
    }

    mOutput.editState().transform.set(ui::Transform::ROT_90, displaySize.getWidth(),
                                      displaySize.getHeight());

    {
        Region result = mOutput.getPhysicalSpaceDirtyRegion(false);

        // The dirtyRegion should be rotated and clipped to the display bounds.
        EXPECT_THAT(result, RegionEq(Region(Rect(100, 50))));
    }
}

} // namespace
} // namespace android::compositionengine
