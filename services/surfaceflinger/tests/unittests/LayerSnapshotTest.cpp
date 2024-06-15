/*
 * Copyright 2022 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <renderengine/mock/FakeExternalTexture.h>

#include "FrontEnd/LayerHierarchy.h"
#include "FrontEnd/LayerLifecycleManager.h"
#include "FrontEnd/LayerSnapshotBuilder.h"
#include "Layer.h"
#include "LayerHierarchyTest.h"
#include "ui/GraphicTypes.h"

#define UPDATE_AND_VERIFY(BUILDER, ...)                                    \
    ({                                                                     \
        SCOPED_TRACE("");                                                  \
        updateAndVerify((BUILDER), /*displayChanges=*/false, __VA_ARGS__); \
    })

#define UPDATE_AND_VERIFY_WITH_DISPLAY_CHANGES(BUILDER, ...)              \
    ({                                                                    \
        SCOPED_TRACE("");                                                 \
        updateAndVerify((BUILDER), /*displayChanges=*/true, __VA_ARGS__); \
    })

namespace android::surfaceflinger::frontend {

using ftl::Flags;
using namespace ftl::flag_operators;

// To run test:
/**
 mp :libsurfaceflinger_unittest && adb sync; adb shell \
    /data/nativetest/libsurfaceflinger_unittest/libsurfaceflinger_unittest \
    --gtest_filter="LayerSnapshotTest.*" --gtest_brief=1
*/

class LayerSnapshotTest : public LayerSnapshotTestBase {
protected:
    LayerSnapshotTest() : LayerSnapshotTestBase() {
        UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    }

    void update(LayerSnapshotBuilder& actualBuilder, LayerSnapshotBuilder::Args& args) {
        if (mLifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy)) {
            mHierarchyBuilder.update(mLifecycleManager);
        }
        args.root = mHierarchyBuilder.getHierarchy();
        actualBuilder.update(args);
    }

    void update(LayerSnapshotBuilder& actualBuilder) {
        LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                        .layerLifecycleManager = mLifecycleManager,
                                        .includeMetadata = false,
                                        .displays = mFrontEndDisplayInfos,
                                        .globalShadowSettings = globalShadowSettings,
                                        .supportsBlur = true,
                                        .supportedLayerGenericMetadata = {},
                                        .genericLayerMetadataKeyMap = {}};
        update(actualBuilder, args);
    }

    void updateAndVerify(LayerSnapshotBuilder& actualBuilder, bool hasDisplayChanges,
                         const std::vector<uint32_t> expectedVisibleLayerIdsInZOrder) {
        LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                        .layerLifecycleManager = mLifecycleManager,
                                        .includeMetadata = false,
                                        .displays = mFrontEndDisplayInfos,
                                        .displayChanges = hasDisplayChanges,
                                        .globalShadowSettings = globalShadowSettings,
                                        .supportsBlur = true,
                                        .supportedLayerGenericMetadata = {},
                                        .genericLayerMetadataKeyMap = {}};
        update(actualBuilder, args);

        // rebuild layer snapshots from scratch and verify that it matches the updated state.
        LayerSnapshotBuilder expectedBuilder(args);
        mLifecycleManager.commitChanges();
        ASSERT_TRUE(expectedBuilder.getSnapshots().size() > 0);
        ASSERT_TRUE(actualBuilder.getSnapshots().size() > 0);

        std::vector<uint32_t> actualVisibleLayerIdsInZOrder;
        actualBuilder.forEachVisibleSnapshot(
                [&actualVisibleLayerIdsInZOrder](const LayerSnapshot& snapshot) {
                    actualVisibleLayerIdsInZOrder.push_back(snapshot.path.id);
                });
        EXPECT_EQ(expectedVisibleLayerIdsInZOrder, actualVisibleLayerIdsInZOrder);
    }

    LayerSnapshot* getSnapshot(uint32_t layerId) { return mSnapshotBuilder.getSnapshot(layerId); }
    LayerSnapshot* getSnapshot(const LayerHierarchy::TraversalPath path) {
        return mSnapshotBuilder.getSnapshot(path);
    }
    LayerSnapshotBuilder mSnapshotBuilder;
    static const std::vector<uint32_t> STARTING_ZORDER;
};
const std::vector<uint32_t> LayerSnapshotTest::STARTING_ZORDER = {1,   11,   111, 12, 121,
                                                                  122, 1221, 13,  2};

TEST_F(LayerSnapshotTest, buildSnapshot) {
    LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                    .layerLifecycleManager = mLifecycleManager,
                                    .includeMetadata = false,
                                    .displays = mFrontEndDisplayInfos,
                                    .globalShadowSettings = globalShadowSettings,
                                    .supportedLayerGenericMetadata = {},
                                    .genericLayerMetadataKeyMap = {}};
    LayerSnapshotBuilder builder(args);
}

TEST_F(LayerSnapshotTest, updateSnapshot) {
    LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                    .layerLifecycleManager = mLifecycleManager,
                                    .includeMetadata = false,
                                    .displays = mFrontEndDisplayInfos,
                                    .globalShadowSettings = globalShadowSettings,
                                    .supportedLayerGenericMetadata = {},
                                    .genericLayerMetadataKeyMap = {}

    };

    LayerSnapshotBuilder builder;
    builder.update(args);
}

// update using parent snapshot data
TEST_F(LayerSnapshotTest, croppedByParent) {
    /// MAKE ALL LAYERS VISIBLE BY DEFAULT
    DisplayInfo info;
    info.info.logicalHeight = 100;
    info.info.logicalWidth = 200;
    mFrontEndDisplayInfos.emplace_or_replace(ui::LayerStack::fromValue(1), info);
    Rect layerCrop(0, 0, 10, 20);
    setCrop(11, layerCrop);
    EXPECT_TRUE(mLifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Geometry));
    UPDATE_AND_VERIFY_WITH_DISPLAY_CHANGES(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(11)->geomCrop, layerCrop);
    EXPECT_EQ(getSnapshot(111)->geomLayerBounds, layerCrop.toFloatRect());
    float maxHeight = static_cast<float>(info.info.logicalHeight * 10);
    float maxWidth = static_cast<float>(info.info.logicalWidth * 10);

    FloatRect maxDisplaySize(-maxWidth, -maxHeight, maxWidth, maxHeight);
    EXPECT_EQ(getSnapshot(1)->geomLayerBounds, maxDisplaySize);
}

// visibility tests
TEST_F(LayerSnapshotTest, newLayerHiddenByPolicy) {
    createLayer(112, 11);
    hideLayer(112);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    showLayer(112);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 11, 111, 112, 12, 121, 122, 1221, 13, 2});
}

TEST_F(LayerSnapshotTest, hiddenByParent) {
    hideLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 13, 2});
}

TEST_F(LayerSnapshotTest, reparentShowsChild) {
    hideLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 13, 2});

    showLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
}

TEST_F(LayerSnapshotTest, reparentHidesChild) {
    hideLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 13, 2});

    reparentLayer(121, 11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 122, 1221, 13, 2});
}

TEST_F(LayerSnapshotTest, unHidingUpdatesSnapshot) {
    hideLayer(11);
    Rect crop(1, 2, 3, 4);
    setCrop(111, crop);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 13, 2});

    showLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(111)->geomLayerBounds, crop.toFloatRect());
}

TEST_F(LayerSnapshotTest, childBehindParentCanBeHiddenByParent) {
    setZ(111, -1);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 111, 11, 12, 121, 122, 1221, 13, 2});

    hideLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 13, 2});
}

// relative tests
TEST_F(LayerSnapshotTest, RelativeParentCanHideChild) {
    reparentRelativeLayer(13, 11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 11, 13, 111, 12, 121, 122, 1221, 2});

    hideLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 2});
}

TEST_F(LayerSnapshotTest, ReparentingToHiddenRelativeParentHidesChild) {
    hideLayer(11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 13, 2});
    reparentRelativeLayer(13, 11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 12, 121, 122, 1221, 2});
}

TEST_F(LayerSnapshotTest, AlphaInheritedByChildren) {
    setAlpha(1, 0.5);
    setAlpha(122, 0.5);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->alpha, 0.5f);
    EXPECT_EQ(getSnapshot(12)->alpha, 0.5f);
    EXPECT_EQ(getSnapshot(1221)->alpha, 0.25f);
}

// Change states
TEST_F(LayerSnapshotTest, UpdateClearsPreviousChangeStates) {
    setCrop(1, Rect(1, 2, 3, 4));
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_TRUE(getSnapshot(1)->changes.test(RequestedLayerState::Changes::Geometry));
    EXPECT_TRUE(getSnapshot(11)->changes.test(RequestedLayerState::Changes::Geometry));
    setCrop(2, Rect(1, 2, 3, 4));
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_TRUE(getSnapshot(2)->changes.test(RequestedLayerState::Changes::Geometry));
    EXPECT_FALSE(getSnapshot(1)->changes.test(RequestedLayerState::Changes::Geometry));
    EXPECT_FALSE(getSnapshot(11)->changes.test(RequestedLayerState::Changes::Geometry));
}

TEST_F(LayerSnapshotTest, FastPathClearsPreviousChangeStates) {
    setColor(11, {1._hf, 0._hf, 0._hf});
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(11)->changes, RequestedLayerState::Changes::Content);
    EXPECT_EQ(getSnapshot(11)->clientChanges, layer_state_t::eColorChanged);
    EXPECT_EQ(getSnapshot(1)->changes.get(), 0u);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(11)->changes.get(), 0u);
}

TEST_F(LayerSnapshotTest, FastPathSetsChangeFlagToContent) {
    setColor(1, {1._hf, 0._hf, 0._hf});
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->changes, RequestedLayerState::Changes::Content);
    EXPECT_EQ(getSnapshot(1)->clientChanges, layer_state_t::eColorChanged);
}

TEST_F(LayerSnapshotTest, GameMode) {
    std::vector<TransactionState> transactions;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.what = layer_state_t::eMetadataChanged;
    transactions.back().states.front().state.metadata = LayerMetadata();
    transactions.back().states.front().state.metadata.setInt32(METADATA_GAME_MODE, 42);
    transactions.back().states.front().layerId = 1;
    transactions.back().states.front().state.layerId = static_cast<int32_t>(1);
    mLifecycleManager.applyTransactions(transactions);
    EXPECT_EQ(mLifecycleManager.getGlobalChanges(), RequestedLayerState::Changes::GameMode);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->clientChanges, layer_state_t::eMetadataChanged);
    EXPECT_EQ(static_cast<int32_t>(getSnapshot(1)->gameMode), 42);
    EXPECT_EQ(static_cast<int32_t>(getSnapshot(11)->gameMode), 42);
}

TEST_F(LayerSnapshotTest, NoLayerVoteForParentWithChildVotes) {
    // ROOT
    // ├── 1
    // │   ├── 11 (frame rate set)
    // │   │   └── 111
    // │   ├── 12
    // │   │   ├── 121
    // │   │   └── 122
    // │   │       └── 1221
    // │   └── 13
    // └── 2

    setFrameRate(11, 90.0, ANATIVEWINDOW_FRAME_RATE_EXACT, ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    EXPECT_EQ(getSnapshot(11)->frameRate.vote.rate.getIntValue(), 90);
    EXPECT_EQ(getSnapshot(11)->frameRate.vote.type, scheduler::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(111)->frameRate.vote.rate.getIntValue(), 90);
    EXPECT_EQ(getSnapshot(111)->frameRate.vote.type, scheduler::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(1)->frameRate.vote.rate.getIntValue(), 0);
    EXPECT_EQ(getSnapshot(1)->frameRate.vote.type, scheduler::FrameRateCompatibility::NoVote);
}

TEST_F(LayerSnapshotTest, NoLayerVoteForParentWithChildVotesDoesNotAffectSiblings) {
    // ROOT
    // ├── 1 (verify layer has no vote)
    // │   ├── 11 (frame rate set)
    // │   │   └── 111
    // │   ├── 12 (frame rate set)
    // │   │   ├── 121
    // │   │   └── 122
    // │   │       └── 1221
    // │   └── 13 (verify layer has default vote)
    // └── 2

    setFrameRate(11, 90.0, ANATIVEWINDOW_FRAME_RATE_EXACT, ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS);
    setFrameRate(12, 45.0, ANATIVEWINDOW_FRAME_RATE_EXACT, ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    EXPECT_EQ(getSnapshot(11)->frameRate.vote.rate.getIntValue(), 90);
    EXPECT_EQ(getSnapshot(11)->frameRate.vote.type, scheduler::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(111)->frameRate.vote.rate.getIntValue(), 90);
    EXPECT_EQ(getSnapshot(111)->frameRate.vote.type, scheduler::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(12)->frameRate.vote.rate.getIntValue(), 45);
    EXPECT_EQ(getSnapshot(12)->frameRate.vote.type, scheduler::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(121)->frameRate.vote.rate.getIntValue(), 45);
    EXPECT_EQ(getSnapshot(121)->frameRate.vote.type, scheduler::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(1221)->frameRate.vote.rate.getIntValue(), 45);
    EXPECT_EQ(getSnapshot(1221)->frameRate.vote.type, scheduler::FrameRateCompatibility::Exact);

    EXPECT_EQ(getSnapshot(1)->frameRate.vote.rate.getIntValue(), 0);
    EXPECT_EQ(getSnapshot(1)->frameRate.vote.type, scheduler::FrameRateCompatibility::NoVote);
    EXPECT_EQ(getSnapshot(13)->frameRate.vote.rate.getIntValue(), 0);
    EXPECT_EQ(getSnapshot(13)->frameRate.vote.type, scheduler::FrameRateCompatibility::Default);
    EXPECT_EQ(getSnapshot(2)->frameRate.vote.rate.getIntValue(), 0);
    EXPECT_EQ(getSnapshot(2)->frameRate.vote.type, scheduler::FrameRateCompatibility::Default);
}

TEST_F(LayerSnapshotTest, CanCropTouchableRegion) {
    // ROOT
    // ├── 1
    // │   ├── 11
    // │   │   └── 111 (touchregion set to touch but cropped by layer 13)
    // │   ├── 12
    // │   │   ├── 121
    // │   │   └── 122
    // │   │       └── 1221
    // │   └── 13 (crop set to touchCrop)
    // └── 2

    Rect touchCrop{300, 300, 400, 500};
    setCrop(13, touchCrop);
    Region touch{Rect{0, 0, 1000, 1000}};
    setTouchableRegionCrop(111, touch, /*touchCropId=*/13, /*replaceTouchableRegionWithCrop=*/true);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 111})->inputInfo.touchableRegion.bounds(), touchCrop);

    Rect modifiedTouchCrop{100, 300, 400, 700};
    setCrop(13, modifiedTouchCrop);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 111})->inputInfo.touchableRegion.bounds(), modifiedTouchCrop);
}

TEST_F(LayerSnapshotTest, CanCropTouchableRegionWithDisplayTransform) {
    DisplayInfo displayInfo;
    displayInfo.transform = ui::Transform(ui::Transform::RotationFlags::ROT_90, 1000, 1000);
    mFrontEndDisplayInfos.emplace_or_replace(ui::LayerStack::fromValue(1), displayInfo);

    Rect touchCrop{300, 300, 400, 500};
    createRootLayer(3);
    setCrop(3, touchCrop);
    setLayerStack(3, 1);
    Region touch{Rect{0, 0, 1000, 1000}};
    setTouchableRegionCrop(3, touch, /*touchCropId=*/3, /*replaceTouchableRegionWithCrop=*/false);

    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 11, 111, 12, 121, 122, 1221, 13, 2, 3});
    Rect rotatedCrop = {500, 300, 700, 400};
    EXPECT_EQ(getSnapshot({.id = 3})->inputInfo.touchableRegion.bounds(), rotatedCrop);
}

TEST_F(LayerSnapshotTest, blurUpdatesWhenAlphaChanges) {
    int blurRadius = 42;
    setBackgroundBlurRadius(1221, static_cast<uint32_t>(blurRadius));

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1221})->backgroundBlurRadius, blurRadius);

    blurRadius = 21;
    setBackgroundBlurRadius(1221, static_cast<uint32_t>(blurRadius));
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1221})->backgroundBlurRadius, blurRadius);

    static constexpr float alpha = 0.5;
    setAlpha(12, alpha);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1221})->backgroundBlurRadius,
              static_cast<int>(static_cast<float>(blurRadius) * alpha));
}

// Display Mirroring Tests
// tree with 3 levels of children
// ROOT (DISPLAY 0)
// ├── 1
// │   ├── 11
// │   │   └── 111
// │   ├── 12 (has skip screenshot flag)
// │   │   ├── 121
// │   │   └── 122
// │   │       └── 1221
// │   └── 13
// └── 2
// ROOT (DISPLAY 1)
// └── 3 (mirrors display 0)
TEST_F(LayerSnapshotTest, displayMirrorRespectsLayerSkipScreenshotFlag) {
    setFlags(12, layer_state_t::eLayerSkipScreenshot, layer_state_t::eLayerSkipScreenshot);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 1);

    std::vector<uint32_t> expected = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 3, 1, 11, 111, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
}

// ROOT (DISPLAY 0)
// ├── 1
// │   ├── 11
// │   │   └── 111
// │   └── 13
// └── 2
// ROOT (DISPLAY 3)
// └── 3 (mirrors display 0)
TEST_F(LayerSnapshotTest, mirrorLayerGetsCorrectLayerStack) {
    reparentLayer(12, UNASSIGNED_LAYER_ID);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 3);
    createDisplayMirrorLayer(4, ui::LayerStack::fromValue(0));
    setLayerStack(4, 4);

    std::vector<uint32_t> expected = {1,  11, 111, 13, 2,  3,   1,  11, 111,
                                      13, 2,  4,   1,  11, 111, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    EXPECT_EQ(getSnapshot({.id = 111, .mirrorRootIds = 3u})->outputFilter.layerStack.id, 3u);
    EXPECT_EQ(getSnapshot({.id = 111, .mirrorRootIds = 4u})->outputFilter.layerStack.id, 4u);
}

// ROOT (DISPLAY 0)
// ├── 1 (crop 50x50)
// │   ├── 11
// │   │   └── 111
// │   └── 13
// └── 2
// ROOT (DISPLAY 3)
// └── 3 (mirrors display 0) (crop 100x100)
TEST_F(LayerSnapshotTest, mirrorLayerTouchIsCroppedByMirrorRoot) {
    reparentLayer(12, UNASSIGNED_LAYER_ID);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 3);
    setCrop(1, Rect{50, 50});
    setCrop(3, Rect{100, 100});
    setCrop(111, Rect{200, 200});
    Region touch{Rect{0, 0, 1000, 1000}};
    setTouchableRegion(111, touch);
    std::vector<uint32_t> expected = {1, 11, 111, 13, 2, 3, 1, 11, 111, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    EXPECT_TRUE(getSnapshot({.id = 111})->inputInfo.touchableRegion.hasSameRects(touch));
    Region touchCroppedByMirrorRoot{Rect{0, 0, 50, 50}};
    EXPECT_TRUE(getSnapshot({.id = 111, .mirrorRootIds = 3u})
                        ->inputInfo.touchableRegion.hasSameRects(touchCroppedByMirrorRoot));
}

TEST_F(LayerSnapshotTest, canRemoveDisplayMirror) {
    setFlags(12, layer_state_t::eLayerSkipScreenshot, layer_state_t::eLayerSkipScreenshot);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 1);
    std::vector<uint32_t> expected = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 3, 1, 11, 111, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    destroyLayerHandle(3);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
}

TEST_F(LayerSnapshotTest, cleanUpUnreachableSnapshotsAfterMirroring) {
    size_t startingNumSnapshots = mSnapshotBuilder.getSnapshots().size();
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 1);
    std::vector<uint32_t> expected = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 3,
                                      1, 11, 111, 12, 121, 122, 1221, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    destroyLayerHandle(3);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    EXPECT_EQ(startingNumSnapshots, mSnapshotBuilder.getSnapshots().size());
}

TEST_F(LayerSnapshotTest, canMirrorDisplayWithMirrors) {
    reparentLayer(12, UNASSIGNED_LAYER_ID);
    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 11);
    std::vector<uint32_t> expected = {1, 11, 111, 13, 14, 11, 111, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);

    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 3);
    expected = {1, 11, 111, 13, 14, 11, 111, 2, 3, 1, 11, 111, 13, 14, 11, 111, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    EXPECT_EQ(getSnapshot({.id = 11, .mirrorRootIds = 14u})->outputFilter.layerStack.id, 0u);
    EXPECT_EQ(getSnapshot({.id = 11, .mirrorRootIds = 3u})->outputFilter.layerStack.id, 3u);
    EXPECT_EQ(getSnapshot({.id = 11, .mirrorRootIds = 3u, 14u})->outputFilter.layerStack.id, 3u);
}

// Rel z doesn't create duplicate snapshots but this is for completeness
TEST_F(LayerSnapshotTest, cleanUpUnreachableSnapshotsAfterRelZ) {
    size_t startingNumSnapshots = mSnapshotBuilder.getSnapshots().size();
    reparentRelativeLayer(13, 11);
    UPDATE_AND_VERIFY(mSnapshotBuilder, {1, 11, 13, 111, 12, 121, 122, 1221, 2});
    setZ(13, 0);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    EXPECT_EQ(startingNumSnapshots, mSnapshotBuilder.getSnapshots().size());
}

TEST_F(LayerSnapshotTest, cleanUpUnreachableSnapshotsAfterLayerDestruction) {
    size_t startingNumSnapshots = mSnapshotBuilder.getSnapshots().size();
    destroyLayerHandle(2);
    destroyLayerHandle(122);

    std::vector<uint32_t> expected = {1, 11, 111, 12, 121, 122, 1221, 13};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);

    EXPECT_LE(startingNumSnapshots - 2, mSnapshotBuilder.getSnapshots().size());
}

TEST_F(LayerSnapshotTest, snashotContainsMetadataFromLayerCreationArgs) {
    LayerCreationArgs args(std::make_optional<uint32_t>(200));
    args.name = "testlayer";
    args.addToRoot = true;
    args.metadata.setInt32(42, 24);

    std::vector<std::unique_ptr<RequestedLayerState>> layers;
    layers.emplace_back(std::make_unique<RequestedLayerState>(args));
    EXPECT_TRUE(layers.back()->metadata.has(42));
    EXPECT_EQ(layers.back()->metadata.getInt32(42, 0), 24);
    mLifecycleManager.addLayers(std::move(layers));

    std::vector<uint32_t> expected = STARTING_ZORDER;
    expected.push_back(200);
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);

    EXPECT_TRUE(mSnapshotBuilder.getSnapshot(200)->layerMetadata.has(42));
    EXPECT_EQ(mSnapshotBuilder.getSnapshot(200)->layerMetadata.getInt32(42, 0), 24);
}

TEST_F(LayerSnapshotTest, frameRateSelectionPriorityPassedToChildLayers) {
    setFrameRateSelectionPriority(11, 1);

    setFrameRateSelectionPriority(12, 2);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1})->frameRateSelectionPriority, Layer::PRIORITY_UNSET);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRateSelectionPriority, 1);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRateSelectionPriority, 2);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRateSelectionPriority, 2);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRateSelectionPriority, 2);

    // reparent and verify the child gets the new parent's framerate selection priority
    reparentLayer(122, 11);

    std::vector<uint32_t> expected = {1, 11, 111, 122, 1221, 12, 121, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    EXPECT_EQ(getSnapshot({.id = 1})->frameRateSelectionPriority, Layer::PRIORITY_UNSET);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRateSelectionPriority, 1);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRateSelectionPriority, 2);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRateSelectionPriority, 1);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRateSelectionPriority, 1);
}

TEST_F(LayerSnapshotTest, framerate) {
    setFrameRate(11, 244.f, 0, 0);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    // verify parent is gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_TRUE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer and children get the requested votes
    EXPECT_TRUE(getSnapshot({.id = 11})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 11})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_TRUE(getSnapshot({.id = 111})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 111})->changes.test(RequestedLayerState::Changes::FrameRate));

    // reparent and verify the child gets the new parent's framerate
    reparentLayer(122, 11);

    std::vector<uint32_t> expected = {1, 11, 111, 122, 1221, 12, 121, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    // verify parent is gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);

    // verify layer and children get the requested votes
    EXPECT_TRUE(getSnapshot({.id = 11})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);

    EXPECT_TRUE(getSnapshot({.id = 111})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);

    EXPECT_TRUE(getSnapshot({.id = 122})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));

    // reparent and verify the new parent gets no vote
    reparentLayer(11, 2);
    expected = {1, 12, 121, 13, 2, 11, 111, 122, 1221};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);

    // verify old parent has invalid framerate (default)
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify new parent get no vote
    EXPECT_FALSE(getSnapshot({.id = 2})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 2})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_TRUE(getSnapshot({.id = 2})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer and children get the requested votes (unchanged)
    EXPECT_TRUE(getSnapshot({.id = 11})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);

    EXPECT_TRUE(getSnapshot({.id = 111})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);

    EXPECT_TRUE(getSnapshot({.id = 122})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
}

TEST_F(LayerSnapshotTest, translateDataspace) {
    setDataspace(1, ui::Dataspace::UNKNOWN);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1})->dataspace, ui::Dataspace::V0_SRGB);
}

// This test is similar to "frameRate" test case but checks that the setFrameRateCategory API
// interaction also works correctly with the setFrameRate API within SF frontend.
TEST_F(LayerSnapshotTest, frameRateWithCategory) {
    // ROOT
    // ├── 1
    // │   ├── 11 (frame rate set to 244.f)
    // │   │   └── 111
    // │   ├── 12
    // │   │   ├── 121
    // │   │   └── 122 (frame rate category set to Normal)
    // │   │       └── 1221
    // │   └── 13
    // └── 2
    setFrameRate(11, 244.f, 0, 0);
    setFrameRateCategory(122, ANATIVEWINDOW_FRAME_RATE_CATEGORY_NORMAL);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    // verify parent 1 gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_TRUE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 11 and children 111 get the requested votes
    EXPECT_TRUE(getSnapshot({.id = 11})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 11})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_TRUE(getSnapshot({.id = 111})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 111})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify parent 12 gets no vote
    EXPECT_FALSE(getSnapshot({.id = 12})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 12})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_TRUE(getSnapshot({.id = 12})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 122 and children 1221 get the requested votes
    EXPECT_FALSE(getSnapshot({.id = 122})->frameRate.vote.rate.isValid());
    EXPECT_TRUE(getSnapshot({.id = 122})->frameRate.isValid());
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.category, FrameRateCategory::Normal);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));
    EXPECT_TRUE(
            getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::AffectsChildren));

    EXPECT_FALSE(getSnapshot({.id = 1221})->frameRate.vote.rate.isValid());
    EXPECT_TRUE(getSnapshot({.id = 1221})->frameRate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.category, FrameRateCategory::Normal);
    EXPECT_TRUE(getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::FrameRate));
    EXPECT_TRUE(
            getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::AffectsChildren));

    // reparent and verify the child does NOT get the new parent's framerate because it already has
    // the frame rate category specified.
    // ROOT
    //  ├─1
    //  │  ├─11 (frame rate set to 244.f)
    //  │  │  ├─111
    //  │  │  └─122 (frame rate category set to Normal)
    //  │  │     └─1221
    //  │  ├─12
    //  │  │  └─121
    //  │  └─13
    //  └─2
    reparentLayer(122, 11);

    std::vector<uint32_t> expected = {1, 11, 111, 122, 1221, 12, 121, 13, 2};
    UPDATE_AND_VERIFY(mSnapshotBuilder, expected);
    // verify parent is gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);

    // verify layer 11 and children 111 get the requested votes
    EXPECT_TRUE(getSnapshot({.id = 11})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);

    EXPECT_TRUE(getSnapshot({.id = 111})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);

    // verify layer 122 and children 1221 get the requested category vote (unchanged from
    // reparenting)
    EXPECT_FALSE(getSnapshot({.id = 122})->frameRate.vote.rate.isValid());
    EXPECT_TRUE(getSnapshot({.id = 122})->frameRate.isValid());
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.category, FrameRateCategory::Normal);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_FALSE(getSnapshot({.id = 1221})->frameRate.vote.rate.isValid());
    EXPECT_TRUE(getSnapshot({.id = 1221})->frameRate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.category, FrameRateCategory::Normal);
    EXPECT_TRUE(getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::FrameRate));
}

TEST_F(LayerSnapshotTest, frameRateSelectionStrategy) {
    // ROOT
    // ├── 1
    // │   ├── 11
    // │   │   └── 111
    // │   ├── 12 (frame rate set to 244.f with strategy OverrideChildren)
    // │   │   ├── 121
    // │   │   └── 122 (frame rate set to 123.f but should be overridden by layer 12)
    // │   │       └── 1221
    // │   └── 13
    // └── 2
    setFrameRate(12, 244.f, 0, 0);
    setFrameRate(122, 123.f, 0, 0);
    setFrameRateSelectionStrategy(12, 1 /* OverrideChildren */);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    // verify parent 1 gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_TRUE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 12 and all descendants (121, 122, 1221) get the requested vote
    EXPECT_EQ(getSnapshot({.id = 12})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 12})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 121})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 121})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 121})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::FrameRate));

    // ROOT
    // ├── 1
    // │   ├── 11
    // │   │   └── 111
    // │   ├── 12 (frame rate set to default with strategy default)
    // │   │   ├── 121
    // │   │   └── 122 (frame rate set to 123.f)
    // │   │       └── 1221
    // │   └── 13
    // └── 2
    setFrameRate(12, -1.f, 0, 0);
    setFrameRateSelectionStrategy(12, 0 /* Default */);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    // verify parent 1 gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_FALSE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 12 and all descendants (121, 122, 1221) get the requested vote
    EXPECT_FALSE(getSnapshot({.id = 12})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 12})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 12})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_FALSE(getSnapshot({.id = 121})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 121})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_EQ(getSnapshot({.id = 121})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 121})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.rate.getValue(), 123.f);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.vote.rate.getValue(), 123.f);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::FrameRate));
}

TEST_F(LayerSnapshotTest, frameRateSelectionStrategyWithCategory) {
    // ROOT
    // ├── 1
    // │   ├── 11
    // │   │   └── 111
    // │   ├── 12 (frame rate category set to high with strategy OverrideChildren)
    // │   │   ├── 121
    // │   │   └── 122 (frame rate set to 123.f but should be overridden by layer 12)
    // │   │       └── 1221
    // │   └── 13
    // └── 2
    setFrameRateCategory(12, ANATIVEWINDOW_FRAME_RATE_CATEGORY_HIGH);
    setFrameRate(122, 123.f, 0, 0);
    setFrameRateSelectionStrategy(12, 1 /* OverrideChildren */);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    // verify parent 1 gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_TRUE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 12 and all descendants (121, 122, 1221) get the requested vote
    EXPECT_EQ(getSnapshot({.id = 12})->frameRate.category, FrameRateCategory::High);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 12})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 121})->frameRate.category, FrameRateCategory::High);
    EXPECT_EQ(getSnapshot({.id = 121})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 121})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.category, FrameRateCategory::High);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.category, FrameRateCategory::High);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::FrameRate));

    // ROOT
    // ├── 1
    // │   ├── 11
    // │   │   └── 111
    // │   ├── 12 (frame rate category to default with strategy default)
    // │   │   ├── 121
    // │   │   └── 122 (frame rate set to 123.f)
    // │   │       └── 1221
    // │   └── 13
    // └── 2
    setFrameRateCategory(12, ANATIVEWINDOW_FRAME_RATE_CATEGORY_DEFAULT);
    setFrameRateSelectionStrategy(12, 0 /* Default */);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    // verify parent 1 gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.category, FrameRateCategory::Default);
    EXPECT_FALSE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 12 and all descendants (121, 122, 1221) get the requested vote
    EXPECT_FALSE(getSnapshot({.id = 12})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 12})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRate.category, FrameRateCategory::Default);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 12})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_FALSE(getSnapshot({.id = 12})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 121})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_EQ(getSnapshot({.id = 121})->frameRate.category, FrameRateCategory::Default);
    EXPECT_EQ(getSnapshot({.id = 121})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_TRUE(getSnapshot({.id = 121})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.rate.getValue(), 123.f);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.category, FrameRateCategory::Default);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.vote.rate.getValue(), 123.f);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.category, FrameRateCategory::Default);
    EXPECT_TRUE(getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::FrameRate));
}

TEST_F(LayerSnapshotTest, frameRateSelectionStrategyWithOverrideChildrenAndSelf) {
    // ROOT
    // ├── 1
    // │   ├── 11 (frame rate set to 11.f with strategy Self)
    // │   │   └── 111 (frame rate is not inherited)
    // │   ├── 12 (frame rate set to 244.f)
    // │   │   ├── 121
    // │   │   └── 122 (strategy OverrideChildren and inherits frame rate 244.f)
    // │   │       └── 1221 (frame rate set to 123.f but should be overridden by layer 122)
    // │   └── 13
    // └── 2
    setFrameRate(11, 11.f, 0, 0);
    setFrameRateSelectionStrategy(11, 2 /* Self */);
    setFrameRate(12, 244.f, 0, 0);
    setFrameRateSelectionStrategy(122, 1 /* OverrideChildren */);
    setFrameRate(1221, 123.f, 0, 0);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    // verify parent 1 gets no vote
    EXPECT_FALSE(getSnapshot({.id = 1})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::NoVote);
    EXPECT_EQ(getSnapshot({.id = 1})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.rate.getValue(), 11.f);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Self);
    EXPECT_TRUE(getSnapshot({.id = 11})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 11 does does not propagate its framerate to 111.
    EXPECT_FALSE(getSnapshot({.id = 111})->frameRate.vote.rate.isValid());
    EXPECT_EQ(getSnapshot({.id = 111})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 111})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 12 and all descendants (121, 122, 1221) get the requested vote
    EXPECT_EQ(getSnapshot({.id = 12})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 12})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 12})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 121})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 121})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::Propagate);
    EXPECT_TRUE(getSnapshot({.id = 121})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 122})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 122})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 122})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 1221})->frameRate.vote.rate.getValue(), 244.f);
    EXPECT_EQ(getSnapshot({.id = 1221})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 1221})->changes.test(RequestedLayerState::Changes::FrameRate));

    // ROOT
    // ├── 1 (frame rate set to 1.f with strategy OverrideChildren)
    // │   ├── 11 (frame rate set to 11.f with strategy Self, but overridden by 1)
    // │   │   └── 111 (frame rate inherited from 11 due to override from 1)
    // ⋮   ⋮
    setFrameRate(1, 1.f, 0, 0);
    setFrameRateSelectionStrategy(1, 1 /* OverrideChildren */);
    setFrameRate(11, 11.f, 0, 0);
    setFrameRateSelectionStrategy(11, 2 /* Self */);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.rate.getValue(), 1.f);
    EXPECT_EQ(getSnapshot({.id = 1})->frameRate.vote.type,
              scheduler::FrameRateCompatibility::Default);
    EXPECT_EQ(getSnapshot({.id = 1})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 1})->changes.test(RequestedLayerState::Changes::FrameRate));

    EXPECT_EQ(getSnapshot({.id = 11})->frameRate.vote.rate.getValue(), 1.f);
    EXPECT_EQ(getSnapshot({.id = 11})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 11})->changes.test(RequestedLayerState::Changes::FrameRate));

    // verify layer 11 does does not propagate its framerate to 111.
    EXPECT_EQ(getSnapshot({.id = 111})->frameRate.vote.rate.getValue(), 1.f);
    EXPECT_EQ(getSnapshot({.id = 111})->frameRateSelectionStrategy,
              scheduler::LayerInfo::FrameRateSelectionStrategy::OverrideChildren);
    EXPECT_TRUE(getSnapshot({.id = 111})->changes.test(RequestedLayerState::Changes::FrameRate));
}

TEST_F(LayerSnapshotTest, skipRoundCornersWhenProtected) {
    setRoundedCorners(1, 42.f);
    setRoundedCorners(2, 42.f);
    setCrop(1, Rect{1000, 1000});
    setCrop(2, Rect{1000, 1000});

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_TRUE(getSnapshot({.id = 1})->roundedCorner.hasRoundedCorners());
    EXPECT_EQ(getSnapshot({.id = 1})->roundedCorner.radius.x, 42.f);
    EXPECT_TRUE(getSnapshot({.id = 2})->roundedCorner.hasRoundedCorners());

    // add a buffer with the protected bit, check rounded corners are not set when
    // skipRoundCornersWhenProtected == true
    setBuffer(1,
              std::make_shared<
                      renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                               1ULL /* bufferId */,
                                                               HAL_PIXEL_FORMAT_RGBA_8888,
                                                               GRALLOC_USAGE_PROTECTED /*usage*/));

    LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                    .layerLifecycleManager = mLifecycleManager,
                                    .includeMetadata = false,
                                    .displays = mFrontEndDisplayInfos,
                                    .displayChanges = false,
                                    .globalShadowSettings = globalShadowSettings,
                                    .supportsBlur = true,
                                    .supportedLayerGenericMetadata = {},
                                    .genericLayerMetadataKeyMap = {},
                                    .skipRoundCornersWhenProtected = true};
    update(mSnapshotBuilder, args);
    EXPECT_FALSE(getSnapshot({.id = 1})->roundedCorner.hasRoundedCorners());
    // layer 2 doesn't have a buffer and should be unaffected
    EXPECT_TRUE(getSnapshot({.id = 2})->roundedCorner.hasRoundedCorners());

    // remove protected bit, check rounded corners are set
    setBuffer(1,
              std::make_shared<renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                                        2ULL /* bufferId */,
                                                                        HAL_PIXEL_FORMAT_RGBA_8888,
                                                                        0 /*usage*/));
    update(mSnapshotBuilder, args);
    EXPECT_TRUE(getSnapshot({.id = 1})->roundedCorner.hasRoundedCorners());
    EXPECT_EQ(getSnapshot({.id = 1})->roundedCorner.radius.x, 42.f);
}

TEST_F(LayerSnapshotTest, setRefreshRateIndicatorCompositionType) {
    setFlags(1, layer_state_t::eLayerIsRefreshRateIndicator,
             layer_state_t::eLayerIsRefreshRateIndicator);
    setBuffer(1,
              std::make_shared<renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                                        42ULL /* bufferId */,
                                                                        HAL_PIXEL_FORMAT_RGBA_8888,
                                                                        0 /*usage*/));
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1})->compositionType,
              aidl::android::hardware::graphics::composer3::Composition::REFRESH_RATE_INDICATOR);
}

TEST_F(LayerSnapshotTest, setBufferCrop) {
    // validate no buffer but has crop
    Rect crop = Rect(0, 0, 50, 50);
    setBufferCrop(1, crop);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->geomContentCrop, crop);

    setBuffer(1,
              std::make_shared<renderengine::mock::FakeExternalTexture>(100U /*width*/,
                                                                        100U /*height*/,
                                                                        42ULL /* bufferId */,
                                                                        HAL_PIXEL_FORMAT_RGBA_8888,
                                                                        0 /*usage*/));
    // validate a buffer crop within the buffer bounds
    setBufferCrop(1, crop);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->geomContentCrop, crop);

    // validate a buffer crop outside the buffer bounds
    crop = Rect(0, 0, 150, 150);
    setBufferCrop(1, crop);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->geomContentCrop, Rect(0, 0, 100, 100));

    // validate no buffer crop
    setBufferCrop(1, Rect());
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->geomContentCrop, Rect(0, 0, 100, 100));
}

TEST_F(LayerSnapshotTest, setShadowRadius) {
    static constexpr float SHADOW_RADIUS = 123.f;
    setShadowRadius(1, SHADOW_RADIUS);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot(1)->shadowSettings.length, SHADOW_RADIUS);
}

TEST_F(LayerSnapshotTest, setTrustedOverlayForNonVisibleInput) {
    hideLayer(1);
    setTrustedOverlay(1, true);
    Region touch{Rect{0, 0, 1000, 1000}};
    setTouchableRegion(1, touch);

    UPDATE_AND_VERIFY(mSnapshotBuilder, {2});
    EXPECT_TRUE(getSnapshot(1)->inputInfo.inputConfig.test(
            gui::WindowInfo::InputConfig::TRUSTED_OVERLAY));
}

TEST_F(LayerSnapshotTest, isFrontBuffered) {
    setBuffer(1,
              std::make_shared<renderengine::mock::FakeExternalTexture>(
                      1U /*width*/, 1U /*height*/, 1ULL /* bufferId */, HAL_PIXEL_FORMAT_RGBA_8888,
                      GRALLOC_USAGE_HW_TEXTURE | AHARDWAREBUFFER_USAGE_FRONT_BUFFER /*usage*/));

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_TRUE(getSnapshot(1)->isFrontBuffered());

    setBuffer(1,
              std::make_shared<
                      renderengine::mock::FakeExternalTexture>(1U /*width*/, 1U /*height*/,
                                                               1ULL /* bufferId */,
                                                               HAL_PIXEL_FORMAT_RGBA_8888,
                                                               GRALLOC_USAGE_HW_TEXTURE /*usage*/));

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_FALSE(getSnapshot(1)->isFrontBuffered());
}

TEST_F(LayerSnapshotTest, setSecureRootSnapshot) {
    setFlags(1, layer_state_t::eLayerSecure, layer_state_t::eLayerSecure);
    LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                    .layerLifecycleManager = mLifecycleManager,
                                    .includeMetadata = false,
                                    .displays = mFrontEndDisplayInfos,
                                    .displayChanges = false,
                                    .globalShadowSettings = globalShadowSettings,
                                    .supportsBlur = true,
                                    .supportedLayerGenericMetadata = {},
                                    .genericLayerMetadataKeyMap = {}};
    args.rootSnapshot.isSecure = true;
    update(mSnapshotBuilder, args);

    EXPECT_TRUE(getSnapshot(1)->isSecure);
    // Ensure child is also marked as secure
    EXPECT_TRUE(getSnapshot(11)->isSecure);
}

// b/314350323
TEST_F(LayerSnapshotTest, propagateDropInputMode) {
    setDropInputMode(1, gui::DropInputMode::ALL);
    LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                    .layerLifecycleManager = mLifecycleManager,
                                    .includeMetadata = false,
                                    .displays = mFrontEndDisplayInfos,
                                    .displayChanges = false,
                                    .globalShadowSettings = globalShadowSettings,
                                    .supportsBlur = true,
                                    .supportedLayerGenericMetadata = {},
                                    .genericLayerMetadataKeyMap = {}};
    args.rootSnapshot.isSecure = true;
    update(mSnapshotBuilder, args);

    EXPECT_EQ(getSnapshot(1)->dropInputMode, gui::DropInputMode::ALL);
    // Ensure child also has the correct drop input mode regardless of whether either layer has
    // an input channel
    EXPECT_EQ(getSnapshot(11)->dropInputMode, gui::DropInputMode::ALL);
}

TEST_F(LayerSnapshotTest, NonVisibleLayerWithInput) {
    LayerHierarchyTestBase::createRootLayer(3);
    setColor(3, {-1._hf, -1._hf, -1._hf});
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    std::vector<TransactionState> transactions;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.what = layer_state_t::eInputInfoChanged;
    transactions.back().states.front().layerId = 3;
    transactions.back().states.front().state.windowInfoHandle = sp<gui::WindowInfoHandle>::make();
    auto inputInfo = transactions.back().states.front().state.windowInfoHandle->editInfo();
    inputInfo->token = sp<BBinder>::make();
    mLifecycleManager.applyTransactions(transactions);

    update(mSnapshotBuilder);

    bool foundInputLayer = false;
    mSnapshotBuilder.forEachInputSnapshot([&](const frontend::LayerSnapshot& snapshot) {
        if (snapshot.uniqueSequence == 3) {
            foundInputLayer = true;
        }
    });
    EXPECT_TRUE(foundInputLayer);
}

TEST_F(LayerSnapshotTest, canOccludePresentation) {
    setFlags(12, layer_state_t::eCanOccludePresentation, layer_state_t::eCanOccludePresentation);
    LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                    .layerLifecycleManager = mLifecycleManager,
                                    .includeMetadata = false,
                                    .displays = mFrontEndDisplayInfos,
                                    .displayChanges = false,
                                    .globalShadowSettings = globalShadowSettings,
                                    .supportsBlur = true,
                                    .supportedLayerGenericMetadata = {},
                                    .genericLayerMetadataKeyMap = {}};
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    EXPECT_EQ(getSnapshot(1)->inputInfo.canOccludePresentation, false);

    // ensure we can set the property on the window info for layer and all its children
    EXPECT_EQ(getSnapshot(12)->inputInfo.canOccludePresentation, true);
    EXPECT_EQ(getSnapshot(121)->inputInfo.canOccludePresentation, true);
    EXPECT_EQ(getSnapshot(1221)->inputInfo.canOccludePresentation, true);
}

} // namespace android::surfaceflinger::frontend
