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

#include "FrontEnd/LayerHierarchy.h"
#include "FrontEnd/LayerLifecycleManager.h"
#include "FrontEnd/LayerSnapshotBuilder.h"
#include "LayerHierarchyTest.h"

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

class LayerSnapshotTest : public LayerHierarchyTestBase {
protected:
    LayerSnapshotTest() : LayerHierarchyTestBase() {
        UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    }

    void createRootLayer(uint32_t id) override {
        LayerHierarchyTestBase::createRootLayer(id);
        setColor(id);
    }

    void createLayer(uint32_t id, uint32_t parentId) override {
        LayerHierarchyTestBase::createLayer(id, parentId);
        setColor(parentId);
    }

    void mirrorLayer(uint32_t id, uint32_t parent, uint32_t layerToMirror) override {
        LayerHierarchyTestBase::mirrorLayer(id, parent, layerToMirror);
        setColor(id);
    }

    void updateAndVerify(LayerSnapshotBuilder& actualBuilder, bool hasDisplayChanges,
                         const std::vector<uint32_t> expectedVisibleLayerIdsInZOrder) {
        if (mLifecycleManager.getGlobalChanges().test(RequestedLayerState::Changes::Hierarchy)) {
            mHierarchyBuilder.update(mLifecycleManager.getLayers(),
                                     mLifecycleManager.getDestroyedLayers());
        }
        LayerSnapshotBuilder::Args args{.root = mHierarchyBuilder.getHierarchy(),
                                        .layerLifecycleManager = mLifecycleManager,
                                        .includeMetadata = false,
                                        .displays = mFrontEndDisplayInfos,
                                        .displayChanges = hasDisplayChanges,
                                        .globalShadowSettings = globalShadowSettings,
                                        .supportsBlur = true,
                                        .supportedLayerGenericMetadata = {},
                                        .genericLayerMetadataKeyMap = {}};
        actualBuilder.update(args);

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

    LayerHierarchyBuilder mHierarchyBuilder{{}};
    LayerSnapshotBuilder mSnapshotBuilder;
    DisplayInfos mFrontEndDisplayInfos;
    renderengine::ShadowSettings globalShadowSettings;
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

    std::vector<TransactionState> transactions;
    transactions.emplace_back();
    transactions.back().states.push_back({});
    transactions.back().states.front().state.what = layer_state_t::eFrameRateChanged;
    transactions.back().states.front().state.frameRate = 90.0;
    transactions.back().states.front().state.frameRateCompatibility =
            ANATIVEWINDOW_FRAME_RATE_EXACT;
    transactions.back().states.front().state.changeFrameRateStrategy =
            ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS;
    transactions.back().states.front().layerId = 11;
    mLifecycleManager.applyTransactions(transactions);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);

    EXPECT_EQ(getSnapshot(11)->frameRate.rate.getIntValue(), 90);
    EXPECT_EQ(getSnapshot(11)->frameRate.type, scheduler::LayerInfo::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(111)->frameRate.rate.getIntValue(), 90);
    EXPECT_EQ(getSnapshot(111)->frameRate.type,
              scheduler::LayerInfo::FrameRateCompatibility::Exact);
    EXPECT_EQ(getSnapshot(1)->frameRate.rate.getIntValue(), 0);
    EXPECT_EQ(getSnapshot(1)->frameRate.type, scheduler::LayerInfo::FrameRateCompatibility::NoVote);
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

TEST_F(LayerSnapshotTest, blurUpdatesWhenAlphaChanges) {
    static constexpr int blurRadius = 42;
    setBackgroundBlurRadius(1221, blurRadius);

    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1221})->backgroundBlurRadius, blurRadius);

    static constexpr float alpha = 0.5;
    setAlpha(12, alpha);
    UPDATE_AND_VERIFY(mSnapshotBuilder, STARTING_ZORDER);
    EXPECT_EQ(getSnapshot({.id = 1221})->backgroundBlurRadius, blurRadius * alpha);
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
    EXPECT_EQ(getSnapshot({.id = 111, .mirrorRootId = 3})->outputFilter.layerStack.id, 3u);
    EXPECT_EQ(getSnapshot({.id = 111, .mirrorRootId = 4})->outputFilter.layerStack.id, 4u);
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
    EXPECT_TRUE(getSnapshot({.id = 111, .mirrorRootId = 3})
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

} // namespace android::surfaceflinger::frontend
