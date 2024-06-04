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
#include "LayerHierarchyTest.h"

#define UPDATE_AND_VERIFY(HIERARCHY)  \
    ({                                \
        SCOPED_TRACE("");             \
        updateAndVerify((HIERARCHY)); \
    })

namespace android::surfaceflinger::frontend {

// To run test:
/**
 mp :libsurfaceflinger_unittest && adb sync; adb shell \
    /data/nativetest/libsurfaceflinger_unittest/libsurfaceflinger_unittest \
    --gtest_filter="LayerHierarchyTest.*" --gtest_repeat=100 \
    --gtest_shuffle \
    --gtest_brief=1
*/

class LayerHierarchyTest : public LayerHierarchyTestBase {
protected:
    LayerHierarchyTest() : LayerHierarchyTestBase() { mLifecycleManager.commitChanges(); }
};

// reparenting tests
TEST_F(LayerHierarchyTest, addLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    createRootLayer(3);
    createLayer(112, 11);
    createLayer(12211, 1221);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    expectedTraversalPath = {1, 11, 111, 112, 12, 121, 122, 1221, 12211, 13, 2, 3};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, reparentLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentLayer(2, 11);
    reparentLayer(111, 12);
    reparentLayer(1221, 1);
    reparentLayer(1221, 13);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 2, 12, 111, 121, 122, 13, 1221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, reparentLayerToNull) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    reparentLayer(2, UNASSIGNED_LAYER_ID);
    reparentLayer(11, UNASSIGNED_LAYER_ID);
    reparentLayer(1221, 13);
    reparentLayer(1221, UNASSIGNED_LAYER_ID);

    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 12, 121, 122, 13};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {2, 11, 111, 1221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, reparentLayerToNullAndDestroyHandles) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentLayer(2, UNASSIGNED_LAYER_ID);
    reparentLayer(11, UNASSIGNED_LAYER_ID);
    reparentLayer(1221, UNASSIGNED_LAYER_ID);

    destroyLayerHandle(2);
    destroyLayerHandle(11);
    destroyLayerHandle(1221);

    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 12, 121, 122, 13};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, destroyHandleThenDestroyParentLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    destroyLayerHandle(111);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    // handle is destroyed but layer is kept alive and reachable by parent
    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    // destroy parent layer and the child gets destroyed
    reparentLayer(11, UNASSIGNED_LAYER_ID);
    destroyLayerHandle(11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, layerSurvivesTemporaryReparentToNull) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentLayer(11, UNASSIGNED_LAYER_ID);
    reparentLayer(11, 1);

    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

// offscreen tests
TEST_F(LayerHierarchyTest, layerMovesOnscreen) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    reparentLayer(11, UNASSIGNED_LAYER_ID);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    reparentLayer(11, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, addLayerToOffscreenParent) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    reparentLayer(11, UNASSIGNED_LAYER_ID);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    createLayer(112, 11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {11, 111, 112};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

// rel-z tests
TEST_F(LayerHierarchyTest, setRelativeParent) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, reparentFromRelativeParentWithSetLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    // This calls setLayer
    removeRelativeZ(11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, reparentToRelativeParent) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    reparentLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, setParentAsRelativeParent) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    reparentRelativeLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, relativeChildMovesOffscreenIsNotTraversable) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    reparentLayer(2, UNASSIGNED_LAYER_ID);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 12, 121, 122, 1221, 13};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {2, 11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, reparentRelativeLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(11, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    reparentLayer(11, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 2, 11, 111};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    setZ(11, 0);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

// mirror tests
TEST_F(LayerHierarchyTest, canTraverseMirrorLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1,    11, 111, 12, 121, 122,
                                                   1221, 13, 14,  11, 111, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, canMirrorOffscreenLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    reparentLayer(11, UNASSIGNED_LAYER_ID);
    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 12, 121, 122, 1221, 13, 14, 11, 111, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, newChildLayerIsUpdatedInMirrorHierarchy) {
    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 11);
    mLifecycleManager.commitChanges();
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    createLayer(1111, 111);
    createLayer(112, 11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1,    11, 111, 1111, 112, 12,   121, 122,
                                                   1221, 13, 14,  11,   111, 1111, 112, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

// mirror & relatives tests
TEST_F(LayerHierarchyTest, mirrorWithRelativeOutsideMirrorHierarchy) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(111, 12);
    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 11);

    // ROOT
    // ├── 1
    // │   ├── 11
    // │   │   └── 111
    // │   ├── 12
    // │   │   ├── 121
    // │   │   ├── 122
    // │   │   │   └── 1221
    // │   │   └ - 111 (relative)
    // │   ├── 13
    // │   └── 14
    // │       └ * 11 (mirroring)
    // └── 2

    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1,    11, 111, 12, 111, 121, 122,
                                                   1221, 13, 14,  11, 111, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    // 111 is not reachable in the mirror
    expectedTraversalPath = {1, 11, 12, 111, 121, 122, 1221, 13, 14, 11, 2};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, mirrorWithRelativeInsideMirrorHierarchy) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(1221, 12);
    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 12);

    // ROOT
    // ├── 1
    // │   ├── 11
    // │   │   └── 111
    // │   ├── 12
    // │   │   ├── 121
    // │   │   ├── 122
    // │   │   │   └── 1221
    // │   │   └ - 1221 (relative)
    // │   ├── 13
    // │   └── 14
    // │       └ * 12 (mirroring)
    // └── 2

    UPDATE_AND_VERIFY(hierarchyBuilder);
    std::vector<uint32_t> expectedTraversalPath = {1,  11, 111, 12,  121, 122,  1221, 1221,
                                                   13, 14, 12,  121, 122, 1221, 1221, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    // relative layer 1221 is traversable in the mirrored hierarchy as well
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 14, 12, 121, 122, 1221, 2};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, childMovesOffscreenWhenRelativeParentDies) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    reparentRelativeLayer(11, 2);
    reparentLayer(2, UNASSIGNED_LAYER_ID);
    destroyLayerHandle(2);

    UPDATE_AND_VERIFY(hierarchyBuilder);
    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 12, 121, 122, 1221, 13};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {11, 111};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    // remove relative parent so layer becomes onscreen again
    removeRelativeZ(11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, offscreenLayerCannotBeRelativeToOnscreenLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentRelativeLayer(1221, 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    // verify relz path
    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 1221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 13, 2, 1221};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    // offscreen layer cannot be reached as a relative child
    reparentLayer(12, UNASSIGNED_LAYER_ID);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    expectedTraversalPath = {1, 11, 111, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {12, 121, 122, 1221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    // layer when onscreen can be reached as a relative child again
    reparentLayer(12, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 1221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 13, 2, 1221};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, backgroundLayersAreBehindParentLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    updateBackgroundColor(1, 0.5);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    auto hierarchy = hierarchyBuilder.getPartialHierarchy(1, /*childrenOnly=*/true);
    auto bgLayerId = hierarchy.mChildren.front().first->getLayer()->id;
    std::vector<uint32_t> expectedTraversalPath = {1,   bgLayerId, 11,   111, 12,
                                                   121, 122,       1221, 13,  2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {bgLayerId, 1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

// cycle tests
TEST_F(LayerHierarchyTest, ParentBecomesTheChild) {
    // remove default hierarchy
    mLifecycleManager = LayerLifecycleManager();
    createRootLayer(1);
    createLayer(11, 1);
    reparentLayer(1, 11);
    mLifecycleManager.commitChanges();
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);

    std::vector<uint32_t> expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, RelativeLoops) {
    // remove default hierarchy
    mLifecycleManager = LayerLifecycleManager();
    createRootLayer(1);
    createRootLayer(2);
    createLayer(11, 1);
    reparentRelativeLayer(11, 2);
    reparentRelativeLayer(2, 11);
    LayerHierarchyBuilder hierarchyBuilder;
    // this call is expected to fix the loop!
    hierarchyBuilder.update(mLifecycleManager);
    uint32_t unused;
    EXPECT_FALSE(hierarchyBuilder.getHierarchy().hasRelZLoop(unused));

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 2, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {11, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, IndirectRelativeLoops) {
    // remove default hierarchy
    mLifecycleManager = LayerLifecycleManager();
    createRootLayer(1);
    createRootLayer(2);
    createLayer(11, 1);
    createLayer(111, 11);
    createLayer(21, 2);
    createLayer(22, 2);
    createLayer(221, 22);
    reparentRelativeLayer(22, 111);
    reparentRelativeLayer(11, 221);
    LayerHierarchyBuilder hierarchyBuilder;
    // this call is expected to fix the loop!
    hierarchyBuilder.update(mLifecycleManager);
    uint32_t unused;
    EXPECT_FALSE(hierarchyBuilder.getHierarchy().hasRelZLoop(unused));

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 22, 221, 2, 21, 22, 221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 2, 21};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {11, 111, 22, 221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, ReparentRootLayerToNull) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentLayer(1, UNASSIGNED_LAYER_ID);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, AddRemoveLayerInSameTransaction) {
    // remove default hierarchy
    mLifecycleManager = LayerLifecycleManager();
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    createRootLayer(1);
    destroyLayerHandle(1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

// traversal path test
TEST_F(LayerHierarchyTest, traversalPathId) {
    setZ(122, -1);
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    auto checkTraversalPathIdVisitor =
            [](const LayerHierarchy& hierarchy,
               const LayerHierarchy::TraversalPath& traversalPath) -> bool {
        EXPECT_EQ(hierarchy.getLayer()->id, traversalPath.id);
        return true;
    };
    hierarchyBuilder.getHierarchy().traverse(checkTraversalPathIdVisitor);
    hierarchyBuilder.getHierarchy().traverseInZOrder(checkTraversalPathIdVisitor);
}

TEST_F(LayerHierarchyTest, zorderRespectsLayerSequenceId) {
    // remove default hierarchy
    mLifecycleManager = LayerLifecycleManager();
    createRootLayer(1);
    createRootLayer(2);
    createRootLayer(4);
    createRootLayer(5);
    createLayer(11, 1);
    createLayer(51, 5);
    createLayer(53, 5);

    mLifecycleManager.commitChanges();
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    std::vector<uint32_t> expectedTraversalPath = {1, 11, 2, 4, 5, 51, 53};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);

    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    // A new layer is added with a smaller sequence id. Make sure its sorted correctly. While
    // sequence ids are always incremented, this scenario can happen when a layer is reparented.
    createRootLayer(3);
    createLayer(52, 5);

    UPDATE_AND_VERIFY(hierarchyBuilder);
    expectedTraversalPath = {1, 11, 2, 3, 4, 5, 51, 52, 53};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, zorderRespectsLayerZ) {
    // remove default hierarchy
    mLifecycleManager = LayerLifecycleManager();
    createRootLayer(1);
    createLayer(11, 1);
    createLayer(12, 1);
    createLayer(13, 1);
    setZ(11, -1);
    setZ(12, 2);
    setZ(13, 1);

    mLifecycleManager.commitChanges();
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    std::vector<uint32_t> expectedTraversalPath = {1, 11, 13, 12};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);

    expectedTraversalPath = {11, 1, 13, 12};
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, zorderRespectsLayerStack) {
    // remove default hierarchy
    mLifecycleManager = LayerLifecycleManager();
    createRootLayer(1);
    createRootLayer(2);
    createLayer(11, 1);
    createLayer(21, 2);
    setLayerStack(1, 20);
    setLayerStack(2, 10);

    mLifecycleManager.commitChanges();
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    std::vector<uint32_t> expectedTraversalPath = {2, 21, 1, 11};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);

    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

TEST_F(LayerHierarchyTest, canMirrorDisplay) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    setFlags(12, layer_state_t::eLayerSkipScreenshot, layer_state_t::eLayerSkipScreenshot);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expected = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 3,
                                      1, 11, 111, 12, 121, 122, 1221, 13, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expected);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expected);
    expected = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expected);
}

TEST_F(LayerHierarchyTest, mirrorNonExistingDisplay) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    setFlags(12, layer_state_t::eLayerSkipScreenshot, layer_state_t::eLayerSkipScreenshot);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(5));
    setLayerStack(3, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expected = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 3};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expected);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expected);
    expected = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expected);
}

TEST_F(LayerHierarchyTest, newRootLayerIsMirrored) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    setFlags(12, layer_state_t::eLayerSkipScreenshot, layer_state_t::eLayerSkipScreenshot);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    createRootLayer(4);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expected = {1, 11, 111, 12, 121, 122, 1221, 13, 2, 4, 3,
                                      1, 11, 111, 12, 121, 122, 1221, 13, 2, 4};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expected);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expected);
    expected = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expected);
}

TEST_F(LayerHierarchyTest, removedRootLayerIsNoLongerMirrored) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    setFlags(12, layer_state_t::eLayerSkipScreenshot, layer_state_t::eLayerSkipScreenshot);
    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    reparentLayer(1, UNASSIGNED_LAYER_ID);
    destroyLayerHandle(1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expected = {2, 3, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expected);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expected);
    expected = {11, 111, 12, 121, 122, 1221, 13};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expected);
}

TEST_F(LayerHierarchyTest, canMirrorDisplayWithMirrors) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    reparentLayer(12, UNASSIGNED_LAYER_ID);
    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 11);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    createDisplayMirrorLayer(3, ui::LayerStack::fromValue(0));
    setLayerStack(3, 1);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expected = {1, 11, 111, 13, 14, 11, 111, 2, 3,
                                      1, 11, 111, 13, 14, 11, 111, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expected);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expected);
    expected = {12, 121, 122, 1221};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expected);
}

// (b/343901186)
TEST_F(LayerHierarchyTest, cleanUpDanglingMirrorLayer) {
    LayerHierarchyBuilder hierarchyBuilder;
    hierarchyBuilder.update(mLifecycleManager);
    mirrorLayer(/*layer*/ 14, /*parent*/ 1, /*layerToMirror*/ 2);
    UPDATE_AND_VERIFY(hierarchyBuilder);

    std::vector<uint32_t> expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 14, 2, 2};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);

    // destroy layer handle
    reparentLayer(2, UNASSIGNED_LAYER_ID);
    destroyLayerHandle(2);
    UPDATE_AND_VERIFY(hierarchyBuilder);
    expectedTraversalPath = {1, 11, 111, 12, 121, 122, 1221, 13, 14};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    EXPECT_EQ(getTraversalPathInZOrder(hierarchyBuilder.getHierarchy()), expectedTraversalPath);
    expectedTraversalPath = {};
    EXPECT_EQ(getTraversalPath(hierarchyBuilder.getOffscreenHierarchy()), expectedTraversalPath);
}

} // namespace android::surfaceflinger::frontend
