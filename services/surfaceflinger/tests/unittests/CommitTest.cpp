/*
 * Copyright 2023 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "CommitTest"

#include <DisplayHardware/HWComposer.h>
#include <FrontEnd/LayerCreationArgs.h>
#include <FrontEnd/RequestedLayerState.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/Feature.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/LayerMetadata.h>
#include <gui/SurfaceComposerClient.h>
#include <mock/DisplayHardware/MockComposer.h>
#include <renderengine/mock/RenderEngine.h>
#include "TestableSurfaceFlinger.h"

namespace android {

class CommitTest : public testing::Test {
protected:
    TestableSurfaceFlinger mFlinger;
    renderengine::mock::RenderEngine* mRenderEngine = new renderengine::mock::RenderEngine();

    void flinger_setup() {
        mFlinger.setupMockScheduler();
        mFlinger.setupComposer(std::make_unique<Hwc2::mock::Composer>());
        mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
    }

    LayerCreationArgs createArgs(uint32_t id, LayerMetadata metadata, uint32_t parentId) {
        LayerCreationArgs args(mFlinger.flinger(), nullptr, "layer",
                               gui::ISurfaceComposerClient::eNoColorFill, metadata, id);
        args.parentId = parentId;
        return args;
    }
};

namespace {

TEST_F(CommitTest, noUpdatesDoesNotScheduleComposite) {
    flinger_setup();
    bool unused;
    bool mustComposite = mFlinger.updateLayerSnapshots(VsyncId{1}, /*frameTimeNs=*/0,
                                                       /*transactionsFlushed=*/0, unused);
    EXPECT_FALSE(mustComposite);
}

// Ensure that we handle eTransactionNeeded correctly
TEST_F(CommitTest, eTransactionNeededFlagSchedulesComposite) {
    flinger_setup();
    // update display level color matrix
    mFlinger.setDaltonizerType(ColorBlindnessType::Deuteranomaly);
    bool unused;
    bool mustComposite = mFlinger.updateLayerSnapshots(VsyncId{1}, /*frameTimeNs=*/0,
                                                       /*transactionsFlushed=*/0, unused);
    EXPECT_TRUE(mustComposite);
}

TEST_F(CommitTest, metadataNotIncluded) {
    mFlinger.setupMockScheduler();
    mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
    compositionengine::mock::CompositionEngine* mCompositionEngine =
            new compositionengine::mock::CompositionEngine();

    // CompositionEngine setup with unset flag
    compositionengine::FeatureFlags flags;
    impl::HWComposer hwc = impl::HWComposer(std::make_unique<Hwc2::mock::Composer>());

    EXPECT_CALL(*mCompositionEngine, getFeatureFlags).WillOnce(testing::Return(flags));
    EXPECT_THAT(flags.test(compositionengine::Feature::kSnapshotLayerMetadata), false);

    EXPECT_CALL(*mCompositionEngine, getHwComposer).WillOnce(testing::ReturnRef(hwc));

    mFlinger.setupCompositionEngine(
            std::unique_ptr<compositionengine::CompositionEngine>(mCompositionEngine));

    // Create a parent layer with metadata and a child layer without. Metadata should not
    // be included in the child layer when the flag is not set.
    std::unordered_map<uint32_t, std::vector<uint8_t>> metadata = {{1, {'a', 'b'}}};
    auto parentArgs = createArgs(1, LayerMetadata(metadata), UNASSIGNED_LAYER_ID);
    auto parent = std::make_unique<frontend::RequestedLayerState>(parentArgs);
    mFlinger.addLayer(parent);
    mFlinger.injectLegacyLayer(sp<Layer>::make(parentArgs));

    auto childArgs = createArgs(11, LayerMetadata(), 1);
    auto child = std::make_unique<frontend::RequestedLayerState>(childArgs);
    mFlinger.addLayer(child);
    mFlinger.injectLegacyLayer(sp<Layer>::make(childArgs));

    bool unused;
    bool mustComposite = mFlinger.updateLayerSnapshots(VsyncId{1}, /*frameTimeNs=*/0,
                                                       /*transactionsFlushed=*/1, unused);
    EXPECT_TRUE(mustComposite);

    auto parentMetadata = mFlinger.mutableLayerSnapshotBuilder().getSnapshot(1)->layerMetadata.mMap;
    auto childMetadata = mFlinger.mutableLayerSnapshotBuilder().getSnapshot(11)->layerMetadata.mMap;

    EXPECT_EQ(metadata.at(1), parentMetadata.at(1));
    EXPECT_NE(parentMetadata, childMetadata);
}

TEST_F(CommitTest, metadataIsIncluded) {
    mFlinger.setupMockScheduler();
    mFlinger.setupRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
    compositionengine::mock::CompositionEngine* mCompositionEngine =
            new compositionengine::mock::CompositionEngine();

    // CompositionEngine setup with set flag
    compositionengine::FeatureFlags flags;
    flags |= compositionengine::Feature::kSnapshotLayerMetadata;
    impl::HWComposer hwc = impl::HWComposer(std::make_unique<Hwc2::mock::Composer>());

    EXPECT_CALL(*mCompositionEngine, getFeatureFlags).WillOnce(testing::Return(flags));
    EXPECT_THAT(flags.test(compositionengine::Feature::kSnapshotLayerMetadata), true);

    EXPECT_CALL(*mCompositionEngine, getHwComposer).WillOnce(testing::ReturnRef(hwc));

    mFlinger.setupCompositionEngine(
            std::unique_ptr<compositionengine::CompositionEngine>(mCompositionEngine));

    // Create a parent layer with metadata and a child layer without. Metadata from the
    // parent should be included in the child layer when the flag is set.
    std::unordered_map<uint32_t, std::vector<uint8_t>> metadata = {{1, {'a', 'b'}}};
    auto parentArgs = createArgs(1, LayerMetadata(metadata), UNASSIGNED_LAYER_ID);
    auto parent = std::make_unique<frontend::RequestedLayerState>(parentArgs);
    mFlinger.addLayer(parent);
    mFlinger.injectLegacyLayer(sp<Layer>::make(parentArgs));

    auto childArgs = createArgs(11, LayerMetadata(), 1);
    auto child = std::make_unique<frontend::RequestedLayerState>(childArgs);
    mFlinger.addLayer(child);
    mFlinger.injectLegacyLayer(sp<Layer>::make(childArgs));

    bool unused;
    bool mustComposite = mFlinger.updateLayerSnapshots(VsyncId{1}, /*frameTimeNs=*/0,
                                                       /*transactionsFlushed=*/1, unused);
    EXPECT_TRUE(mustComposite);

    auto parentMetadata = mFlinger.mutableLayerSnapshotBuilder().getSnapshot(1)->layerMetadata.mMap;
    auto childMetadata = mFlinger.mutableLayerSnapshotBuilder().getSnapshot(11)->layerMetadata.mMap;

    EXPECT_EQ(metadata.at(1), parentMetadata.at(1));
    EXPECT_EQ(parentMetadata, childMetadata);
}

} // namespace
} // namespace android
