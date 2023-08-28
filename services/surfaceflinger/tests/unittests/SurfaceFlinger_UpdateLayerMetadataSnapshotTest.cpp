#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/LayerMetadata.h>

#include "TestableSurfaceFlinger.h"

namespace android {

using testing::_;
using testing::Return;

class SurfaceFlingerUpdateLayerMetadataSnapshotTest : public testing::Test {
public:
    SurfaceFlingerUpdateLayerMetadataSnapshotTest() { mFlinger.setupMockScheduler(); }

protected:
    sp<Layer> createLayer(const char* name, LayerMetadata& inOutlayerMetadata) {
        LayerCreationArgs args =
                LayerCreationArgs{mFlinger.flinger(), nullptr, name, 0, inOutlayerMetadata};
        inOutlayerMetadata = args.metadata;
        return sp<Layer>::make(args);
    }

    TestableSurfaceFlinger mFlinger;
};

class LayerMetadataBuilder {
public:
    LayerMetadataBuilder(LayerMetadata layerMetadata = {}) : mLayerMetadata(layerMetadata) {}

    LayerMetadataBuilder& setInt32(uint32_t key, int32_t value) {
        mLayerMetadata.setInt32(key, value);
        return *this;
    }

    LayerMetadata build() { return mLayerMetadata; }

private:
    LayerMetadata mLayerMetadata;
};

bool operator==(const LayerMetadata& lhs, const LayerMetadata& rhs) {
    return lhs.mMap == rhs.mMap;
}

std::ostream& operator<<(std::ostream& stream, const LayerMetadata& layerMetadata) {
    stream << "LayerMetadata{";
    for (auto it = layerMetadata.mMap.cbegin(); it != layerMetadata.mMap.cend(); it++) {
        if (it != layerMetadata.mMap.cbegin()) {
            stream << ", ";
        }
        stream << layerMetadata.itemToString(it->first, ":");
    }
    return stream << "}";
}

// Test that the snapshot's layer metadata is set.
TEST_F(SurfaceFlingerUpdateLayerMetadataSnapshotTest, updatesSnapshotMetadata) {
    auto layerMetadata = LayerMetadataBuilder().setInt32(METADATA_TASK_ID, 1).build();
    auto layer = createLayer("layer", layerMetadata);
    mFlinger.mutableDrawingState().layersSortedByZ.add(layer);

    mFlinger.updateLayerMetadataSnapshot();

    EXPECT_EQ(layer->getLayerSnapshot()->layerMetadata, layerMetadata);
}

// Test that snapshot layer metadata is set by merging the child's metadata on top of its
// parent's metadata.
TEST_F(SurfaceFlingerUpdateLayerMetadataSnapshotTest, mergesSnapshotMetadata) {
    auto layerAMetadata = LayerMetadataBuilder()
                                  .setInt32(METADATA_OWNER_UID, 1)
                                  .setInt32(METADATA_TASK_ID, 2)
                                  .build();
    auto layerA = createLayer("parent", layerAMetadata);
    auto layerBMetadata = LayerMetadataBuilder().setInt32(METADATA_TASK_ID, 3).build();
    auto layerB = createLayer("child", layerBMetadata);
    layerA->addChild(layerB);
    layerA->commitChildList();
    mFlinger.mutableDrawingState().layersSortedByZ.add(layerA);

    mFlinger.updateLayerMetadataSnapshot();

    EXPECT_EQ(layerA->getLayerSnapshot()->layerMetadata, layerAMetadata);
    auto expectedChildMetadata =
            LayerMetadataBuilder(layerAMetadata).setInt32(METADATA_TASK_ID, 3).build();
    EXPECT_EQ(layerB->getLayerSnapshot()->layerMetadata, expectedChildMetadata);
}

// Test that snapshot relative layer metadata is set to the parent's layer metadata merged on top of
// that parent's relative layer metadata.
TEST_F(SurfaceFlingerUpdateLayerMetadataSnapshotTest, updatesRelativeMetadata) {
    auto layerAMetadata = LayerMetadataBuilder().setInt32(METADATA_TASK_ID, 1).build();
    auto layerA = createLayer("relative-parent", layerAMetadata);
    auto layerAHandle = layerA->getHandle();
    auto layerBMetadata = LayerMetadataBuilder().setInt32(METADATA_TASK_ID, 2).build();
    auto layerB = createLayer("relative-child", layerBMetadata);
    layerB->setRelativeLayer(layerAHandle, 1);
    mFlinger.mutableDrawingState().layersSortedByZ.add(layerA);
    mFlinger.mutableDrawingState().layersSortedByZ.add(layerB);

    mFlinger.updateLayerMetadataSnapshot();

    EXPECT_EQ(layerA->getLayerSnapshot()->relativeLayerMetadata, LayerMetadata{});
    EXPECT_EQ(layerB->getLayerSnapshot()->relativeLayerMetadata, layerAMetadata);
}

// Test that snapshot relative layer metadata is set correctly when a layer is interleaved within
// two other layers.
//
// Layer
//      A
//     / \
//    B   D
//   /
//  C
//
// Z-order Relatives
//    B <- D <- C
TEST_F(SurfaceFlingerUpdateLayerMetadataSnapshotTest, updatesRelativeMetadataInterleaved) {
    auto layerAMetadata = LayerMetadataBuilder().setInt32(METADATA_OWNER_UID, 1).build();
    auto layerA = createLayer("layer-a", layerAMetadata);
    auto layerBMetadata = LayerMetadataBuilder()
                                  .setInt32(METADATA_TASK_ID, 2)
                                  .setInt32(METADATA_OWNER_PID, 3)
                                  .build();
    auto layerB = createLayer("layer-b", layerBMetadata);
    auto layerBHandle = layerB->getHandle();
    LayerMetadata layerCMetadata;
    auto layerC = createLayer("layer-c", layerCMetadata);
    auto layerDMetadata = LayerMetadataBuilder().setInt32(METADATA_TASK_ID, 4).build();
    auto layerD = createLayer("layer-d", layerDMetadata);
    auto layerDHandle = layerD->getHandle();
    layerB->addChild(layerC);
    layerA->addChild(layerB);
    layerA->addChild(layerD);
    layerC->setRelativeLayer(layerDHandle, 1);
    layerD->setRelativeLayer(layerBHandle, 1);
    layerA->commitChildList();
    mFlinger.mutableDrawingState().layersSortedByZ.add(layerA);

    mFlinger.updateLayerMetadataSnapshot();

    auto expectedLayerDRelativeMetadata =
            LayerMetadataBuilder()
                    // From layer A, parent of relative parent
                    .setInt32(METADATA_OWNER_UID, 1)
                    // From layer B, relative parent
                    .setInt32(METADATA_TASK_ID, 2)
                    .setInt32(METADATA_OWNER_PID, 3)
                    // added by layer creation args
                    .setInt32(gui::METADATA_CALLING_UID,
                              layerDMetadata.getInt32(gui::METADATA_CALLING_UID, 0))
                    .build();
    EXPECT_EQ(layerD->getLayerSnapshot()->relativeLayerMetadata, expectedLayerDRelativeMetadata);
    auto expectedLayerCRelativeMetadata =
            LayerMetadataBuilder()
                    // From layer A, parent of relative parent
                    .setInt32(METADATA_OWNER_UID, 1)
                    // From layer B, relative parent of relative parent
                    .setInt32(METADATA_OWNER_PID, 3)
                    // From layer D, relative parent
                    .setInt32(METADATA_TASK_ID, 4)
                    // added by layer creation args
                    .setInt32(gui::METADATA_CALLING_UID,
                              layerDMetadata.getInt32(gui::METADATA_CALLING_UID, 0))
                    .build();
    EXPECT_EQ(layerC->getLayerSnapshot()->relativeLayerMetadata, expectedLayerCRelativeMetadata);
}

TEST_F(SurfaceFlingerUpdateLayerMetadataSnapshotTest,
       updatesRelativeMetadataMultipleRelativeChildren) {
    auto layerAMetadata = LayerMetadataBuilder().setInt32(METADATA_OWNER_UID, 1).build();
    auto layerA = createLayer("layer-a", layerAMetadata);
    auto layerAHandle = layerA->getHandle();
    LayerMetadata layerBMetadata;
    auto layerB = createLayer("layer-b", layerBMetadata);
    LayerMetadata layerCMetadata;
    auto layerC = createLayer("layer-c", layerCMetadata);
    layerB->setRelativeLayer(layerAHandle, 1);
    layerC->setRelativeLayer(layerAHandle, 2);
    layerA->commitChildList();
    mFlinger.mutableDrawingState().layersSortedByZ.add(layerA);
    mFlinger.mutableDrawingState().layersSortedByZ.add(layerB);
    mFlinger.mutableDrawingState().layersSortedByZ.add(layerC);

    mFlinger.updateLayerMetadataSnapshot();

    EXPECT_EQ(layerA->getLayerSnapshot()->relativeLayerMetadata, LayerMetadata{});
    EXPECT_EQ(layerB->getLayerSnapshot()->relativeLayerMetadata, layerAMetadata);
    EXPECT_EQ(layerC->getLayerSnapshot()->relativeLayerMetadata, layerAMetadata);
}

} // namespace android
