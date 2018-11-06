#include <bufferhub/BufferNode.h>
#include <errno.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ui/GraphicBufferMapper.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

namespace {

using testing::NotNull;

const uint32_t kWidth = 640;
const uint32_t kHeight = 480;
const uint32_t kLayerCount = 1;
const uint32_t kFormat = 1;
const uint64_t kUsage = 0;
const size_t kUserMetadataSize = 0;
const size_t kMaxClientsCount = dvr::BufferHubDefs::kMaxNumberOfClients;

class BufferNodeTest : public ::testing::Test {
protected:
    void SetUp() override {
        buffer_node =
                new BufferNode(kWidth, kHeight, kLayerCount, kFormat, kUsage, kUserMetadataSize);
        ASSERT_TRUE(buffer_node->IsValid());
    }

    void TearDown() override {
        if (buffer_node != nullptr) {
            delete buffer_node;
        }
    }

    BufferNode* buffer_node = nullptr;
};

TEST_F(BufferNodeTest, TestCreateBufferNode) {
    EXPECT_EQ(buffer_node->user_metadata_size(), kUserMetadataSize);
    // Test the handle just allocated is good (i.e. able to be imported)
    GraphicBufferMapper& mapper = GraphicBufferMapper::get();
    const native_handle_t* outHandle;
    status_t ret =
            mapper.importBuffer(buffer_node->buffer_handle(), buffer_node->buffer_desc().width,
                                buffer_node->buffer_desc().height,
                                buffer_node->buffer_desc().layers,
                                buffer_node->buffer_desc().format, buffer_node->buffer_desc().usage,
                                buffer_node->buffer_desc().stride, &outHandle);
    EXPECT_EQ(ret, OK);
    EXPECT_THAT(outHandle, NotNull());
}

TEST_F(BufferNodeTest, TestAddNewActiveClientsBitToMask_twoNewClients) {
    uint64_t new_client_state_mask_1 = buffer_node->AddNewActiveClientsBitToMask();
    EXPECT_EQ(buffer_node->GetActiveClientsBitMask(), new_client_state_mask_1);

    // Request and add a new client_state_mask again.
    // Active clients bit mask should be the union of the two new
    // client_state_masks.
    uint64_t new_client_state_mask_2 = buffer_node->AddNewActiveClientsBitToMask();
    EXPECT_EQ(buffer_node->GetActiveClientsBitMask(),
              new_client_state_mask_1 | new_client_state_mask_2);
}

TEST_F(BufferNodeTest, TestAddNewActiveClientsBitToMask_32NewClients) {
    uint64_t new_client_state_mask = 0ULL;
    uint64_t current_mask = 0ULL;
    uint64_t expected_mask = 0ULL;

    for (int i = 0; i < kMaxClientsCount; ++i) {
        new_client_state_mask = buffer_node->AddNewActiveClientsBitToMask();
        EXPECT_NE(new_client_state_mask, 0);
        EXPECT_FALSE(new_client_state_mask & current_mask);
        expected_mask = current_mask | new_client_state_mask;
        current_mask = buffer_node->GetActiveClientsBitMask();
        EXPECT_EQ(current_mask, expected_mask);
    }

    // Method should fail upon requesting for more than maximum allowable clients.
    new_client_state_mask = buffer_node->AddNewActiveClientsBitToMask();
    EXPECT_EQ(new_client_state_mask, 0ULL);
    EXPECT_EQ(errno, E2BIG);
}

TEST_F(BufferNodeTest, TestRemoveActiveClientsBitFromMask) {
    buffer_node->AddNewActiveClientsBitToMask();
    uint64_t current_mask = buffer_node->GetActiveClientsBitMask();
    uint64_t new_client_state_mask = buffer_node->AddNewActiveClientsBitToMask();
    EXPECT_NE(buffer_node->GetActiveClientsBitMask(), current_mask);

    buffer_node->RemoveClientsBitFromMask(new_client_state_mask);
    EXPECT_EQ(buffer_node->GetActiveClientsBitMask(), current_mask);

    // Remove the test_mask again to the active client bit mask should not modify
    // the value of active clients bit mask.
    buffer_node->RemoveClientsBitFromMask(new_client_state_mask);
    EXPECT_EQ(buffer_node->GetActiveClientsBitMask(), current_mask);
}

} // namespace

} // namespace implementation
} // namespace V1_0
} // namespace bufferhub
} // namespace frameworks
} // namespace android
