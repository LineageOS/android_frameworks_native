#include <private/dvr/buffer_hub_binder.h>

#include <gtest/gtest.h>

namespace android {
namespace dvr {

namespace {

class BufferHubBinderServiceTest : public ::testing::Test {
  // Add setup and teardown if necessary
};

TEST_F(BufferHubBinderServiceTest, TestInitialize) {
  // Test if start binder server returns OK
  EXPECT_EQ(BufferHubBinderService::start(), OK);
}

}  // namespace

}  // namespace dvr
}  // namespace android