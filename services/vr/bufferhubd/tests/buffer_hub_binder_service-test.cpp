#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <private/dvr/buffer_hub_binder.h>

namespace android {
namespace dvr {

namespace {

using testing::Ne;

class BufferHubBinderServiceTest : public ::testing::Test {
  // Add setup and teardown if necessary
};

TEST_F(BufferHubBinderServiceTest, TestInitialize) {
  // Create a new service will kill the current one.
  // So just check if Binder service is running
  sp<IBufferHub> service = BufferHubBinderService::getServiceProxy();
  EXPECT_THAT(service, Ne(nullptr));
}

}  // namespace

}  // namespace dvr
}  // namespace android