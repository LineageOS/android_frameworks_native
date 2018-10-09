#include <binder/IServiceManager.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <private/dvr/buffer_hub_binder.h>

namespace android {
namespace dvr {

namespace {

class BufferHubBinderServiceTest : public ::testing::Test {
  // Add setup and teardown if necessary
};

TEST_F(BufferHubBinderServiceTest, TestInitialize) {
  // Create a new service will kill the current one.
  // So just check if Binder service is running
  sp<IServiceManager> sm = defaultServiceManager();
  sp<IBinder> service =
      sm->checkService(String16(BufferHubBinderService::getServiceName()));
  EXPECT_THAT(service, ::testing::Ne(nullptr));
}

}  // namespace

}  // namespace dvr
}  // namespace android