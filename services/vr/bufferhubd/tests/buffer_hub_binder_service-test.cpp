#include <binder/IServiceManager.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <private/dvr/IBufferClient.h>
#include <private/dvr/IBufferHub.h>
#include <ui/PixelFormat.h>

namespace android {
namespace dvr {

namespace {

using testing::NotNull;

const int kWidth = 640;
const int kHeight = 480;
const int kLayerCount = 1;
const int kFormat = HAL_PIXEL_FORMAT_RGBA_8888;
const int kUsage = 0;
const size_t kUserMetadataSize = 0;

class BufferHubBinderServiceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    status_t ret = getService<IBufferHub>(
        String16(IBufferHub::getServiceName()), &service);
    ASSERT_EQ(ret, OK);
    ASSERT_THAT(service, NotNull());
  }

  sp<IBufferHub> service;
};

TEST_F(BufferHubBinderServiceTest, TestCreateBuffer) {
  sp<IBufferClient> bufferClient = service->createBuffer(
      kWidth, kHeight, kLayerCount, kFormat, kUsage, kUserMetadataSize);
  ASSERT_THAT(bufferClient, NotNull());
  EXPECT_TRUE(bufferClient->isValid());
}

TEST_F(BufferHubBinderServiceTest, TestDuplicateBuffer) {
  sp<IBufferClient> bufferClient = service->createBuffer(
      kWidth, kHeight, kLayerCount, kFormat, kUsage, kUserMetadataSize);
  EXPECT_THAT(bufferClient, NotNull());
  EXPECT_TRUE(bufferClient->isValid());

  uint64_t token1 = 0ULL;
  status_t ret = bufferClient->duplicate(&token1);
  EXPECT_EQ(ret, NO_ERROR);

  // Should be different
  uint64_t token2 = 0ULL;
  ret = bufferClient->duplicate(&token2);
  EXPECT_EQ(ret, NO_ERROR);
  EXPECT_NE(token2, token1);
}

}  // namespace

}  // namespace dvr
}  // namespace android