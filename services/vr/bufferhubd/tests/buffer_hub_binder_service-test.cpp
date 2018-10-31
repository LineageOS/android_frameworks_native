#include <binder/IServiceManager.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <private/dvr/IBufferClient.h>
#include <private/dvr/IBufferHub.h>
#include <ui/PixelFormat.h>

namespace android {
namespace dvr {

namespace {

using testing::IsNull;
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

TEST_F(BufferHubBinderServiceTest, TestDuplicateAndImportBuffer) {
  sp<IBufferClient> bufferClient = service->createBuffer(
      kWidth, kHeight, kLayerCount, kFormat, kUsage, kUserMetadataSize);
  ASSERT_THAT(bufferClient, NotNull());
  EXPECT_TRUE(bufferClient->isValid());

  uint64_t token1 = 0ULL;
  status_t ret = bufferClient->duplicate(&token1);
  EXPECT_EQ(ret, NO_ERROR);

  // Tokens should be unique even corresponding to the same buffer
  uint64_t token2 = 0ULL;
  ret = bufferClient->duplicate(&token2);
  EXPECT_EQ(ret, NO_ERROR);
  EXPECT_NE(token2, token1);

  sp<IBufferClient> bufferClient1;
  ret = service->importBuffer(token1, &bufferClient1);
  EXPECT_EQ(ret, NO_ERROR);
  ASSERT_THAT(bufferClient1, NotNull());
  EXPECT_TRUE(bufferClient1->isValid());

  // Consumes the token to keep the service clean
  sp<IBufferClient> bufferClient2;
  ret = service->importBuffer(token2, &bufferClient2);
  EXPECT_EQ(ret, NO_ERROR);
  ASSERT_THAT(bufferClient2, NotNull());
  EXPECT_TRUE(bufferClient2->isValid());
}

TEST_F(BufferHubBinderServiceTest, TestImportUnexistingToken) {
  // There is very little chance that this test fails if there is a token = 0
  // in the service.
  uint64_t unexistingToken = 0ULL;
  sp<IBufferClient> bufferClient;
  status_t ret = service->importBuffer(unexistingToken, &bufferClient);
  EXPECT_EQ(ret, PERMISSION_DENIED);
  EXPECT_THAT(bufferClient, IsNull());
}

}  // namespace

}  // namespace dvr
}  // namespace android