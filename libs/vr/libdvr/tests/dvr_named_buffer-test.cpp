#include <android/hardware_buffer.h>
#include <dvr/display_manager_client.h>
#include <dvr/dvr_buffer.h>
#include <dvr/dvr_surface.h>
#include <system/graphics.h>

#include <base/logging.h>
#include <gtest/gtest.h>

namespace android {
namespace dvr {

namespace {

class DvrNamedBufferTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = dvrDisplayManagerClientCreate();
    ASSERT_NE(nullptr, client_);
  }

  void TearDown() override {
    if (client_ != nullptr) {
      dvrDisplayManagerClientDestroy(client_);
      client_ = nullptr;
    }
  }

  DvrDisplayManagerClient* client_ = nullptr;
};

TEST_F(DvrNamedBufferTest, TestNamedBuffersSameName) {
  const char* buffer_name = "same_name";
  DvrBuffer* buffer1 =
      dvrDisplayManagerSetupNamedBuffer(client_, buffer_name, 10, 0, 0);
  ASSERT_NE(nullptr, buffer1);

  DvrBuffer* buffer2 =
      dvrDisplayManagerSetupNamedBuffer(client_, buffer_name, 10, 0, 0);
  ASSERT_NE(nullptr, buffer2);

  AHardwareBuffer* hardware_buffer1 = nullptr;
  int e1 = dvrBufferGetAHardwareBuffer(buffer1, &hardware_buffer1);
  ASSERT_EQ(0, e1);

  AHardwareBuffer* hardware_buffer2 = nullptr;
  int e2 = dvrBufferGetAHardwareBuffer(buffer2, &hardware_buffer2);
  ASSERT_EQ(0, e2);
  ASSERT_NE(nullptr, hardware_buffer1);

  AHardwareBuffer_Desc desc1 = {};
  AHardwareBuffer_describe(hardware_buffer1, &desc1);
  AHardwareBuffer_Desc desc2 = {};
  AHardwareBuffer_describe(hardware_buffer2, &desc2);
  ASSERT_EQ(desc1.width, 10u);
  ASSERT_EQ(desc1.height, 1u);
  ASSERT_EQ(desc1.layers, 1u);
  ASSERT_EQ(desc1.format, HAL_PIXEL_FORMAT_BLOB);
  ASSERT_EQ(desc1.usage0, 0u);
  ASSERT_EQ(desc1.usage1, 0u);
  ASSERT_EQ(desc2.width, 10u);
  ASSERT_EQ(desc2.height, 1u);
  ASSERT_EQ(desc2.layers, 1u);
  ASSERT_EQ(desc2.format, HAL_PIXEL_FORMAT_BLOB);
  ASSERT_EQ(desc2.usage0, 0u);
  ASSERT_EQ(desc2.usage1, 0u);

  dvrBufferDestroy(buffer1);
  dvrBufferDestroy(buffer2);

  DvrBuffer* buffer3 = nullptr;
  int e3 = dvrGetNamedBuffer(buffer_name, &buffer3);
  ASSERT_NE(nullptr, buffer3);
  ASSERT_EQ(0, e3);

  AHardwareBuffer* hardware_buffer3 = nullptr;
  int e4 = dvrBufferGetAHardwareBuffer(buffer2, &hardware_buffer3);
  ASSERT_EQ(0, e4);
  ASSERT_NE(nullptr, hardware_buffer3);

  AHardwareBuffer_Desc desc3 = {};
  AHardwareBuffer_describe(hardware_buffer3, &desc3);
  ASSERT_EQ(desc3.width, 10u);
  ASSERT_EQ(desc3.height, 1u);
  ASSERT_EQ(desc3.layers, 1u);
  ASSERT_EQ(desc3.format, HAL_PIXEL_FORMAT_BLOB);
  ASSERT_EQ(desc3.usage0, 0u);
  ASSERT_EQ(desc3.usage1, 0u);

  dvrBufferDestroy(buffer3);
}

TEST_F(DvrNamedBufferTest, TestMultipleNamedBuffers) {
  const char* buffer_name1 = "test1";
  const char* buffer_name2 = "test2";
  DvrBuffer* setup_buffer1 =
      dvrDisplayManagerSetupNamedBuffer(client_, buffer_name1, 10, 0, 0);
  ASSERT_NE(nullptr, setup_buffer1);
  dvrBufferDestroy(setup_buffer1);

  DvrBuffer* setup_buffer2 =
      dvrDisplayManagerSetupNamedBuffer(client_, buffer_name2, 10, 0, 0);
  ASSERT_NE(nullptr, setup_buffer2);
  dvrBufferDestroy(setup_buffer2);

  DvrBuffer* buffer1 = nullptr;
  int e1 = dvrGetNamedBuffer(buffer_name1, &buffer1);
  ASSERT_NE(nullptr, buffer1);
  ASSERT_EQ(0, e1);
  dvrBufferDestroy(buffer1);

  DvrBuffer* buffer2 = nullptr;
  int e2 = dvrGetNamedBuffer(buffer_name2, &buffer2);
  ASSERT_NE(nullptr, buffer2);
  ASSERT_EQ(0, e2);
  dvrBufferDestroy(buffer2);
}

}  // namespace

}  // namespace dvr
}  // namespace android
