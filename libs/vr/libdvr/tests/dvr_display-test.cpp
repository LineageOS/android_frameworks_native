#include <android/hardware_buffer.h>
#include <android/log.h>
#include <dlfcn.h>
#include <dvr/dvr_api.h>
#include <dvr/dvr_display_types.h>
#include <dvr/dvr_surface.h>

#include <gtest/gtest.h>

#define LOG_TAG "dvr_display-test"

#ifndef ALOGD
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif

#define ASSERT_NOT_NULL(x) ASSERT_TRUE((x) != nullptr)

class DvrDisplayTest : public ::testing::Test {
 protected:
  void SetUp() override {
    int flags = RTLD_NOW | RTLD_LOCAL;

    // Here we need to ensure that libdvr is loaded with RTLD_NODELETE flag set
    // (so that calls to `dlclose` don't actually unload the library). This is a
    // workaround for an Android NDK bug. See more detail:
    // https://github.com/android-ndk/ndk/issues/360
    flags |= RTLD_NODELETE;
    platform_handle_ = dlopen("libdvr.so", flags);
    ASSERT_NOT_NULL(platform_handle_) << "Dvr shared library missing.";

    auto dvr_get_api = reinterpret_cast<decltype(&dvrGetApi)>(
        dlsym(platform_handle_, "dvrGetApi"));
    ASSERT_NOT_NULL(dvr_get_api) << "Platform library missing dvrGetApi.";

    ASSERT_EQ(dvr_get_api(&api_, sizeof(api_), /*version=*/1), 0)
        << "Unable to find compatible Dvr API.";
  }

  void TearDown() override {
    if (write_queue_ != nullptr) {
      api_.WriteBufferQueueDestroy(write_queue_);
      write_queue_ = nullptr;
    }
    if (platform_handle_ != nullptr) {
      dlclose(platform_handle_);
    }
  }

  void* platform_handle_ = nullptr;
  DvrApi_v1 api_;
  DvrWriteBufferQueue* write_queue_ = nullptr;
};

TEST_F(DvrDisplayTest, DisplaySingleColor) {
  // Create direct surface.
  DvrSurface* direct_surface = nullptr;
  std::vector<DvrSurfaceAttribute> direct_surface_attributes = {
      {.key = DVR_SURFACE_ATTRIBUTE_DIRECT,
       .value.type = DVR_SURFACE_ATTRIBUTE_TYPE_BOOL,
       .value.bool_value = true},
      {.key = DVR_SURFACE_ATTRIBUTE_Z_ORDER,
       .value.type = DVR_SURFACE_ATTRIBUTE_TYPE_INT32,
       .value.int32_value = 10},
      {.key = DVR_SURFACE_ATTRIBUTE_VISIBLE,
       .value.type = DVR_SURFACE_ATTRIBUTE_TYPE_BOOL,
       .value.bool_value = true},
  };
  int ret =
      api_.SurfaceCreate(direct_surface_attributes.data(),
                         direct_surface_attributes.size(), &direct_surface);
  ASSERT_EQ(ret, 0) << "Failed to create direct surface.";

  // Get screen dimension.
  DvrNativeDisplayMetrics display_metrics;
  ret = api_.GetNativeDisplayMetrics(sizeof(display_metrics), &display_metrics);
  ASSERT_EQ(ret, 0) << "Failed to get display metrics.";
  ALOGD(
      "display_width: %d, display_height: %d, display_x_dpi: %d, "
      "display_y_dpi: %d, vsync_period_ns: %d.",
      display_metrics.display_width, display_metrics.display_height,
      display_metrics.display_x_dpi, display_metrics.display_y_dpi,
      display_metrics.vsync_period_ns);

  // Create a buffer queue with the direct surface.
  constexpr uint32_t kLayerCount = 1;
  constexpr uint64_t kUsage = AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                              AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT |
                              AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN;
  constexpr uint32_t kFormat = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM;
  constexpr size_t kCapacity = 1;
  constexpr size_t kMetadataSize = 0;
  uint32_t width = display_metrics.display_width;
  uint32_t height = display_metrics.display_height;
  ret = api_.SurfaceCreateWriteBufferQueue(
      direct_surface, width, height, kFormat, kLayerCount, kUsage, kCapacity,
      kMetadataSize, &write_queue_);
  EXPECT_EQ(0, ret) << "Failed to create buffer queue.";
  ASSERT_NOT_NULL(write_queue_) << "Write buffer queue should not be null.";

  // Get buffer from WriteBufferQueue.
  DvrWriteBuffer* write_buffer = nullptr;
  constexpr int kTimeoutMs = 1000;
  DvrNativeBufferMetadata out_meta;
  int out_fence_fd = -1;
  ret = api_.WriteBufferQueueGainBuffer(write_queue_, kTimeoutMs, &write_buffer,
                                        &out_meta, &out_fence_fd);
  EXPECT_EQ(0, ret) << "Failed to get the buffer.";
  ASSERT_NOT_NULL(write_buffer) << "Gained buffer should not be null.";

  // Convert to an android hardware buffer.
  AHardwareBuffer* ah_buffer{nullptr};
  ret = api_.WriteBufferGetAHardwareBuffer(write_buffer, &ah_buffer);
  EXPECT_EQ(0, ret) << "Failed to get a hardware buffer from the write buffer.";
  ASSERT_NOT_NULL(ah_buffer) << "AHardware buffer should not be null.";

  // Change the content of the android hardware buffer.
  void* buffer_data{nullptr};
  int32_t fence = -1;
  ret = AHardwareBuffer_lock(ah_buffer, AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
                             fence, nullptr, &buffer_data);
  EXPECT_EQ(0, ret) << "Failed to lock the hardware buffer.";
  ASSERT_NOT_NULL(buffer_data) << "Buffer data should not be null.";

  uint32_t color_texture = 0xff0000ff;  // Red color in RGBA.
  for (uint32_t i = 0; i < width * height; ++i) {
    memcpy(reinterpret_cast<void*>(reinterpret_cast<int64_t>(buffer_data) +
                                   i * sizeof(color_texture)),
           &color_texture, sizeof(color_texture));
  }

  fence = -1;
  ret = AHardwareBuffer_unlock(ah_buffer, &fence);
  EXPECT_EQ(0, ret) << "Failed to unlock the hardware buffer.";

  // Release the android hardware buffer.
  AHardwareBuffer_release(ah_buffer);

  // Post buffer.
  int ready_fence_fd = -1;
  ret = api_.WriteBufferQueuePostBuffer(write_queue_, write_buffer, &out_meta,
                                        ready_fence_fd);
  EXPECT_EQ(0, ret) << "Failed to post the buffer.";

  sleep(5);  // For visual check on the device under test.
}
