#include <dvr/dvr_api.h>
#include <dvr/dvr_buffer_queue.h>
#include <gui/Surface.h>
#include <private/dvr/buffer_hub_queue_client.h>

#include <base/logging.h>
#include <gtest/gtest.h>

#include "../dvr_internal.h"
#include "../dvr_buffer_queue_internal.h"

namespace android {
namespace dvr {

namespace {

static constexpr uint32_t kBufferWidth = 100;
static constexpr uint32_t kBufferHeight = 1;
static constexpr uint32_t kLayerCount = 1;
static constexpr uint32_t kBufferFormat = HAL_PIXEL_FORMAT_BLOB;
static constexpr uint64_t kBufferUsage = GRALLOC_USAGE_SW_READ_RARELY;
static constexpr size_t kQueueCapacity = 3;

typedef uint64_t TestMeta;

class DvrBufferQueueTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto config = ProducerQueueConfigBuilder()
                      .SetDefaultWidth(kBufferWidth)
                      .SetDefaultHeight(kBufferHeight)
                      .SetDefaultFormat(kBufferFormat)
                      .SetMetadata<TestMeta>()
                      .Build();
    write_queue_ =
        new DvrWriteBufferQueue(ProducerQueue::Create(config, UsagePolicy{}));
    ASSERT_NE(nullptr, write_queue_);
  }

  void TearDown() override {
    if (write_queue_ != nullptr) {
      dvrWriteBufferQueueDestroy(write_queue_);
      write_queue_ = nullptr;
    }
  }

  void AllocateBuffers(size_t buffer_count) {
    size_t out_slot;
    for (size_t i = 0; i < buffer_count; i++) {
      auto status = write_queue_->producer_queue()->AllocateBuffer(
          kBufferWidth, kBufferHeight, kLayerCount, kBufferFormat, kBufferUsage,
          &out_slot);
      ASSERT_TRUE(status.ok());
    }
  }

  DvrWriteBufferQueue* write_queue_{nullptr};
};

TEST_F(DvrBufferQueueTest, TestWrite_QueueDestroy) {
  dvrWriteBufferQueueDestroy(write_queue_);
  write_queue_ = nullptr;
}

TEST_F(DvrBufferQueueTest, TestWrite_QueueGetCapacity) {
  AllocateBuffers(kQueueCapacity);
  size_t capacity = dvrWriteBufferQueueGetCapacity(write_queue_);

  ALOGD_IF(TRACE, "TestWrite_QueueGetCapacity, capacity=%zu", capacity);
  ASSERT_EQ(kQueueCapacity, capacity);
}

TEST_F(DvrBufferQueueTest, TestCreateReadQueueFromWriteQueue) {
  DvrReadBufferQueue* read_queue = nullptr;
  int ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue);

  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue);

  dvrReadBufferQueueDestroy(read_queue);
}

TEST_F(DvrBufferQueueTest, TestCreateReadQueueFromReadQueue) {
  DvrReadBufferQueue* read_queue1 = nullptr;
  DvrReadBufferQueue* read_queue2 = nullptr;
  int ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue1);

  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue1);

  ret = dvrReadBufferQueueCreateReadQueue(read_queue1, &read_queue2);
  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue2);
  ASSERT_NE(read_queue1, read_queue2);

  dvrReadBufferQueueDestroy(read_queue1);
  dvrReadBufferQueueDestroy(read_queue2);
}

TEST_F(DvrBufferQueueTest, CreateEmptyBuffer) {
  AllocateBuffers(3);

  DvrReadBuffer* read_buffer = nullptr;
  DvrWriteBuffer* write_buffer = nullptr;

  EXPECT_FALSE(dvrReadBufferIsValid(read_buffer));
  EXPECT_FALSE(dvrWriteBufferIsValid(write_buffer));

  dvrReadBufferCreateEmpty(&read_buffer);
  ASSERT_NE(nullptr, read_buffer);

  dvrWriteBufferCreateEmpty(&write_buffer);
  ASSERT_NE(nullptr, write_buffer);

  EXPECT_FALSE(dvrReadBufferIsValid(read_buffer));
  EXPECT_FALSE(dvrWriteBufferIsValid(write_buffer));

  DvrReadBufferQueue* read_queue = nullptr;

  ASSERT_EQ(0, dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue));

  const int kTimeoutMs = 0;
  int fence_fd = -1;
  ASSERT_EQ(0, dvrWriteBufferQueueDequeue(write_queue_, kTimeoutMs,
                                          write_buffer, &fence_fd));
  EXPECT_EQ(-1, fence_fd);
  EXPECT_TRUE(dvrWriteBufferIsValid(write_buffer));

  ASSERT_EQ(0, dvrWriteBufferClear(write_buffer));
  EXPECT_FALSE(dvrWriteBufferIsValid(write_buffer));
}

TEST_F(DvrBufferQueueTest, TestDequeuePostDequeueRelease) {
  static constexpr int kTimeout = 0;
  DvrReadBufferQueue* read_queue = nullptr;
  DvrReadBuffer* rb = nullptr;
  DvrWriteBuffer* wb = nullptr;
  int fence_fd = -1;

  int ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue);

  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue);

  dvrWriteBufferCreateEmpty(&wb);
  ASSERT_NE(nullptr, wb);

  dvrReadBufferCreateEmpty(&rb);
  ASSERT_NE(nullptr, rb);

  AllocateBuffers(kQueueCapacity);

  // Gain buffer for writing.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb));
  ALOGD_IF(TRACE, "TestDequeuePostDequeueRelease, gain buffer %p, fence_fd=%d",
           wb, fence_fd);
  pdx::LocalHandle release_fence(fence_fd);

  // Post buffer to the read_queue.
  TestMeta seq = 42U;
  ret = dvrWriteBufferPost(wb, /* fence */ -1, &seq, sizeof(seq));
  ASSERT_EQ(0, ret);
  dvrWriteBufferDestroy(wb);
  wb = nullptr;

  // Acquire buffer for reading.
  TestMeta acquired_seq = 0U;
  ret = dvrReadBufferQueueDequeue(read_queue, kTimeout, rb, &fence_fd,
                                  &acquired_seq, sizeof(acquired_seq));
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrReadBufferIsValid(rb));
  ASSERT_EQ(seq, acquired_seq);
  ALOGD_IF(TRACE,
           "TestDequeuePostDequeueRelease, acquire buffer %p, fence_fd=%d", rb,
           fence_fd);
  pdx::LocalHandle acquire_fence(fence_fd);

  // Release buffer to the write_queue.
  ret = dvrReadBufferRelease(rb, -1);
  ASSERT_EQ(0, ret);
  dvrReadBufferDestroy(rb);
  rb = nullptr;

  // TODO(b/34387835) Currently buffer allocation has to happen after all queues
  // are initialized.
  size_t capacity = dvrReadBufferQueueGetCapacity(read_queue);

  ALOGD_IF(TRACE, "TestDequeuePostDequeueRelease, capacity=%zu", capacity);
  ASSERT_EQ(kQueueCapacity, capacity);

  dvrReadBufferQueueDestroy(read_queue);
}

TEST_F(DvrBufferQueueTest, TestGetExternalSurface) {
  ANativeWindow* window = nullptr;

  // The |write_queue_| doesn't have proper metadata (must be
  // DvrNativeBufferMetadata) configured during creation.
  int ret = dvrWriteBufferQueueGetExternalSurface(write_queue_, &window);
  ASSERT_EQ(-EINVAL, ret);
  ASSERT_EQ(nullptr, window);

  // A write queue with DvrNativeBufferMetadata should work fine.
  auto config = ProducerQueueConfigBuilder()
                    .SetMetadata<DvrNativeBufferMetadata>()
                    .Build();
  std::unique_ptr<DvrWriteBufferQueue, decltype(&dvrWriteBufferQueueDestroy)>
      write_queue(
          new DvrWriteBufferQueue(ProducerQueue::Create(config, UsagePolicy{})),
          dvrWriteBufferQueueDestroy);
  ASSERT_NE(nullptr, write_queue.get());

  ret = dvrWriteBufferQueueGetExternalSurface(write_queue.get(), &window);
  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, window);

  sp<Surface> surface = static_cast<Surface*>(window);
  ASSERT_TRUE(Surface::isValid(surface));
}

// Create buffer queue of three buffers and dequeue three buffers out of it.
// Before each dequeue operation, we resize the buffer queue and expect the
// queue always return buffer with desired dimension.
TEST_F(DvrBufferQueueTest, TestResizeBuffer) {
  static constexpr int kTimeout = 0;
  int fence_fd = -1;

  DvrWriteBuffer* wb1 = nullptr;
  DvrWriteBuffer* wb2 = nullptr;
  DvrWriteBuffer* wb3 = nullptr;
  AHardwareBuffer* ahb1 = nullptr;
  AHardwareBuffer* ahb2 = nullptr;
  AHardwareBuffer* ahb3 = nullptr;
  AHardwareBuffer_Desc buffer_desc;

  dvrWriteBufferCreateEmpty(&wb1);
  ASSERT_NE(nullptr, wb1);
  dvrWriteBufferCreateEmpty(&wb2);
  ASSERT_NE(nullptr, wb2);
  dvrWriteBufferCreateEmpty(&wb3);
  ASSERT_NE(nullptr, wb3);

  AllocateBuffers(kQueueCapacity);

  // Resize before dequeuing.
  constexpr int w1 = 10;
  int ret = dvrWriteBufferQueueResizeBuffer(write_queue_, w1, kBufferHeight);

  // Gain first buffer for writing. All buffers will be resized.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb1, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb1));
  ALOGD_IF(TRACE, "TestResiveBuffer, gain buffer %p", wb1);
  pdx::LocalHandle release_fence1(fence_fd);

  // Check the buffer dimension.
  ret = dvrWriteBufferGetAHardwareBuffer(wb1, &ahb1);
  ASSERT_EQ(0, ret);
  AHardwareBuffer_describe(ahb1, &buffer_desc);
  ASSERT_EQ(w1, buffer_desc.width);
  ASSERT_EQ(kBufferHeight, buffer_desc.height);
  AHardwareBuffer_release(ahb1);

  // Resize the queue. We are testing with blob format, keep height to be 1.
  constexpr int w2 = 20;
  ret = dvrWriteBufferQueueResizeBuffer(write_queue_, w2, kBufferHeight);
  ASSERT_EQ(0, ret);

  // The next buffer we dequeued should have new width.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb2, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb2));
  ALOGD_IF(TRACE, "TestResiveBuffer, gain buffer %p, fence_fd=%d", wb2,
           fence_fd);
  pdx::LocalHandle release_fence2(fence_fd);

  // Check the buffer dimension, should be new width
  ret = dvrWriteBufferGetAHardwareBuffer(wb2, &ahb2);
  ASSERT_EQ(0, ret);
  AHardwareBuffer_describe(ahb2, &buffer_desc);
  ASSERT_EQ(w2, buffer_desc.width);
  AHardwareBuffer_release(ahb2);

  // Resize the queue for the third time.
  constexpr int w3 = 30;
  ret = dvrWriteBufferQueueResizeBuffer(write_queue_, w3, kBufferHeight);
  ASSERT_EQ(0, ret);

  // The next buffer we dequeued should have new width.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb3, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb3));
  ALOGD_IF(TRACE, "TestResiveBuffer, gain buffer %p, fence_fd=%d", wb3,
           fence_fd);
  pdx::LocalHandle release_fence3(fence_fd);

  // Check the buffer dimension, should be new width
  ret = dvrWriteBufferGetAHardwareBuffer(wb3, &ahb3);
  ASSERT_EQ(0, ret);
  AHardwareBuffer_describe(ahb3, &buffer_desc);
  ASSERT_EQ(w3, buffer_desc.width);
  AHardwareBuffer_release(ahb3);
}

}  // namespace

}  // namespace dvr
}  // namespace android
