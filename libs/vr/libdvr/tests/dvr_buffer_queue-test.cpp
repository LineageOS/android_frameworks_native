#include <dvr/dvr_api.h>
#include <dvr/dvr_buffer_queue.h>
#include <gui/Surface.h>
#include <private/dvr/buffer_hub_queue_client.h>

#include <base/logging.h>
#include <gtest/gtest.h>

#include "../dvr_internal.h"

namespace android {
namespace dvr {

namespace {

static constexpr int kBufferWidth = 100;
static constexpr int kBufferHeight = 1;
static constexpr int kLayerCount = 1;
static constexpr int kBufferFormat = HAL_PIXEL_FORMAT_BLOB;
static constexpr int kBufferUsage = GRALLOC_USAGE_SW_READ_RARELY;
static constexpr size_t kQueueCapacity = 3;

typedef uint64_t TestMeta;

class DvrBufferQueueTest : public ::testing::Test {
 protected:
  void SetUp() override {
    write_queue_ = CreateDvrWriteBufferQueueFromProducerQueue(
        ProducerQueue::Create<TestMeta>(0, 0, 0, 0));
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
      int ret = GetProducerQueueFromDvrWriteBufferQueue(write_queue_)
                    ->AllocateBuffer(kBufferWidth, kBufferHeight, kLayerCount,
                                     kBufferFormat, kBufferUsage, &out_slot);
      ASSERT_EQ(0, ret);
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
  std::unique_ptr<DvrWriteBufferQueue, decltype(&dvrWriteBufferQueueDestroy)>
      write_queue(
          CreateDvrWriteBufferQueueFromProducerQueue(
              ProducerQueue::Create<DvrNativeBufferMetadata>(0, 0, 0, 0)),
          dvrWriteBufferQueueDestroy);
  ASSERT_NE(nullptr, write_queue.get());

  ret = dvrWriteBufferQueueGetExternalSurface(write_queue.get(), &window);
  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, window);

  sp<Surface> surface = static_cast<Surface*>(window);
  ASSERT_TRUE(Surface::isValid(surface));
}

}  // namespace

}  // namespace dvr
}  // namespace android
