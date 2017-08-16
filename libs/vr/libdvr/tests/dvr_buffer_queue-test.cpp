#include <android/log.h>
#include <android/native_window.h>
#include <android-base/unique_fd.h>
#include <dvr/dvr_api.h>
#include <dvr/dvr_buffer_queue.h>

#include <gtest/gtest.h>

#include <array>
#include <unordered_map>

#ifndef ALOGD
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif

#ifndef ALOGD_IF
#define ALOGD_IF(cond, ...) \
  ((__predict_false(cond)) ? ((void)ALOGD(__VA_ARGS__)) : (void)0)
#endif

namespace {

static constexpr uint32_t kBufferWidth = 100;
static constexpr uint32_t kBufferHeight = 1;
static constexpr uint32_t kLayerCount = 1;
static constexpr uint32_t kBufferFormat = AHARDWAREBUFFER_FORMAT_BLOB;
static constexpr uint64_t kBufferUsage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN;
static constexpr size_t kQueueCapacity = 3;

typedef uint64_t TestMeta;

class DvrBufferQueueTest : public ::testing::Test {
 public:
  static void BufferAvailableCallback(void* context) {
    DvrBufferQueueTest* thiz = static_cast<DvrBufferQueueTest*>(context);
    thiz->HandleBufferAvailable();
  }

  static void BufferRemovedCallback(DvrReadBuffer* buffer, void* context) {
    DvrBufferQueueTest* thiz = static_cast<DvrBufferQueueTest*>(context);
    thiz->HandleBufferRemoved(buffer);
  }

 protected:
  void TearDown() override {
    if (write_queue_ != nullptr) {
      dvrWriteBufferQueueDestroy(write_queue_);
      write_queue_ = nullptr;
    }
  }

  void HandleBufferAvailable() {
    buffer_available_count_ += 1;
    ALOGD_IF(TRACE, "Buffer avaiable, count=%d", buffer_available_count_);
  }

  void HandleBufferRemoved(DvrReadBuffer* buffer) {
    buffer_removed_count_ += 1;
    ALOGD_IF(TRACE, "Buffer removed, buffer=%p, count=%d", buffer,
             buffer_removed_count_);
  }

  DvrWriteBufferQueue* write_queue_{nullptr};
  int buffer_available_count_{0};
  int buffer_removed_count_{0};
};

TEST_F(DvrBufferQueueTest, TestWrite_QueueCreateDestroy) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      /*capacity=*/0, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  dvrWriteBufferQueueDestroy(write_queue_);
  write_queue_ = nullptr;
}

TEST_F(DvrBufferQueueTest, TestWrite_QueueGetCapacity) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      kQueueCapacity, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  size_t capacity = dvrWriteBufferQueueGetCapacity(write_queue_);

  ALOGD_IF(TRACE, "TestWrite_QueueGetCapacity, capacity=%zu", capacity);
  ASSERT_EQ(kQueueCapacity, capacity);
}

TEST_F(DvrBufferQueueTest, TestCreateReadQueueFromWriteQueue) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      /*capacity=*/0, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  DvrReadBufferQueue* read_queue = nullptr;
  ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue);

  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue);

  dvrReadBufferQueueDestroy(read_queue);
}

TEST_F(DvrBufferQueueTest, TestCreateReadQueueFromReadQueue) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      /*capacity=*/0, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  DvrReadBufferQueue* read_queue1 = nullptr;
  DvrReadBufferQueue* read_queue2 = nullptr;
  ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue1);

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
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      kQueueCapacity, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

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
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      kQueueCapacity, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  static constexpr int kTimeout = 0;
  DvrReadBufferQueue* read_queue = nullptr;
  DvrReadBuffer* rb = nullptr;
  DvrWriteBuffer* wb = nullptr;
  int fence_fd = -1;

  ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue);

  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue);

  dvrReadBufferQueueSetBufferAvailableCallback(read_queue,
                                               &BufferAvailableCallback, this);

  dvrWriteBufferCreateEmpty(&wb);
  ASSERT_NE(nullptr, wb);

  dvrReadBufferCreateEmpty(&rb);
  ASSERT_NE(nullptr, rb);

  // Gain buffer for writing.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb));
  ALOGD_IF(TRACE, "TestDequeuePostDequeueRelease, gain buffer %p, fence_fd=%d",
           wb, fence_fd);
  android::base::unique_fd release_fence(fence_fd);

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

  // Dequeue is successfully, BufferAvailableCallback should be fired once.
  ASSERT_EQ(1, buffer_available_count_);
  ASSERT_TRUE(dvrReadBufferIsValid(rb));
  ASSERT_EQ(seq, acquired_seq);
  ALOGD_IF(TRACE,
           "TestDequeuePostDequeueRelease, acquire buffer %p, fence_fd=%d", rb,
           fence_fd);
  android::base::unique_fd acquire_fence(fence_fd);

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
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      /*capacity=*/0, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  ANativeWindow* window = nullptr;

  // The |write_queue_| doesn't have proper metadata (must be
  // DvrNativeBufferMetadata) configured during creation.
  ret = dvrWriteBufferQueueGetExternalSurface(write_queue_, &window);
  ASSERT_EQ(-EINVAL, ret);
  ASSERT_EQ(nullptr, window);
  dvrWriteBufferQueueDestroy(write_queue_);
  write_queue_ = nullptr;

  // A write queue with DvrNativeBufferMetadata should work fine.
  ASSERT_EQ(nullptr, write_queue_);

  ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      /*capacity=*/0, sizeof(DvrNativeBufferMetadata), &write_queue_);
  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, write_queue_);

  ret = dvrWriteBufferQueueGetExternalSurface(write_queue_, &window);
  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, window);

  // TODO(b/64723700): Remove dependencies of Android platform bits so that we
  // can run dvr_buffer_queue-test in DTS.
  uint32_t width = ANativeWindow_getWidth(window);
  uint32_t height = ANativeWindow_getHeight(window);
  uint32_t format = ANativeWindow_getFormat(window);
  ASSERT_EQ(kBufferWidth, width);
  ASSERT_EQ(kBufferHeight, height);
  ASSERT_EQ(kBufferFormat, format);
}

// Create buffer queue of three buffers and dequeue three buffers out of it.
// Before each dequeue operation, we resize the buffer queue and expect the
// queue always return buffer with desired dimension.
TEST_F(DvrBufferQueueTest, TestResizeBuffer) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      kQueueCapacity, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  static constexpr int kTimeout = 0;
  int fence_fd = -1;

  DvrReadBufferQueue* read_queue = nullptr;
  DvrWriteBuffer* wb1 = nullptr;
  DvrWriteBuffer* wb2 = nullptr;
  DvrWriteBuffer* wb3 = nullptr;
  AHardwareBuffer* ahb1 = nullptr;
  AHardwareBuffer* ahb2 = nullptr;
  AHardwareBuffer* ahb3 = nullptr;
  AHardwareBuffer_Desc buffer_desc;

  ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue);

  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue);

  dvrReadBufferQueueSetBufferRemovedCallback(read_queue, &BufferRemovedCallback,
                                             this);

  dvrWriteBufferCreateEmpty(&wb1);
  ASSERT_NE(nullptr, wb1);
  dvrWriteBufferCreateEmpty(&wb2);
  ASSERT_NE(nullptr, wb2);
  dvrWriteBufferCreateEmpty(&wb3);
  ASSERT_NE(nullptr, wb3);

  // Handle all pending events on the read queue.
  ret = dvrReadBufferQueueHandleEvents(read_queue);
  ASSERT_EQ(0, ret);

  size_t capacity = dvrReadBufferQueueGetCapacity(read_queue);
  ALOGD_IF(TRACE, "TestResizeBuffer, capacity=%zu", capacity);
  ASSERT_EQ(kQueueCapacity, capacity);

  // Resize before dequeuing.
  constexpr uint32_t w1 = 10;
  ret = dvrWriteBufferQueueResizeBuffer(write_queue_, w1, kBufferHeight);
  ASSERT_EQ(0, ret);

  // Gain first buffer for writing. All buffers will be resized.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb1, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb1));
  ALOGD_IF(TRACE, "TestResizeBuffer, gain buffer %p", wb1);
  android::base::unique_fd release_fence1(fence_fd);

  // Check the buffer dimension.
  ret = dvrWriteBufferGetAHardwareBuffer(wb1, &ahb1);
  ASSERT_EQ(0, ret);
  AHardwareBuffer_describe(ahb1, &buffer_desc);
  ASSERT_EQ(w1, buffer_desc.width);
  ASSERT_EQ(kBufferHeight, buffer_desc.height);
  AHardwareBuffer_release(ahb1);

  // For the first resize, all buffers are reallocated.
  int expected_buffer_removed_count = kQueueCapacity;
  ret = dvrReadBufferQueueHandleEvents(read_queue);
  ASSERT_EQ(0, ret);
  ASSERT_EQ(expected_buffer_removed_count, buffer_removed_count_);

  // Resize the queue. We are testing with blob format, keep height to be 1.
  constexpr uint32_t w2 = 20;
  ret = dvrWriteBufferQueueResizeBuffer(write_queue_, w2, kBufferHeight);
  ASSERT_EQ(0, ret);

  // The next buffer we dequeued should have new width.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb2, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb2));
  ALOGD_IF(TRACE, "TestResizeBuffer, gain buffer %p, fence_fd=%d", wb2,
           fence_fd);
  android::base::unique_fd release_fence2(fence_fd);

  // Check the buffer dimension, should be new width
  ret = dvrWriteBufferGetAHardwareBuffer(wb2, &ahb2);
  ASSERT_EQ(0, ret);
  AHardwareBuffer_describe(ahb2, &buffer_desc);
  ASSERT_EQ(w2, buffer_desc.width);
  AHardwareBuffer_release(ahb2);

  // For the second resize, all but one buffers are reallocated.
  expected_buffer_removed_count += (kQueueCapacity - 1);
  ret = dvrReadBufferQueueHandleEvents(read_queue);
  ASSERT_EQ(0, ret);
  ASSERT_EQ(expected_buffer_removed_count, buffer_removed_count_);

  // Resize the queue for the third time.
  constexpr uint32_t w3 = 30;
  ret = dvrWriteBufferQueueResizeBuffer(write_queue_, w3, kBufferHeight);
  ASSERT_EQ(0, ret);

  // The next buffer we dequeued should have new width.
  ret = dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wb3, &fence_fd);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(dvrWriteBufferIsValid(wb3));
  ALOGD_IF(TRACE, "TestResizeBuffer, gain buffer %p, fence_fd=%d", wb3,
           fence_fd);
  android::base::unique_fd release_fence3(fence_fd);

  // Check the buffer dimension, should be new width
  ret = dvrWriteBufferGetAHardwareBuffer(wb3, &ahb3);
  ASSERT_EQ(0, ret);
  AHardwareBuffer_describe(ahb3, &buffer_desc);
  ASSERT_EQ(w3, buffer_desc.width);
  AHardwareBuffer_release(ahb3);

  // For the third resize, all but two buffers are reallocated.
  expected_buffer_removed_count += (kQueueCapacity - 2);
  ret = dvrReadBufferQueueHandleEvents(read_queue);
  ASSERT_EQ(0, ret);
  ASSERT_EQ(expected_buffer_removed_count, buffer_removed_count_);

  dvrReadBufferQueueDestroy(read_queue);
}

TEST_F(DvrBufferQueueTest, DequeueEmptyMetadata) {
  // Overrides default queue parameters: Empty metadata.
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      /*capacity=*/1, /*metadata_size=*/0, &write_queue_);
  ASSERT_EQ(0, ret);

  DvrReadBuffer* rb = nullptr;
  DvrWriteBuffer* wb = nullptr;
  dvrReadBufferCreateEmpty(&rb);
  dvrWriteBufferCreateEmpty(&wb);

  DvrReadBufferQueue* read_queue = nullptr;
  EXPECT_EQ(0, dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue));

  const int kTimeoutMs = 0;
  int fence_fd = -1;
  EXPECT_EQ(0, dvrWriteBufferQueueDequeue(write_queue_, 0, wb, &fence_fd));

  EXPECT_EQ(0, dvrWriteBufferPost(wb, /*fence=*/-1, nullptr, 0));
  EXPECT_EQ(0, dvrWriteBufferClear(wb));
  dvrWriteBufferDestroy(wb);
  wb = nullptr;

  // When acquire buffer, it's legit to pass nullptr as out_meta iff metadata
  // size is Zero.
  EXPECT_EQ(0, dvrReadBufferQueueDequeue(read_queue, kTimeoutMs, rb, &fence_fd,
                                         nullptr, 0));
  EXPECT_TRUE(dvrReadBufferIsValid(rb));
}

TEST_F(DvrBufferQueueTest, DequeueMismatchMetadata) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      /*capacity=*/1, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  DvrReadBuffer* rb = nullptr;
  DvrWriteBuffer* wb = nullptr;
  dvrReadBufferCreateEmpty(&rb);
  dvrWriteBufferCreateEmpty(&wb);

  DvrReadBufferQueue* read_queue = nullptr;
  EXPECT_EQ(0, dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue));

  const int kTimeoutMs = 0;
  int fence_fd = -1;
  EXPECT_EQ(0, dvrWriteBufferQueueDequeue(write_queue_, 0, wb, &fence_fd));

  TestMeta seq = 42U;
  EXPECT_EQ(0, dvrWriteBufferPost(wb, /*fence=*/-1, &seq, sizeof(seq)));
  EXPECT_EQ(0, dvrWriteBufferClear(wb));
  dvrWriteBufferDestroy(wb);
  wb = nullptr;

  // Dequeue with wrong metadata will cause EINVAL.
  int8_t wrong_metadata;
  EXPECT_EQ(-EINVAL,
            dvrReadBufferQueueDequeue(read_queue, kTimeoutMs, rb, &fence_fd,
                                      &wrong_metadata, sizeof(wrong_metadata)));
  EXPECT_FALSE(dvrReadBufferIsValid(rb));

  // Dequeue with empty metadata will cause EINVAL.
  EXPECT_EQ(-EINVAL, dvrReadBufferQueueDequeue(read_queue, kTimeoutMs, rb,
                                               &fence_fd, nullptr, 0));
  EXPECT_FALSE(dvrReadBufferIsValid(rb));
}

TEST_F(DvrBufferQueueTest, TestReadQueueEventFd) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      kQueueCapacity, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  DvrReadBufferQueue* read_queue = nullptr;
  ret = dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue);

  ASSERT_EQ(0, ret);
  ASSERT_NE(nullptr, read_queue);

  int event_fd = dvrReadBufferQueueGetEventFd(read_queue);
  ASSERT_GT(event_fd, 0);
}

// Verifies a Dvr{Read,Write}BufferQueue contains the same set of
// Dvr{Read,Write}Buffer(s) during their lifecycles. And for the same buffer_id,
// the corresponding AHardwareBuffer handle stays the same.
TEST_F(DvrBufferQueueTest, TestStableBufferIdAndHardwareBuffer) {
  int ret = dvrWriteBufferQueueCreate(
      kBufferWidth, kBufferHeight, kBufferFormat, kLayerCount, kBufferUsage,
      kQueueCapacity, sizeof(TestMeta), &write_queue_);
  ASSERT_EQ(0, ret);

  int fence_fd = -1;
  DvrReadBufferQueue* read_queue = nullptr;
  EXPECT_EQ(0, dvrWriteBufferQueueCreateReadQueue(write_queue_, &read_queue));

  // Read buffers.
  std::array<DvrReadBuffer*, kQueueCapacity> rbs;
  // Write buffers.
  std::array<DvrWriteBuffer*, kQueueCapacity> wbs;
  // Hardware buffers for Read buffers.
  std::unordered_map<int, AHardwareBuffer*> rhbs;
  // Hardware buffers for Write buffers.
  std::unordered_map<int, AHardwareBuffer*> whbs;

  for (size_t i = 0; i < kQueueCapacity; i++) {
    dvrReadBufferCreateEmpty(&rbs[i]);
    dvrWriteBufferCreateEmpty(&wbs[i]);
  }

  constexpr int kNumTests = 100;
  constexpr int kTimeout = 0;
  TestMeta seq = 0U;

  // This test runs the following operations many many times. Thus we prefer to
  // use ASSERT_XXX rather than EXPECT_XXX to avoid spamming the output.
  std::function<void(size_t i)> Gain = [&](size_t i) {
    ASSERT_EQ(0, dvrWriteBufferQueueDequeue(write_queue_, kTimeout, wbs[i],
                                            &fence_fd));
    ASSERT_LT(fence_fd, 0);  // expect invalid fence.
    ASSERT_TRUE(dvrWriteBufferIsValid(wbs[i]));
    int buffer_id = dvrWriteBufferGetId(wbs[i]);
    ASSERT_GT(buffer_id, 0);

    AHardwareBuffer* hb = nullptr;
    ASSERT_EQ(0, dvrWriteBufferGetAHardwareBuffer(wbs[i], &hb));

    auto whb_it = whbs.find(buffer_id);
    if (whb_it == whbs.end()) {
      // If this is a new buffer id, check that total number of unique
      // hardware buffers won't exceed queue capacity.
      ASSERT_LT(whbs.size(), kQueueCapacity);
      whbs.emplace(buffer_id, hb);
    } else {
      // If this is a buffer id we have seen before, check that the
      // buffer_id maps to the same AHardwareBuffer handle.
      ASSERT_EQ(hb, whb_it->second);
    }
  };

  std::function<void(size_t i)> Post = [&](size_t i) {
    ASSERT_TRUE(dvrWriteBufferIsValid(wbs[i]));

    seq++;
    ASSERT_EQ(0, dvrWriteBufferPost(wbs[i], /*fence=*/-1, &seq, sizeof(seq)));
  };

  std::function<void(size_t i)> Acquire = [&](size_t i) {
    TestMeta out_seq = 0U;
    ASSERT_EQ(0,
              dvrReadBufferQueueDequeue(read_queue, kTimeout, rbs[i], &fence_fd,
                                        &out_seq, sizeof(out_seq)));
    ASSERT_LT(fence_fd, 0);  // expect invalid fence.
    ASSERT_TRUE(dvrReadBufferIsValid(rbs[i]));

    int buffer_id = dvrReadBufferGetId(rbs[i]);
    ASSERT_GT(buffer_id, 0);

    AHardwareBuffer* hb = nullptr;
    ASSERT_EQ(0, dvrReadBufferGetAHardwareBuffer(rbs[i], &hb));

    auto rhb_it = rhbs.find(buffer_id);
    if (rhb_it == rhbs.end()) {
      // If this is a new buffer id, check that total number of unique hardware
      // buffers won't exceed queue capacity.
      ASSERT_LT(rhbs.size(), kQueueCapacity);
      rhbs.emplace(buffer_id, hb);
    } else {
      // If this is a buffer id we have seen before, check that the buffer_id
      // maps to the same AHardwareBuffer handle.
      ASSERT_EQ(hb, rhb_it->second);
    }
  };

  std::function<void(size_t i)> Release = [&](size_t i) {
    ASSERT_TRUE(dvrReadBufferIsValid(rbs[i]));

    seq++;
    ASSERT_EQ(0, dvrReadBufferRelease(rbs[i], /*fence=*/-1));
  };

  // Scenario one:
  for (int i = 0; i < kNumTests; i++) {
    // Gain all write buffers.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Gain(i));
    }
    // Post all write buffers.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Post(i));
    }
    // Acquire all read buffers.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Acquire(i));
    }
    // Release all read buffers.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Release(i));
    }
  }

  // Scenario two:
  for (int i = 0; i < kNumTests; i++) {
    // Gain and post all write buffers.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Gain(i));
      ASSERT_NO_FATAL_FAILURE(Post(i));
    }
    // Acquire and release all read buffers.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Acquire(i));
      ASSERT_NO_FATAL_FAILURE(Release(i));
    }
  }

  // Scenario three:
  for (int i = 0; i < kNumTests; i++) {
    // Gain all write buffers then post them in reversed order.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Gain(i));
    }
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Post(kQueueCapacity - 1 - i));
    }

    // Acquire all write buffers then release them in reversed order.
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Acquire(i));
    }
    for (size_t i = 0; i < kQueueCapacity; i++) {
      ASSERT_NO_FATAL_FAILURE(Release(kQueueCapacity - 1 - i));
    }
  }

  // Clean up all read buffers and write buffers.
  for (size_t i = 0; i < kQueueCapacity; i++) {
    dvrReadBufferDestroy(rbs[i]);
    dvrWriteBufferDestroy(wbs[i]);
  }
}

}  // namespace
