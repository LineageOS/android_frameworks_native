#include <base/logging.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/buffer_hub_queue_client.h>

#include <gtest/gtest.h>

#include <vector>

namespace android {
namespace dvr {

using pdx::LocalHandle;

namespace {

constexpr int kBufferWidth = 100;
constexpr int kBufferHeight = 1;
constexpr int kBufferLayerCount = 1;
constexpr int kBufferFormat = HAL_PIXEL_FORMAT_BLOB;
constexpr int kBufferUsage = GRALLOC_USAGE_SW_READ_RARELY;

class BufferHubQueueTest : public ::testing::Test {
 public:
  template <typename Meta>
  bool CreateProducerQueue(uint64_t usage_set_mask = 0,
                           uint64_t usage_clear_mask = 0,
                           uint64_t usage_deny_set_mask = 0,
                           uint64_t usage_deny_clear_mask = 0) {
    producer_queue_ =
        ProducerQueue::Create<Meta>(usage_set_mask, usage_clear_mask,
                                    usage_deny_set_mask, usage_deny_clear_mask);
    return producer_queue_ != nullptr;
  }

  bool CreateConsumerQueue() {
    if (producer_queue_) {
      consumer_queue_ = producer_queue_->CreateConsumerQueue();
      return consumer_queue_ != nullptr;
    } else {
      return false;
    }
  }

  template <typename Meta>
  bool CreateQueues(int usage_set_mask = 0, int usage_clear_mask = 0,
                    int usage_deny_set_mask = 0,
                    int usage_deny_clear_mask = 0) {
    return CreateProducerQueue<Meta>(usage_set_mask, usage_clear_mask,
                                     usage_deny_set_mask,
                                     usage_deny_clear_mask) &&
           CreateConsumerQueue();
  }

  void AllocateBuffer() {
    // Create producer buffer.
    size_t slot;
    int ret = producer_queue_->AllocateBuffer(kBufferWidth, kBufferHeight,
                                              kBufferLayerCount, kBufferFormat,
                                              kBufferUsage, &slot);
    ASSERT_EQ(ret, 0);
  }

 protected:
  std::unique_ptr<ProducerQueue> producer_queue_;
  std::unique_ptr<ConsumerQueue> consumer_queue_;
};

TEST_F(BufferHubQueueTest, TestDequeue) {
  const size_t nb_dequeue_times = 16;

  ASSERT_TRUE(CreateQueues<size_t>());

  // Allocate only one buffer.
  AllocateBuffer();

  // But dequeue multiple times.
  for (size_t i = 0; i < nb_dequeue_times; i++) {
    size_t slot;
    LocalHandle fence;
    auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
    ASSERT_TRUE(p1_status.ok());
    auto p1 = p1_status.take();
    ASSERT_NE(nullptr, p1);
    size_t mi = i;
    ASSERT_EQ(p1->Post(LocalHandle(), &mi, sizeof(mi)), 0);
    size_t mo;
    auto c1_status = consumer_queue_->Dequeue(100, &slot, &mo, &fence);
    ASSERT_TRUE(c1_status.ok());
    auto c1 = c1_status.take();
    ASSERT_NE(nullptr, c1);
    ASSERT_EQ(mi, mo);
    c1->Release(LocalHandle());
  }
}

TEST_F(BufferHubQueueTest, TestProducerConsumer) {
  const size_t nb_buffer = 16;
  size_t slot;
  uint64_t seq;

  ASSERT_TRUE(CreateQueues<uint64_t>());

  for (size_t i = 0; i < nb_buffer; i++) {
    AllocateBuffer();

    // Producer queue has all the available buffers on initialize.
    ASSERT_EQ(producer_queue_->count(), i + 1);
    ASSERT_EQ(producer_queue_->capacity(), i + 1);

    // Consumer queue has no avaiable buffer on initialize.
    ASSERT_EQ(consumer_queue_->count(), 0U);
    // Consumer queue does not import buffers until a dequeue is issued.
    ASSERT_EQ(consumer_queue_->capacity(), i);
    // Dequeue returns timeout since no buffer is ready to consumer, but
    // this implicitly triggers buffer import and bump up |capacity|.
    LocalHandle fence;
    auto status = consumer_queue_->Dequeue(0, &slot, &seq, &fence);
    ASSERT_FALSE(status.ok());
    ASSERT_EQ(ETIMEDOUT, status.error());
    ASSERT_EQ(consumer_queue_->capacity(), i + 1);
  }

  for (size_t i = 0; i < nb_buffer; i++) {
    LocalHandle fence;
    // First time, there is no buffer available to dequeue.
    auto consumer_status = consumer_queue_->Dequeue(0, &slot, &seq, &fence);
    ASSERT_FALSE(consumer_status.ok());
    ASSERT_EQ(ETIMEDOUT, consumer_status.error());

    // Make sure Producer buffer is Post()'ed so that it's ready to Accquire
    // in the consumer's Dequeue() function.
    auto producer_status = producer_queue_->Dequeue(0, &slot, &fence);
    ASSERT_TRUE(producer_status.ok());
    auto producer = producer_status.take();
    ASSERT_NE(nullptr, producer);

    uint64_t seq_in = static_cast<uint64_t>(i);
    ASSERT_EQ(producer->Post({}, &seq_in, sizeof(seq_in)), 0);

    // Second time, the just |Post()|'ed buffer should be dequeued.
    uint64_t seq_out = 0;
    consumer_status = consumer_queue_->Dequeue(0, &slot, &seq_out, &fence);
    ASSERT_TRUE(consumer_status.ok());
    auto consumer = consumer_status.take();
    ASSERT_NE(nullptr, consumer);
    ASSERT_EQ(seq_in, seq_out);
  }
}

TEST_F(BufferHubQueueTest, TestMultipleConsumers) {
  ASSERT_TRUE(CreateProducerQueue<void>());

  // Allocate buffers.
  const size_t kBufferCount = 4u;
  for (size_t i = 0; i < kBufferCount; i++) {
    AllocateBuffer();
  }
  ASSERT_EQ(kBufferCount, producer_queue_->count());

  // Build a silent consumer queue to test multi-consumer queue features.
  auto silent_queue = producer_queue_->CreateSilentConsumerQueue();
  ASSERT_NE(nullptr, silent_queue);

  // Check that buffers are correctly imported on construction.
  EXPECT_EQ(kBufferCount, silent_queue->capacity());

  // Dequeue and post a buffer.
  size_t slot;
  LocalHandle fence;
  auto producer_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(producer_status.ok());
  auto producer_buffer = producer_status.take();
  ASSERT_NE(nullptr, producer_buffer);
  ASSERT_EQ(0, producer_buffer->Post<void>({}));

  // Currently we expect no buffer to be available prior to calling
  // WaitForBuffers/HandleQueueEvents.
  // TODO(eieio): Note this behavior may change in the future.
  EXPECT_EQ(0u, silent_queue->count());
  EXPECT_FALSE(silent_queue->HandleQueueEvents());
  EXPECT_EQ(0u, silent_queue->count());

  // Build a new consumer queue to test multi-consumer queue features.
  consumer_queue_ = silent_queue->CreateConsumerQueue();
  ASSERT_NE(nullptr, consumer_queue_);

  // Check that buffers are correctly imported on construction.
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());
  EXPECT_EQ(1u, consumer_queue_->count());

  // Reclaim released/ignored buffers.
  producer_queue_->HandleQueueEvents();
  ASSERT_EQ(kBufferCount - 1, producer_queue_->count());

  // Post another buffer.
  producer_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(producer_status.ok());
  producer_buffer = producer_status.take();
  ASSERT_NE(nullptr, producer_buffer);
  ASSERT_EQ(0, producer_buffer->Post<void>({}));

  // Verify that the consumer queue receives it.
  EXPECT_EQ(1u, consumer_queue_->count());
  EXPECT_TRUE(consumer_queue_->HandleQueueEvents());
  EXPECT_EQ(2u, consumer_queue_->count());

  // Dequeue and acquire/release (discard) buffers on the consumer end.
  auto consumer_status = consumer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(consumer_status.ok());
  auto consumer_buffer = consumer_status.take();
  ASSERT_NE(nullptr, consumer_buffer);
  consumer_buffer->Discard();

  // Buffer should be returned to the producer queue without being handled by
  // the silent consumer queue.
  EXPECT_EQ(1u, consumer_queue_->count());
  EXPECT_EQ(kBufferCount - 2, producer_queue_->count());
  EXPECT_TRUE(producer_queue_->HandleQueueEvents());
  EXPECT_EQ(kBufferCount - 1, producer_queue_->count());
}

struct TestMetadata {
  char a;
  int32_t b;
  int64_t c;
};

TEST_F(BufferHubQueueTest, TestMetadata) {
  ASSERT_TRUE(CreateQueues<TestMetadata>());
  AllocateBuffer();

  std::vector<TestMetadata> ms = {
      {'0', 0, 0}, {'1', 10, 3333}, {'@', 123, 1000000000}};

  for (auto mi : ms) {
    size_t slot;
    LocalHandle fence;
    auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
    ASSERT_TRUE(p1_status.ok());
    auto p1 = p1_status.take();
    ASSERT_NE(nullptr, p1);
    ASSERT_EQ(p1->Post(LocalHandle(-1), &mi, sizeof(mi)), 0);
    TestMetadata mo;
    auto c1_status = consumer_queue_->Dequeue(0, &slot, &mo, &fence);
    ASSERT_TRUE(c1_status.ok());
    auto c1 = c1_status.take();
    ASSERT_EQ(mi.a, mo.a);
    ASSERT_EQ(mi.b, mo.b);
    ASSERT_EQ(mi.c, mo.c);
    c1->Release(LocalHandle(-1));
  }
}

TEST_F(BufferHubQueueTest, TestMetadataMismatch) {
  ASSERT_TRUE(CreateQueues<int64_t>());
  AllocateBuffer();

  int64_t mi = 3;
  size_t slot;
  LocalHandle fence;
  auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(p1_status.ok());
  auto p1 = p1_status.take();
  ASSERT_NE(nullptr, p1);
  ASSERT_EQ(p1->Post(LocalHandle(-1), &mi, sizeof(mi)), 0);

  int32_t mo;
  // Acquire a buffer with mismatched metadata is not OK.
  auto c1_status = consumer_queue_->Dequeue(0, &slot, &mo, &fence);
  ASSERT_FALSE(c1_status.ok());
}

TEST_F(BufferHubQueueTest, TestEnqueue) {
  ASSERT_TRUE(CreateQueues<int64_t>());
  AllocateBuffer();

  size_t slot;
  LocalHandle fence;
  auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(p1_status.ok());
  auto p1 = p1_status.take();
  ASSERT_NE(nullptr, p1);

  int64_t mo;
  producer_queue_->Enqueue(p1, slot);
  auto c1_status = consumer_queue_->Dequeue(0, &slot, &mo, &fence);
  ASSERT_FALSE(c1_status.ok());
}

TEST_F(BufferHubQueueTest, TestAllocateBuffer) {
  ASSERT_TRUE(CreateQueues<int64_t>());

  size_t s1;
  AllocateBuffer();
  LocalHandle fence;
  auto p1_status = producer_queue_->Dequeue(0, &s1, &fence);
  ASSERT_TRUE(p1_status.ok());
  auto p1 = p1_status.take();
  ASSERT_NE(nullptr, p1);

  // producer queue is exhausted
  size_t s2;
  auto p2_status = producer_queue_->Dequeue(0, &s2, &fence);
  ASSERT_FALSE(p2_status.ok());
  ASSERT_EQ(ETIMEDOUT, p2_status.error());

  // dynamically add buffer.
  AllocateBuffer();
  ASSERT_EQ(producer_queue_->count(), 1U);
  ASSERT_EQ(producer_queue_->capacity(), 2U);

  // now we can dequeue again
  p2_status = producer_queue_->Dequeue(0, &s2, &fence);
  ASSERT_TRUE(p2_status.ok());
  auto p2 = p2_status.take();
  ASSERT_NE(nullptr, p2);
  ASSERT_EQ(producer_queue_->count(), 0U);
  // p1 and p2 should have different slot number
  ASSERT_NE(s1, s2);

  // Consumer queue does not import buffers until |Dequeue| or |ImportBuffers|
  // are called. So far consumer_queue_ should be empty.
  ASSERT_EQ(consumer_queue_->count(), 0U);

  int64_t seq = 1;
  ASSERT_EQ(p1->Post(LocalHandle(), seq), 0);
  size_t cs1, cs2;
  auto c1_status = consumer_queue_->Dequeue(0, &cs1, &seq, &fence);
  ASSERT_TRUE(c1_status.ok());
  auto c1 = c1_status.take();
  ASSERT_NE(nullptr, c1);
  ASSERT_EQ(consumer_queue_->count(), 0U);
  ASSERT_EQ(consumer_queue_->capacity(), 2U);
  ASSERT_EQ(cs1, s1);

  ASSERT_EQ(p2->Post(LocalHandle(), seq), 0);
  auto c2_status = consumer_queue_->Dequeue(0, &cs2, &seq, &fence);
  ASSERT_TRUE(c2_status.ok());
  auto c2 = c2_status.take();
  ASSERT_NE(nullptr, c2);
  ASSERT_EQ(cs2, s2);
}

TEST_F(BufferHubQueueTest, TestUsageSetMask) {
  const uint32_t set_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(set_mask, 0, 0, 0));

  // When allocation, leave out |set_mask| from usage bits on purpose.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(kBufferWidth, kBufferHeight,
                                            kBufferFormat, kBufferLayerCount,
                                            kBufferUsage & ~set_mask, &slot);
  ASSERT_EQ(0, ret);

  LocalHandle fence;
  auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(p1_status.ok());
  auto p1 = p1_status.take();
  ASSERT_EQ(p1->usage() & set_mask, set_mask);
}

TEST_F(BufferHubQueueTest, TestUsageClearMask) {
  const uint32_t clear_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(0, clear_mask, 0, 0));

  // When allocation, add |clear_mask| into usage bits on purpose.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(kBufferWidth, kBufferHeight,
                                            kBufferLayerCount, kBufferFormat,
                                            kBufferUsage | clear_mask, &slot);
  ASSERT_EQ(0, ret);

  LocalHandle fence;
  auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(p1_status.ok());
  auto p1 = p1_status.take();
  ASSERT_EQ(0u, p1->usage() & clear_mask);
}

TEST_F(BufferHubQueueTest, TestUsageDenySetMask) {
  const uint32_t deny_set_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(0, 0, deny_set_mask, 0));

  // Now that |deny_set_mask| is illegal, allocation without those bits should
  // be able to succeed.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
      kBufferUsage & ~deny_set_mask, &slot);
  ASSERT_EQ(ret, 0);

  // While allocation with those bits should fail.
  ret = producer_queue_->AllocateBuffer(kBufferWidth, kBufferHeight,
                                        kBufferLayerCount, kBufferFormat,
                                        kBufferUsage | deny_set_mask, &slot);
  ASSERT_EQ(ret, -EINVAL);
}

TEST_F(BufferHubQueueTest, TestUsageDenyClearMask) {
  const uint32_t deny_clear_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(0, 0, 0, deny_clear_mask));

  // Now that clearing |deny_clear_mask| is illegal (i.e. setting these bits are
  // mandatory), allocation with those bits should be able to succeed.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
      kBufferUsage | deny_clear_mask, &slot);
  ASSERT_EQ(ret, 0);

  // While allocation without those bits should fail.
  ret = producer_queue_->AllocateBuffer(kBufferWidth, kBufferHeight,
                                        kBufferLayerCount, kBufferFormat,
                                        kBufferUsage & ~deny_clear_mask, &slot);
  ASSERT_EQ(ret, -EINVAL);
}

}  // namespace

}  // namespace dvr
}  // namespace android
