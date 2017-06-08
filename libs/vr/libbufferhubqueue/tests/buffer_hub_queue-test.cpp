#include <base/logging.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/buffer_hub_queue_client.h>

#include <gtest/gtest.h>

#include <vector>

// Enable/disable debug logging.
#define TRACE 0

namespace android {
namespace dvr {

using pdx::LocalHandle;

namespace {

constexpr uint32_t kBufferWidth = 100;
constexpr uint32_t kBufferHeight = 1;
constexpr uint32_t kBufferLayerCount = 1;
constexpr uint32_t kBufferFormat = HAL_PIXEL_FORMAT_BLOB;
constexpr uint64_t kBufferUsage = GRALLOC_USAGE_SW_READ_RARELY;

class BufferHubQueueTest : public ::testing::Test {
 public:
  bool CreateProducerQueue(const ProducerQueueConfig& config,
                           const UsagePolicy& usage) {
    producer_queue_ = ProducerQueue::Create(config, usage);
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

  bool CreateQueues(const ProducerQueueConfig& config,
                    const UsagePolicy& usage) {
    return CreateProducerQueue(config, usage) && CreateConsumerQueue();
  }

  void AllocateBuffer(size_t* slot_out = nullptr) {
    // Create producer buffer.
    auto status = producer_queue_->AllocateBuffer(
        kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
        kBufferUsage);

    ASSERT_TRUE(status.ok());
    size_t slot = status.take();
    if (slot_out)
      *slot_out = slot;
  }

 protected:
  ProducerQueueConfigBuilder config_builder_;
  std::unique_ptr<ProducerQueue> producer_queue_;
  std::unique_ptr<ConsumerQueue> consumer_queue_;
};

TEST_F(BufferHubQueueTest, TestDequeue) {
  const size_t nb_dequeue_times = 16;

  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<size_t>().Build(),
                           UsagePolicy{}));

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
  const size_t kBufferCount = 16;
  size_t slot;
  uint64_t seq;

  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<uint64_t>().Build(),
                           UsagePolicy{}));

  for (size_t i = 0; i < kBufferCount; i++) {
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

  // Use /dev/zero as a stand-in for a fence. As long as BufferHub does not need
  // to merge fences, which only happens when multiple consumers release the
  // same buffer with release fences, the file object should simply pass
  // through.
  LocalHandle post_fence("/dev/zero", O_RDONLY);
  struct stat post_fence_stat;
  ASSERT_EQ(0, fstat(post_fence.Get(), &post_fence_stat));

  for (size_t i = 0; i < kBufferCount; i++) {
    LocalHandle fence;

    // First time there is no buffer available to dequeue.
    auto consumer_status = consumer_queue_->Dequeue(0, &slot, &seq, &fence);
    ASSERT_FALSE(consumer_status.ok());
    ASSERT_EQ(ETIMEDOUT, consumer_status.error());

    // Make sure Producer buffer is POSTED so that it's ready to Accquire
    // in the consumer's Dequeue() function.
    auto producer_status = producer_queue_->Dequeue(0, &slot, &fence);
    ASSERT_TRUE(producer_status.ok());
    auto producer = producer_status.take();
    ASSERT_NE(nullptr, producer);

    uint64_t seq_in = static_cast<uint64_t>(i);
    ASSERT_EQ(producer->Post(post_fence, &seq_in, sizeof(seq_in)), 0);

    // Second time the just the POSTED buffer should be dequeued.
    uint64_t seq_out = 0;
    consumer_status = consumer_queue_->Dequeue(0, &slot, &seq_out, &fence);
    ASSERT_TRUE(consumer_status.ok());
    EXPECT_TRUE(fence.IsValid());

    struct stat acquire_fence_stat;
    ASSERT_EQ(0, fstat(fence.Get(), &acquire_fence_stat));

    // The file descriptors should refer to the same file object. Testing the
    // device id and inode is a proxy for testing that the fds refer to the same
    // file object.
    EXPECT_NE(post_fence.Get(), fence.Get());
    EXPECT_EQ(post_fence_stat.st_dev, acquire_fence_stat.st_dev);
    EXPECT_EQ(post_fence_stat.st_ino, acquire_fence_stat.st_ino);

    auto consumer = consumer_status.take();
    ASSERT_NE(nullptr, consumer);
    ASSERT_EQ(seq_in, seq_out);
  }
}

TEST_F(BufferHubQueueTest, TestRemoveBuffer) {
  ASSERT_TRUE(CreateProducerQueue(config_builder_.Build(), UsagePolicy{}));

  // Allocate buffers.
  const size_t kBufferCount = 4u;
  for (size_t i = 0; i < kBufferCount; i++) {
    AllocateBuffer();
  }
  ASSERT_EQ(kBufferCount, producer_queue_->count());
  ASSERT_EQ(kBufferCount, producer_queue_->capacity());

  consumer_queue_ = producer_queue_->CreateConsumerQueue();
  ASSERT_NE(nullptr, consumer_queue_);

  // Check that buffers are correctly imported on construction.
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());
  EXPECT_EQ(0u, consumer_queue_->count());

  // Dequeue all the buffers and keep track of them in an array. This prevents
  // the producer queue ring buffer ref counts from interfering with the tests.
  struct Entry {
    std::shared_ptr<BufferProducer> buffer;
    LocalHandle fence;
    size_t slot;
  };
  std::array<Entry, kBufferCount> buffers;

  for (size_t i = 0; i < kBufferCount; i++) {
    Entry* entry = &buffers[i];
    auto producer_status =
        producer_queue_->Dequeue(0, &entry->slot, &entry->fence);
    ASSERT_TRUE(producer_status.ok());
    entry->buffer = producer_status.take();
    ASSERT_NE(nullptr, entry->buffer);
    EXPECT_EQ(i, entry->slot);
  }

  // Remove a buffer and make sure both queues reflect the change.
  ASSERT_TRUE(producer_queue_->RemoveBuffer(buffers[0].slot));
  EXPECT_EQ(kBufferCount - 1, producer_queue_->capacity());

  // As long as the removed buffer is still alive the consumer queue won't know
  // its gone.
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());
  EXPECT_FALSE(consumer_queue_->HandleQueueEvents());
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());

  // Release the removed buffer.
  buffers[0].buffer = nullptr;

  // Now the consumer queue should know it's gone.
  EXPECT_FALSE(consumer_queue_->HandleQueueEvents());
  EXPECT_EQ(kBufferCount - 1, consumer_queue_->capacity());

  // Allocate a new buffer. This should take the first empty slot.
  size_t slot;
  AllocateBuffer(&slot);
  ALOGE_IF(TRACE, "ALLOCATE %zu", slot);
  EXPECT_EQ(buffers[0].slot, slot);
  EXPECT_EQ(kBufferCount, producer_queue_->capacity());

  // The consumer queue should pick up the new buffer.
  EXPECT_EQ(kBufferCount - 1, consumer_queue_->capacity());
  EXPECT_FALSE(consumer_queue_->HandleQueueEvents());
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());

  // Remove and allocate a buffer.
  ASSERT_TRUE(producer_queue_->RemoveBuffer(buffers[1].slot));
  EXPECT_EQ(kBufferCount - 1, producer_queue_->capacity());
  buffers[1].buffer = nullptr;

  AllocateBuffer(&slot);
  ALOGE_IF(TRACE, "ALLOCATE %zu", slot);
  EXPECT_EQ(buffers[1].slot, slot);
  EXPECT_EQ(kBufferCount, producer_queue_->capacity());

  // The consumer queue should pick up the new buffer but the count shouldn't
  // change.
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());
  EXPECT_FALSE(consumer_queue_->HandleQueueEvents());
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());

  // Remove and allocate a buffer, but don't free the buffer right away.
  ASSERT_TRUE(producer_queue_->RemoveBuffer(buffers[2].slot));
  EXPECT_EQ(kBufferCount - 1, producer_queue_->capacity());

  AllocateBuffer(&slot);
  ALOGE_IF(TRACE, "ALLOCATE %zu", slot);
  EXPECT_EQ(buffers[2].slot, slot);
  EXPECT_EQ(kBufferCount, producer_queue_->capacity());

  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());
  EXPECT_FALSE(consumer_queue_->HandleQueueEvents());
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());

  // Release the producer buffer to trigger a POLLHUP event for an already
  // removed buffer.
  buffers[2].buffer = nullptr;
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());
  EXPECT_FALSE(consumer_queue_->HandleQueueEvents());
  EXPECT_EQ(kBufferCount, consumer_queue_->capacity());
}

TEST_F(BufferHubQueueTest, TestMultipleConsumers) {
  // ProducerConfigureBuilder doesn't set Metadata{size}, which means there
  // is no metadata associated with this BufferQueue's buffer.
  ASSERT_TRUE(CreateProducerQueue(config_builder_.Build(), UsagePolicy{}));

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
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<TestMetadata>().Build(),
                           UsagePolicy{}));

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
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<int64_t>().Build(),
                           UsagePolicy{}));

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
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<int64_t>().Build(),
                           UsagePolicy{}));
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
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<int64_t>().Build(),
                           UsagePolicy{}));

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
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<int64_t>().Build(),
                           UsagePolicy{set_mask, 0, 0, 0}));

  // When allocation, leave out |set_mask| from usage bits on purpose.
  auto status = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
      kBufferUsage & ~set_mask);
  ASSERT_TRUE(status.ok());

  LocalHandle fence;
  size_t slot;
  auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(p1_status.ok());
  auto p1 = p1_status.take();
  ASSERT_EQ(p1->usage() & set_mask, set_mask);
}

TEST_F(BufferHubQueueTest, TestUsageClearMask) {
  const uint32_t clear_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<int64_t>().Build(),
                           UsagePolicy{0, clear_mask, 0, 0}));

  // When allocation, add |clear_mask| into usage bits on purpose.
  auto status = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
      kBufferUsage | clear_mask);
  ASSERT_TRUE(status.ok());

  LocalHandle fence;
  size_t slot;
  auto p1_status = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_TRUE(p1_status.ok());
  auto p1 = p1_status.take();
  ASSERT_EQ(0u, p1->usage() & clear_mask);
}

TEST_F(BufferHubQueueTest, TestUsageDenySetMask) {
  const uint32_t deny_set_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<int64_t>().Build(),
                           UsagePolicy{0, 0, deny_set_mask, 0}));

  // Now that |deny_set_mask| is illegal, allocation without those bits should
  // be able to succeed.
  auto status = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
      kBufferUsage & ~deny_set_mask);
  ASSERT_TRUE(status.ok());

  // While allocation with those bits should fail.
  status = producer_queue_->AllocateBuffer(kBufferWidth, kBufferHeight,
                                           kBufferLayerCount, kBufferFormat,
                                           kBufferUsage | deny_set_mask);
  ASSERT_FALSE(status.ok());
  ASSERT_EQ(EINVAL, status.error());
}

TEST_F(BufferHubQueueTest, TestUsageDenyClearMask) {
  const uint32_t deny_clear_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues(config_builder_.SetMetadata<int64_t>().Build(),
                           UsagePolicy{0, 0, 0, deny_clear_mask}));

  // Now that clearing |deny_clear_mask| is illegal (i.e. setting these bits are
  // mandatory), allocation with those bits should be able to succeed.
  auto status = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
      kBufferUsage | deny_clear_mask);
  ASSERT_TRUE(status.ok());

  // While allocation without those bits should fail.
  status = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferLayerCount, kBufferFormat,
      kBufferUsage & ~deny_clear_mask);
  ASSERT_FALSE(status.ok());
  ASSERT_EQ(EINVAL, status.error());
}

TEST_F(BufferHubQueueTest, TestQueueInfo) {
  static const bool kIsAsync = true;
  ASSERT_TRUE(CreateQueues(config_builder_.SetIsAsync(kIsAsync)
                               .SetDefaultWidth(kBufferWidth)
                               .SetDefaultHeight(kBufferHeight)
                               .SetDefaultFormat(kBufferFormat)
                               .Build(),
                           UsagePolicy{}));

  EXPECT_EQ(producer_queue_->default_width(), kBufferWidth);
  EXPECT_EQ(producer_queue_->default_height(), kBufferHeight);
  EXPECT_EQ(producer_queue_->default_format(), kBufferFormat);
  EXPECT_EQ(producer_queue_->is_async(), kIsAsync);

  EXPECT_EQ(consumer_queue_->default_width(), kBufferWidth);
  EXPECT_EQ(consumer_queue_->default_height(), kBufferHeight);
  EXPECT_EQ(consumer_queue_->default_format(), kBufferFormat);
  EXPECT_EQ(consumer_queue_->is_async(), kIsAsync);
}

}  // namespace

}  // namespace dvr
}  // namespace android
