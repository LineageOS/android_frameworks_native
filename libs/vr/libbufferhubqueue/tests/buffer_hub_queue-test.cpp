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
constexpr int kBufferFormat = HAL_PIXEL_FORMAT_BLOB;
constexpr int kBufferUsage = GRALLOC_USAGE_SW_READ_RARELY;
constexpr int kBufferSliceCount = 1;  // number of slices in each buffer

class BufferHubQueueTest : public ::testing::Test {
 public:
  template <typename Meta>
  bool CreateQueues(int usage_set_mask = 0, int usage_clear_mask = 0,
                    int usage_deny_set_mask = 0,
                    int usage_deny_clear_mask = 0) {
    producer_queue_ =
        ProducerQueue::Create<Meta>(usage_set_mask, usage_clear_mask,
                                    usage_deny_set_mask, usage_deny_clear_mask);
    if (!producer_queue_)
      return false;

    consumer_queue_ = producer_queue_->CreateConsumerQueue();
    if (!consumer_queue_)
      return false;

    return true;
  }

  void AllocateBuffer() {
    // Create producer buffer.
    size_t slot;
    int ret = producer_queue_->AllocateBuffer(kBufferWidth, kBufferHeight,
                                              kBufferFormat, kBufferUsage,
                                              kBufferSliceCount, &slot);
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
    auto p1 = producer_queue_->Dequeue(0, &slot, &fence);
    ASSERT_NE(nullptr, p1);
    size_t mi = i;
    ASSERT_EQ(p1->Post(LocalHandle(), &mi, sizeof(mi)), 0);
    size_t mo;
    auto c1 = consumer_queue_->Dequeue(100, &slot, &mo, &fence);
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
    // Dequeue returns nullptr since no buffer is ready to consumer, but
    // this implicitly triggers buffer import and bump up |capacity|.
    LocalHandle fence;
    auto consumer_null = consumer_queue_->Dequeue(0, &slot, &seq, &fence);
    ASSERT_EQ(nullptr, consumer_null);
    ASSERT_EQ(consumer_queue_->capacity(), i + 1);
  }

  for (size_t i = 0; i < nb_buffer; i++) {
    LocalHandle fence;
    // First time, there is no buffer available to dequeue.
    auto buffer_null = consumer_queue_->Dequeue(0, &slot, &seq, &fence);
    ASSERT_EQ(nullptr, buffer_null);

    // Make sure Producer buffer is Post()'ed so that it's ready to Accquire
    // in the consumer's Dequeue() function.
    auto producer = producer_queue_->Dequeue(0, &slot, &fence);
    ASSERT_NE(nullptr, producer);

    uint64_t seq_in = static_cast<uint64_t>(i);
    ASSERT_EQ(producer->Post({}, &seq_in, sizeof(seq_in)), 0);

    // Second time, the just |Post()|'ed buffer should be dequeued.
    uint64_t seq_out = 0;
    auto consumer = consumer_queue_->Dequeue(0, &slot, &seq_out, &fence);
    ASSERT_NE(nullptr, consumer);
    ASSERT_EQ(seq_in, seq_out);
  }
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
    auto p1 = producer_queue_->Dequeue(0, &slot, &fence);
    ASSERT_NE(nullptr, p1);
    ASSERT_EQ(p1->Post(LocalHandle(-1), &mi, sizeof(mi)), 0);
    TestMetadata mo;
    auto c1 = consumer_queue_->Dequeue(0, &slot, &mo, &fence);
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
  auto p1 = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_NE(nullptr, p1);
  ASSERT_EQ(p1->Post(LocalHandle(-1), &mi, sizeof(mi)), 0);

  int32_t mo;
  // Acquire a buffer with mismatched metadata is not OK.
  auto c1 = consumer_queue_->Dequeue(0, &slot, &mo, &fence);
  ASSERT_EQ(nullptr, c1);
}

TEST_F(BufferHubQueueTest, TestEnqueue) {
  ASSERT_TRUE(CreateQueues<int64_t>());
  AllocateBuffer();

  size_t slot;
  LocalHandle fence;
  auto p1 = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_NE(nullptr, p1);

  int64_t mo;
  producer_queue_->Enqueue(p1, slot);
  auto c1 = consumer_queue_->Dequeue(0, &slot, &mo, &fence);
  ASSERT_EQ(nullptr, c1);
}

TEST_F(BufferHubQueueTest, TestAllocateBuffer) {
  ASSERT_TRUE(CreateQueues<int64_t>());

  size_t s1;
  AllocateBuffer();
  LocalHandle fence;
  auto p1 = producer_queue_->Dequeue(0, &s1, &fence);
  ASSERT_NE(nullptr, p1);

  // producer queue is exhausted
  size_t s2;
  auto p2_null = producer_queue_->Dequeue(0, &s2, &fence);
  ASSERT_EQ(nullptr, p2_null);

  // dynamically add buffer.
  AllocateBuffer();
  ASSERT_EQ(producer_queue_->count(), 1U);
  ASSERT_EQ(producer_queue_->capacity(), 2U);

  // now we can dequeue again
  auto p2 = producer_queue_->Dequeue(0, &s2, &fence);
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
  auto c1 = consumer_queue_->Dequeue(0, &cs1, &seq, &fence);
  ASSERT_NE(nullptr, c1);
  ASSERT_EQ(consumer_queue_->count(), 0U);
  ASSERT_EQ(consumer_queue_->capacity(), 2U);
  ASSERT_EQ(cs1, s1);

  ASSERT_EQ(p2->Post(LocalHandle(), seq), 0);
  auto c2 = consumer_queue_->Dequeue(0, &cs2, &seq, &fence);
  ASSERT_NE(nullptr, c2);
  ASSERT_EQ(cs2, s2);
}

TEST_F(BufferHubQueueTest, TestUsageSetMask) {
  const int set_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(set_mask, 0, 0, 0));

  // When allocation, leave out |set_mask| from usage bits on purpose.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferFormat, kBufferUsage & ~set_mask,
      kBufferSliceCount, &slot);
  ASSERT_EQ(ret, 0);

  LocalHandle fence;
  auto p1 = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_EQ(p1->usage() & set_mask, set_mask);
}

TEST_F(BufferHubQueueTest, TestUsageClearMask) {
  const int clear_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(0, clear_mask, 0, 0));

  // When allocation, add |clear_mask| into usage bits on purpose.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferFormat, kBufferUsage | clear_mask,
      kBufferSliceCount, &slot);
  ASSERT_EQ(ret, 0);

  LocalHandle fence;
  auto p1 = producer_queue_->Dequeue(0, &slot, &fence);
  ASSERT_EQ(p1->usage() & clear_mask, 0);
}

TEST_F(BufferHubQueueTest, TestUsageDenySetMask) {
  const int deny_set_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(0, 0, deny_set_mask, 0));

  // Now that |deny_set_mask| is illegal, allocation without those bits should
  // be able to succeed.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferFormat, kBufferUsage & ~deny_set_mask,
      kBufferSliceCount, &slot);
  ASSERT_EQ(ret, 0);

  // While allocation with those bits should fail.
  ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferFormat, kBufferUsage | deny_set_mask,
      kBufferSliceCount, &slot);
  ASSERT_EQ(ret, -EINVAL);
}

TEST_F(BufferHubQueueTest, TestUsageDenyClearMask) {
  const int deny_clear_mask = GRALLOC_USAGE_SW_WRITE_OFTEN;
  ASSERT_TRUE(CreateQueues<int64_t>(0, 0, 0, deny_clear_mask));

  // Now that clearing |deny_clear_mask| is illegal (i.e. setting these bits are
  // mandatory), allocation with those bits should be able to succeed.
  size_t slot;
  int ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferFormat,
      kBufferUsage | deny_clear_mask, kBufferSliceCount, &slot);
  ASSERT_EQ(ret, 0);

  // While allocation without those bits should fail.
  ret = producer_queue_->AllocateBuffer(
      kBufferWidth, kBufferHeight, kBufferFormat,
      kBufferUsage & ~deny_clear_mask, kBufferSliceCount, &slot);
  ASSERT_EQ(ret, -EINVAL);
}

}  // namespace

}  // namespace dvr
}  // namespace android
