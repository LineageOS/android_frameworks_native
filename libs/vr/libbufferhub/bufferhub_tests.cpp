#include <gtest/gtest.h>
#include <private/dvr/buffer_hub_client.h>

#include <mutex>
#include <thread>

#define RETRY_EINTR(fnc_call)                 \
  ([&]() -> decltype(fnc_call) {              \
    decltype(fnc_call) result;                \
    do {                                      \
      result = (fnc_call);                    \
    } while (result == -1 && errno == EINTR); \
    return result;                            \
  })()

using android::dvr::BufferProducer;
using android::dvr::BufferConsumer;
using android::pdx::LocalHandle;

const int kWidth = 640;
const int kHeight = 480;
const int kFormat = HAL_PIXEL_FORMAT_RGBA_8888;
const int kUsage = 0;
const uint64_t kContext = 42;

using LibBufferHubTest = ::testing::Test;

TEST_F(LibBufferHubTest, TestBasicUsage) {
  std::unique_ptr<BufferProducer> p = BufferProducer::Create(
      kWidth, kHeight, kFormat, kUsage, sizeof(uint64_t));
  ASSERT_TRUE(p.get() != nullptr);
  std::unique_ptr<BufferConsumer> c =
      BufferConsumer::Import(p->CreateConsumer());
  ASSERT_TRUE(c.get() != nullptr);
  // Check that consumers can spawn other consumers.
  std::unique_ptr<BufferConsumer> c2 =
      BufferConsumer::Import(c->CreateConsumer());
  ASSERT_TRUE(c2.get() != nullptr);

  EXPECT_EQ(0, p->Post(LocalHandle(), kContext));
  // Both consumers should be triggered.
  EXPECT_GE(0, RETRY_EINTR(p->Poll(0)));
  EXPECT_LT(0, RETRY_EINTR(c->Poll(10)));
  EXPECT_LT(0, RETRY_EINTR(c2->Poll(10)));

  uint64_t context;
  LocalHandle fence;
  EXPECT_LE(0, c->Acquire(&fence, &context));
  EXPECT_EQ(kContext, context);
  EXPECT_GE(0, RETRY_EINTR(c->Poll(0)));

  EXPECT_LE(0, c2->Acquire(&fence, &context));
  EXPECT_EQ(kContext, context);
  EXPECT_GE(0, RETRY_EINTR(c2->Poll(0)));

  EXPECT_EQ(0, c->Release(LocalHandle()));
  EXPECT_GE(0, RETRY_EINTR(p->Poll(0)));
  EXPECT_EQ(0, c2->Discard());

  EXPECT_LE(0, RETRY_EINTR(p->Poll(0)));
  EXPECT_EQ(0, p->Gain(&fence));
  EXPECT_GE(0, RETRY_EINTR(p->Poll(0)));
}

TEST_F(LibBufferHubTest, TestWithCustomMetadata) {
  struct Metadata {
    int64_t field1;
    int64_t field2;
  };
  std::unique_ptr<BufferProducer> p = BufferProducer::Create(
      kWidth, kHeight, kFormat, kUsage, sizeof(Metadata));
  ASSERT_TRUE(p.get() != nullptr);
  std::unique_ptr<BufferConsumer> c =
      BufferConsumer::Import(p->CreateConsumer());
  ASSERT_TRUE(c.get() != nullptr);

  Metadata m = {1, 3};
  EXPECT_EQ(0, p->Post(LocalHandle(), m));
  EXPECT_LE(0, RETRY_EINTR(c->Poll(10)));

  LocalHandle fence;
  Metadata m2 = {};
  EXPECT_EQ(0, c->Acquire(&fence, &m2));
  EXPECT_EQ(m.field1, m2.field1);
  EXPECT_EQ(m.field2, m2.field2);

  EXPECT_EQ(0, c->Release(LocalHandle()));
  EXPECT_LT(0, RETRY_EINTR(p->Poll(0)));
}

TEST_F(LibBufferHubTest, TestPostWithWrongMetaSize) {
  struct Metadata {
    int64_t field1;
    int64_t field2;
  };
  std::unique_ptr<BufferProducer> p = BufferProducer::Create(
      kWidth, kHeight, kFormat, kUsage, sizeof(Metadata));
  ASSERT_TRUE(p.get() != nullptr);
  std::unique_ptr<BufferConsumer> c =
      BufferConsumer::Import(p->CreateConsumer());
  ASSERT_TRUE(c.get() != nullptr);

  int64_t sequence = 3;
  EXPECT_NE(0, p->Post(LocalHandle(), sequence));
  EXPECT_GE(0, RETRY_EINTR(c->Poll(10)));
}

TEST_F(LibBufferHubTest, TestAcquireWithWrongMetaSize) {
  struct Metadata {
    int64_t field1;
    int64_t field2;
  };
  std::unique_ptr<BufferProducer> p = BufferProducer::Create(
      kWidth, kHeight, kFormat, kUsage, sizeof(Metadata));
  ASSERT_TRUE(p.get() != nullptr);
  std::unique_ptr<BufferConsumer> c =
      BufferConsumer::Import(p->CreateConsumer());
  ASSERT_TRUE(c.get() != nullptr);

  Metadata m = {1, 3};
  EXPECT_EQ(0, p->Post(LocalHandle(), m));

  LocalHandle fence;
  int64_t sequence;
  EXPECT_NE(0, c->Acquire(&fence, &sequence));
}

TEST_F(LibBufferHubTest, TestAcquireWithNoMeta) {
  std::unique_ptr<BufferProducer> p = BufferProducer::Create(
      kWidth, kHeight, kFormat, kUsage, sizeof(uint64_t));
  ASSERT_TRUE(p.get() != nullptr);
  std::unique_ptr<BufferConsumer> c =
      BufferConsumer::Import(p->CreateConsumer());
  ASSERT_TRUE(c.get() != nullptr);

  int64_t sequence = 3;
  EXPECT_EQ(0, p->Post(LocalHandle(), sequence));

  LocalHandle fence;
  EXPECT_EQ(0, c->Acquire(&fence));
}

TEST_F(LibBufferHubTest, TestWithNoMeta) {
  std::unique_ptr<BufferProducer> p =
      BufferProducer::Create(kWidth, kHeight, kFormat, kUsage);
  ASSERT_TRUE(p.get() != nullptr);
  std::unique_ptr<BufferConsumer> c =
      BufferConsumer::Import(p->CreateConsumer());
  ASSERT_TRUE(c.get() != nullptr);

  LocalHandle fence;

  EXPECT_EQ(0, p->Post<void>(LocalHandle()));
  EXPECT_EQ(0, c->Acquire(&fence));
}

TEST_F(LibBufferHubTest, TestFailureToPostMetaFromABufferWithoutMeta) {
  std::unique_ptr<BufferProducer> p =
      BufferProducer::Create(kWidth, kHeight, kFormat, kUsage);
  ASSERT_TRUE(p.get() != nullptr);
  std::unique_ptr<BufferConsumer> c =
      BufferConsumer::Import(p->CreateConsumer());
  ASSERT_TRUE(c.get() != nullptr);

  int64_t sequence = 3;
  EXPECT_NE(0, p->Post(LocalHandle(), sequence));
}

TEST_F(LibBufferHubTest, TestPersistentBufferPersistence) {
  auto p = BufferProducer::Create("TestPersistentBuffer", -1, -1, kWidth,
                                  kHeight, kFormat, kUsage);
  ASSERT_NE(nullptr, p);

  // Record the original buffer id for later comparison.
  const int buffer_id = p->id();

  auto c = BufferConsumer::Import(p->CreateConsumer());
  ASSERT_NE(nullptr, c);

  EXPECT_EQ(0, p->Post<void>(LocalHandle()));

  // Close the connection to the producer. This should not affect the consumer.
  p = nullptr;

  LocalHandle fence;
  EXPECT_EQ(0, c->Acquire(&fence));
  EXPECT_EQ(0, c->Release(LocalHandle()));

  // Attempt to reconnect to the persistent buffer.
  p = BufferProducer::Create("TestPersistentBuffer");
  ASSERT_NE(nullptr, p);
  EXPECT_EQ(buffer_id, p->id());
  EXPECT_EQ(0, p->Gain(&fence));
}

TEST_F(LibBufferHubTest, TestPersistentBufferMismatchParams) {
  auto p = BufferProducer::Create("TestPersistentBuffer", -1, -1, kWidth,
                                  kHeight, kFormat, kUsage);
  ASSERT_NE(nullptr, p);

  // Close the connection to the producer.
  p = nullptr;

  // Mismatch the params.
  p = BufferProducer::Create("TestPersistentBuffer", -1, -1, kWidth * 2,
                             kHeight, kFormat, kUsage);
  ASSERT_EQ(nullptr, p);
}

TEST_F(LibBufferHubTest, TestRemovePersistentBuffer) {
  auto p = BufferProducer::Create("TestPersistentBuffer", -1, -1, kWidth,
                                  kHeight, kFormat, kUsage);
  ASSERT_NE(nullptr, p);

  LocalHandle fence;
  auto c = BufferConsumer::Import(p->CreateConsumer());
  ASSERT_NE(nullptr, c);
  EXPECT_NE(-EPIPE, c->Acquire(&fence));

  // Test that removing persistence and closing the producer orphans the
  // consumer.
  EXPECT_EQ(0, p->RemovePersistence());
  p = nullptr;

  EXPECT_EQ(-EPIPE, c->Release(LocalHandle()));
}
