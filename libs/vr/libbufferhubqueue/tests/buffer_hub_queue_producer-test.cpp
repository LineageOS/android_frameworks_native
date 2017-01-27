#include <private/dvr/buffer_hub_queue_producer.h>

#include <base/logging.h>
#include <gui/Surface.h>
#include <gtest/gtest.h>

namespace android {
namespace dvr {

namespace {

class BufferHubQueueProducerTest : public ::testing::Test {};

TEST_F(BufferHubQueueProducerTest, TempTestBufferHubQueueProducer) {
  auto core = BufferHubQueueCore::Create();
  sp<BufferHubQueueProducer> producer = new BufferHubQueueProducer(core);
  sp<Surface> surface = new Surface(producer, true);
}

}  // namespace

}  // namespace dvr
}  // namespace android
