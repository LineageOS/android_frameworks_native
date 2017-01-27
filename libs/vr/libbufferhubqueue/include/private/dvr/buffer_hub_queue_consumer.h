#ifndef ANDROID_DVR_BUFFER_HUB_QUEUE_CONSUMER_H_
#define ANDROID_DVR_BUFFER_HUB_QUEUE_CONSUMER_H_

#include <private/dvr/buffer_hub_queue_core.h>

#include <gui/IGraphicBufferConsumer.h>

namespace android {
namespace dvr {

class BufferHubQueueConsumer : public IGraphicBufferConsumer {
 public:
  BufferHubQueueConsumer(const std::shared_ptr<BufferHubQueueCore>& core);

 private:
  std::shared_ptr<BufferHubQueueCore> core_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_QUEUE_CONSUMER_H_
