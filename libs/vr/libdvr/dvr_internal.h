#ifndef ANDROID_DVR_INTERNAL_H_
#define ANDROID_DVR_INTERNAL_H_

#include <sys/cdefs.h>

#include <memory>

extern "C" {

typedef struct DvrBuffer DvrBuffer;
typedef struct DvrReadBuffer DvrReadBuffer;
typedef struct DvrWriteBuffer DvrWriteBuffer;
typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;
typedef struct DvrReadBufferQueue DvrReadBufferQueue;

}  // extern "C"

namespace android {
namespace dvr {

class BufferProducer;
class BufferConsumer;
class ConsumerQueue;
class IonBuffer;
class ProducerQueue;

DvrBuffer* CreateDvrBufferFromIonBuffer(
    const std::shared_ptr<IonBuffer>& ion_buffer);

DvrReadBuffer* CreateDvrReadBufferFromBufferConsumer(
    const std::shared_ptr<BufferConsumer>& buffer_consumer);
DvrWriteBuffer* CreateDvrWriteBufferFromBufferProducer(
    const std::shared_ptr<BufferProducer>& buffer_producer);

DvrReadBufferQueue* CreateDvrReadBufferQueueFromConsumerQueue(
    const std::shared_ptr<ConsumerQueue>& consumer_queue);
DvrWriteBufferQueue* CreateDvrWriteBufferQueueFromProducerQueue(
    const std::shared_ptr<ProducerQueue>& producer_queue);
ProducerQueue* GetProducerQueueFromDvrWriteBufferQueue(
    DvrWriteBufferQueue* write_queue);

}  // namespace dvr
}  // namespace android

extern "C" {

struct DvrWriteBuffer {
  std::shared_ptr<android::dvr::BufferProducer> write_buffer;
};

struct DvrReadBuffer {
  std::shared_ptr<android::dvr::BufferConsumer> read_buffer;
};

struct DvrBuffer {
  std::shared_ptr<android::dvr::IonBuffer> buffer;
};

struct DvrWriteBufferQueue {
  std::shared_ptr<android::dvr::ProducerQueue> producer_queue;
  ANativeWindow* native_window{nullptr};
};

struct DvrReadBufferQueue {
  std::shared_ptr<android::dvr::ConsumerQueue> consumer_queue;
};

}  // extern "C"

#endif  // ANDROID_DVR_INTERNAL_H_
