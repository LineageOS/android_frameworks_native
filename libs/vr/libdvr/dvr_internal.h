#ifndef ANDROID_DVR_INTERNAL_H_
#define ANDROID_DVR_INTERNAL_H_

#include <sys/cdefs.h>

#include <memory>

extern "C" {

typedef struct DvrBuffer DvrBuffer;
typedef struct DvrReadBuffer DvrReadBuffer;
typedef struct DvrWriteBuffer DvrWriteBuffer;

}  // extern "C"

namespace android {
namespace dvr {

// TODO(b/116855254): Remove this typedef once rename is complete in libdvr.
// Note that the dvr::BufferProducer and dvr::BufferConsumer were poorly named,
// they should really be named as ProducerBuffer and ConsumerBuffer.
typedef class ProducerBuffer BufferProducer;
typedef class ConsumerBuffer BufferConsumer;
class IonBuffer;

DvrBuffer* CreateDvrBufferFromIonBuffer(
    const std::shared_ptr<IonBuffer>& ion_buffer);

DvrReadBuffer* CreateDvrReadBufferFromBufferConsumer(
    const std::shared_ptr<BufferConsumer>& buffer_consumer);
DvrWriteBuffer* CreateDvrWriteBufferFromBufferProducer(
    const std::shared_ptr<BufferProducer>& buffer_producer);

}  // namespace dvr
}  // namespace android

extern "C" {

struct DvrWriteBuffer {
  // The slot nubmer of the buffer, a valid slot number must be in the range of
  // [0, android::BufferQueueDefs::NUM_BUFFER_SLOTS). This is only valid for
  // DvrWriteBuffer acquired from a DvrWriteBufferQueue.
  int32_t slot = -1;

  std::shared_ptr<android::dvr::BufferProducer> write_buffer;
};

struct DvrReadBuffer {
  // The slot nubmer of the buffer, a valid slot number must be in the range of
  // [0, android::BufferQueueDefs::NUM_BUFFER_SLOTS). This is only valid for
  // DvrReadBuffer acquired from a DvrReadBufferQueue.
  int32_t slot = -1;

  std::shared_ptr<android::dvr::BufferConsumer> read_buffer;
};

struct DvrBuffer {
  std::shared_ptr<android::dvr::IonBuffer> buffer;
};

}  // extern "C"

#endif  // ANDROID_DVR_INTERNAL_H_
