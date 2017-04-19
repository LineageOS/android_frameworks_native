#include "include/dvr/dvr_buffer.h"

#include <android/hardware_buffer.h>
#include <private/dvr/buffer_hub_client.h>
#include <ui/GraphicBuffer.h>

using namespace android;

struct DvrWriteBuffer {
  std::shared_ptr<dvr::BufferProducer> write_buffer;
};

struct DvrReadBuffer {
  std::shared_ptr<dvr::BufferConsumer> read_buffer;
};

struct DvrBuffer {
  std::shared_ptr<dvr::IonBuffer> buffer;
};

namespace android {
namespace dvr {

DvrWriteBuffer* CreateDvrWriteBufferFromBufferProducer(
    const std::shared_ptr<dvr::BufferProducer>& buffer_producer) {
  if (!buffer_producer)
    return nullptr;
  return new DvrWriteBuffer{std::move(buffer_producer)};
}

DvrReadBuffer* CreateDvrReadBufferFromBufferConsumer(
    const std::shared_ptr<dvr::BufferConsumer>& buffer_consumer) {
  if (!buffer_consumer)
    return nullptr;
  return new DvrReadBuffer{std::move(buffer_consumer)};
}

DvrBuffer* CreateDvrBufferFromIonBuffer(
    const std::shared_ptr<IonBuffer>& ion_buffer) {
  if (!ion_buffer)
    return nullptr;
  return new DvrBuffer{std::move(ion_buffer)};
}

}  // namespace dvr
}  // namespace android

namespace {

void InitializeGraphicBuffer(const dvr::BufferHubBuffer* buffer,
                             sp<GraphicBuffer>* graphic_buffer) {
  *graphic_buffer = sp<GraphicBuffer>(new GraphicBuffer(
      buffer->width(), buffer->height(), buffer->format(), 1, /* layer count */
      buffer->usage(), buffer->stride(), buffer->native_handle(),
      false /* keep ownership */));
}

int ConvertToAHardwareBuffer(GraphicBuffer* graphic_buffer,
                             AHardwareBuffer** hardware_buffer) {
  if (!hardware_buffer || !graphic_buffer) {
    return -EINVAL;
  }
  *hardware_buffer = reinterpret_cast<AHardwareBuffer*>(graphic_buffer);
  AHardwareBuffer_acquire(*hardware_buffer);
  return 0;
}

}  // anonymous namespace

extern "C" {

void dvrWriteBufferDestroy(DvrWriteBuffer* write_buffer) {
  delete write_buffer;
}

int dvrWriteBufferGetId(DvrWriteBuffer* write_buffer) {
  return write_buffer->write_buffer->id();
}

int dvrWriteBufferGetAHardwareBuffer(DvrWriteBuffer* write_buffer,
                                     AHardwareBuffer** hardware_buffer) {
  return ConvertToAHardwareBuffer(
      write_buffer->write_buffer->buffer()->buffer().get(), hardware_buffer);
}

int dvrWriteBufferPost(DvrWriteBuffer* write_buffer, int ready_fence_fd,
                       const void* meta, size_t meta_size_bytes) {
  pdx::LocalHandle fence(ready_fence_fd);
  int result = write_buffer->write_buffer->Post(fence, meta, meta_size_bytes);
  return result;
}

int dvrWriteBufferGain(DvrWriteBuffer* write_buffer, int* release_fence_fd) {
  pdx::LocalHandle release_fence;
  int result = write_buffer->write_buffer->Gain(&release_fence);
  *release_fence_fd = release_fence.Release();
  return result;
}

int dvrWriteBufferGainAsync(DvrWriteBuffer* write_buffer) {
  return write_buffer->write_buffer->GainAsync();
}

void dvrReadBufferDestroy(DvrReadBuffer* read_buffer) { delete read_buffer; }

int dvrReadBufferGetId(DvrReadBuffer* read_buffer) {
  return read_buffer->read_buffer->id();
}

int dvrReadBufferGetAHardwareBuffer(DvrReadBuffer* read_buffer,
                                    AHardwareBuffer** hardware_buffer) {
  return ConvertToAHardwareBuffer(
      read_buffer->read_buffer->buffer()->buffer().get(), hardware_buffer);
}

int dvrReadBufferAcquire(DvrReadBuffer* read_buffer, int* ready_fence_fd,
                         void* meta, size_t meta_size_bytes) {
  pdx::LocalHandle ready_fence;
  int result =
      read_buffer->read_buffer->Acquire(&ready_fence, meta, meta_size_bytes);
  *ready_fence_fd = ready_fence.Release();
  return result;
}

int dvrReadBufferRelease(DvrReadBuffer* read_buffer, int release_fence_fd) {
  pdx::LocalHandle fence(release_fence_fd);
  int result = read_buffer->read_buffer->Release(fence);
  return result;
}

int dvrReadBufferReleaseAsync(DvrReadBuffer* read_buffer) {
  return read_buffer->read_buffer->ReleaseAsync();
}

void dvrBufferDestroy(DvrBuffer* buffer) { delete buffer; }

int dvrBufferGetAHardwareBuffer(DvrBuffer* buffer,
                                AHardwareBuffer** hardware_buffer) {
  return ConvertToAHardwareBuffer(buffer->buffer->buffer().get(),
                                  hardware_buffer);
}

const struct native_handle* dvrWriteBufferGetNativeHandle(
    DvrWriteBuffer* write_buffer) {
  return write_buffer->write_buffer->native_handle();
}

const struct native_handle* dvrReadBufferGetNativeHandle(
    DvrReadBuffer* read_buffer) {
  return read_buffer->read_buffer->native_handle();
}

const struct native_handle* dvrBufferGetNativeHandle(DvrBuffer* buffer) {
  return buffer->buffer->handle();
}

}  // extern "C"
