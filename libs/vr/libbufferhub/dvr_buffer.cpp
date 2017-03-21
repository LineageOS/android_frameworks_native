#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/dvr_buffer.h>
#include <ui/GraphicBuffer.h>

using namespace android;

struct DvrWriteBuffer {
  std::unique_ptr<dvr::BufferProducer> write_buffer_;
  sp<GraphicBuffer> graphic_buffer_;
};

struct DvrReadBuffer {
  std::unique_ptr<dvr::BufferConsumer> read_buffer_;
  sp<GraphicBuffer> graphic_buffer_;
};

namespace android {
namespace dvr {

DvrWriteBuffer* CreateDvrWriteBufferFromBufferProducer(
    std::unique_ptr<dvr::BufferProducer> buffer_producer) {
  DvrWriteBuffer* write_buffer = new DvrWriteBuffer;
  write_buffer->write_buffer_ = std::move(buffer_producer);
  return write_buffer;
}

DvrReadBuffer* CreateDvrReadBufferFromBufferConsumer(
    std::unique_ptr<dvr::BufferConsumer> buffer_consumer) {
  DvrReadBuffer* read_buffer = new DvrReadBuffer;
  read_buffer->read_buffer_ = std::move(buffer_consumer);
  return read_buffer;
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

}  // anonymous namespace

extern "C" {

void dvrWriteBufferDestroy(DvrWriteBuffer* client) { delete client; }

void dvrWriteBufferGetBlobFds(DvrWriteBuffer* client, int* fds,
                              size_t* fds_count, size_t max_fds_count) {
  client->write_buffer_->GetBlobFds(fds, fds_count, max_fds_count);
}

int dvrWriteBufferGetAHardwareBuffer(DvrWriteBuffer* client,
                                     AHardwareBuffer** hardware_buffer) {
  if (!client->graphic_buffer_.get()) {
    InitializeGraphicBuffer(client->write_buffer_.get(),
                            &client->graphic_buffer_);
  }
  *hardware_buffer =
      reinterpret_cast<AHardwareBuffer*>(client->graphic_buffer_.get());
  return 0;
}

int dvrWriteBufferPost(DvrWriteBuffer* client, int ready_fence_fd,
                       const void* meta, size_t meta_size_bytes) {
  pdx::LocalHandle fence(ready_fence_fd);
  int result = client->write_buffer_->Post(fence, meta, meta_size_bytes);
  fence.Release();
  return result;
}

int dvrWriteBufferGain(DvrWriteBuffer* client, int* release_fence_fd) {
  pdx::LocalHandle release_fence;
  int result = client->write_buffer_->Gain(&release_fence);
  *release_fence_fd = release_fence.Release();
  return result;
}

int dvrWriteBufferGainAsync(DvrWriteBuffer* client) {
  return client->write_buffer_->GainAsync();
}

void dvrReadBufferGetBlobFds(DvrReadBuffer* client, int* fds, size_t* fds_count,
                             size_t max_fds_count) {
  client->read_buffer_->GetBlobFds(fds, fds_count, max_fds_count);
}

int dvrReadBufferGetAHardwareBuffer(DvrReadBuffer* client,
                                    AHardwareBuffer** hardware_buffer) {
  if (!client->graphic_buffer_.get()) {
    InitializeGraphicBuffer(client->read_buffer_.get(),
                            &client->graphic_buffer_);
  }
  *hardware_buffer =
      reinterpret_cast<AHardwareBuffer*>(client->graphic_buffer_.get());
  return 0;
}

int dvrReadBufferAcquire(DvrReadBuffer* client, int* ready_fence_fd, void* meta,
                         size_t meta_size_bytes) {
  pdx::LocalHandle ready_fence;
  int result =
      client->read_buffer_->Acquire(&ready_fence, meta, meta_size_bytes);
  *ready_fence_fd = ready_fence.Release();
  return result;
}

int dvrReadBufferRelease(DvrReadBuffer* client, int release_fence_fd) {
  pdx::LocalHandle fence(release_fence_fd);
  int result = client->read_buffer_->Release(fence);
  fence.Release();
  return result;
}

int dvrReadBufferReleaseAsync(DvrReadBuffer* client) {
  return client->read_buffer_->ReleaseAsync();
}

}  // extern "C"
