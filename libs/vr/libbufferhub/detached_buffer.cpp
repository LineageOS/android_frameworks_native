#include <private/dvr/detached_buffer.h>

#include <pdx/file_handle.h>
#include <ui/DetachedBufferHandle.h>

using android::pdx::LocalHandle;

namespace android {
namespace dvr {

DetachedBuffer::DetachedBuffer(uint32_t width, uint32_t height,
                               uint32_t layer_count, uint32_t format,
                               uint64_t usage, size_t user_metadata_size) {
  ATRACE_NAME("DetachedBuffer::DetachedBuffer");
  ALOGD_IF(TRACE,
           "DetachedBuffer::DetachedBuffer: width=%u height=%u layer_count=%u, "
           "format=%u usage=%" PRIx64 " user_metadata_size=%zu",
           width, height, layer_count, format, usage, user_metadata_size);

  auto status = client_.InvokeRemoteMethod<DetachedBufferRPC::Create>(
      width, height, layer_count, format, usage, user_metadata_size);
  if (!status) {
    ALOGE(
        "DetachedBuffer::DetachedBuffer: Failed to create detached buffer: %s",
        status.GetErrorMessage().c_str());
    client_.Close(-status.error());
  }

  const int ret = ImportGraphicBuffer();
  if (ret < 0) {
    ALOGE("DetachedBuffer::DetachedBuffer: Failed to import buffer: %s",
          strerror(-ret));
    client_.Close(ret);
  }
}

DetachedBuffer::DetachedBuffer(LocalChannelHandle channel_handle)
    : client_(std::move(channel_handle)) {
  const int ret = ImportGraphicBuffer();
  if (ret < 0) {
    ALOGE("DetachedBuffer::DetachedBuffer: Failed to import buffer: %s",
          strerror(-ret));
    client_.Close(ret);
  }
}

int DetachedBuffer::ImportGraphicBuffer() {
  ATRACE_NAME("DetachedBuffer::DetachedBuffer");

  auto status = client_.InvokeRemoteMethod<DetachedBufferRPC::Import>();
  if (!status) {
    ALOGE("DetachedBuffer::DetachedBuffer: Failed to import GraphicBuffer: %s",
          status.GetErrorMessage().c_str());
    return -status.error();
  }

  BufferDescription<LocalHandle> buffer_desc = status.take();
  if (buffer_desc.id() < 0) {
    ALOGE("DetachedBuffer::DetachedBuffer: Received an invalid id!");
    return -EIO;
  }

  // Stash the buffer id to replace the value in id_.
  const int buffer_id = buffer_desc.id();

  // Import the buffer.
  IonBuffer ion_buffer;
  ALOGD_IF(TRACE, "DetachedBuffer::DetachedBuffer: id=%d.", buffer_id);

  if (const int ret = buffer_desc.ImportBuffer(&ion_buffer)) {
    ALOGE("Failed to import GraphicBuffer, error=%d", ret);
    return ret;
  }

  // If all imports succeed, replace the previous buffer and id.
  id_ = buffer_id;
  buffer_ = std::move(ion_buffer);
  return 0;
}

std::unique_ptr<BufferProducer> DetachedBuffer::Promote() {
  ALOGE("DetachedBuffer::Promote: Not implemented.");
  return nullptr;
}

sp<GraphicBuffer> DetachedBuffer::TakeGraphicBuffer() {
  if (!client_.IsValid() || !buffer_.buffer()) {
    ALOGE("DetachedBuffer::TakeGraphicBuffer: Invalid buffer.");
    return nullptr;
  }

  // Technically this should never happen.
  LOG_FATAL_IF(
      buffer_.buffer()->isDetachedBuffer(),
      "DetachedBuffer::TakeGraphicBuffer: GraphicBuffer is already detached.");

  sp<GraphicBuffer> buffer = std::move(buffer_.buffer());
  buffer->setDetachedBufferHandle(
      DetachedBufferHandle::Create(client_.TakeChannelHandle()));
  return buffer;
}

}  // namespace dvr
}  // namespace android
