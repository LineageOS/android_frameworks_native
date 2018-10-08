#include <pdx/default_transport/client_channel.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <pdx/file_handle.h>
#include <private/dvr/bufferhub_rpc.h>
#include <private/dvr/detached_buffer.h>
#include <ui/DetachedBufferHandle.h>

#include <poll.h>

using android::pdx::LocalChannelHandle;
using android::pdx::LocalHandle;
using android::pdx::Status;
using android::pdx::default_transport::ClientChannel;
using android::pdx::default_transport::ClientChannelFactory;

namespace android {
namespace dvr {

BufferHubClient::BufferHubClient()
    : Client(ClientChannelFactory::Create(BufferHubRPC::kClientPath)) {}

BufferHubClient::BufferHubClient(LocalChannelHandle channel_handle)
    : Client(ClientChannel::Create(std::move(channel_handle))) {}

bool BufferHubClient::IsValid() const {
  return IsConnected() && GetChannelHandle().valid();
}

LocalChannelHandle BufferHubClient::TakeChannelHandle() {
  if (IsConnected()) {
    return std::move(GetChannelHandle());
  } else {
    return {};
  }
}

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
  ATRACE_NAME("DetachedBuffer::ImportGraphicBuffer");

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

  // Import the metadata.
  IonBuffer metadata_buffer;
  if (const int ret = buffer_desc.ImportMetadata(&metadata_buffer)) {
    ALOGE("Failed to import metadata buffer, error=%d", ret);
    return ret;
  }
  size_t metadata_buf_size = metadata_buffer.width();
  if (metadata_buf_size < BufferHubDefs::kMetadataHeaderSize) {
    ALOGE("DetachedBuffer::ImportGraphicBuffer: metadata buffer too small: %zu",
          metadata_buf_size);
    return -EINVAL;
  }

  // If all imports succeed, replace the previous buffer and id.
  id_ = buffer_id;
  buffer_ = std::move(ion_buffer);
  metadata_buffer_ = std::move(metadata_buffer);
  user_metadata_size_ = metadata_buf_size - BufferHubDefs::kMetadataHeaderSize;

  void* metadata_ptr = nullptr;
  if (const int ret =
          metadata_buffer_.Lock(BufferHubDefs::kMetadataUsage, /*x=*/0,
                                /*y=*/0, metadata_buf_size,
                                /*height=*/1, &metadata_ptr)) {
    ALOGE("DetachedBuffer::ImportGraphicBuffer: Failed to lock metadata.");
    return ret;
  }

  // TODO(b/112012161) Set up shared fences.

  // Note that here the buffer state is mapped from shared memory as an atomic
  // object. The std::atomic's constructor will not be called so that the
  // original value stored in the memory region can be preserved.
  metadata_header_ = static_cast<BufferHubDefs::MetadataHeader*>(metadata_ptr);
  if (user_metadata_size_) {
    user_metadata_ptr_ = static_cast<void*>(metadata_header_ + 1);
  } else {
    user_metadata_ptr_ = nullptr;
  }

  id_ = buffer_desc.id();
  buffer_state_bit_ = buffer_desc.buffer_state_bit();

  ALOGD_IF(TRACE,
           "DetachedBuffer::ImportGraphicBuffer: id=%d, buffer_state=%" PRIx64
           ".",
           id(), metadata_header_->buffer_state.load());
  return 0;
}

int DetachedBuffer::Poll(int timeout_ms) {
  ATRACE_NAME("DetachedBuffer::Poll");
  pollfd p = {client_.event_fd(), POLLIN, 0};
  return poll(&p, 1, timeout_ms);
}

Status<LocalChannelHandle> DetachedBuffer::Promote() {
  ATRACE_NAME("DetachedBuffer::Promote");
  ALOGD_IF(TRACE, "DetachedBuffer::Promote: id=%d.", id_);

  auto status_or_handle =
      client_.InvokeRemoteMethod<DetachedBufferRPC::Promote>();
  if (status_or_handle.ok()) {
    // Invalidate the buffer.
    buffer_ = {};
  } else {
    ALOGE("DetachedBuffer::Promote: Failed to promote buffer (id=%d): %s.", id_,
          status_or_handle.GetErrorMessage().c_str());
  }
  return status_or_handle;
}

Status<LocalChannelHandle> DetachedBuffer::Duplicate() {
  ATRACE_NAME("DetachedBuffer::Duplicate");
  ALOGD_IF(TRACE, "DetachedBuffer::Duplicate: id=%d.", id_);

  auto status_or_handle =
      client_.InvokeRemoteMethod<DetachedBufferRPC::Duplicate>();

  if (!status_or_handle.ok()) {
    ALOGE("DetachedBuffer::Duplicate: Failed to duplicate buffer (id=%d): %s.",
          id_, status_or_handle.GetErrorMessage().c_str());
  }
  return status_or_handle;
}

}  // namespace dvr
}  // namespace android
