#include "detached_buffer_channel.h"

using android::pdx::ErrorStatus;
using android::pdx::Message;
using android::pdx::RemoteChannelHandle;
using android::pdx::Status;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

DetachedBufferChannel::DetachedBufferChannel(BufferHubService* service,
                                             int buffer_id, int channel_id,
                                             IonBuffer buffer,
                                             IonBuffer metadata_buffer,
                                             size_t user_metadata_size)
    : BufferHubChannel(service, buffer_id, channel_id, kDetachedBufferType),
      buffer_(std::move(buffer)),
      metadata_buffer_(std::move(metadata_buffer)),
      user_metadata_size_(user_metadata_size) {}

BufferHubChannel::BufferInfo DetachedBufferChannel::GetBufferInfo() const {
  return BufferInfo(buffer_id(), /*consumer_count=*/0, buffer_.width(),
                    buffer_.height(), buffer_.layer_count(), buffer_.format(),
                    buffer_.usage(), /*pending_count=*/0, /*state=*/0,
                    /*signaled_mask=*/0, /*index=*/0);
}

void DetachedBufferChannel::HandleImpulse(Message& /*message*/) {
  ATRACE_NAME("DetachedBufferChannel::HandleImpulse");
}

bool DetachedBufferChannel::HandleMessage(Message& message) {
  ATRACE_NAME("DetachedBufferChannel::HandleMessage");
  switch (message.GetOp()) {
    case BufferHubRPC::DetachedBufferPromote::Opcode:
      DispatchRemoteMethod<BufferHubRPC::DetachedBufferPromote>(
          *this, &DetachedBufferChannel::OnPromote, message);
      return true;

    default:
      return false;
  }
}

Status<RemoteChannelHandle> DetachedBufferChannel::OnPromote(
    Message& /*message*/) {
  ATRACE_NAME("DetachedBufferChannel::OnPromote");
  ALOGD_IF(TRACE, "DetachedBufferChannel::OnPromote: buffer_id=%d",
           buffer_id());

  // TODO(b/69982239): Implement the logic to promote a detached buffer.
  return ErrorStatus(ENOSYS);
}

}  // namespace dvr
}  // namespace android
