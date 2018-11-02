#include <errno.h>
#include <private/dvr/buffer_channel.h>
#include <private/dvr/producer_channel.h>

using android::pdx::BorrowedHandle;
using android::pdx::ErrorStatus;
using android::pdx::Message;
using android::pdx::RemoteChannelHandle;
using android::pdx::Status;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

BufferChannel::BufferChannel(BufferHubService* service, int buffer_id,
                             uint32_t width, uint32_t height,
                             uint32_t layer_count, uint32_t format,
                             uint64_t usage, size_t user_metadata_size)
    : BufferHubChannel(service, buffer_id, buffer_id, kDetachedBufferType) {
  buffer_node_ = std::make_shared<BufferNode>(
      width, height, layer_count, format, usage, user_metadata_size);
  if (!buffer_node_->IsValid()) {
    ALOGE("BufferChannel::BufferChannel: Failed to create BufferNode.");
    return;
  }
  client_state_mask_ = buffer_node_->AddNewActiveClientsBitToMask();
}

BufferChannel::BufferChannel(BufferHubService* service, int buffer_id,
                             int channel_id,
                             std::shared_ptr<BufferNode> buffer_node)
    : BufferHubChannel(service, buffer_id, channel_id, kDetachedBufferType),
      buffer_node_(buffer_node) {
  client_state_mask_ = buffer_node_->AddNewActiveClientsBitToMask();
  if (client_state_mask_ == 0ULL) {
    ALOGE("BufferChannel::BufferChannel: %s", strerror(errno));
    buffer_node_ = nullptr;
  }
}

BufferChannel::~BufferChannel() {
  ALOGD_IF(TRACE, "BufferChannel::~BufferChannel: channel_id=%d buffer_id=%d.",
           channel_id(), buffer_id());
  if (client_state_mask_ != 0ULL) {
    buffer_node_->RemoveClientsBitFromMask(client_state_mask_);
  }
  Hangup();
}

BufferHubChannel::BufferInfo BufferChannel::GetBufferInfo() const {
  return BufferInfo(
      buffer_id(), /*consumer_count=*/0, buffer_node_->buffer_desc().width,
      buffer_node_->buffer_desc().height, buffer_node_->buffer_desc().layers,
      buffer_node_->buffer_desc().format, buffer_node_->buffer_desc().usage,
      /*pending_count=*/0, /*state=*/0, /*signaled_mask=*/0,
      /*index=*/0);
}

void BufferChannel::HandleImpulse(Message& /*message*/) {
  ATRACE_NAME("BufferChannel::HandleImpulse");
}

bool BufferChannel::HandleMessage(Message& message) {
  ATRACE_NAME("BufferChannel::HandleMessage");
  switch (message.GetOp()) {
    case DetachedBufferRPC::Import::Opcode:
      DispatchRemoteMethod<DetachedBufferRPC::Import>(
          *this, &BufferChannel::OnImport, message);
      return true;

    case DetachedBufferRPC::Duplicate::Opcode:
      DispatchRemoteMethod<DetachedBufferRPC::Duplicate>(
          *this, &BufferChannel::OnDuplicate, message);
      return true;

    default:
      return false;
  }
}

Status<BufferTraits<BorrowedHandle>> BufferChannel::OnImport(
    Message& /*message*/) {
  ATRACE_NAME("BufferChannel::OnImport");
  ALOGD_IF(TRACE, "BufferChannel::OnImport: buffer=%d.", buffer_id());

  // TODO(b/112057680) Move away from the GraphicBuffer-based IonBuffer.
  return BufferTraits<BorrowedHandle>{
      /*buffer_handle=*/buffer_node_->buffer_handle(),
      /*metadata_handle=*/buffer_node_->metadata().ashmem_handle().Borrow(),
      /*id=*/buffer_id(),
      /*client_state_mask=*/client_state_mask_,
      /*metadata_size=*/buffer_node_->metadata().metadata_size(),
      /*width=*/buffer_node_->buffer_desc().width,
      /*height=*/buffer_node_->buffer_desc().height,
      /*layer_count=*/buffer_node_->buffer_desc().layers,
      /*format=*/buffer_node_->buffer_desc().format,
      /*usage=*/buffer_node_->buffer_desc().usage,
      /*stride=*/buffer_node_->buffer_desc().stride,
      /*acquire_fence_fd=*/BorrowedHandle{},
      /*released_fence_fd=*/BorrowedHandle{}};
}

Status<RemoteChannelHandle> BufferChannel::OnDuplicate(Message& message) {
  ATRACE_NAME("BufferChannel::OnDuplicate");
  ALOGD_IF(TRACE, "BufferChannel::OnDuplicate: buffer=%d.", buffer_id());

  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);
  if (!status.ok()) {
    ALOGE("BufferChannel::OnDuplicate: Failed to push buffer channel: %s",
          status.GetErrorMessage().c_str());
    return ErrorStatus(ENOMEM);
  }

  auto channel = std::shared_ptr<BufferChannel>(
      new BufferChannel(service(), buffer_id(), channel_id, buffer_node_));
  if (!channel->IsValid()) {
    ALOGE("BufferChannel::OnDuplicate: Invalid buffer. %s", strerror(errno));
    return ErrorStatus(EINVAL);
  }

  const auto channel_status =
      service()->SetChannel(channel_id, std::move(channel));
  if (!channel_status) {
    // Technically, this should never fail, as we just pushed the channel. Note
    // that LOG_FATAL will be stripped out in non-debug build.
    LOG_FATAL(
        "BufferChannel::OnDuplicate: Failed to set new buffer channel: %s.",
        channel_status.GetErrorMessage().c_str());
  }

  return status;
}

}  // namespace dvr
}  // namespace android
