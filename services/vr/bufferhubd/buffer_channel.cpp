#include "buffer_channel.h"
#include "producer_channel.h"

using android::pdx::BorrowedHandle;
using android::pdx::ErrorStatus;
using android::pdx::Message;
using android::pdx::RemoteChannelHandle;
using android::pdx::Status;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

BufferChannel::BufferChannel(BufferHubService* service, int buffer_id,
                             int channel_id, IonBuffer buffer,
                             IonBuffer metadata_buffer,
                             size_t user_metadata_size)
    : BufferHubChannel(service, buffer_id, channel_id, kDetachedBufferType),
      buffer_node_(std::make_shared<BufferNode>(
          std::move(buffer), std::move(metadata_buffer), user_metadata_size)),
      buffer_state_bit_(BufferHubDefs::FindFirstClearedBit()) {
  buffer_node_->set_buffer_state_bit(buffer_state_bit_);
}

BufferChannel::BufferChannel(BufferHubService* service, int buffer_id,
                             uint32_t width, uint32_t height,
                             uint32_t layer_count, uint32_t format,
                             uint64_t usage, size_t user_metadata_size)
    : BufferHubChannel(service, buffer_id, buffer_id, kDetachedBufferType),
      buffer_node_(std::make_shared<BufferNode>(
          width, height, layer_count, format, usage, user_metadata_size)),
      buffer_state_bit_(BufferHubDefs::FindFirstClearedBit()) {
  buffer_node_->set_buffer_state_bit(buffer_state_bit_);
}

BufferChannel::BufferChannel(BufferHubService* service, int buffer_id,
                             int channel_id,
                             std::shared_ptr<BufferNode> buffer_node,
                             uint64_t buffer_state_bit)
    : BufferHubChannel(service, buffer_id, channel_id, kDetachedBufferType),
      buffer_node_(buffer_node),
      buffer_state_bit_(buffer_state_bit) {
  buffer_node_->set_buffer_state_bit(buffer_state_bit_);
}

BufferChannel::~BufferChannel() {
  ALOGD_IF(TRACE, "BufferChannel::~BufferChannel: channel_id=%d buffer_id=%d.",
           channel_id(), buffer_id());
  Hangup();
}

BufferHubChannel::BufferInfo BufferChannel::GetBufferInfo() const {
  return BufferInfo(
      buffer_id(), /*consumer_count=*/0, buffer_node_->buffer().width(),
      buffer_node_->buffer().height(), buffer_node_->buffer().layer_count(),
      buffer_node_->buffer().format(), buffer_node_->buffer().usage(),
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

    case DetachedBufferRPC::Promote::Opcode:
      DispatchRemoteMethod<DetachedBufferRPC::Promote>(
          *this, &BufferChannel::OnPromote, message);
      return true;

    default:
      return false;
  }
}

Status<BufferDescription<BorrowedHandle>> BufferChannel::OnImport(
    Message& /*message*/) {
  ATRACE_NAME("BufferChannel::OnImport");
  ALOGD_IF(TRACE, "BufferChannel::OnImport: buffer=%d.",
           buffer_id());

  return BufferDescription<BorrowedHandle>{buffer_node_->buffer(),
                                           buffer_node_->metadata_buffer(),
                                           buffer_id(),
                                           channel_id(),
                                           buffer_state_bit_,
                                           BorrowedHandle{},
                                           BorrowedHandle{}};
}

Status<RemoteChannelHandle> BufferChannel::OnDuplicate(
    Message& message) {
  ATRACE_NAME("BufferChannel::OnDuplicate");
  ALOGD_IF(TRACE, "BufferChannel::OnDuplicate: buffer=%d.",
           buffer_id());

  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);
  if (!status) {
    ALOGE(
        "BufferChannel::OnDuplicate: Failed to push buffer channel: %s",
        status.GetErrorMessage().c_str());
    return ErrorStatus(ENOMEM);
  }

  // Try find the next buffer state bit which has not been claimed by any
  // other buffers yet.
  uint64_t buffer_state_bit =
      BufferHubDefs::FindNextClearedBit(buffer_node_->active_buffer_bit_mask() |
                                        BufferHubDefs::kProducerStateBit);
  if (buffer_state_bit == 0ULL) {
    ALOGE(
        "BufferChannel::OnDuplicate: reached the maximum mumber of channels "
        "per buffer node: 63.");
    return ErrorStatus(E2BIG);
  }

  auto channel =
      std::shared_ptr<BufferChannel>(new BufferChannel(
          service(), buffer_id(), channel_id, buffer_node_, buffer_state_bit));
  if (!channel) {
    ALOGE("BufferChannel::OnDuplicate: Invalid buffer.");
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

Status<RemoteChannelHandle> BufferChannel::OnPromote(
    Message& message) {
  ATRACE_NAME("BufferChannel::OnPromote");
  ALOGD_IF(TRACE, "BufferChannel::OnPromote: buffer_id=%d", buffer_id());

  // Check whether this is the channel exclusive owner of the buffer_node_.
  if (buffer_state_bit_ != buffer_node_->active_buffer_bit_mask()) {
    ALOGE(
        "BufferChannel::OnPromote: Cannot promote this BufferChannel as its "
        "BufferNode is shared between multiple channels. This channel's  state "
        "bit=0x%" PRIx64 ", acitve_buffer_bit_mask=0x%" PRIx64 ".",
        buffer_state_bit_, buffer_node_->active_buffer_bit_mask());
    return ErrorStatus(EINVAL);
  }

  // Note that the new ProducerChannel will have different channel_id, but
  // inherits the buffer_id from the DetachedBuffer.
  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);
  if (!status) {
    ALOGE(
        "BufferChannel::OnPromote: Failed to push ProducerChannel: %s.",
        status.GetErrorMessage().c_str());
    return ErrorStatus(ENOMEM);
  }

  IonBuffer buffer = std::move(buffer_node_->buffer());
  IonBuffer metadata_buffer = std::move(buffer_node_->metadata_buffer());
  size_t user_metadata_size = buffer_node_->user_metadata_size();

  std::unique_ptr<ProducerChannel> channel = ProducerChannel::Create(
      service(), buffer_id(), channel_id, std::move(buffer),
      std::move(metadata_buffer), user_metadata_size);
  if (!channel) {
    ALOGE(
        "BufferChannel::OnPromote: Failed to create ProducerChannel from a "
        "BufferChannel, buffer_id=%d.",
        buffer_id());
  }

  const auto channel_status =
      service()->SetChannel(channel_id, std::move(channel));
  if (!channel_status) {
    // Technically, this should never fail, as we just pushed the channel. Note
    // that LOG_FATAL will be stripped out in non-debug build.
    LOG_FATAL(
        "BufferChannel::OnPromote: Failed to set new producer buffer channel: "
        "%s.",
        channel_status.GetErrorMessage().c_str());
  }

  return status;
}

}  // namespace dvr
}  // namespace android
