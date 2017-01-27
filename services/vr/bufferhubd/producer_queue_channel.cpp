#include "producer_queue_channel.h"

#include "consumer_queue_channel.h"
#include "producer_channel.h"

using android::pdx::RemoteChannelHandle;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

ProducerQueueChannel::ProducerQueueChannel(
    BufferHubService* service, int channel_id, size_t meta_size_bytes,
    int usage_set_mask, int usage_clear_mask, int usage_deny_set_mask,
    int usage_deny_clear_mask, int* error)
    : BufferHubChannel(service, channel_id, channel_id, kProducerQueueType),
      meta_size_bytes_(meta_size_bytes),
      usage_set_mask_(usage_set_mask),
      usage_clear_mask_(usage_clear_mask),
      usage_deny_set_mask_(usage_deny_set_mask),
      usage_deny_clear_mask_(usage_deny_clear_mask),
      capacity_(0) {
  *error = 0;
}

ProducerQueueChannel::~ProducerQueueChannel() {}

/* static */
std::shared_ptr<ProducerQueueChannel> ProducerQueueChannel::Create(
    BufferHubService* service, int channel_id, size_t meta_size_bytes,
    int usage_set_mask, int usage_clear_mask, int usage_deny_set_mask,
    int usage_deny_clear_mask, int* error) {
  // Configuration between |usage_deny_set_mask| and |usage_deny_clear_mask|
  // should be mutually exclusive.
  if (usage_deny_set_mask & usage_deny_clear_mask) {
    ALOGE(
        "BufferHubService::OnCreateProducerQueue: illegal usage mask "
        "configuration: usage_deny_set_mask=%d, usage_deny_clear_mask=%d",
        usage_deny_set_mask, usage_deny_clear_mask);
    *error = -EINVAL;
    return nullptr;
  }

  std::shared_ptr<ProducerQueueChannel> producer(new ProducerQueueChannel(
      service, channel_id, meta_size_bytes, usage_set_mask, usage_clear_mask,
      usage_deny_set_mask, usage_deny_clear_mask, error));
  if (*error < 0)
    return nullptr;
  else
    return producer;
}

bool ProducerQueueChannel::HandleMessage(Message& message) {
  ATRACE_NAME("ProducerQueueChannel::HandleMessage");
  switch (message.GetOp()) {
    case BufferHubRPC::CreateConsumerQueue::Opcode:
      DispatchRemoteMethod<BufferHubRPC::CreateConsumerQueue>(
          *this, &ProducerQueueChannel::OnCreateConsumerQueue, message);
      return true;

    case BufferHubRPC::ProducerQueueAllocateBuffers::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerQueueAllocateBuffers>(
          *this, &ProducerQueueChannel::OnProducerQueueAllocateBuffers,
          message);
      return true;

    case BufferHubRPC::ProducerQueueDetachBuffer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerQueueDetachBuffer>(
          *this, &ProducerQueueChannel::OnProducerQueueDetachBuffer, message);
      return true;

    default:
      return false;
  }
}

void ProducerQueueChannel::HandleImpulse(Message& /* message */) {
  ATRACE_NAME("ProducerQueueChannel::HandleImpulse");
}

BufferHubChannel::BufferInfo ProducerQueueChannel::GetBufferInfo() const {
  return BufferInfo(channel_id(), consumer_channels_.size(), capacity_,
                    usage_set_mask_, usage_clear_mask_, usage_deny_set_mask_,
                    usage_deny_clear_mask_);
}

std::pair<RemoteChannelHandle, size_t>
ProducerQueueChannel::OnCreateConsumerQueue(Message& message) {
  ATRACE_NAME("ProducerQueueChannel::OnCreateConsumerQueue");
  ALOGD_IF(TRACE, "ProducerQueueChannel::OnCreateConsumerQueue: channel_id=%d",
           channel_id());

  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);
  if (!status) {
    ALOGE(
        "ProducerQueueChannel::OnCreateConsumerQueue: failed to push consumer "
        "channel: %s",
        status.GetErrorMessage().c_str());
    REPLY_ERROR_RETURN(message, ENOMEM, {});
  }

  const int ret = service()->SetChannel(
      channel_id, std::make_shared<ConsumerQueueChannel>(
                      service(), buffer_id(), channel_id, shared_from_this()));
  if (ret < 0) {
    ALOGE(
        "ProducerQueueChannel::OnCreateConsumerQueue: failed to set new "
        "consumer channel: %s",
        strerror(-ret));
    REPLY_ERROR_RETURN(message, ENOMEM, {});
  }

  return std::make_pair(status.take(), meta_size_bytes_);
}

std::vector<std::pair<RemoteChannelHandle, size_t>>
ProducerQueueChannel::OnProducerQueueAllocateBuffers(Message& message,
                                                     int width, int height,
                                                     int format, int usage,
                                                     size_t slice_count,
                                                     size_t buffer_count) {
  ATRACE_NAME("ProducerQueueChannel::OnProducerQueueAllocateBuffers");
  ALOGD_IF(TRACE,
           "ProducerQueueChannel::OnProducerQueueAllocateBuffers: "
           "producer_channel_id=%d",
           channel_id());

  std::vector<std::pair<RemoteChannelHandle, size_t>> buffer_handles;

  // Deny buffer allocation violating preset rules.
  if (usage & usage_deny_set_mask_) {
    ALOGE(
        "ProducerQueueChannel::OnProducerQueueAllocateBuffers: usage: %d is "
        "not permitted. Violating usage_deny_set_mask, the following bits "
        "shall not be set: %d.",
        usage, usage_deny_set_mask_);
    REPLY_ERROR_RETURN(message, EINVAL, buffer_handles);
  }

  if (~usage & usage_deny_clear_mask_) {
    ALOGE(
        "ProducerQueueChannel::OnProducerQueueAllocateBuffers: usage: %d is "
        "not permitted. Violating usage_deny_clear_mask, the following bits "
        "must be set: %d.",
        usage, usage_deny_clear_mask_);
    REPLY_ERROR_RETURN(message, EINVAL, buffer_handles);
  }

  // Force set mask and clear mask. Note that |usage_set_mask_| takes precedence
  // and will overwrite |usage_clear_mask_|.
  int effective_usage = (usage & ~usage_clear_mask_) | usage_set_mask_;

  for (size_t i = 0; i < buffer_count; i++) {
    auto buffer_handle_slot = AllocateBuffer(message, width, height, format,
                                             effective_usage, slice_count);
    if (!buffer_handle_slot.first) {
      ALOGE(
          "ProducerQueueChannel::OnProducerQueueAllocateBuffers: failed to "
          "allocate new buffer.");
      REPLY_ERROR_RETURN(message, ENOMEM, buffer_handles);
    }
    buffer_handles.emplace_back(std::move(buffer_handle_slot.first),
                                buffer_handle_slot.second);
  }

  return buffer_handles;
}

std::pair<RemoteChannelHandle, size_t> ProducerQueueChannel::AllocateBuffer(
    Message& message, int width, int height, int format, int usage,
    size_t slice_count) {
  ATRACE_NAME("ProducerQueueChannel::AllocateBuffer");
  ALOGD_IF(TRACE,
           "ProducerQueueChannel::AllocateBuffer: producer_channel_id=%d",
           channel_id());

  if (capacity_ >= BufferHubRPC::kMaxQueueCapacity) {
    ALOGE("ProducerQueueChannel::AllocateBuffer: reaches kMaxQueueCapacity.");
    return {};
  }

  // Here we are creating a new BufferHubBuffer, initialize the producer
  // channel, and returning its file handle back to the client.
  // buffer_id is the id of the producer channel of BufferHubBuffer.
  int buffer_id;
  auto status = message.PushChannel(0, nullptr, &buffer_id);

  if (!status) {
    ALOGE("ProducerQueueChannel::AllocateBuffer: failed to push channel: %s",
          status.GetErrorMessage().c_str());
    return {};
  }

  ALOGD_IF(TRACE,
           "ProducerQueueChannel::AllocateBuffer: buffer_id=%d width=%d "
           "height=%d format=%d usage=%d slice_count=%zu",
           buffer_id, width, height, format, usage, slice_count);
  auto buffer_handle = status.take();

  int error;
  const auto producer_channel = ProducerChannel::Create(
      service(), buffer_id, width, height, format, usage,
      meta_size_bytes_, slice_count, &error);
  if (!producer_channel) {
    ALOGE(
        "ProducerQueueChannel::AllocateBuffer: Failed to create "
        "BufferHubBuffer producer!!");
    return {};
  }

  ALOGD_IF(
      TRACE,
      "ProducerQueueChannel::AllocateBuffer: buffer_id=%d, buffer_handle=%d",
      buffer_id, buffer_handle.value());

  const int ret = service()->SetChannel(buffer_id, producer_channel);
  if (ret < 0) {
    ALOGE(
        "ProducerQueueChannel::AllocateBuffer: failed to set prodcuer channel "
        "for new BufferHubBuffer: %s",
        strerror(-ret));
    return {};
  }

  // Register the newly allocated buffer's channel_id into the first empty
  // buffer slot.
  size_t slot = 0;
  for (; slot < BufferHubRPC::kMaxQueueCapacity; slot++) {
    if (buffers_[slot].expired())
      break;
  }
  if (slot == BufferHubRPC::kMaxQueueCapacity) {
    ALOGE(
        "ProducerQueueChannel::AllocateBuffer: Cannot find empty slot for new "
        "buffer allocation.");
    return {};
  }

  buffers_[slot] = producer_channel;
  capacity_++;

  // Notify each consumer channel about the new buffer.
  for (auto consumer_channel : consumer_channels_) {
    ALOGD(
        "ProducerQueueChannel::AllocateBuffer: Notified consumer with new "
        "buffer, buffer_id=%d",
        buffer_id);
    consumer_channel->RegisterNewBuffer(producer_channel, slot);
  }

  return {std::move(buffer_handle), slot};
}

int ProducerQueueChannel::OnProducerQueueDetachBuffer(Message& message,
                                                      size_t slot) {
  if (buffers_[slot].expired()) {
    ALOGE(
        "ProducerQueueChannel::OnProducerQueueDetachBuffer: trying to detach "
        "an invalid buffer producer at slot %zu",
        slot);
    return -EINVAL;
  }

  if (capacity_ == 0) {
    ALOGE(
        "ProducerQueueChannel::OnProducerQueueDetachBuffer: trying to detach a "
        "buffer producer while the queue's capacity is already zero.");
    return -EINVAL;
  }

  buffers_[slot].reset();
  capacity_--;
  return 0;
}

void ProducerQueueChannel::AddConsumer(ConsumerQueueChannel* channel) {
  consumer_channels_.push_back(channel);
}

void ProducerQueueChannel::RemoveConsumer(ConsumerQueueChannel* channel) {
  consumer_channels_.erase(
      std::find(consumer_channels_.begin(), consumer_channels_.end(), channel));
}

}  // namespace dvr
}  // namespace android
