#include "buffer_hub.h"

#include <cutils/log.h>
#include <poll.h>
#include <utils/Trace.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <thread>

#include <pdx/default_transport/service_endpoint.h>
#include <private/dvr/bufferhub_rpc.h>
#include "consumer_channel.h"
#include "producer_channel.h"
#include "producer_queue_channel.h"

using android::pdx::Channel;
using android::pdx::Message;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::default_transport::Endpoint;

namespace android {
namespace dvr {

BufferHubService::BufferHubService()
    : BASE("BufferHub", Endpoint::Create(BufferHubRPC::kClientPath)) {}

BufferHubService::~BufferHubService() {}

bool BufferHubService::IsInitialized() const {
  return BASE::IsInitialized() && IonBuffer::GetGrallocModule();
}

std::string BufferHubService::DumpState(size_t /*max_length*/) {
  std::ostringstream stream;
  auto channels = GetChannels<BufferHubChannel>();

  std::sort(channels.begin(), channels.end(),
            [](const std::shared_ptr<BufferHubChannel>& a,
               const std::shared_ptr<BufferHubChannel>& b) {
              return a->buffer_id() < b->buffer_id();
            });

  stream << "Active Producer Buffers:\n";
  stream << std::right;
  stream << std::setw(6) << "Id";
  stream << " ";
  stream << std::setw(9) << "Consumers";
  stream << " ";
  stream << std::setw(14) << "Geometry";
  stream << " ";
  stream << std::setw(6) << "Format";
  stream << " ";
  stream << std::setw(10) << "Usage";
  stream << " ";
  stream << "Name";
  stream << std::endl;

  for (const auto& channel : channels) {
    if (channel->channel_type() == BufferHubChannel::kProducerType) {
      BufferHubChannel::BufferInfo info = channel->GetBufferInfo();

      stream << std::right;
      stream << std::setw(6) << info.id;
      stream << " ";
      stream << std::setw(9) << info.consumer_count;
      stream << " ";
      if (info.format == HAL_PIXEL_FORMAT_BLOB) {
        std::string size = std::to_string(info.width) + " B";
        stream << std::setw(14) << size;
      } else {
        std::string dimensions = std::to_string(info.width) + "x" +
                                 std::to_string(info.height) + "x" +
                                 std::to_string(info.slice_count);
        stream << std::setw(14) << dimensions;
      }
      stream << " ";
      stream << std::setw(6) << info.format;
      stream << " ";
      stream << "0x" << std::hex << std::setfill('0');
      stream << std::setw(8) << info.usage;
      stream << std::dec << std::setfill(' ');
      stream << " ";
      stream << info.name;
      stream << std::endl;
    }
  }

  stream << "Active Consumer Buffers:\n";
  stream << std::right;
  stream << std::setw(6) << "Id";
  stream << " ";
  stream << std::setw(14) << "Geometry";
  stream << " ";
  stream << "Name";
  stream << std::endl;

  for (const auto& channel : channels) {
    if (channel->channel_type() == BufferHubChannel::kConsumerType) {
      BufferHubChannel::BufferInfo info = channel->GetBufferInfo();

      stream << std::right;
      stream << std::setw(6) << info.id;
      stream << " ";

      if (info.consumer_count == 0) {
        // consumer_count is tracked by producer. When it's zero, producer must
        // have already hung up and the consumer is orphaned.
        stream << std::setw(14) << "Orphaned.";
        stream << std::endl;
        continue;
      }

      if (info.format == HAL_PIXEL_FORMAT_BLOB) {
        std::string size = std::to_string(info.width) + " B";
        stream << std::setw(14) << size;
      } else {
        std::string dimensions = std::to_string(info.width) + "x" +
                                 std::to_string(info.height) + "x" +
                                 std::to_string(info.slice_count);
        stream << std::setw(14) << dimensions;
      }
      stream << " ";
      stream << info.name;
      stream << std::endl;
    }
  }

  stream << std::endl;
  stream << "Active Producer Queues:\n";
  stream << std::right << std::setw(6) << "Id";
  stream << std::right << std::setw(12) << " Allocated";
  stream << std::right << std::setw(12) << " Consumers";
  stream << " UsageSetMask";
  stream << " UsageClearMask";
  stream << " UsageDenySetMask";
  stream << " UsageDenyClearMask";
  stream << " ";
  stream << std::endl;

  for (const auto& channel : channels) {
    if (channel->channel_type() == BufferHubChannel::kProducerQueueType) {
      BufferHubChannel::BufferInfo info = channel->GetBufferInfo();

      stream << std::dec << std::setfill(' ');
      stream << std::right << std::setw(6) << info.id;
      stream << std::right << std::setw(12) << info.capacity;
      stream << std::right << std::setw(12) << info.consumer_count;
      stream << std::setw(5) << std::setfill(' ') << "0x";
      stream << std::hex << std::setfill('0');
      stream << std::setw(8) << info.usage_set_mask;
      stream << std::setw(7) << std::setfill(' ') << "0x";
      stream << std::hex << std::setfill('0');
      stream << std::setw(8) << info.usage_clear_mask;
      stream << std::setw(9) << std::setfill(' ') << "0x";
      stream << std::hex << std::setfill('0');
      stream << std::setw(8) << info.usage_deny_set_mask;
      stream << std::setw(11) << std::setfill(' ') << "0x";
      stream << std::hex << std::setfill('0');
      stream << std::setw(8) << info.usage_deny_clear_mask;
    }
  }

  stream << std::endl;
  stream << "Active Consumer Queues:\n";
  stream << std::dec << std::setfill(' ');
  stream << std::right << std::setw(6) << "Id";
  stream << std::right << std::setw(12) << " Imported";
  stream << " ";
  stream << std::endl;

  for (const auto& channel : channels) {
    if (channel->channel_type() == BufferHubChannel::kConsumerQueueType) {
      BufferHubChannel::BufferInfo info = channel->GetBufferInfo();

      stream << std::right << std::setw(6) << info.id;
      stream << std::right << std::setw(12) << info.capacity;
    }
  }

  return stream.str();
}

void BufferHubService::HandleImpulse(Message& message) {
  ATRACE_NAME("BufferHubService::HandleImpulse");
  if (auto channel = message.GetChannel<BufferHubChannel>())
    channel->HandleImpulse(message);
}

int BufferHubService::HandleMessage(Message& message) {
  ATRACE_NAME("BufferHubService::HandleMessage");
  auto channel = message.GetChannel<BufferHubChannel>();

  ALOGD_IF(
      TRACE,
      "BufferHubService::HandleMessage: channel=%p channel_id=%d opcode=%d",
      channel.get(), message.GetChannelId(), message.GetOp());

  // If the channel is already set up, let it handle the message.
  if (channel && !channel->HandleMessage(message))
    return DefaultHandleMessage(message);

  // This channel has not been set up yet, the following are valid operations.
  switch (message.GetOp()) {
    case BufferHubRPC::CreateBuffer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::CreateBuffer>(
          *this, &BufferHubService::OnCreateBuffer, message);
      return 0;

    case BufferHubRPC::CreatePersistentBuffer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::CreatePersistentBuffer>(
          *this, &BufferHubService::OnCreatePersistentBuffer, message);
      return 0;

    case BufferHubRPC::GetPersistentBuffer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::GetPersistentBuffer>(
          *this, &BufferHubService::OnGetPersistentBuffer, message);
      return 0;

    case BufferHubRPC::CreateProducerQueue::Opcode:
      DispatchRemoteMethod<BufferHubRPC::CreateProducerQueue>(
          *this, &BufferHubService::OnCreateProducerQueue, message);
      return 0;

    default:
      return DefaultHandleMessage(message);
  }
}

void BufferHubService::OnChannelClose(Message&,
                                      const std::shared_ptr<Channel>& channel) {
  if (auto buffer = std::static_pointer_cast<BufferHubChannel>(channel))
    buffer->Detach();
}

int BufferHubService::OnCreateBuffer(Message& message, int width, int height,
                                     int format, int usage,
                                     size_t meta_size_bytes,
                                     size_t slice_count) {
  // Use the producer channel id as the global buffer id.
  const int buffer_id = message.GetChannelId();
  ALOGD_IF(TRACE,
           "BufferHubService::OnCreateBuffer: buffer_id=%d width=%d height=%d "
           "format=%d usage=%d meta_size_bytes=%zu slice_count=%zu",
           buffer_id, width, height, format, usage, meta_size_bytes,
           slice_count);

  // See if this channel is already attached to a buffer.
  if (const auto channel = message.GetChannel<BufferHubChannel>()) {
    ALOGE("BufferHubService::OnCreateBuffer: Buffer already created: buffer=%d",
          buffer_id);
    return -EALREADY;
  }

  int error;
  if (const auto producer_channel =
          ProducerChannel::Create(this, buffer_id, width, height, format, usage,
                                  meta_size_bytes, slice_count, &error)) {
    message.SetChannel(producer_channel);
    return 0;
  } else {
    ALOGE("BufferHubService::OnCreateBuffer: Failed to create producer!!");
    return error;
  }
}

int BufferHubService::OnCreatePersistentBuffer(
    Message& message, const std::string& name, int user_id, int group_id,
    int width, int height, int format, int usage, size_t meta_size_bytes,
    size_t slice_count) {
  const int channel_id = message.GetChannelId();
  ALOGD_IF(TRACE,
           "BufferHubService::OnCreatePersistentBuffer: channel_id=%d name=%s "
           "user_id=%d group_id=%d width=%d height=%d format=%d usage=%d "
           "meta_size_bytes=%zu slice_count=%zu",
           channel_id, name.c_str(), user_id, group_id, width, height, format,
           usage, meta_size_bytes, slice_count);

  // See if this channel is already attached to a buffer.
  if (const auto channel = message.GetChannel<BufferHubChannel>()) {
    ALOGE(
        "BufferHubService::OnCreatePersistentBuffer: Channel already attached "
        "to buffer: channel_id=%d buffer_id=%d",
        channel_id, channel->buffer_id());
    return -EALREADY;
  }

  const int euid = message.GetEffectiveUserId();
  const int egid = message.GetEffectiveGroupId();
  int error;

  if (auto buffer = GetNamedBuffer(name)) {
    if (!buffer->CheckAccess(euid, egid)) {
      ALOGE(
          "BufferHubService::OnCreatePersistentBuffer: Requesting process does "
          "not have permission to access named buffer: name=%s euid=%d egid=%d",
          name.c_str(), euid, euid);
      return -EPERM;
    } else if (!buffer->CheckParameters(width, height, format, usage,
                                        meta_size_bytes, slice_count)) {
      ALOGE(
          "BufferHubService::OnCreatePersistentBuffer: Requested an existing "
          "buffer with different parameters: name=%s",
          name.c_str());
      return -EINVAL;
    } else if (!buffer->IsDetached()) {
      ALOGE(
          "BufferHubService::OnCreatePersistentBuffer: Requesting a persistent "
          "buffer that is already attached to a channel: name=%s",
          name.c_str());
      return -EINVAL;
    } else {
      buffer->Attach(channel_id);
      message.SetChannel(buffer);
      return 0;
    }
  } else if (auto buffer = ProducerChannel::Create(
                 this, channel_id, width, height, format, usage,
                 meta_size_bytes, slice_count, &error)) {
    const int ret =
        buffer->OnProducerMakePersistent(message, name, user_id, group_id);
    if (!ret)
      message.SetChannel(buffer);
    return ret;
  } else {
    ALOGE("BufferHubService::OnCreateBuffer: Failed to create producer!!");
    return error;
  }
}

int BufferHubService::OnGetPersistentBuffer(Message& message,
                                            const std::string& name) {
  const int channel_id = message.GetChannelId();
  ALOGD_IF(TRACE,
           "BufferHubService::OnGetPersistentBuffer: channel_id=%d name=%s",
           channel_id, name.c_str());

  // See if this channel is already attached to a buffer.
  if (const auto channel = message.GetChannel<BufferHubChannel>()) {
    ALOGE(
        "BufferHubService::OnGetPersistentBuffer: Channel already attached to "
        "buffer: channel_id=%d buffer_id=%d",
        channel_id, channel->buffer_id());
    return -EALREADY;
  }

  const int euid = message.GetEffectiveUserId();
  const int egid = message.GetEffectiveGroupId();

  if (auto buffer = GetNamedBuffer(name)) {
    if (!buffer->CheckAccess(euid, egid)) {
      ALOGE(
          "BufferHubService::OnGetPersistentBuffer: Requesting process does "
          "not have permission to access named buffer: name=%s euid=%d egid=%d",
          name.c_str(), euid, egid);
      return -EPERM;
    } else if (!buffer->IsDetached()) {
      ALOGE(
          "BufferHubService::OnGetPersistentBuffer: Requesting a persistent "
          "buffer that is already attached to a channel: name=%s",
          name.c_str());
      return -EINVAL;
    } else {
      buffer->Attach(channel_id);
      message.SetChannel(buffer);
      return 0;
    }
  } else {
    ALOGE("BufferHubService::OnGetPersistentBuffer: Buffer \"%s\" not found!",
          name.c_str());
    return -ENOENT;
  }
}

int BufferHubService::OnCreateProducerQueue(
    pdx::Message& message, size_t meta_size_bytes, int usage_set_mask,
    int usage_clear_mask, int usage_deny_set_mask, int usage_deny_clear_mask) {
  // Use the producer channel id as the global queue id.
  const int queue_id = message.GetChannelId();
  ALOGD_IF(TRACE, "BufferHubService::OnCreateProducerQueue: queue_id=%d",
           queue_id);

  // See if this channel is already attached to another object.
  if (const auto channel = message.GetChannel<BufferHubChannel>()) {
    ALOGE("BufferHubService::OnCreateProducerQueue: already created: queue=%d",
          queue_id);
    return -EALREADY;
  }

  int error;
  if (const auto producer_channel = ProducerQueueChannel::Create(
          this, queue_id, meta_size_bytes, usage_set_mask, usage_clear_mask,
          usage_deny_set_mask, usage_deny_clear_mask, &error)) {
    message.SetChannel(producer_channel);
    return 0;
  } else {
    ALOGE("BufferHubService::OnCreateBuffer: Failed to create producer!!");
    return error;
  }
}

bool BufferHubService::AddNamedBuffer(
    const std::string& name, const std::shared_ptr<ProducerChannel>& buffer) {
  auto search = named_buffers_.find(name);
  if (search == named_buffers_.end()) {
    named_buffers_.emplace(name, buffer);
    return true;
  } else {
    return false;
  }
}

std::shared_ptr<ProducerChannel> BufferHubService::GetNamedBuffer(
    const std::string& name) {
  auto search = named_buffers_.find(name);
  if (search != named_buffers_.end())
    return search->second;
  else
    return nullptr;
}

bool BufferHubService::RemoveNamedBuffer(const ProducerChannel& buffer) {
  for (auto it = named_buffers_.begin(); it != named_buffers_.end();) {
    if (it->second.get() == &buffer) {
      named_buffers_.erase(it);
      return true;
    }
    ++it;
  }
  return false;
}

void BufferHubChannel::SignalAvailable() {
  ATRACE_NAME("BufferHubChannel::SignalAvailable");
  if (!IsDetached()) {
    const int ret = service_->ModifyChannelEvents(channel_id_, 0, POLLIN);
    ALOGE_IF(ret < 0,
             "BufferHubChannel::SignalAvailable: failed to signal availability "
             "channel_id=%d: %s",
             channel_id_, strerror(-ret));
  } else {
    ALOGD_IF(TRACE, "BufferHubChannel::SignalAvailable: detached buffer.");
  }
}

void BufferHubChannel::ClearAvailable() {
  ATRACE_NAME("BufferHubChannel::ClearAvailable");
  if (!IsDetached()) {
    const int ret = service_->ModifyChannelEvents(channel_id_, POLLIN, 0);
    ALOGE_IF(ret < 0,
             "BufferHubChannel::ClearAvailable: failed to clear availability "
             "channel_id=%d: %s",
             channel_id_, strerror(-ret));
  } else {
    ALOGD_IF(TRACE, "BufferHubChannel::ClearAvailable: detached buffer.");
  }
}

void BufferHubChannel::Hangup() {
  ATRACE_NAME("BufferHubChannel::Hangup");
  if (!IsDetached()) {
    const int ret = service_->ModifyChannelEvents(channel_id_, 0, POLLHUP);
    ALOGE_IF(
        ret < 0,
        "BufferHubChannel::Hangup: failed to signal hangup channel_id=%d: %s",
        channel_id_, strerror(-ret));
  } else {
    ALOGD_IF(TRACE, "BufferHubChannel::Hangup: detached buffer.");
  }
}

}  // namespace dvr
}  // namespace android
