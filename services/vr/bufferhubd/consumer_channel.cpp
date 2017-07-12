#include "consumer_channel.h"

#include <log/log.h>
#include <utils/Trace.h>

#include <thread>

#include <private/dvr/bufferhub_rpc.h>
#include "producer_channel.h"

using android::pdx::BorrowedHandle;
using android::pdx::Channel;
using android::pdx::ErrorStatus;
using android::pdx::Message;
using android::pdx::Status;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

ConsumerChannel::ConsumerChannel(BufferHubService* service, int buffer_id,
                                 int channel_id,
                                 const std::shared_ptr<Channel> producer)
    : BufferHubChannel(service, buffer_id, channel_id, kConsumerType),
      producer_(producer) {
  GetProducer()->AddConsumer(this);
}

ConsumerChannel::~ConsumerChannel() {
  ALOGD_IF(TRACE,
           "ConsumerChannel::~ConsumerChannel: channel_id=%d buffer_id=%d",
           channel_id(), buffer_id());

  if (auto producer = GetProducer()) {
    if (!released_)  // Producer is waiting for our Release.
      producer->OnConsumerIgnored();
    producer->RemoveConsumer(this);
  }
}

BufferHubChannel::BufferInfo ConsumerChannel::GetBufferInfo() const {
  BufferHubChannel::BufferInfo info;
  if (auto producer = GetProducer()) {
    // If producer has not hung up, copy most buffer info from the producer.
    info = producer->GetBufferInfo();
  }
  info.id = buffer_id();
  return info;
}

std::shared_ptr<ProducerChannel> ConsumerChannel::GetProducer() const {
  return std::static_pointer_cast<ProducerChannel>(producer_.lock());
}

void ConsumerChannel::HandleImpulse(Message& message) {
  ATRACE_NAME("ConsumerChannel::HandleImpulse");
  switch (message.GetOp()) {
    case BufferHubRPC::ConsumerRelease::Opcode:
      OnConsumerRelease(message, {});
      break;
  }
}

bool ConsumerChannel::HandleMessage(Message& message) {
  ATRACE_NAME("ConsumerChannel::HandleMessage");
  auto producer = GetProducer();
  if (!producer)
    REPLY_ERROR_RETURN(message, EPIPE, true);

  switch (message.GetOp()) {
    case BufferHubRPC::GetBuffer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::GetBuffer>(
          *producer, &ProducerChannel::OnGetBuffer, message);
      return true;

    case BufferHubRPC::NewConsumer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::NewConsumer>(
          *producer, &ProducerChannel::OnNewConsumer, message);
      return true;

    case BufferHubRPC::ConsumerAcquire::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ConsumerAcquire>(
          *this, &ConsumerChannel::OnConsumerAcquire, message);
      return true;

    case BufferHubRPC::ConsumerRelease::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ConsumerRelease>(
          *this, &ConsumerChannel::OnConsumerRelease, message);
      return true;

    case BufferHubRPC::ConsumerSetIgnore::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ConsumerSetIgnore>(
          *this, &ConsumerChannel::OnConsumerSetIgnore, message);
      return true;

    default:
      return false;
  }
}

Status<std::pair<BorrowedFence, ConsumerChannel::MetaData>>
ConsumerChannel::OnConsumerAcquire(Message& message,
                                   std::size_t metadata_size) {
  ATRACE_NAME("ConsumerChannel::OnConsumerAcquire");
  auto producer = GetProducer();
  if (!producer)
    return ErrorStatus(EPIPE);

  if (acquired_ || released_) {
    ALOGE(
        "ConsumerChannel::OnConsumerAcquire: Acquire when not posted: "
        "ignored=%d acquired=%d released=%d channel_id=%d buffer_id=%d",
        ignored_, acquired_, released_, message.GetChannelId(),
        producer->buffer_id());
    return ErrorStatus(EBUSY);
  } else {
    auto status = producer->OnConsumerAcquire(message, metadata_size);
    if (status) {
      ClearAvailable();
      acquired_ = true;
    }
    return status;
  }
}

Status<void> ConsumerChannel::OnConsumerRelease(Message& message,
                                                LocalFence release_fence) {
  ATRACE_NAME("ConsumerChannel::OnConsumerRelease");
  auto producer = GetProducer();
  if (!producer)
    return ErrorStatus(EPIPE);

  if (!acquired_ || released_) {
    ALOGE(
        "ConsumerChannel::OnConsumerRelease: Release when not acquired: "
        "ignored=%d acquired=%d released=%d channel_id=%d buffer_id=%d",
        ignored_, acquired_, released_, message.GetChannelId(),
        producer->buffer_id());
    return ErrorStatus(EBUSY);
  } else {
    auto status =
        producer->OnConsumerRelease(message, std::move(release_fence));
    if (status) {
      ClearAvailable();
      acquired_ = false;
      released_ = true;
    }
    return status;
  }
}

Status<void> ConsumerChannel::OnConsumerSetIgnore(Message&, bool ignored) {
  ATRACE_NAME("ConsumerChannel::OnConsumerSetIgnore");
  auto producer = GetProducer();
  if (!producer)
    return ErrorStatus(EPIPE);

  ignored_ = ignored;
  if (ignored_ && acquired_) {
    // Update the producer if ignore is set after the consumer acquires the
    // buffer.
    ClearAvailable();
    producer->OnConsumerIgnored();
    acquired_ = false;
    released_ = true;
  }

  return {};
}

bool ConsumerChannel::OnProducerPosted() {
  if (ignored_) {
    acquired_ = false;
    released_ = true;
    return false;
  } else {
    acquired_ = false;
    released_ = false;
    SignalAvailable();
    return true;
  }
}

void ConsumerChannel::OnProducerClosed() {
  producer_.reset();
  Hangup();
}

}  // namespace dvr
}  // namespace android
