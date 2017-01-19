#include "producer_channel.h"

#include <log/log.h>
#include <sync/sync.h>
#include <sys/poll.h>
#include <utils/Trace.h>

#include <algorithm>
#include <atomic>
#include <thread>

#include <private/dvr/bufferhub_rpc.h>
#include "consumer_channel.h"

using android::pdx::BorrowedHandle;
using android::pdx::Message;
using android::pdx::RemoteChannelHandle;
using android::pdx::rpc::BufferWrapper;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::rpc::WrapBuffer;

namespace android {
namespace dvr {

ProducerChannel::ProducerChannel(BufferHubService* service, int channel_id,
                                 int width, int height, int format, int usage,
                                 size_t meta_size_bytes, size_t slice_count,
                                 int* error)
    : BufferHubChannel(service, channel_id, channel_id, kProducerType),
      pending_consumers_(0),
      slices_(std::max(static_cast<size_t>(1), slice_count)),
      producer_owns_(true),
      meta_size_bytes_(meta_size_bytes),
      meta_(meta_size_bytes ? new uint8_t[meta_size_bytes] : nullptr) {
  for (auto& ion_buffer : slices_) {
    const int ret = ion_buffer.Alloc(width, height, format, usage);
    if (ret < 0) {
      ALOGE("ProducerChannel::ProducerChannel: Failed to allocate buffer: %s",
            strerror(-ret));
      *error = ret;
      return;
    }
  }

  // Success.
  *error = 0;
}

std::shared_ptr<ProducerChannel> ProducerChannel::Create(
    BufferHubService* service, int channel_id, int width, int height,
    int format, int usage, size_t meta_size_bytes, size_t slice_count,
    int* error) {
  std::shared_ptr<ProducerChannel> producer(
      new ProducerChannel(service, channel_id, width, height, format, usage,
                          meta_size_bytes, slice_count, error));
  if (*error < 0)
    return nullptr;
  else
    return producer;
}

ProducerChannel::~ProducerChannel() {
  ALOGD_IF(TRACE,
           "ProducerChannel::~ProducerChannel: channel_id=%d buffer_id=%d",
           channel_id(), buffer_id());
  for (auto consumer : consumer_channels_)
    consumer->OnProducerClosed();
}

BufferHubChannel::BufferInfo ProducerChannel::GetBufferInfo() const {
  return BufferInfo(buffer_id(), consumer_channels_.size(), slices_[0].width(),
                    slices_[0].height(), slices_[0].format(),
                    slices_[0].usage(), slices_.size(), name_);
}

void ProducerChannel::HandleImpulse(Message& message) {
  ATRACE_NAME("ProducerChannel::HandleImpulse");
  switch (message.GetOp()) {
    case BufferHubRPC::ProducerGain::Opcode:
      OnProducerGain(message);
      break;
  }
}

bool ProducerChannel::HandleMessage(Message& message) {
  ATRACE_NAME("ProducerChannel::HandleMessage");
  switch (message.GetOp()) {
    case BufferHubRPC::GetBuffer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::GetBuffer>(
          *this, &ProducerChannel::OnGetBuffer, message);
      return true;

    case BufferHubRPC::GetBuffers::Opcode:
      DispatchRemoteMethod<BufferHubRPC::GetBuffers>(
          *this, &ProducerChannel::OnGetBuffers, message);
      return true;

    case BufferHubRPC::NewConsumer::Opcode:
      DispatchRemoteMethod<BufferHubRPC::NewConsumer>(
          *this, &ProducerChannel::OnNewConsumer, message);
      return true;

    case BufferHubRPC::ProducerPost::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerPost>(
          *this, &ProducerChannel::OnProducerPost, message);
      return true;

    case BufferHubRPC::ProducerGain::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerGain>(
          *this, &ProducerChannel::OnProducerGain, message);
      return true;

    case BufferHubRPC::ProducerMakePersistent::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerMakePersistent>(
          *this, &ProducerChannel::OnProducerMakePersistent, message);
      return true;

    case BufferHubRPC::ProducerRemovePersistence::Opcode:
      DispatchRemoteMethod<BufferHubRPC::ProducerRemovePersistence>(
          *this, &ProducerChannel::OnRemovePersistence, message);
      return true;

    default:
      return false;
  }
}

NativeBufferHandle<BorrowedHandle> ProducerChannel::OnGetBuffer(
    Message& message, unsigned index) {
  ATRACE_NAME("ProducerChannel::OnGetBuffer");
  ALOGD_IF(TRACE, "ProducerChannel::OnGetBuffer: buffer=%d", buffer_id());
  if (index < slices_.size()) {
    return NativeBufferHandle<BorrowedHandle>(slices_[index], buffer_id());
  } else {
    REPLY_ERROR_RETURN(message, EINVAL, NativeBufferHandle<BorrowedHandle>());
  }
}

std::vector<NativeBufferHandle<BorrowedHandle>> ProducerChannel::OnGetBuffers(
    Message&) {
  ATRACE_NAME("ProducerChannel::OnGetBuffers");
  ALOGD_IF(TRACE, "ProducerChannel::OnGetBuffers: buffer_id=%d", buffer_id());
  std::vector<NativeBufferHandle<BorrowedHandle>> buffer_handles;
  for (const auto& buffer : slices_)
    buffer_handles.emplace_back(buffer, buffer_id());
  return buffer_handles;
}

RemoteChannelHandle ProducerChannel::CreateConsumer(Message& message) {
  ATRACE_NAME("ProducerChannel::CreateConsumer");
  ALOGD_IF(TRACE, "ProducerChannel::CreateConsumer: buffer_id=%d", buffer_id());

  int channel_id;
  auto status = message.PushChannel(0, nullptr, &channel_id);
  if (!status) {
    ALOGE(
        "ProducerChannel::CreateConsumer: failed to push consumer channel: %s",
        status.GetErrorMessage().c_str());
    return RemoteChannelHandle();
  }

  auto consumer = std::make_shared<ConsumerChannel>(
      service(), buffer_id(), channel_id, shared_from_this());
  const int ret = service()->SetChannel(channel_id, consumer);
  if (ret < 0) {
    ALOGE(
        "ProducerChannel::CreateConsumer: failed to set new consumer channel: "
        "%s",
        strerror(-ret));
    return RemoteChannelHandle();
  }

  if (!producer_owns_) {
    // Signal the new consumer when adding it to a posted producer.
    if (consumer->OnProducerPosted())
      pending_consumers_++;
  }

  return status.take();
}

RemoteChannelHandle ProducerChannel::OnNewConsumer(Message& message) {
  ATRACE_NAME("ProducerChannel::OnNewConsumer");
  ALOGD_IF(TRACE, "ProducerChannel::OnNewConsumer: buffer_id=%d", buffer_id());

  RemoteChannelHandle consumer_handle(CreateConsumer(message));

  if (consumer_handle.valid())
    return consumer_handle;
  else
    REPLY_ERROR_RETURN(message, ENOMEM, RemoteChannelHandle());
}

int ProducerChannel::OnProducerPost(
    Message&, LocalFence acquire_fence,
    BufferWrapper<std::vector<std::uint8_t>> metadata) {
  ATRACE_NAME("ProducerChannel::OnProducerPost");
  ALOGD_IF(TRACE, "ProducerChannel::OnProducerPost: buffer_id=%d", buffer_id());
  if (!producer_owns_) {
    ALOGE("ProducerChannel::OnProducerPost: Not in gained state!");
    return -EBUSY;
  }

  if (meta_size_bytes_ != metadata.size())
    return -EINVAL;
  std::copy(metadata.begin(), metadata.end(), meta_.get());

  post_fence_ = std::move(acquire_fence);
  producer_owns_ = false;

  // Signal any interested consumers. If there are none, automatically release
  // the buffer.
  pending_consumers_ = 0;
  for (auto consumer : consumer_channels_) {
    if (consumer->OnProducerPosted())
      pending_consumers_++;
  }
  if (pending_consumers_ == 0)
    SignalAvailable();
  ALOGD_IF(TRACE, "ProducerChannel::OnProducerPost: %d pending consumers",
           pending_consumers_);

  return 0;
}

LocalFence ProducerChannel::OnProducerGain(Message& message) {
  ATRACE_NAME("ProducerChannel::OnGain");
  ALOGD_IF(TRACE, "ProducerChannel::OnGain: buffer_id=%d", buffer_id());
  if (producer_owns_) {
    ALOGE("ProducerChanneL::OnGain: Already in gained state: channel=%d",
          channel_id());
    REPLY_ERROR_RETURN(message, EALREADY, {});
  }

  // There are still pending consumers, return busy.
  if (pending_consumers_ > 0)
    REPLY_ERROR_RETURN(message, EBUSY, {});

  ClearAvailable();
  producer_owns_ = true;
  post_fence_.get_fd();
  return std::move(returned_fence_);
}

std::pair<BorrowedFence, BufferWrapper<std::uint8_t*>>
ProducerChannel::OnConsumerAcquire(Message& message,
                                   std::size_t metadata_size) {
  ATRACE_NAME("ProducerChannel::OnConsumerAcquire");
  ALOGD_IF(TRACE, "ProducerChannel::OnConsumerAcquire: buffer_id=%d",
           buffer_id());
  if (producer_owns_) {
    ALOGE("ProducerChannel::OnConsumerAcquire: Not in posted state!");
    REPLY_ERROR_RETURN(message, EBUSY, {});
  }

  // Return a borrowed fd to avoid unnecessary duplication of the underlying fd.
  // Serialization just needs to read the handle.
  if (metadata_size == 0)
    return std::make_pair(post_fence_.borrow(),
                          WrapBuffer<std::uint8_t>(nullptr, 0));
  else
    return std::make_pair(post_fence_.borrow(),
                          WrapBuffer(meta_.get(), meta_size_bytes_));
}

int ProducerChannel::OnConsumerRelease(Message&, LocalFence release_fence) {
  ATRACE_NAME("ProducerChannel::OnConsumerRelease");
  ALOGD_IF(TRACE, "ProducerChannel::OnConsumerRelease: buffer_id=%d",
           buffer_id());
  if (producer_owns_) {
    ALOGE("ProducerChannel::OnConsumerRelease: Not in acquired state!");
    return -EBUSY;
  }

  // Attempt to merge the fences if necessary.
  if (release_fence) {
    if (returned_fence_) {
      LocalFence merged_fence(sync_merge("bufferhub_merged",
                                         returned_fence_.get_fd(),
                                         release_fence.get_fd()));
      const int error = errno;
      if (!merged_fence) {
        ALOGE("ProducerChannel::OnConsumerRelease: Failed to merge fences: %s",
              strerror(error));
        return -error;
      }
      returned_fence_ = std::move(merged_fence);
    } else {
      returned_fence_ = std::move(release_fence);
    }
  }

  OnConsumerIgnored();
  return 0;
}

void ProducerChannel::OnConsumerIgnored() {
  if (!--pending_consumers_)
    SignalAvailable();
  ALOGD_IF(TRACE,
           "ProducerChannel::OnConsumerIgnored: buffer_id=%d %d consumers left",
           buffer_id(), pending_consumers_);
}

int ProducerChannel::OnProducerMakePersistent(Message& message,
                                              const std::string& name,
                                              int user_id, int group_id) {
  ATRACE_NAME("ProducerChannel::OnProducerMakePersistent");
  ALOGD_IF(TRACE,
           "ProducerChannel::OnProducerMakePersistent: buffer_id=%d name=%s "
           "user_id=%d group_id=%d",
           buffer_id(), name.c_str(), user_id, group_id);

  if (name.empty() || (user_id < 0 && user_id != kNoCheckId) ||
      (group_id < 0 && group_id != kNoCheckId)) {
    return -EINVAL;
  }

  // Try to add this buffer with the requested name.
  if (service()->AddNamedBuffer(name, std::static_pointer_cast<ProducerChannel>(
                                          shared_from_this()))) {
    // If successful, set the requested permissions.

    // A value of zero indicates that the ids from the sending process should be
    // used.
    if (user_id == kUseCallerId)
      user_id = message.GetEffectiveUserId();
    if (group_id == kUseCallerId)
      group_id = message.GetEffectiveGroupId();

    owner_user_id_ = user_id;
    owner_group_id_ = group_id;
    name_ = name;
    return 0;
  } else {
    // Otherwise a buffer with that name already exists.
    return -EALREADY;
  }
}

int ProducerChannel::OnRemovePersistence(Message&) {
  if (service()->RemoveNamedBuffer(*this))
    return 0;
  else
    return -ENOENT;
}

void ProducerChannel::AddConsumer(ConsumerChannel* channel) {
  consumer_channels_.push_back(channel);
}

void ProducerChannel::RemoveConsumer(ConsumerChannel* channel) {
  consumer_channels_.erase(
      std::find(consumer_channels_.begin(), consumer_channels_.end(), channel));
}

// Returns true if either the user or group ids match the owning ids or both
// owning ids are not set, in which case access control does not apply.
bool ProducerChannel::CheckAccess(int euid, int egid) {
  const bool no_check =
      owner_user_id_ == kNoCheckId && owner_group_id_ == kNoCheckId;
  const bool euid_check = euid == owner_user_id_ || euid == kRootId;
  const bool egid_check = egid == owner_group_id_ || egid == kRootId;
  return no_check || euid_check || egid_check;
}

// Returns true if the given parameters match the underlying buffer parameters.
bool ProducerChannel::CheckParameters(int width, int height, int format,
                                      int usage, size_t meta_size_bytes,
                                      size_t slice_count) {
  return slices_.size() == slice_count && meta_size_bytes == meta_size_bytes_ &&
         slices_[0].width() == width && slices_[0].height() == height &&
         slices_[0].format() == format && slices_[0].usage() == usage;
}

}  // namespace dvr
}  // namespace android
