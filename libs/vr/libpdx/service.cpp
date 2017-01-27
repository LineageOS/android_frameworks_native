#define LOG_TAG "ServiceFramework"
#include "pdx/service.h"

#include <cutils/log.h>
#include <fcntl.h>
#include <utils/misc.h>

#include <algorithm>
#include <cstdint>

#include <pdx/trace.h>
#include "errno_guard.h"

#define TRACE 0

namespace android {
namespace pdx {

std::shared_ptr<Channel> Channel::GetFromMessageInfo(const MessageInfo& info) {
  return info.channel ? info.channel->shared_from_this()
                      : std::shared_ptr<Channel>();
}

Message::Message() : replied_(true) {}

Message::Message(const MessageInfo& info)
    : service_{Service::GetFromMessageInfo(info)},
      channel_{Channel::GetFromMessageInfo(info)},
      info_{info},
      replied_{IsImpulse()} {
  auto svc = service_.lock();
  if (svc)
    state_ = svc->endpoint()->AllocateMessageState();
}

// C++11 specifies the move semantics for shared_ptr but not weak_ptr. This
// means we have to manually implement the desired move semantics for Message.
Message::Message(Message&& other) { *this = std::move(other); }

Message& Message::operator=(Message&& other) {
  Destroy();
  auto base = reinterpret_cast<std::uint8_t*>(&info_);
  std::fill(&base[0], &base[sizeof(info_)], 0);
  replied_ = true;
  std::swap(service_, other.service_);
  std::swap(channel_, other.channel_);
  std::swap(info_, other.info_);
  std::swap(state_, other.state_);
  std::swap(replied_, other.replied_);
  return *this;
}

Message::~Message() { Destroy(); }

void Message::Destroy() {
  auto svc = service_.lock();
  if (svc) {
    if (!replied_) {
      ALOGE(
          "ERROR: Service \"%s\" failed to reply to message: op=%d pid=%d "
          "cid=%d\n",
          svc->name_.c_str(), info_.op, info_.pid, info_.cid);
      svc->endpoint()->DefaultHandleMessage(info_);
    }
    svc->endpoint()->FreeMessageState(state_);
  }
  state_ = nullptr;
  service_.reset();
  channel_.reset();
}

const std::uint8_t* Message::ImpulseBegin() const {
  return reinterpret_cast<const std::uint8_t*>(info_.impulse);
}

const std::uint8_t* Message::ImpulseEnd() const {
  return ImpulseBegin() + (IsImpulse() ? GetSendLength() : 0);
}

ssize_t Message::ReadVector(const struct iovec* vector, size_t vector_length) {
  PDX_TRACE_NAME("Message::ReadVector");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    const ssize_t ret =
        svc->endpoint()->ReadMessageData(this, vector, vector_length);
    return ReturnCodeOrError(ret);
  } else {
    return -ESHUTDOWN;
  }
}

ssize_t Message::Read(void* buffer, size_t length) {
  PDX_TRACE_NAME("Message::Read");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    const struct iovec vector = {buffer, length};
    const ssize_t ret = svc->endpoint()->ReadMessageData(this, &vector, 1);
    return ReturnCodeOrError(ret);
  } else {
    return -ESHUTDOWN;
  }
}

ssize_t Message::WriteVector(const struct iovec* vector, size_t vector_length) {
  PDX_TRACE_NAME("Message::WriteVector");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    const ssize_t ret =
        svc->endpoint()->WriteMessageData(this, vector, vector_length);
    return ReturnCodeOrError(ret);
  } else {
    return -ESHUTDOWN;
  }
}

ssize_t Message::Write(const void* buffer, size_t length) {
  PDX_TRACE_NAME("Message::Write");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    const struct iovec vector = {const_cast<void*>(buffer), length};
    const ssize_t ret = svc->endpoint()->WriteMessageData(this, &vector, 1);
    return ReturnCodeOrError(ret);
  } else {
    return -ESHUTDOWN;
  }
}

FileReference Message::PushFileHandle(const LocalHandle& handle) {
  PDX_TRACE_NAME("Message::PushFileHandle");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    return ReturnCodeOrError(svc->endpoint()->PushFileHandle(this, handle));
  } else {
    return -ESHUTDOWN;
  }
}

FileReference Message::PushFileHandle(const BorrowedHandle& handle) {
  PDX_TRACE_NAME("Message::PushFileHandle");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    return ReturnCodeOrError(svc->endpoint()->PushFileHandle(this, handle));
  } else {
    return -ESHUTDOWN;
  }
}

FileReference Message::PushFileHandle(const RemoteHandle& handle) {
  PDX_TRACE_NAME("Message::PushFileHandle");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    return ReturnCodeOrError(svc->endpoint()->PushFileHandle(this, handle));
  } else {
    return -ESHUTDOWN;
  }
}

ChannelReference Message::PushChannelHandle(const LocalChannelHandle& handle) {
  PDX_TRACE_NAME("Message::PushChannelHandle");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    return ReturnCodeOrError(svc->endpoint()->PushChannelHandle(this, handle));
  } else {
    return -ESHUTDOWN;
  }
}

ChannelReference Message::PushChannelHandle(
    const BorrowedChannelHandle& handle) {
  PDX_TRACE_NAME("Message::PushChannelHandle");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    return ReturnCodeOrError(svc->endpoint()->PushChannelHandle(this, handle));
  } else {
    return -ESHUTDOWN;
  }
}

ChannelReference Message::PushChannelHandle(const RemoteChannelHandle& handle) {
  PDX_TRACE_NAME("Message::PushChannelHandle");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    return ReturnCodeOrError(svc->endpoint()->PushChannelHandle(this, handle));
  } else {
    return -ESHUTDOWN;
  }
}

bool Message::GetFileHandle(FileReference ref, LocalHandle* handle) {
  PDX_TRACE_NAME("Message::GetFileHandle");
  auto svc = service_.lock();
  if (!svc)
    return false;

  if (ref >= 0) {
    ErrnoGuard errno_guard;
    *handle = svc->endpoint()->GetFileHandle(this, ref);
    if (!handle->IsValid())
      return false;
  } else {
    *handle = LocalHandle{ref};
  }
  return true;
}

bool Message::GetChannelHandle(ChannelReference ref,
                               LocalChannelHandle* handle) {
  PDX_TRACE_NAME("Message::GetChannelHandle");
  auto svc = service_.lock();
  if (!svc)
    return false;

  if (ref >= 0) {
    ErrnoGuard errno_guard;
    *handle = svc->endpoint()->GetChannelHandle(this, ref);
    if (!handle->valid())
      return false;
  } else {
    *handle = LocalChannelHandle{nullptr, ref};
  }
  return true;
}

int Message::Reply(int return_code) {
  PDX_TRACE_NAME("Message::Reply");
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    const int ret = svc->endpoint()->MessageReply(this, return_code);
    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::ReplyFileDescriptor(unsigned int fd) {
  PDX_TRACE_NAME("Message::ReplyFileDescriptor");
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    const int ret = svc->endpoint()->MessageReplyFd(this, fd);
    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::ReplyError(unsigned error) {
  PDX_TRACE_NAME("Message::ReplyError");
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    const int ret = svc->endpoint()->MessageReply(this, -error);
    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::Reply(const LocalHandle& handle) {
  PDX_TRACE_NAME("Message::ReplyFileHandle");
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    int ret;

    if (handle)
      ret = svc->endpoint()->MessageReplyFd(this, handle.Get());
    else
      ret = svc->endpoint()->MessageReply(this, handle.Get());

    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::Reply(const BorrowedHandle& handle) {
  PDX_TRACE_NAME("Message::ReplyFileHandle");
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    int ret;

    if (handle)
      ret = svc->endpoint()->MessageReplyFd(this, handle.Get());
    else
      ret = svc->endpoint()->MessageReply(this, handle.Get());

    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::Reply(const RemoteHandle& handle) {
  PDX_TRACE_NAME("Message::ReplyFileHandle");
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    const int ret = svc->endpoint()->MessageReply(this, handle.Get());
    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::Reply(const LocalChannelHandle& handle) {
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    const int ret = svc->endpoint()->MessageReplyChannelHandle(this, handle);
    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::Reply(const BorrowedChannelHandle& handle) {
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    const int ret = svc->endpoint()->MessageReplyChannelHandle(this, handle);
    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::Reply(const RemoteChannelHandle& handle) {
  auto svc = service_.lock();
  if (!replied_ && svc) {
    ErrnoGuard errno_guard;
    const int ret = svc->endpoint()->MessageReplyChannelHandle(this, handle);
    replied_ = ret == 0;
    return ReturnCodeOrError(ret);
  } else {
    return -EINVAL;
  }
}

int Message::ModifyChannelEvents(int clear_mask, int set_mask) {
  PDX_TRACE_NAME("Message::ModifyChannelEvents");
  if (auto svc = service_.lock()) {
    ErrnoGuard errno_guard;
    const int ret =
        svc->endpoint()->ModifyChannelEvents(info_.cid, clear_mask, set_mask);
    return ReturnCodeOrError(ret);
  } else {
    return -ESHUTDOWN;
  }
}

Status<RemoteChannelHandle> Message::PushChannel(
    int flags, const std::shared_ptr<Channel>& channel, int* channel_id) {
  PDX_TRACE_NAME("Message::PushChannel");
  if (auto svc = service_.lock()) {
    return svc->PushChannel(this, flags, channel, channel_id);
  } else {
    return ErrorStatus(ESHUTDOWN);
  }
}

Status<RemoteChannelHandle> Message::PushChannel(
    Service* service, int flags, const std::shared_ptr<Channel>& channel,
    int* channel_id) {
  PDX_TRACE_NAME("Message::PushChannel");
  return service->PushChannel(this, flags, channel, channel_id);
}

Status<int> Message::CheckChannel(ChannelReference ref,
                                  std::shared_ptr<Channel>* channel) const {
  PDX_TRACE_NAME("Message::CheckChannel");
  if (auto svc = service_.lock()) {
    return svc->CheckChannel(this, ref, channel);
  } else {
    return ErrorStatus(ESHUTDOWN);
  }
}

Status<int> Message::CheckChannel(const Service* service, ChannelReference ref,
                                  std::shared_ptr<Channel>* channel) const {
  PDX_TRACE_NAME("Message::CheckChannel");
  return service->CheckChannel(this, ref, channel);
}

pid_t Message::GetProcessId() const { return info_.pid; }

pid_t Message::GetThreadId() const { return info_.tid; }

uid_t Message::GetEffectiveUserId() const { return info_.euid; }

gid_t Message::GetEffectiveGroupId() const { return info_.egid; }

int Message::GetChannelId() const { return info_.cid; }

int Message::GetMessageId() const { return info_.mid; }

int Message::GetOp() const { return info_.op; }

int Message::GetFlags() const { return info_.flags; }

size_t Message::GetSendLength() const { return info_.send_len; }

size_t Message::GetReceiveLength() const { return info_.recv_len; }

size_t Message::GetFileDescriptorCount() const { return info_.fd_count; }

std::shared_ptr<Channel> Message::GetChannel() const { return channel_.lock(); }

void Message::SetChannel(const std::shared_ptr<Channel>& chan) {
  channel_ = chan;

  if (auto svc = service_.lock())
    svc->SetChannel(info_.cid, chan);
}

std::shared_ptr<Service> Message::GetService() const { return service_.lock(); }

const MessageInfo& Message::GetInfo() const { return info_; }

Service::Service(const std::string& name, std::unique_ptr<Endpoint> endpoint)
    : name_(name), endpoint_{std::move(endpoint)} {
  if (!endpoint_)
    return;

  const int ret = endpoint_->SetService(this);
  ALOGE_IF(ret < 0, "Failed to set service context because: %s",
           strerror(-ret));
}

Service::~Service() {
  if (endpoint_) {
    const int ret = endpoint_->SetService(nullptr);
    ALOGE_IF(ret < 0, "Failed to clear service context because: %s",
             strerror(-ret));
  }
}

std::shared_ptr<Service> Service::GetFromMessageInfo(const MessageInfo& info) {
  return info.service ? info.service->shared_from_this()
                      : std::shared_ptr<Service>();
}

bool Service::IsInitialized() const { return endpoint_.get() != nullptr; }

std::shared_ptr<Channel> Service::OnChannelOpen(Message& /*message*/) {
  return nullptr;
}

void Service::OnChannelClose(Message& /*message*/,
                             const std::shared_ptr<Channel>& /*channel*/) {}

int Service::SetChannel(int channel_id,
                        const std::shared_ptr<Channel>& channel) {
  PDX_TRACE_NAME("Service::SetChannel");
  ErrnoGuard errno_guard;
  std::lock_guard<std::mutex> autolock(channels_mutex_);

  const int ret = endpoint_->SetChannel(channel_id, channel.get());
  if (ret == -1) {
    ALOGE("%s::SetChannel: Failed to set channel context: %s\n", name_.c_str(),
          strerror(errno));

    // It's possible someone mucked with things behind our back by calling the C
    // API directly. Since we know the channel id isn't valid, make sure we
    // don't have it in the channels map.
    if (errno == ENOENT)
      channels_.erase(channel_id);

    return ReturnCodeOrError(ret);
  }

  if (channel != nullptr)
    channels_[channel_id] = channel;
  else
    channels_.erase(channel_id);

  return ret;
}

std::shared_ptr<Channel> Service::GetChannel(int channel_id) const {
  PDX_TRACE_NAME("Service::GetChannel");
  std::lock_guard<std::mutex> autolock(channels_mutex_);

  auto search = channels_.find(channel_id);
  if (search != channels_.end())
    return search->second;
  else
    return nullptr;
}

int Service::CloseChannel(int channel_id) {
  PDX_TRACE_NAME("Service::CloseChannel");
  ErrnoGuard errno_guard;
  std::lock_guard<std::mutex> autolock(channels_mutex_);

  const int ret = endpoint_->CloseChannel(channel_id);

  // Always erase the map entry, in case someone mucked with things behind our
  // back using the C API directly.
  channels_.erase(channel_id);

  return ReturnCodeOrError(ret);
}

int Service::ModifyChannelEvents(int channel_id, int clear_mask, int set_mask) {
  PDX_TRACE_NAME("Service::ModifyChannelEvents");
  return endpoint_->ModifyChannelEvents(channel_id, clear_mask, set_mask);
}

Status<RemoteChannelHandle> Service::PushChannel(
    Message* message, int flags, const std::shared_ptr<Channel>& channel,
    int* channel_id) {
  PDX_TRACE_NAME("Service::PushChannel");
  ErrnoGuard errno_guard;

  std::lock_guard<std::mutex> autolock(channels_mutex_);

  int channel_id_temp = -1;
  Status<RemoteChannelHandle> ret =
      endpoint_->PushChannel(message, flags, channel.get(), &channel_id_temp);
  ALOGE_IF(!ret.ok(), "%s::PushChannel: Failed to push channel: %s",
           name_.c_str(), strerror(ret.error()));

  if (channel && channel_id_temp != -1)
    channels_[channel_id_temp] = channel;
  if (channel_id)
    *channel_id = channel_id_temp;

  return ret;
}

Status<int> Service::CheckChannel(const Message* message, ChannelReference ref,
                                  std::shared_ptr<Channel>* channel) const {
  PDX_TRACE_NAME("Service::CheckChannel");
  ErrnoGuard errno_guard;

  // Synchronization to maintain consistency between the kernel's channel
  // context pointer and the userspace channels_ map. Other threads may attempt
  // to modify the map at the same time, which could cause the channel context
  // pointer returned by the kernel to be invalid.
  std::lock_guard<std::mutex> autolock(channels_mutex_);

  Channel* channel_context = nullptr;
  Status<int> ret = endpoint_->CheckChannel(
      message, ref, channel ? &channel_context : nullptr);
  if (ret && channel) {
    if (channel_context)
      *channel = channel_context->shared_from_this();
    else
      *channel = nullptr;
  }

  return ret;
}

std::string Service::DumpState(size_t /*max_length*/) { return ""; }

int Service::HandleMessage(Message& message) {
  return DefaultHandleMessage(message);
}

void Service::HandleImpulse(Message& /*impulse*/) {}

bool Service::HandleSystemMessage(Message& message) {
  const MessageInfo& info = message.GetInfo();

  switch (info.op) {
    case opcodes::CHANNEL_OPEN: {
      ALOGD("%s::OnChannelOpen: pid=%d cid=%d\n", name_.c_str(), info.pid,
            info.cid);
      message.SetChannel(OnChannelOpen(message));
      message.Reply(0);
      return true;
    }

    case opcodes::CHANNEL_CLOSE: {
      ALOGD("%s::OnChannelClose: pid=%d cid=%d\n", name_.c_str(), info.pid,
            info.cid);
      OnChannelClose(message, Channel::GetFromMessageInfo(info));
      message.SetChannel(nullptr);
      message.Reply(0);
      return true;
    }

    case opcodes::REPORT_SYSPROP_CHANGE:
      ALOGD("%s:REPORT_SYSPROP_CHANGE: pid=%d cid=%d\n", name_.c_str(),
            info.pid, info.cid);
      OnSysPropChange();
      android::report_sysprop_change();
      message.Reply(0);
      return true;

    case opcodes::DUMP_STATE: {
      ALOGD("%s:DUMP_STATE: pid=%d cid=%d\n", name_.c_str(), info.pid,
            info.cid);
      auto response = DumpState(message.GetReceiveLength());
      const size_t response_size = response.size() < message.GetReceiveLength()
                                       ? response.size()
                                       : message.GetReceiveLength();
      const ssize_t bytes_written =
          message.Write(response.data(), response_size);
      if (bytes_written < static_cast<ssize_t>(response_size))
        message.ReplyError(EIO);
      else
        message.Reply(bytes_written);
      return true;
    }

    default:
      return false;
  }
}

int Service::DefaultHandleMessage(Message& message) {
  const MessageInfo& info = message.GetInfo();

  ALOGD_IF(TRACE, "Service::DefaultHandleMessage: pid=%d cid=%d op=%d\n",
           info.pid, info.cid, info.op);

  switch (info.op) {
    case opcodes::CHANNEL_OPEN:
    case opcodes::CHANNEL_CLOSE:
    case opcodes::REPORT_SYSPROP_CHANGE:
    case opcodes::DUMP_STATE:
      HandleSystemMessage(message);
      return 0;

    default:
      return message.ReplyError(ENOTSUP);
  }
}

void Service::OnSysPropChange() {}

int Service::ReceiveAndDispatch() {
  ErrnoGuard errno_guard;
  Message message;
  const int ret = endpoint_->MessageReceive(&message);
  if (ret < 0) {
    ALOGE("Failed to receive message: %s\n", strerror(errno));
    return ReturnCodeOrError(ret);
  }

  std::shared_ptr<Service> service = message.GetService();

  if (!service) {
    ALOGE("Service::ReceiveAndDispatch: service context is NULL!!!\n");
    // Don't block the sender indefinitely in this error case.
    endpoint_->MessageReply(&message, -EINVAL);
    return -EINVAL;
  }

  if (message.IsImpulse()) {
    service->HandleImpulse(message);
    return 0;
  } else if (service->HandleSystemMessage(message)) {
    return 0;
  } else {
    return service->HandleMessage(message);
  }
}

int Service::Cancel() {
  ErrnoGuard errno_guard;
  const int ret = endpoint_->Cancel();
  return ReturnCodeOrError(ret);
}

}  // namespace pdx
}  // namespace android
