#include "uds/service_endpoint.h"

#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <algorithm>  // std::min

#include <pdx/service.h>
#include <uds/channel_manager.h>
#include <uds/client_channel_factory.h>
#include <uds/ipc_helper.h>

namespace {

constexpr int kMaxBackLogForSocketListen = 1;

using android::pdx::BorrowedChannelHandle;
using android::pdx::BorrowedHandle;
using android::pdx::ChannelReference;
using android::pdx::FileReference;
using android::pdx::LocalChannelHandle;
using android::pdx::LocalHandle;
using android::pdx::Status;
using android::pdx::uds::ChannelInfo;
using android::pdx::uds::ChannelManager;

struct MessageState {
  bool GetLocalFileHandle(int index, LocalHandle* handle) {
    if (index < 0) {
      handle->Reset(index);
    } else if (static_cast<size_t>(index) < request.file_descriptors.size()) {
      *handle = std::move(request.file_descriptors[index]);
    } else {
      return false;
    }
    return true;
  }

  bool GetLocalChannelHandle(int index, LocalChannelHandle* handle) {
    if (index < 0) {
      *handle = LocalChannelHandle{nullptr, index};
    } else if (static_cast<size_t>(index) < request.channels.size()) {
      auto& channel_info = request.channels[index];
      *handle = ChannelManager::Get().CreateHandle(
          std::move(channel_info.data_fd), std::move(channel_info.event_fd));
    } else {
      return false;
    }
    return true;
  }

  FileReference PushFileHandle(BorrowedHandle handle) {
    if (!handle)
      return handle.Get();
    response.file_descriptors.push_back(std::move(handle));
    return response.file_descriptors.size() - 1;
  }

  ChannelReference PushChannelHandle(BorrowedChannelHandle handle) {
    if (!handle)
      return handle.value();

    if (auto* channel_data =
            ChannelManager::Get().GetChannelData(handle.value())) {
      ChannelInfo<BorrowedHandle> channel_info;
      channel_info.data_fd.Reset(handle.value());
      channel_info.event_fd = channel_data->event_receiver.event_fd();
      response.channels.push_back(std::move(channel_info));
      return response.channels.size() - 1;
    } else {
      return -1;
    }
  }

  ChannelReference PushChannelHandle(BorrowedHandle data_fd,
                                     BorrowedHandle event_fd) {
    if (!data_fd || !event_fd)
      return -1;
    ChannelInfo<BorrowedHandle> channel_info;
    channel_info.data_fd = std::move(data_fd);
    channel_info.event_fd = std::move(event_fd);
    response.channels.push_back(std::move(channel_info));
    return response.channels.size() - 1;
  }

  ssize_t WriteData(const iovec* vector, size_t vector_length) {
    ssize_t size = 0;
    for (size_t i = 0; i < vector_length; i++) {
      const auto* data = reinterpret_cast<const uint8_t*>(vector[i].iov_base);
      response_data.insert(response_data.end(), data, data + vector[i].iov_len);
      size += vector[i].iov_len;
    }
    return size;
  }

  ssize_t ReadData(const iovec* vector, size_t vector_length) {
    size_t size_remaining = request_data.size() - request_data_read_pos;
    ssize_t size = 0;
    for (size_t i = 0; i < vector_length && size_remaining > 0; i++) {
      size_t size_to_copy = std::min(size_remaining, vector[i].iov_len);
      memcpy(vector[i].iov_base, request_data.data() + request_data_read_pos,
             size_to_copy);
      size += size_to_copy;
      request_data_read_pos += size_to_copy;
      size_remaining -= size_to_copy;
    }
    return size;
  }

  android::pdx::uds::RequestHeader<LocalHandle> request;
  android::pdx::uds::ResponseHeader<BorrowedHandle> response;
  std::vector<LocalHandle> sockets_to_close;
  std::vector<uint8_t> request_data;
  size_t request_data_read_pos{0};
  std::vector<uint8_t> response_data;
};

}  // anonymous namespace

namespace android {
namespace pdx {
namespace uds {

Endpoint::Endpoint(const std::string& endpoint_path, bool blocking)
    : endpoint_path_{ClientChannelFactory::GetEndpointPath(endpoint_path)},
      is_blocking_{blocking} {
  LocalHandle fd{socket(AF_UNIX, SOCK_STREAM, 0)};
  if (!fd) {
    ALOGE("Endpoint::Endpoint: Failed to create socket: %s", strerror(errno));
    return;
  }

  sockaddr_un local;
  local.sun_family = AF_UNIX;
  strncpy(local.sun_path, endpoint_path_.c_str(), sizeof(local.sun_path));
  local.sun_path[sizeof(local.sun_path) - 1] = '\0';

  unlink(local.sun_path);
  if (bind(fd.Get(), (struct sockaddr*)&local, sizeof(local)) == -1) {
    ALOGE("Endpoint::Endpoint: bind error: %s", strerror(errno));
    return;
  }
  if (listen(fd.Get(), kMaxBackLogForSocketListen) == -1) {
    ALOGE("Endpoint::Endpoint: listen error: %s", strerror(errno));
    return;
  }

  cancel_event_fd_.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
  if (!cancel_event_fd_) {
    ALOGE("Endpoint::Endpoint: Failed to create event fd: %s\n",
          strerror(errno));
    return;
  }

  epoll_fd_.Reset(epoll_create(1));  // Size arg is ignored, but must be > 0.
  if (!epoll_fd_) {
    ALOGE("Endpoint::Endpoint: Failed to create epoll fd: %s\n",
          strerror(errno));
    return;
  }

  epoll_event socket_event;
  socket_event.events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT;
  socket_event.data.fd = fd.Get();

  epoll_event cancel_event;
  cancel_event.events = EPOLLIN;
  cancel_event.data.fd = cancel_event_fd_.Get();

  if (epoll_ctl(epoll_fd_.Get(), EPOLL_CTL_ADD, fd.Get(), &socket_event) < 0 ||
      epoll_ctl(epoll_fd_.Get(), EPOLL_CTL_ADD, cancel_event_fd_.Get(),
                &cancel_event) < 0) {
    ALOGE("Endpoint::Endpoint: Failed to add event fd to epoll fd: %s\n",
          strerror(errno));
    cancel_event_fd_.Close();
    epoll_fd_.Close();
  } else {
    socket_fd_ = std::move(fd);
  }
}

void* Endpoint::AllocateMessageState() { return new MessageState; }

void Endpoint::FreeMessageState(void* state) {
  delete static_cast<MessageState*>(state);
}

Status<void> Endpoint::AcceptConnection(Message* message) {
  sockaddr_un remote;
  socklen_t addrlen = sizeof(remote);
  LocalHandle channel_fd{
      accept(socket_fd_.Get(), reinterpret_cast<sockaddr*>(&remote), &addrlen)};
  if (!channel_fd) {
    ALOGE("Endpoint::AcceptConnection: failed to accept connection: %s",
          strerror(errno));
    return ErrorStatus(errno);
  }

  int optval = 1;
  if (setsockopt(channel_fd.Get(), SOL_SOCKET, SO_PASSCRED, &optval,
                 sizeof(optval)) == -1) {
    ALOGE(
        "Endpoint::AcceptConnection: Failed to enable the receiving of the "
        "credentials for channel %d: %s",
        channel_fd.Get(), strerror(errno));
    return ErrorStatus(errno);
  }

  auto status = ReceiveMessageForChannel(channel_fd.Get(), message);
  if (status)
    status = OnNewChannel(std::move(channel_fd));
  return status;
}

int Endpoint::SetService(Service* service) {
  service_ = service;
  return 0;
}

int Endpoint::SetChannel(int channel_id, Channel* channel) {
  std::lock_guard<std::mutex> autolock(channel_mutex_);
  auto channel_data = channels_.find(channel_id);
  if (channel_data == channels_.end())
    return -EINVAL;
  channel_data->second.channel_state = channel;
  return 0;
}

Status<void> Endpoint::OnNewChannel(LocalHandle channel_fd) {
  std::lock_guard<std::mutex> autolock(channel_mutex_);
  Status<void> status;
  status.PropagateError(OnNewChannelLocked(std::move(channel_fd), nullptr));
  return status;
}

Status<Endpoint::ChannelData*> Endpoint::OnNewChannelLocked(
    LocalHandle channel_fd, Channel* channel_state) {
  epoll_event event;
  event.events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT;
  event.data.fd = channel_fd.Get();
  if (epoll_ctl(epoll_fd_.Get(), EPOLL_CTL_ADD, channel_fd.Get(), &event) < 0) {
    ALOGE(
        "Endpoint::OnNewChannelLocked: Failed to add channel to endpoint: %s\n",
        strerror(errno));
    return ErrorStatus(errno);
  }
  ChannelData channel_data;
  const int channel_id = channel_fd.Get();
  channel_data.event_set.AddDataFd(channel_fd);
  channel_data.data_fd = std::move(channel_fd);
  channel_data.channel_state = channel_state;
  auto pair = channels_.emplace(channel_id, std::move(channel_data));
  return &pair.first->second;
}

Status<void> Endpoint::ReenableEpollEvent(int fd) {
  epoll_event event;
  event.events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT;
  event.data.fd = fd;
  if (epoll_ctl(epoll_fd_.Get(), EPOLL_CTL_MOD, fd, &event) < 0) {
    ALOGE(
        "Endpoint::ReenableEpollEvent: Failed to re-enable channel to "
        "endpoint: %s\n",
        strerror(errno));
    return ErrorStatus(errno);
  }
  return {};
}

int Endpoint::CloseChannel(int channel_id) {
  std::lock_guard<std::mutex> autolock(channel_mutex_);
  return CloseChannelLocked(channel_id);
}

int Endpoint::CloseChannelLocked(int channel_id) {
  ALOGD_IF(TRACE, "Endpoint::CloseChannelLocked: channel_id=%d", channel_id);

  auto channel_data = channels_.find(channel_id);
  if (channel_data == channels_.end())
    return -EINVAL;

  int ret = 0;
  epoll_event dummy;  // See BUGS in man 2 epoll_ctl.
  if (epoll_ctl(epoll_fd_.Get(), EPOLL_CTL_DEL, channel_id, &dummy) < 0) {
    ret = -errno;
    ALOGE(
        "Endpoint::CloseChannelLocked: Failed to remove channel from endpoint: "
        "%s\n",
        strerror(errno));
  }

  channels_.erase(channel_data);
  return ret;
}

int Endpoint::ModifyChannelEvents(int channel_id, int clear_mask,
                                  int set_mask) {
  std::lock_guard<std::mutex> autolock(channel_mutex_);

  auto search = channels_.find(channel_id);
  if (search != channels_.end()) {
    auto& channel_data = search->second;
    channel_data.event_set.ModifyEvents(clear_mask, set_mask);
    return 0;
  }

  return -EINVAL;
}

Status<RemoteChannelHandle> Endpoint::PushChannel(Message* message,
                                                  int /*flags*/,
                                                  Channel* channel,
                                                  int* channel_id) {
  int channel_pair[2] = {};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, channel_pair) == -1) {
    ALOGE("Endpoint::PushChannel: Failed to create a socket pair: %s",
          strerror(errno));
    return ErrorStatus(errno);
  }

  LocalHandle local_socket{channel_pair[0]};
  LocalHandle remote_socket{channel_pair[1]};

  int optval = 1;
  if (setsockopt(local_socket.Get(), SOL_SOCKET, SO_PASSCRED, &optval,
                 sizeof(optval)) == -1) {
    ALOGE(
        "Endpoint::PushChannel: Failed to enable the receiving of the "
        "credentials for channel %d: %s",
        local_socket.Get(), strerror(errno));
    return ErrorStatus(errno);
  }

  std::lock_guard<std::mutex> autolock(channel_mutex_);
  *channel_id = local_socket.Get();
  auto channel_data = OnNewChannelLocked(std::move(local_socket), channel);
  if (!channel_data)
    return ErrorStatus(channel_data.error());

  // Flags are ignored for now.
  // TODO(xiaohuit): Implement those.

  auto* state = static_cast<MessageState*>(message->GetState());
  ChannelReference ref = state->PushChannelHandle(
      remote_socket.Borrow(),
      channel_data.get()->event_set.event_fd().Borrow());
  state->sockets_to_close.push_back(std::move(remote_socket));
  return RemoteChannelHandle{ref};
}

Status<int> Endpoint::CheckChannel(const Message* /*message*/,
                                   ChannelReference /*ref*/,
                                   Channel** /*channel*/) {
  // TODO(xiaohuit): Implement this.
  return ErrorStatus(EFAULT);
}

int Endpoint::DefaultHandleMessage(const MessageInfo& /* info */) {
  ALOGE(
      "Endpoint::CheckChannel: Not implemented! Endpoint DefaultHandleMessage "
      "does nothing!");
  return 0;
}

Channel* Endpoint::GetChannelState(int channel_id) {
  std::lock_guard<std::mutex> autolock(channel_mutex_);
  auto channel_data = channels_.find(channel_id);
  return (channel_data != channels_.end()) ? channel_data->second.channel_state
                                           : nullptr;
}

int Endpoint::GetChannelSocketFd(int channel_id) {
  std::lock_guard<std::mutex> autolock(channel_mutex_);
  auto channel_data = channels_.find(channel_id);
  return (channel_data != channels_.end()) ? channel_data->second.data_fd.Get()
                                           : -1;
}

int Endpoint::GetChannelEventFd(int channel_id) {
  std::lock_guard<std::mutex> autolock(channel_mutex_);
  auto channel_data = channels_.find(channel_id);
  return (channel_data != channels_.end())
             ? channel_data->second.event_set.event_fd().Get()
             : -1;
}

Status<void> Endpoint::ReceiveMessageForChannel(int channel_id,
                                                Message* message) {
  RequestHeader<LocalHandle> request;
  auto status = ReceiveData(channel_id, &request);
  if (!status) {
    if (status.error() == ESHUTDOWN) {
      BuildCloseMessage(channel_id, message);
      return {};
    } else {
      CloseChannel(channel_id);
      return status;
    }
  }

  MessageInfo info;
  info.pid = request.cred.pid;
  info.tid = -1;
  info.cid = channel_id;
  info.mid = request.is_impulse ? Message::IMPULSE_MESSAGE_ID
                                : GetNextAvailableMessageId();
  info.euid = request.cred.uid;
  info.egid = request.cred.gid;
  info.op = request.op;
  info.flags = 0;
  info.service = service_;
  info.channel = GetChannelState(channel_id);
  info.send_len = request.send_len;
  info.recv_len = request.max_recv_len;
  info.fd_count = request.file_descriptors.size();
  static_assert(sizeof(info.impulse) == request.impulse_payload.size(),
                "Impulse payload sizes must be the same in RequestHeader and "
                "MessageInfo");
  memcpy(info.impulse, request.impulse_payload.data(),
         request.impulse_payload.size());
  *message = Message{info};
  auto* state = static_cast<MessageState*>(message->GetState());
  state->request = std::move(request);
  if (request.send_len > 0 && !request.is_impulse) {
    state->request_data.resize(request.send_len);
    status = ReceiveData(channel_id, state->request_data.data(),
                         state->request_data.size());
  }

  if (status && request.is_impulse)
    status = ReenableEpollEvent(channel_id);

  if (!status) {
    if (status.error() == ESHUTDOWN) {
      BuildCloseMessage(channel_id, message);
      return {};
    } else {
      CloseChannel(channel_id);
      return status;
    }
  }

  return status;
}

void Endpoint::BuildCloseMessage(int channel_id, Message* message) {
  ALOGD_IF(TRACE, "Endpoint::BuildCloseMessage: channel_id=%d", channel_id);
  MessageInfo info;
  info.pid = -1;
  info.tid = -1;
  info.cid = channel_id;
  info.mid = GetNextAvailableMessageId();
  info.euid = -1;
  info.egid = -1;
  info.op = opcodes::CHANNEL_CLOSE;
  info.flags = 0;
  info.service = service_;
  info.channel = GetChannelState(channel_id);
  info.send_len = 0;
  info.recv_len = 0;
  info.fd_count = 0;
  *message = Message{info};
}

int Endpoint::MessageReceive(Message* message) {
  // Receive at most one event from the epoll set. This should prevent multiple
  // dispatch threads from attempting to handle messages on the same socket at
  // the same time.
  epoll_event event;
  int count = RETRY_EINTR(
      epoll_wait(epoll_fd_.Get(), &event, 1, is_blocking_ ? -1 : 0));
  if (count < 0) {
    ALOGE("Endpoint::MessageReceive: Failed to wait for epoll events: %s\n",
          strerror(errno));
    return -errno;
  } else if (count == 0) {
    return -ETIMEDOUT;
  }

  if (event.data.fd == cancel_event_fd_.Get()) {
    return -ESHUTDOWN;
  }

  if (event.data.fd == socket_fd_.Get()) {
    auto status = AcceptConnection(message);
    if (!status)
      return -status.error();
    status = ReenableEpollEvent(socket_fd_.Get());
    return status ? 0 : -status.error();
  }

  int channel_id = event.data.fd;
  if (event.events & (EPOLLRDHUP | EPOLLHUP)) {
    BuildCloseMessage(channel_id, message);
    return 0;
  }

  auto status = ReceiveMessageForChannel(channel_id, message);
  if (!status)
    return -status.error();
  return 0;
}

int Endpoint::MessageReply(Message* message, int return_code) {
  const int channel_id = message->GetChannelId();
  const int channel_socket = GetChannelSocketFd(channel_id);
  if (channel_socket < 0)
    return -EBADF;

  auto* state = static_cast<MessageState*>(message->GetState());
  switch (message->GetOp()) {
    case opcodes::CHANNEL_CLOSE:
      return CloseChannel(channel_id);

    case opcodes::CHANNEL_OPEN:
      if (return_code < 0)
        return CloseChannel(channel_id);
      // Reply with the event fd.
      return_code = state->PushFileHandle(
          BorrowedHandle{GetChannelEventFd(channel_socket)});
      state->response_data.clear();  // Just in case...
      break;
  }

  state->response.ret_code = return_code;
  state->response.recv_len = state->response_data.size();
  auto status = SendData(channel_socket, state->response);
  if (status && !state->response_data.empty()) {
    status = SendData(channel_socket, state->response_data.data(),
                      state->response_data.size());
  }

  if (status)
    status = ReenableEpollEvent(channel_socket);

  return status ? 0 : -status.error();
}

int Endpoint::MessageReplyFd(Message* message, unsigned int push_fd) {
  auto* state = static_cast<MessageState*>(message->GetState());
  auto ref = state->PushFileHandle(BorrowedHandle{static_cast<int>(push_fd)});
  return MessageReply(message, ref);
}

int Endpoint::MessageReplyChannelHandle(Message* message,
                                        const LocalChannelHandle& handle) {
  auto* state = static_cast<MessageState*>(message->GetState());
  auto ref = state->PushChannelHandle(handle.Borrow());
  return MessageReply(message, ref);
}

int Endpoint::MessageReplyChannelHandle(Message* message,
                                        const BorrowedChannelHandle& handle) {
  auto* state = static_cast<MessageState*>(message->GetState());
  auto ref = state->PushChannelHandle(handle.Duplicate());
  return MessageReply(message, ref);
}

int Endpoint::MessageReplyChannelHandle(Message* message,
                                        const RemoteChannelHandle& handle) {
  return MessageReply(message, handle.value());
}

ssize_t Endpoint::ReadMessageData(Message* message, const iovec* vector,
                                  size_t vector_length) {
  auto* state = static_cast<MessageState*>(message->GetState());
  return state->ReadData(vector, vector_length);
}

ssize_t Endpoint::WriteMessageData(Message* message, const iovec* vector,
                                   size_t vector_length) {
  auto* state = static_cast<MessageState*>(message->GetState());
  return state->WriteData(vector, vector_length);
}

FileReference Endpoint::PushFileHandle(Message* message,
                                       const LocalHandle& handle) {
  auto* state = static_cast<MessageState*>(message->GetState());
  return state->PushFileHandle(handle.Borrow());
}

FileReference Endpoint::PushFileHandle(Message* message,
                                       const BorrowedHandle& handle) {
  auto* state = static_cast<MessageState*>(message->GetState());
  return state->PushFileHandle(handle.Duplicate());
}

FileReference Endpoint::PushFileHandle(Message* /*message*/,
                                       const RemoteHandle& handle) {
  return handle.Get();
}

ChannelReference Endpoint::PushChannelHandle(Message* message,
                                             const LocalChannelHandle& handle) {
  auto* state = static_cast<MessageState*>(message->GetState());
  return state->PushChannelHandle(handle.Borrow());
}

ChannelReference Endpoint::PushChannelHandle(
    Message* message, const BorrowedChannelHandle& handle) {
  auto* state = static_cast<MessageState*>(message->GetState());
  return state->PushChannelHandle(handle.Duplicate());
}

ChannelReference Endpoint::PushChannelHandle(
    Message* /*message*/, const RemoteChannelHandle& handle) {
  return handle.value();
}

LocalHandle Endpoint::GetFileHandle(Message* message, FileReference ref) const {
  LocalHandle handle;
  auto* state = static_cast<MessageState*>(message->GetState());
  state->GetLocalFileHandle(ref, &handle);
  return handle;
}

LocalChannelHandle Endpoint::GetChannelHandle(Message* message,
                                              ChannelReference ref) const {
  LocalChannelHandle handle;
  auto* state = static_cast<MessageState*>(message->GetState());
  state->GetLocalChannelHandle(ref, &handle);
  return handle;
}

int Endpoint::Cancel() {
  return (eventfd_write(cancel_event_fd_.Get(), 1) < 0) ? -errno : 0;
}

std::unique_ptr<Endpoint> Endpoint::Create(const std::string& endpoint_path,
                                           mode_t /*unused_mode*/,
                                           bool blocking) {
  return std::unique_ptr<Endpoint>(new Endpoint(endpoint_path, blocking));
}

}  // namespace uds
}  // namespace pdx
}  // namespace android
