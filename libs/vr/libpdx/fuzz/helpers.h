/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Authors: corbin.souffrant@leviathansecurity.com
//          brian.balling@leviathansecurity.com

#ifndef LEV_FUZZERS_LIBPDX_HELPERS_H_
#define LEV_FUZZERS_LIBPDX_HELPERS_H_

#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

#include <fuzzer/FuzzedDataProvider.h>
#include <pdx/client.h>
#include <pdx/service.h>
#include <pdx/service_dispatcher.h>
#include <pdx/service_endpoint.h>
#include <sys/eventfd.h>
#include <memory>
#include <vector>

using namespace android::pdx;

// Vector of operations we can call in the dispatcher.
static const std::vector<std::function<void(
    const std::unique_ptr<ServiceDispatcher>&, FuzzedDataProvider*)>>
    dispatcher_operations = {
        [](const std::unique_ptr<ServiceDispatcher>& dispatcher,
           FuzzedDataProvider*) -> void { dispatcher->EnterDispatchLoop(); },
        [](const std::unique_ptr<ServiceDispatcher>& dispatcher,
           FuzzedDataProvider*) -> void { dispatcher->ReceiveAndDispatch(); },
        [](const std::unique_ptr<ServiceDispatcher>& dispatcher,
           FuzzedDataProvider* fdp) -> void {
          dispatcher->ReceiveAndDispatch(fdp->ConsumeIntegral<int>());
        }};

// Most of the fuzzing occurs within the endpoint, which is derived from an
// abstract class. So we are returning garbage data for most functions besides
// the ones we added or need to actually use.
class FuzzEndpoint : public Endpoint {
 public:
  explicit FuzzEndpoint(FuzzedDataProvider* fdp) {
    _fdp = fdp;
    _epoll_fd = eventfd(0, 0);
  }

  ~FuzzEndpoint() { close(_epoll_fd); }

  // Returns an fd that can be used with epoll() to wait for incoming messages
  // from this endpoint.
  int epoll_fd() const { return _epoll_fd; }

  // Associates a Service instance with an endpoint by setting the service
  // context pointer to the address of the Service. Only one Service may be
  // associated with a given endpoint.
  Status<void> SetService(Service* service) {
    _service = service;
    return Status<void>(0);
  }

  // Set the channel context for the given channel.
  Status<void> SetChannel(int channel_id, Channel* channel) {
    UNUSED(channel_id);
    _channel = std::shared_ptr<Channel>(channel);
    return Status<void>(0);
  }

  // Receives a message on the given endpoint file descriptor.
  // This is called by the dispatcher to determine what operations
  // to make, so we are fuzzing the response.
  Status<void> MessageReceive(Message* message) {
    // Create a randomized MessageInfo struct.
    MessageInfo info;
    eventfd_t wakeup_val = 0;
    info.pid = _fdp->ConsumeIntegral<int>();
    info.tid = _fdp->ConsumeIntegral<int>();
    info.cid = _fdp->ConsumeIntegral<int>();
    info.mid = _fdp->ConsumeIntegral<int>();
    info.euid = _fdp->ConsumeIntegral<int>();
    info.egid = _fdp->ConsumeIntegral<int>();
    info.op = _fdp->ConsumeIntegral<int32_t>();
    info.flags = _fdp->ConsumeIntegral<uint32_t>();
    info.service = _service;
    info.channel = _channel.get();
    info.send_len = _fdp->ConsumeIntegral<size_t>();
    info.recv_len = _fdp->ConsumeIntegral<size_t>();
    info.fd_count = _fdp->ConsumeIntegral<size_t>();
    if (_fdp->remaining_bytes() >= 32) {
      std::vector<uint8_t> impulse_vec = _fdp->ConsumeBytes<uint8_t>(32);
      memcpy(info.impulse, impulse_vec.data(), 32);
    }

    *message = Message(info);
    eventfd_read(_epoll_fd, &wakeup_val);

    return Status<void>();
  }

  // Returns a tag that uniquely identifies a specific underlying IPC
  // transport.
  uint32_t GetIpcTag() const { return 0; }

  // Close a channel, signaling the client file object and freeing the channel
  // id. Once closed, the client side of the channel always returns the error
  // ESHUTDOWN and signals the poll/epoll events POLLHUP and POLLFREE.
  Status<void> CloseChannel(int channel_id) {
    UNUSED(channel_id);
    return Status<void>();
  }

  // Update the event bits for the given channel (given by id), using the
  // given clear and set masks.
  Status<void> ModifyChannelEvents(int channel_id, int clear_mask,
                                   int set_mask) {
    UNUSED(channel_id);
    UNUSED(clear_mask);
    UNUSED(set_mask);
    return Status<void>();
  }

  // Create a new channel and push it as a file descriptor to the process
  // sending the |message|. |flags| may be set to O_NONBLOCK and/or
  // O_CLOEXEC to control the initial behavior of the new file descriptor (the
  // sending process may change these later using fcntl()). The internal
  // Channel instance associated with this channel is set to |channel|,
  // which may be nullptr. The new channel id allocated for this channel is
  // returned in |channel_id|, which may also be nullptr if not needed.
  Status<RemoteChannelHandle> PushChannel(Message* message, int flags,
                                          Channel* channel, int* channel_id) {
    UNUSED(message);
    UNUSED(flags);
    UNUSED(channel);
    UNUSED(channel_id);
    return Status<RemoteChannelHandle>();
  }

  // Check whether the |ref| is a reference to a channel to the service
  // represented by the |endpoint|. If the channel reference in question is
  // valid, the Channel object is returned in |channel| when non-nullptr and
  // the channel ID is returned through the Status object.
  Status<int> CheckChannel(const Message* message, ChannelReference ref,
                           Channel** channel) {
    UNUSED(message);
    UNUSED(ref);
    UNUSED(channel);
    return Status<int>();
  }

  // Replies to the message with a return code.
  Status<void> MessageReply(Message* message, int return_code) {
    UNUSED(message);
    UNUSED(return_code);
    return Status<void>();
  }

  // Replies to the message with a file descriptor.
  Status<void> MessageReplyFd(Message* message, unsigned int push_fd) {
    UNUSED(message);
    UNUSED(push_fd);
    return Status<void>();
  }

  // Replies to the message with a local channel handle.
  Status<void> MessageReplyChannelHandle(Message* message,
                                         const LocalChannelHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<void>();
  }

  // Replies to the message with a borrowed local channel handle.
  Status<void> MessageReplyChannelHandle(Message* message,
                                         const BorrowedChannelHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<void>();
  }

  // Replies to the message with a remote channel handle.
  Status<void> MessageReplyChannelHandle(Message* message,
                                         const RemoteChannelHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<void>();
  }

  // Reads message data into an array of memory buffers.
  Status<size_t> ReadMessageData(Message* message, const iovec* vector,
                                 size_t vector_length) {
    UNUSED(message);
    UNUSED(vector);
    UNUSED(vector_length);
    return Status<size_t>();
  }

  // Sends reply data for message.
  Status<size_t> WriteMessageData(Message* message, const iovec* vector,
                                  size_t vector_length) {
    UNUSED(message);
    UNUSED(vector);
    UNUSED(vector_length);
    return Status<size_t>();
  }

  // Records a file descriptor into the message buffer and returns the
  // remapped reference to be sent to the remote process.
  Status<FileReference> PushFileHandle(Message* message,
                                       const LocalHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<FileReference>();
  }

  Status<FileReference> PushFileHandle(Message* message,
                                       const BorrowedHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<FileReference>();
  }

  Status<FileReference> PushFileHandle(Message* message,
                                       const RemoteHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<FileReference>();
  }

  Status<ChannelReference> PushChannelHandle(Message* message,
                                             const LocalChannelHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<ChannelReference>();
  }

  Status<ChannelReference> PushChannelHandle(
      Message* message, const BorrowedChannelHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<ChannelReference>();
  }

  Status<ChannelReference> PushChannelHandle(
      Message* message, const RemoteChannelHandle& handle) {
    UNUSED(message);
    UNUSED(handle);
    return Status<ChannelReference>();
  }

  // Obtains a file descriptor/channel handle from a message for the given
  // reference.
  LocalHandle GetFileHandle(Message* message, FileReference ref) const {
    UNUSED(message);
    UNUSED(ref);
    return LocalHandle();
  }

  LocalChannelHandle GetChannelHandle(Message* message,
                                      ChannelReference ref) const {
    UNUSED(message);
    UNUSED(ref);
    return LocalChannelHandle();
  }

  // Transport-specific message state management.
  void* AllocateMessageState() { return nullptr; }

  void FreeMessageState(void* state) { UNUSED(state); }

  // Cancels the endpoint, unblocking any receiver threads waiting for a
  // message.
  Status<void> Cancel() { return Status<void>(); }

 private:
  FuzzedDataProvider* _fdp;
  std::shared_ptr<Channel> _channel;
  Service* _service;
  int _epoll_fd;
};

#endif  // LEV_FUZZERS_LIBPDX_HELPERS_H_
