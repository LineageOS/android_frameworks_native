#include "uds/ipc_helper.h"

#include <alloca.h>
#include <errno.h>
#include <log/log.h>
#include <poll.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <algorithm>

#include <pdx/service.h>
#include <pdx/utility.h>

namespace android {
namespace pdx {
namespace uds {

uint32_t kMagicPreamble = 0x7564736d;  // 'udsm'.

struct MessagePreamble {
  uint32_t magic{0};
  uint32_t data_size{0};
  uint32_t fd_count{0};
};

Status<void> SendPayload::Send(const BorrowedHandle& socket_fd) {
  return Send(socket_fd, nullptr);
}

Status<void> SendPayload::Send(const BorrowedHandle& socket_fd,
                               const ucred* cred) {
  MessagePreamble preamble;
  preamble.magic = kMagicPreamble;
  preamble.data_size = buffer_.size();
  preamble.fd_count = file_handles_.size();

  ssize_t ret = RETRY_EINTR(
      send(socket_fd.Get(), &preamble, sizeof(preamble), MSG_NOSIGNAL));
  if (ret < 0)
    return ErrorStatus(errno);
  if (ret != sizeof(preamble))
    return ErrorStatus(EIO);

  msghdr msg = {};
  iovec recv_vect = {buffer_.data(), buffer_.size()};
  msg.msg_iov = &recv_vect;
  msg.msg_iovlen = 1;

  if (cred || !file_handles_.empty()) {
    const size_t fd_bytes = file_handles_.size() * sizeof(int);
    msg.msg_controllen = (cred ? CMSG_SPACE(sizeof(ucred)) : 0) +
                         (fd_bytes == 0 ? 0 : CMSG_SPACE(fd_bytes));
    msg.msg_control = alloca(msg.msg_controllen);

    cmsghdr* control = CMSG_FIRSTHDR(&msg);
    if (cred) {
      control->cmsg_level = SOL_SOCKET;
      control->cmsg_type = SCM_CREDENTIALS;
      control->cmsg_len = CMSG_LEN(sizeof(ucred));
      memcpy(CMSG_DATA(control), cred, sizeof(ucred));
      control = CMSG_NXTHDR(&msg, control);
    }

    if (fd_bytes) {
      control->cmsg_level = SOL_SOCKET;
      control->cmsg_type = SCM_RIGHTS;
      control->cmsg_len = CMSG_LEN(fd_bytes);
      memcpy(CMSG_DATA(control), file_handles_.data(), fd_bytes);
    }
  }

  ret = RETRY_EINTR(sendmsg(socket_fd.Get(), &msg, MSG_NOSIGNAL));
  if (ret < 0)
    return ErrorStatus(errno);
  if (static_cast<size_t>(ret) != buffer_.size())
    return ErrorStatus(EIO);
  return {};
}

// MessageWriter
void* SendPayload::GetNextWriteBufferSection(size_t size) {
  return buffer_.grow_by(size);
}

OutputResourceMapper* SendPayload::GetOutputResourceMapper() { return this; }

// OutputResourceMapper
Status<FileReference> SendPayload::PushFileHandle(const LocalHandle& handle) {
  if (handle) {
    const int ref = file_handles_.size();
    file_handles_.push_back(handle.Get());
    return ref;
  } else {
    return handle.Get();
  }
}

Status<FileReference> SendPayload::PushFileHandle(
    const BorrowedHandle& handle) {
  if (handle) {
    const int ref = file_handles_.size();
    file_handles_.push_back(handle.Get());
    return ref;
  } else {
    return handle.Get();
  }
}

Status<FileReference> SendPayload::PushFileHandle(const RemoteHandle& handle) {
  return handle.Get();
}

Status<ChannelReference> SendPayload::PushChannelHandle(
    const LocalChannelHandle& /*handle*/) {
  return ErrorStatus{EOPNOTSUPP};
}
Status<ChannelReference> SendPayload::PushChannelHandle(
    const BorrowedChannelHandle& /*handle*/) {
  return ErrorStatus{EOPNOTSUPP};
}
Status<ChannelReference> SendPayload::PushChannelHandle(
    const RemoteChannelHandle& /*handle*/) {
  return ErrorStatus{EOPNOTSUPP};
}

Status<void> ReceivePayload::Receive(const BorrowedHandle& socket_fd) {
  return Receive(socket_fd, nullptr);
}

Status<void> ReceivePayload::Receive(const BorrowedHandle& socket_fd,
                                     ucred* cred) {
  MessagePreamble preamble;
  ssize_t ret = RETRY_EINTR(
      recv(socket_fd.Get(), &preamble, sizeof(preamble), MSG_WAITALL));
  if (ret < 0)
    return ErrorStatus(errno);
  else if (ret == 0)
    return ErrorStatus(ESHUTDOWN);
  else if (ret != sizeof(preamble) || preamble.magic != kMagicPreamble)
    return ErrorStatus(EIO);

  buffer_.resize(preamble.data_size);
  file_handles_.clear();
  read_pos_ = 0;

  msghdr msg = {};
  iovec recv_vect = {buffer_.data(), buffer_.size()};
  msg.msg_iov = &recv_vect;
  msg.msg_iovlen = 1;

  if (cred || preamble.fd_count) {
    const size_t receive_fd_bytes = preamble.fd_count * sizeof(int);
    msg.msg_controllen =
        (cred ? CMSG_SPACE(sizeof(ucred)) : 0) +
        (receive_fd_bytes == 0 ? 0 : CMSG_SPACE(receive_fd_bytes));
    msg.msg_control = alloca(msg.msg_controllen);
  }

  ret = RETRY_EINTR(recvmsg(socket_fd.Get(), &msg, MSG_WAITALL));
  if (ret < 0)
    return ErrorStatus(errno);
  else if (ret == 0)
    return ErrorStatus(ESHUTDOWN);
  else if (static_cast<uint32_t>(ret) != preamble.data_size)
    return ErrorStatus(EIO);

  bool cred_available = false;
  file_handles_.reserve(preamble.fd_count);
  cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  while (cmsg) {
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
        cred && cmsg->cmsg_len == CMSG_LEN(sizeof(ucred))) {
      cred_available = true;
      memcpy(cred, CMSG_DATA(cmsg), sizeof(ucred));
    } else if (cmsg->cmsg_level == SOL_SOCKET &&
               cmsg->cmsg_type == SCM_RIGHTS) {
      socklen_t payload_len = cmsg->cmsg_len - CMSG_LEN(0);
      const int* fds = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
      size_t fd_count = payload_len / sizeof(int);
      std::transform(fds, fds + fd_count, std::back_inserter(file_handles_),
                     [](int fd) { return LocalHandle{fd}; });
    }
    cmsg = CMSG_NXTHDR(&msg, cmsg);
  }

  if (cred && !cred_available) {
    return ErrorStatus(EIO);
  }

  return {};
}

// MessageReader
MessageReader::BufferSection ReceivePayload::GetNextReadBufferSection() {
  return {buffer_.data() + read_pos_, &*buffer_.end()};
}

void ReceivePayload::ConsumeReadBufferSectionData(const void* new_start) {
  read_pos_ = PointerDistance(new_start, buffer_.data());
}

InputResourceMapper* ReceivePayload::GetInputResourceMapper() { return this; }

// InputResourceMapper
bool ReceivePayload::GetFileHandle(FileReference ref, LocalHandle* handle) {
  if (ref < 0) {
    *handle = LocalHandle{ref};
    return true;
  }
  if (static_cast<size_t>(ref) > file_handles_.size())
    return false;
  *handle = std::move(file_handles_[ref]);
  return true;
}

bool ReceivePayload::GetChannelHandle(ChannelReference /*ref*/,
                                      LocalChannelHandle* /*handle*/) {
  return false;
}

Status<void> SendData(const BorrowedHandle& socket_fd, const void* data,
                      size_t size) {
  ssize_t size_written =
      RETRY_EINTR(send(socket_fd.Get(), data, size, MSG_NOSIGNAL));
  if (size_written < 0)
    return ErrorStatus(errno);
  if (static_cast<size_t>(size_written) != size)
    return ErrorStatus(EIO);
  return {};
}

Status<void> SendDataVector(const BorrowedHandle& socket_fd, const iovec* data,
                            size_t count) {
  msghdr msg = {};
  msg.msg_iov = const_cast<iovec*>(data);
  msg.msg_iovlen = count;
  ssize_t size_written =
      RETRY_EINTR(sendmsg(socket_fd.Get(), &msg, MSG_NOSIGNAL));
  if (size_written < 0)
    return ErrorStatus(errno);
  if (static_cast<size_t>(size_written) != CountVectorSize(data, count))
    return ErrorStatus(EIO);
  return {};
}

Status<void> ReceiveData(const BorrowedHandle& socket_fd, void* data,
                         size_t size) {
  ssize_t size_read =
      RETRY_EINTR(recv(socket_fd.Get(), data, size, MSG_WAITALL));
  if (size_read < 0)
    return ErrorStatus(errno);
  else if (size_read == 0)
    return ErrorStatus(ESHUTDOWN);
  else if (static_cast<size_t>(size_read) != size)
    return ErrorStatus(EIO);
  return {};
}

Status<void> ReceiveDataVector(const BorrowedHandle& socket_fd,
                               const iovec* data, size_t count) {
  msghdr msg = {};
  msg.msg_iov = const_cast<iovec*>(data);
  msg.msg_iovlen = count;
  ssize_t size_read = RETRY_EINTR(recvmsg(socket_fd.Get(), &msg, MSG_WAITALL));
  if (size_read < 0)
    return ErrorStatus(errno);
  else if (size_read == 0)
    return ErrorStatus(ESHUTDOWN);
  else if (static_cast<size_t>(size_read) != CountVectorSize(data, count))
    return ErrorStatus(EIO);
  return {};
}

size_t CountVectorSize(const iovec* vector, size_t count) {
  return std::accumulate(
      vector, vector + count, size_t{0},
      [](size_t size, const iovec& vec) { return size + vec.iov_len; });
}

void InitRequest(android::pdx::uds::RequestHeader<BorrowedHandle>* request,
                 int opcode, uint32_t send_len, uint32_t max_recv_len,
                 bool is_impulse) {
  request->op = opcode;
  request->cred.pid = getpid();
  request->cred.uid = geteuid();
  request->cred.gid = getegid();
  request->send_len = send_len;
  request->max_recv_len = max_recv_len;
  request->is_impulse = is_impulse;
}

Status<void> WaitForEndpoint(const std::string& endpoint_path,
                             int64_t timeout_ms) {
  // Endpoint path must be absolute.
  if (endpoint_path.empty() || endpoint_path.front() != '/')
    return ErrorStatus(EINVAL);

  // Create inotify fd.
  LocalHandle fd{inotify_init()};
  if (!fd)
    return ErrorStatus(errno);

  // Set the inotify fd to non-blocking.
  int ret = fcntl(fd.Get(), F_GETFL);
  fcntl(fd.Get(), F_SETFL, ret | O_NONBLOCK);

  // Setup the pollfd.
  pollfd pfd = {fd.Get(), POLLIN, 0};

  // Find locations of each path separator.
  std::vector<size_t> separators{0};  // The path is absolute, so '/' is at #0.
  size_t pos = endpoint_path.find('/', 1);
  while (pos != std::string::npos) {
    separators.push_back(pos);
    pos = endpoint_path.find('/', pos + 1);
  }
  separators.push_back(endpoint_path.size());

  // Walk down the path, checking for existence and waiting if needed.
  pos = 1;
  size_t links = 0;
  std::string current;
  while (pos < separators.size() && links <= MAXSYMLINKS) {
    std::string previous = current;
    current = endpoint_path.substr(0, separators[pos]);

    // Check for existence; proceed to setup a watch if not.
    if (access(current.c_str(), F_OK) < 0) {
      if (errno != ENOENT)
        return ErrorStatus(errno);

      // Extract the name of the path component to wait for.
      std::string next = current.substr(
          separators[pos - 1] + 1, separators[pos] - separators[pos - 1] - 1);

      // Add a watch on the last existing directory we reach.
      int wd = inotify_add_watch(
          fd.Get(), previous.c_str(),
          IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF | IN_MOVED_TO);
      if (wd < 0) {
        if (errno != ENOENT)
          return ErrorStatus(errno);
        // Restart at the beginning if previous was deleted.
        links = 0;
        current.clear();
        pos = 1;
        continue;
      }

      // Make sure current didn't get created before the watch was added.
      ret = access(current.c_str(), F_OK);
      if (ret < 0) {
        if (errno != ENOENT)
          return ErrorStatus(errno);

        bool exit_poll = false;
        while (!exit_poll) {
          // Wait for an event or timeout.
          ret = poll(&pfd, 1, timeout_ms);
          if (ret <= 0)
            return ErrorStatus(ret == 0 ? ETIMEDOUT : errno);

          // Read events.
          char buffer[sizeof(inotify_event) + NAME_MAX + 1];

          ret = read(fd.Get(), buffer, sizeof(buffer));
          if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
              continue;
            else
              return ErrorStatus(errno);
          } else if (static_cast<size_t>(ret) < sizeof(struct inotify_event)) {
            return ErrorStatus(EIO);
          }

          auto* event = reinterpret_cast<const inotify_event*>(buffer);
          auto* end = reinterpret_cast<const inotify_event*>(buffer + ret);
          while (event < end) {
            std::string event_for;
            if (event->len > 0)
              event_for = event->name;

            if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
              // See if this is the droid we're looking for.
              if (next == event_for) {
                exit_poll = true;
                break;
              }
            } else if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
              // Restart at the beginning if our watch dir is deleted.
              links = 0;
              current.clear();
              pos = 0;
              exit_poll = true;
              break;
            }

            event = reinterpret_cast<const inotify_event*>(AdvancePointer(
                event, sizeof(struct inotify_event) + event->len));
          }  // while (event < end)
        }    // while (!exit_poll)
      }      // Current dir doesn't exist.
      ret = inotify_rm_watch(fd.Get(), wd);
      if (ret < 0 && errno != EINVAL)
        return ErrorStatus(errno);
    }  // if (access(current.c_str(), F_OK) < 0)

    // Check for symbolic link and update link count.
    struct stat stat_buf;
    ret = lstat(current.c_str(), &stat_buf);
    if (ret < 0 && errno != ENOENT)
      return ErrorStatus(errno);
    else if (ret == 0 && S_ISLNK(stat_buf.st_mode))
      links++;
    pos++;
  }  // while (pos < separators.size() && links <= MAXSYMLINKS)

  return {};
}

}  // namespace uds
}  // namespace pdx
}  // namespace android
