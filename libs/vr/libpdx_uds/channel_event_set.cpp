#include "private/uds/channel_event_set.h"

#include <log/log.h>

#include <uds/ipc_helper.h>

namespace android {
namespace pdx {
namespace uds {

ChannelEventSet::ChannelEventSet() {
  const int flags = EFD_CLOEXEC | EFD_NONBLOCK;
  LocalHandle epoll_fd, event_fd;

  if (!SetupHandle(epoll_create1(EPOLL_CLOEXEC), &epoll_fd, "epoll") ||
      !SetupHandle(eventfd(0, flags), &event_fd, "event")) {
    return;
  }

  epoll_event event;
  event.events = 0;
  event.data.u32 = 0;
  if (epoll_ctl(epoll_fd.Get(), EPOLL_CTL_ADD, event_fd.Get(), &event) < 0) {
    const int error = errno;
    ALOGE("ChannelEventSet::ChannelEventSet: Failed to add event_fd: %s",
          strerror(error));
    return;
  }

  epoll_fd_ = std::move(epoll_fd);
  event_fd_ = std::move(event_fd);
}

Status<void> ChannelEventSet::AddDataFd(const LocalHandle& data_fd) {
  epoll_event event;
  event.events = EPOLLHUP | EPOLLRDHUP;
  event.data.u32 = event.events;
  if (epoll_ctl(epoll_fd_.Get(), EPOLL_CTL_ADD, data_fd.Get(), &event) < 0) {
    const int error = errno;
    ALOGE("ChannelEventSet::ChannelEventSet: Failed to add event_fd: %s",
          strerror(error));
    return ErrorStatus{error};
  } else {
    return {};
  }
}

int ChannelEventSet::ModifyEvents(int clear_mask, int set_mask) {
  ALOGD_IF(TRACE, "ChannelEventSet::ModifyEvents: clear_mask=%x set_mask=%x",
           clear_mask, set_mask);
  const int old_bits = event_bits_;
  const int new_bits = (event_bits_ & ~clear_mask) | set_mask;
  event_bits_ = new_bits;

  // If anything changed clear the event and update the event mask.
  if (old_bits != new_bits) {
    eventfd_t value;
    eventfd_read(event_fd_.Get(), &value);

    epoll_event event;
    event.events = POLLIN;
    event.data.u32 = event_bits_;
    if (epoll_ctl(epoll_fd_.Get(), EPOLL_CTL_MOD, event_fd_.Get(), &event) <
        0) {
      const int error = errno;
      ALOGE("ChannelEventSet::AddEventHandle: Failed to update event: %s",
            strerror(error));
      return -error;
    }
  }

  // If there are any bits set, re-trigger the eventfd.
  if (new_bits)
    eventfd_write(event_fd_.Get(), 1);

  return 0;
}

Status<void> ChannelEventSet::SetupHandle(int fd, LocalHandle* handle,
                                          const char* error_name) {
  const int error = errno;
  handle->Reset(fd);
  if (!*handle) {
    ALOGE("ChannelEventSet::SetupHandle: Failed to setup %s handle: %s",
          error_name, strerror(error));
    return ErrorStatus{error};
  }
  return {};
}

Status<int> ChannelEventReceiver::GetPendingEvents() const {
  constexpr long kTimeoutMs = 0;
  epoll_event event;
  const int count =
      RETRY_EINTR(epoll_wait(epoll_fd_.Get(), &event, 1, kTimeoutMs));

  Status<int> status;
  if (count < 0) {
    status.SetError(errno);
    ALOGE("ChannelEventReceiver::GetPendingEvents: Failed to get events: %s",
          status.GetErrorMessage().c_str());
    return status;
  }

  const int mask_out = event.data.u32;
  ALOGD_IF(TRACE, "ChannelEventReceiver::GetPendingEvents: mask_out=%x",
           mask_out);

  status.SetValue(mask_out);
  return status;
}

}  // namespace uds
}  // namespace pdx
}  // namespace android
