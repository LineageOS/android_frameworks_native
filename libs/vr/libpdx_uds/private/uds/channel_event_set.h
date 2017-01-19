#ifndef ANDROID_PDX_UDS_CHANNEL_EVENT_SET_H_
#define ANDROID_PDX_UDS_CHANNEL_EVENT_SET_H_

#include <errno.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <pdx/file_handle.h>
#include <pdx/status.h>

namespace android {
namespace pdx {
namespace uds {

class ChannelEventSet {
 public:
  ChannelEventSet();
  ChannelEventSet(ChannelEventSet&&) = default;
  ChannelEventSet& operator=(ChannelEventSet&&) = default;

  BorrowedHandle event_fd() const { return epoll_fd_.Borrow(); }

  explicit operator bool() const { return !!epoll_fd_ && !!event_fd_; }

  Status<void> AddDataFd(const LocalHandle& data_fd);
  int ModifyEvents(int clear_mask, int set_mask);

 private:
  LocalHandle epoll_fd_;
  LocalHandle event_fd_;
  uint32_t event_bits_ = 0;

  static Status<void> SetupHandle(int fd, LocalHandle* handle,
                                  const char* error_name);

  ChannelEventSet(const ChannelEventSet&) = delete;
  void operator=(const ChannelEventSet&) = delete;
};

class ChannelEventReceiver {
 public:
  ChannelEventReceiver() = default;
  ChannelEventReceiver(LocalHandle epoll_fd) : epoll_fd_{std::move(epoll_fd)} {}
  ChannelEventReceiver(ChannelEventReceiver&&) = default;
  ChannelEventReceiver& operator=(ChannelEventReceiver&&) = default;

  BorrowedHandle event_fd() const { return epoll_fd_.Borrow(); }
  Status<int> GetPendingEvents() const;

 private:
  LocalHandle epoll_fd_;

  ChannelEventReceiver(const ChannelEventReceiver&) = delete;
  void operator=(const ChannelEventReceiver&) = delete;
};

}  // namespace uds
}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_UDS_CHANNEL_EVENT_SET_H_
