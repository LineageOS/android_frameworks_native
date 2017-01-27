#include "epoll_event_dispatcher.h"

#include <log/log.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>

#include <dvr/performance_client_api.h>

namespace android {
namespace dvr {

EpollEventDispatcher::EpollEventDispatcher()
    : exit_thread_(false), epoll_fd_(-1), event_fd_(-1) {
  epoll_fd_ = epoll_create(64);
  if (epoll_fd_ < 0) {
    ALOGE("Failed to create epoll fd: %s", strerror(errno));
    return;
  }

  event_fd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (event_fd_ < 0) {
    ALOGE("Failed to create event for epolling: %s", strerror(errno));
    return;
  }

  // Add watch for eventfd. This should only watch for EPOLLIN, which gets set
  // when eventfd_write occurs. Use "this" as a unique sentinal value to
  // identify events from the event fd.
  epoll_event event = {.events = EPOLLIN, .data = {.ptr = this}};
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, event_fd_, &event) < 0) {
    ALOGE("Failed to add eventfd to epoll set because: %s", strerror(errno));
    return;
  }

  thread_ = std::thread(&EpollEventDispatcher::EventThread, this);
}

EpollEventDispatcher::~EpollEventDispatcher() {
  Stop();

  close(epoll_fd_);
  close(event_fd_);
}

void EpollEventDispatcher::Stop() {
  exit_thread_.store(true);
  eventfd_write(event_fd_, 1);
}

int EpollEventDispatcher::AddEventHandler(int fd, int event_mask,
                                          Handler handler) {
  std::lock_guard<std::mutex> lock(lock_);

  epoll_event event;
  event.events = event_mask;
  event.data.ptr = &(handlers_[fd] = handler);

  ALOGD_IF(
      TRACE,
      "EpollEventDispatcher::AddEventHandler: fd=%d event_mask=0x%x handler=%p",
      fd, event_mask, event.data.ptr);

  int err = epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event);
  return err < 0 ? -errno : 0;
}

int EpollEventDispatcher::RemoveEventHandler(int fd) {
  ALOGD_IF(TRACE, "EpollEventDispatcher::RemoveEventHandler: fd=%d", fd);
  std::lock_guard<std::mutex> lock(lock_);

  epoll_event dummy;  // See BUGS in man 2 epoll_ctl.
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, &dummy) < 0) {
    ALOGE("Failed to remove fd from epoll set because: %s", strerror(errno));
    return -errno;
  }

  // If the fd was valid above, add it to the list of ids to remove.
  removed_handlers_.push_back(fd);

  // Wake up the event thread to clean up.
  eventfd_write(event_fd_, 1);

  return 0;
}

void EpollEventDispatcher::EventThread() {
  prctl(PR_SET_NAME, reinterpret_cast<unsigned long>("EpollEvent"), 0, 0, 0);

  const int error = dvrSetSchedulerClass(0, "graphics");
  LOG_ALWAYS_FATAL_IF(
      error < 0,
      "EpollEventDispatcher::EventThread: Failed to set scheduler class: %s",
      strerror(-error));

  const size_t kMaxNumEvents = 128;
  epoll_event events[kMaxNumEvents];

  while (!exit_thread_.load()) {
    int num_events = epoll_wait(epoll_fd_, events, kMaxNumEvents, -1);
    if (num_events < 0 && errno != EINTR)
      break;

    ALOGD_IF(TRACE, "EpollEventDispatcher::EventThread: num_events=%d",
             num_events);

    for (int i = 0; i < num_events; i++) {
      ALOGD_IF(
          TRACE,
          "EpollEventDispatcher::EventThread: event %d: handler=%p events=0x%x",
          i, events[i].data.ptr, events[i].events);

      if (events[i].data.ptr == this) {
        // Clear pending event on event_fd_. Serialize the read with respect to
        // writes from other threads.
        std::lock_guard<std::mutex> lock(lock_);
        eventfd_t value;
        eventfd_read(event_fd_, &value);
      } else {
        auto handler = reinterpret_cast<Handler*>(events[i].data.ptr);
        if (handler)
          (*handler)(events[i].events);
      }
    }

    // Remove any handlers that have been posted for removal. This is done here
    // instead of in RemoveEventHandler() to prevent races between the dispatch
    // thread and the code requesting the removal. Handlers are guaranteed to
    // stay alive between exiting epoll_wait() and the dispatch loop above.
    std::lock_guard<std::mutex> lock(lock_);
    for (auto handler_fd : removed_handlers_) {
      ALOGD_IF(TRACE,
               "EpollEventDispatcher::EventThread: removing handler: fd=%d",
               handler_fd);
      handlers_.erase(handler_fd);
    }
    removed_handlers_.clear();
  }
}

}  // namespace dvr
}  // namespace android
