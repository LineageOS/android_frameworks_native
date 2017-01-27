#include "include/private/dvr/native_buffer_queue.h"

#include <base/logging.h>
#include <cutils/log.h>
#include <sys/epoll.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <array>

#include <private/dvr/display_types.h>

namespace android {
namespace dvr {

NativeBufferQueue::NativeBufferQueue(
    const std::shared_ptr<DisplaySurfaceClient>& surface, size_t capacity)
    : NativeBufferQueue(nullptr, surface, capacity) {}

NativeBufferQueue::NativeBufferQueue(
    EGLDisplay display, const std::shared_ptr<DisplaySurfaceClient>& surface,
    size_t capacity)
    : surface_(surface),
      buffers_(capacity),
      buffer_queue_(capacity) {
  CHECK(surface);

  epoll_fd_ = epoll_create(64);
  if (epoll_fd_ < 0) {
    ALOGE("NativeBufferQueue::NativeBufferQueue: Failed to create epoll fd: %s",
          strerror(errno));
    return;
  }

  // The kSurfaceBufferMaxCount must be >= the capacity so that shader code
  // can bind surface buffer array data.
  CHECK(kSurfaceBufferMaxCount >= capacity);

  for (size_t i = 0; i < capacity; i++) {
    uint32_t buffer_index = 0;
    auto buffer = surface_->AllocateBuffer(&buffer_index);
    if (!buffer) {
      ALOGE("NativeBufferQueue::NativeBufferQueue: Failed to allocate buffer!");
      return;
    }

    // TODO(jbates): store an index associated with each buffer so that we can
    // determine which index in DisplaySurfaceMetadata it is associated
    // with.
    buffers_.push_back(new NativeBufferProducer(buffer, display, buffer_index));
    NativeBufferProducer* native_buffer = buffers_.back().get();

    epoll_event event = {.events = EPOLLIN | EPOLLET,
                         .data = {.ptr = native_buffer}};
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, buffer->event_fd(), &event) <
        0) {
      ALOGE(
          "NativeBufferQueue::NativeBufferQueue: Failed to add buffer producer "
          "to epoll set: %s",
          strerror(errno));
      return;
    }

    Enqueue(native_buffer);
  }
}

NativeBufferQueue::~NativeBufferQueue() {
  if (epoll_fd_ >= 0)
    close(epoll_fd_);
}

bool NativeBufferQueue::WaitForBuffers() {
  ATRACE_NAME("NativeBufferQueue::WaitForBuffers");
  // Intentionally set this to one so that we don't waste time retrieving too
  // many buffers.
  constexpr size_t kMaxEvents = 1;
  std::array<epoll_event, kMaxEvents> events;

  while (buffer_queue_.IsEmpty()) {
    int num_events = epoll_wait(epoll_fd_, events.data(), events.size(), -1);
    if (num_events < 0 && errno != EINTR) {
      ALOGE("NativeBufferQueue:WaitForBuffers: Failed to wait for buffers: %s",
            strerror(errno));
      return false;
    }

    ALOGD_IF(TRACE, "NativeBufferQueue::WaitForBuffers: num_events=%d",
             num_events);

    for (int i = 0; i < num_events; i++) {
      NativeBufferProducer* buffer =
          static_cast<NativeBufferProducer*>(events[i].data.ptr);
      ALOGD_IF(TRACE,
               "NativeBufferQueue::WaitForBuffers: event %d: buffer_id=%d "
               "events=0x%x",
               i, buffer->buffer()->id(), events[i].events);

      if (events[i].events & EPOLLIN) {
        const int ret = buffer->GainAsync();
        if (ret < 0) {
          ALOGE("NativeBufferQueue::WaitForBuffers: Failed to gain buffer: %s",
                strerror(-ret));
          continue;
        }

        Enqueue(buffer);
      }
    }
  }

  return true;
}

void NativeBufferQueue::Enqueue(NativeBufferProducer* buf) {
  ATRACE_NAME("NativeBufferQueue::Enqueue");
  if (buffer_queue_.IsFull()) {
    ALOGE("NativeBufferQueue::Enqueue: Queue is full!");
    return;
  }

  buffer_queue_.Append(buf);
}

NativeBufferProducer* NativeBufferQueue::Dequeue() {
  ATRACE_NAME("NativeBufferQueue::Dequeue");
  ALOGD_IF(TRACE, "NativeBufferQueue::Dequeue: count=%zd",
           buffer_queue_.GetSize());

  if (buffer_queue_.IsEmpty() && !WaitForBuffers())
    return nullptr;

  NativeBufferProducer* buf = buffer_queue_.Front();
  buffer_queue_.PopFront();
  if (buf == nullptr) {
    ALOGE("NativeBufferQueue::Dequeue: Buffer at tail was nullptr!!!");
    return nullptr;
  }

  return buf;
}

size_t NativeBufferQueue::GetFreeBufferCount() const {
  return buffer_queue_.GetSize();
}

size_t NativeBufferQueue::GetQueueCapacity() const {
  return buffer_queue_.GetCapacity();
}

}  // namespace dvr
}  // namespace android
