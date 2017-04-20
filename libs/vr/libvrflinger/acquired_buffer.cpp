#include "acquired_buffer.h"

#include <log/log.h>
#include <sync/sync.h>

using android::pdx::LocalHandle;

namespace android {
namespace dvr {

AcquiredBuffer::AcquiredBuffer(const std::shared_ptr<BufferConsumer>& buffer,
                               LocalHandle acquire_fence)
    : buffer_(buffer), acquire_fence_(std::move(acquire_fence)) {}

AcquiredBuffer::AcquiredBuffer(const std::shared_ptr<BufferConsumer>& buffer,
                               int* error) {
  LocalHandle fence;
  const int ret = buffer->Acquire(&fence);

  if (error)
    *error = ret;

  if (ret < 0) {
    ALOGW("AcquiredBuffer::AcquiredBuffer: Failed to acquire buffer: %s",
          strerror(-ret));
    buffer_ = nullptr;
    // Default construct sets acquire_fence_ to empty.
  } else {
    buffer_ = buffer;
    acquire_fence_ = std::move(fence);
  }
}

AcquiredBuffer::AcquiredBuffer(AcquiredBuffer&& other)
    : buffer_(std::move(other.buffer_)),
      acquire_fence_(std::move(other.acquire_fence_)) {}

AcquiredBuffer::~AcquiredBuffer() { Release(LocalHandle(kEmptyFence)); }

AcquiredBuffer& AcquiredBuffer::operator=(AcquiredBuffer&& other) {
  if (this != &other) {
    Release(LocalHandle(kEmptyFence));

    buffer_ = std::move(other.buffer_);
    acquire_fence_ = std::move(other.acquire_fence_);
  }
  return *this;
}

bool AcquiredBuffer::IsAvailable() const {
  if (IsEmpty())
    return false;

  // Only check the fence if the acquire fence is not empty.
  if (acquire_fence_) {
    const int ret = sync_wait(acquire_fence_.Get(), 0);
    ALOGD_IF(TRACE || (ret < 0 && errno != ETIME),
             "AcquiredBuffer::IsAvailable: acquire_fence_=%d sync_wait()=%d "
             "errno=%d.",
             acquire_fence_.Get(), ret, ret < 0 ? errno : 0);
    if (ret == 0) {
      // The fence is completed, so to avoid further calls to sync_wait we close
      // it here.
      acquire_fence_.Close();
    }
    return ret == 0;
  } else {
    return true;
  }
}

LocalHandle AcquiredBuffer::ClaimAcquireFence() {
  return std::move(acquire_fence_);
}

std::shared_ptr<BufferConsumer> AcquiredBuffer::ClaimBuffer() {
  return std::move(buffer_);
}

int AcquiredBuffer::Release(LocalHandle release_fence) {
  if (buffer_) {
    // Close the release fence since we can't transfer it with an async release.
    release_fence.Close();
    const int ret = buffer_->ReleaseAsync();
    if (ret < 0) {
      ALOGE("AcquiredBuffer::Release: Failed to release buffer %d: %s",
            buffer_->id(), strerror(-ret));
      if (ret != -ESHUTDOWN)
        return ret;
    }

    buffer_ = nullptr;
    acquire_fence_.Close();
  }

  return 0;
}

}  // namespace dvr
}  // namespace android
