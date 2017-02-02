#include <private/dvr/frame_time_history.h>

#include <log/log.h>

namespace android {
namespace dvr {

void FrameTimeHistory::AddSample(int64_t frame_time) {
  if (size_ == frame_times_.size()) {
    int64_t expired_frame_time = frame_times_[start_];
    frame_times_[start_] = frame_time;
    start_ = (start_ + 1) % frame_times_.size();
    total_frame_time_ -= expired_frame_time;
  } else {
    frame_times_[(start_ + size_) % frame_times_.size()] = frame_time;
    size_++;
  }
  total_frame_time_ += frame_time;
}

int FrameTimeHistory::GetSampleCount() const { return size_; }

int64_t FrameTimeHistory::GetAverage() const {
  LOG_ALWAYS_FATAL_IF(size_ == 0);
  return total_frame_time_ / size_;
}

void FrameTimeHistory::ResetWithSeed(int64_t frame_time_seed) {
  start_ = 0;
  size_ = frame_times_.size();
  for (size_t i = 0; i < size_; ++i)
    frame_times_[i] = frame_time_seed;
  total_frame_time_ = frame_time_seed * size_;
}

}  // namespace dvr
}  // namespace android
