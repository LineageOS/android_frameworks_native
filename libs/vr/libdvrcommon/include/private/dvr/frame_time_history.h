#ifndef ANDROID_DVR_FRAME_TIME_HISTORY_H_
#define ANDROID_DVR_FRAME_TIME_HISTORY_H_

#include <stdint.h>

#include <array>

namespace android {
namespace dvr {

// Maintains frame time history and provides averaging utility methods.
class FrameTimeHistory {
 public:
  void AddSample(int64_t frame_time);
  int GetSampleCount() const;
  int64_t GetAverage() const;
  float GetAverageFps() const {
    return 1000000000.0f / static_cast<float>(GetAverage());
  }
  void ResetWithSeed(int64_t frame_time_seed);

 private:
  static constexpr int kFrameTimeHistoryNumSamples = 30;
  std::array<int64_t, kFrameTimeHistoryNumSamples> frame_times_;
  int start_ = 0;
  size_t size_ = 0;
  int64_t total_frame_time_ = 0;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_FRAME_TIME_HISTORY_H_
