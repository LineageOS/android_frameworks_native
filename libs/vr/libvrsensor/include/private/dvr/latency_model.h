#ifndef ANDROID_DVR_LATENCY_MODEL_H_
#define ANDROID_DVR_LATENCY_MODEL_H_

#include <vector>

namespace android {
namespace dvr {

// This class holds a rolling average of the sensor latency.
class LatencyModel {
 public:
  LatencyModel(size_t window_size, double weight_mass_in_window);
  ~LatencyModel() = default;

  void AddLatency(int64_t latency_ns);
  int64_t CurrentLatencyEstimate() const {
    return static_cast<int64_t>(rolling_average_);
  }

 private:
  // The rolling average of the latencies.
  double rolling_average_ = 0;

  // The alpha parameter for an exponential moving average.
  double alpha_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_LATENCY_MODEL_H_
