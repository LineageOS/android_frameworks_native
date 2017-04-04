#include <private/dvr/latency_model.h>

#include <cmath>

namespace android {
namespace dvr {

LatencyModel::LatencyModel(size_t window_size, double weight_mass_in_window) {
  // Compute an alpha so the weight of the last window_size measurements is
  // weight_mass_in_window of the total weights.

  // The weight in a series of k measurements:
  // alpha + (1 + (1 - alpha) + (1 - alpha)^2 + ... (1 - alpha)^k-1)
  // = alpha x (1 - (1 - alpha) ^ k) / alpha
  // = 1 - (1 - alpha) ^ k
  // weight_mass_in_window = 1 - (1 - alpha) ^ k / lim_k->inf (1 - alpha) ^ k
  // weight_mass_in_window = 1 - (1 - alpha) ^ k / 1
  // 1 - weight_mass_in_window = (1 - alpha) ^ k
  // log(1 - weight_mass_in_window) = k * log(1 - alpha)
  // 10 ^ (log(1 - weight_mass_in_window) / k) = 1 - alpha
  // alpha = 1 - 10 ^ (log(1 - weight_mass_in_window) / k)
  // alpha = 1 - 10 ^ (log(1 - weight_mass_in_window) / window_size)

  alpha_ = 1 - std::pow(10.0, std::log10(1 - weight_mass_in_window) /
                                  static_cast<double>(window_size));
}

void LatencyModel::AddLatency(int64_t latency_ns) {
  rolling_average_ = latency_ns * alpha_ + rolling_average_ * (1 - alpha_);
}

}  // namespace dvr
}  // namespace android
