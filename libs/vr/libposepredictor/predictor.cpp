#include <linear_predictor.h>
#include <polynomial_predictor.h>
#include <predictor.h>

namespace posepredictor {

vec3 Predictor::AngularVelocity(const quat& a, const quat& b, real delta_time) {
  const auto delta_q = a.inverse() * b;
  // Check that delta_q.w() == 1, Eigen doesn't respect this convention. If
  // delta_q.w() == -1, we'll get the opposite velocity.
  return 2.0 * (delta_q.w() < 0 ? static_cast<vec3>(-delta_q.vec()) : delta_q.vec()) / delta_time;
}

Velocity Predictor::PredictVelocity(int64_t time_ns) const {
  const auto a = Predict(time_ns - kFiniteDifferenceNs);
  const auto b = Predict(time_ns + kFiniteDifferenceNs);
  const auto delta_time = NsToSeconds(2 * kFiniteDifferenceNs);

  return {(b.position - a.position) / delta_time,
          AngularVelocity(a.orientation, b.orientation, delta_time)};
}

// The factory method.
std::unique_ptr<Predictor> Predictor::Create(PredictorType type) {
  switch (type) {
    case PredictorType::Linear:
      return std::make_unique<LinearPosePredictor>();
    case PredictorType::Quadric:
      return std::make_unique<QuadricPosePredictor>();
    case PredictorType::Cubic:
      return std::make_unique<CubicPosePredictor>();
  }
}
}  // namespace posepredictor
