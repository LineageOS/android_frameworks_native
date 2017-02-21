#include <linear_predictor.h>

namespace posepredictor {

using AngleAxis = Eigen::AngleAxis<real>;

void LinearPosePredictor::Add(const Pose& sample) {
  // If we are receiving a new sample, move the index to the next item.
  // If the time stamp is the same as the last frame, we will just overwrite
  // it with the new data.
  if (sample.time_ns != samples_[current_index_].time_ns) {
    current_index_ ^= 1;
  }

  // Save the sample.
  samples_[current_index_] = sample;

  // The previous sample we received.
  const auto& previous_sample = samples_[current_index_ ^ 1];

  // Ready to compute velocities.
  const auto pose_delta_time =
      NsToSeconds(sample.time_ns - previous_sample.time_ns);

  if (pose_delta_time > 0.0) {
    velocity_ = (sample.position - previous_sample.position) / pose_delta_time;
    rotational_velocity_ = Predictor::AngularVelocity(
        previous_sample.orientation, sample.orientation, pose_delta_time);
  } else {
    velocity_ = vec3::Zero();
    rotational_velocity_ = vec3::Zero();
  }

  // Temporary experiment with acceleration estimate.
  angular_speed_ = rotational_velocity_.norm();
  angular_accel_ = 0.0;
  if (forward_predict_angular_speed_) {
    angular_accel_ =
        pose_delta_time > 0.0
            ? (angular_speed_ - last_angular_speed_) / pose_delta_time
            : 0.0;
  }
  last_angular_speed_ = angular_speed_;

  rotational_axis_ = vec3(0.0, 1.0, 0.0);
  if (angular_speed_ > 0.0) {
    rotational_axis_ = rotational_velocity_ / angular_speed_;
  }
}

Pose LinearPosePredictor::Predict(int64_t time_ns) const {
  const auto& sample = samples_[current_index_];

  const auto dt = NsToSeconds(time_ns - sample.time_ns);

  // Temporary forward prediction code.
  auto angle = angular_speed_ * dt;
  if (__builtin_expect(forward_predict_angular_speed_, 0)) {
    angle += 0.5 * angular_accel_ * dt * dt;
  }

  return {time_ns, sample.position + velocity_ * dt,
          sample.orientation * quat(AngleAxis(angle, rotational_axis_))};
}

Velocity LinearPosePredictor::PredictVelocity(int64_t /* time_ns */) const {
  return {velocity_, rotational_velocity_};
}

}  // namespace posepredictor
