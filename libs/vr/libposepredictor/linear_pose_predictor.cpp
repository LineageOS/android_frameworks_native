#include <cutils/log.h>

#include <private/dvr/linear_pose_predictor.h>

namespace android {
namespace dvr {

using AngleAxisd = Eigen::AngleAxis<double>;

void LinearPosePredictor::Add(const Sample& sample, DvrPoseAsync* out_pose) {
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

  const double inverse_dt = 1. / pose_delta_time;
  if (pose_delta_time > 0.0) {
    velocity_ = (sample.position - previous_sample.position) * inverse_dt;
  } else {
    velocity_ = vec3d::Zero();
  }

  quatd delta_q = sample.orientation.inverse() * previous_sample.orientation;
  // Check that delta_q.w() == 1, Eigen doesn't respect this convention. If
  // delta_q.w() == -1, we'll get the opposite velocity.
  if (delta_q.w() < 0) {
    delta_q.w() = -delta_q.w();
    delta_q.vec() = -delta_q.vec();
  }
  rotational_velocity_ = -2.0 * delta_q.vec() * inverse_dt;

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

  rotational_axis_ = vec3d(0.0, 1.0, 0.0);
  if (angular_speed_ > 0.0) {
    rotational_axis_ = rotational_velocity_ / angular_speed_;
  }

  out_pose->orientation = {static_cast<float>(sample.orientation.vec().x()),
                           static_cast<float>(sample.orientation.vec().y()),
                           static_cast<float>(sample.orientation.vec().z()),
                           static_cast<float>(sample.orientation.w())};

  out_pose->translation = {static_cast<float>(sample.position.x()),
                           static_cast<float>(sample.position.y()),
                           static_cast<float>(sample.position.z()), 0.0f};

  out_pose->right_orientation = {
      static_cast<float>(sample.orientation.vec().x()),
      static_cast<float>(sample.orientation.vec().y()),
      static_cast<float>(sample.orientation.vec().z()),
      static_cast<float>(sample.orientation.w())};

  out_pose->right_translation = {static_cast<float>(sample.position.x()),
                                 static_cast<float>(sample.position.y()),
                                 static_cast<float>(sample.position.z()), 0.0f};

  out_pose->angular_velocity = {static_cast<float>(rotational_velocity_.x()),
                                static_cast<float>(rotational_velocity_.y()),
                                static_cast<float>(rotational_velocity_.z()),
                                0.0f};

  out_pose->velocity = {static_cast<float>(velocity_.x()),
                        static_cast<float>(velocity_.y()),
                        static_cast<float>(velocity_.z()), 0.0f};
  out_pose->timestamp_ns = sample.time_ns;
  out_pose->flags = DVR_POSE_FLAG_HEAD | DVR_POSE_FLAG_VALID;
  memset(out_pose->pad, 0, sizeof(out_pose->pad));
}

void LinearPosePredictor::Predict(int64_t left_time_ns, int64_t right_time_ns,
                                  DvrPoseAsync* out_pose) const {
  const auto& sample = samples_[current_index_];

  double dt = NsToSeconds(left_time_ns - sample.time_ns);
  double r_dt = NsToSeconds(right_time_ns - sample.time_ns);

  // Temporary forward prediction code.
  auto start_t_head_future = sample.position + velocity_ * dt;
  auto r_start_t_head_future = sample.position + velocity_ * r_dt;
  double angle = angular_speed_ * dt;
  double r_angle = angular_speed_ * r_dt;
  if (__builtin_expect(forward_predict_angular_speed_, 0)) {
    angle += 0.5 * angular_accel_ * dt * dt;
    r_angle += 0.5 * angular_accel_ * r_dt * r_dt;
  }
  auto start_q_head_future =
      sample.orientation * quatd(AngleAxisd(angle, rotational_axis_));
  auto r_start_q_head_future =
      sample.orientation * quatd(AngleAxisd(r_angle, rotational_axis_));

  out_pose->orientation = {static_cast<float>(start_q_head_future.x()),
                           static_cast<float>(start_q_head_future.y()),
                           static_cast<float>(start_q_head_future.z()),
                           static_cast<float>(start_q_head_future.w())};

  out_pose->translation = {static_cast<float>(start_t_head_future.x()),
                           static_cast<float>(start_t_head_future.y()),
                           static_cast<float>(start_t_head_future.z()), 0.0f};

  out_pose->right_orientation = {static_cast<float>(r_start_q_head_future.x()),
                                 static_cast<float>(r_start_q_head_future.y()),
                                 static_cast<float>(r_start_q_head_future.z()),
                                 static_cast<float>(r_start_q_head_future.w())};

  out_pose->right_translation = {static_cast<float>(r_start_t_head_future.x()),
                                 static_cast<float>(r_start_t_head_future.y()),
                                 static_cast<float>(r_start_t_head_future.z()),
                                 0.0f};

  out_pose->angular_velocity = {static_cast<float>(rotational_velocity_.x()),
                                static_cast<float>(rotational_velocity_.y()),
                                static_cast<float>(rotational_velocity_.z()),
                                0.0f};

  out_pose->velocity = {static_cast<float>(velocity_.x()),
                        static_cast<float>(velocity_.y()),
                        static_cast<float>(velocity_.z()), 0.0f};

  out_pose->timestamp_ns = left_time_ns;
  out_pose->flags = DVR_POSE_FLAG_HEAD | DVR_POSE_FLAG_VALID;
  memset(out_pose->pad, 0, sizeof(out_pose->pad));
}

}  // namespace dvr
}  // namespace android
