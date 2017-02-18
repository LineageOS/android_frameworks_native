#include <private/dvr/pose_predictor.h>

namespace android {
namespace dvr {

vec3d PosePredictor::AngularVelocity(const quatd& a, const quatd& b,
                                     double delta_time) {
  const auto delta_q = b.inverse() * a;
  // Check that delta_q.w() == 1, Eigen doesn't respect this convention. If
  // delta_q.w() == -1, we'll get the opposite velocity.
  return 2.0 * (delta_q.w() < 0 ? -delta_q.vec() : delta_q.vec()) / delta_time;
}

void PosePredictor::InitializeFromSample(const Sample& sample,
                                         DvrPoseAsync* out_pose,
                                         const vec3d& velocity,
                                         const vec3d& angular_velocity) {
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

  out_pose->angular_velocity = {static_cast<float>(angular_velocity.x()),
                                static_cast<float>(angular_velocity.y()),
                                static_cast<float>(angular_velocity.z()), 0.0f};

  out_pose->velocity = {static_cast<float>(velocity.x()),
                        static_cast<float>(velocity.y()),
                        static_cast<float>(velocity.z()), 0.0f};
  out_pose->timestamp_ns = sample.time_ns;
  out_pose->flags = DVR_POSE_FLAG_HEAD | DVR_POSE_FLAG_VALID;
  memset(out_pose->pad, 0, sizeof(out_pose->pad));
}

}  // namespace dvr
}  // namespace android
