#include <private/dvr/dvr_pose_predictor.h>

namespace android {
namespace dvr {

namespace {
template <typename Vec3Type>
float32x4_t FromVec3(const Vec3Type& from) {
  return {static_cast<float>(from.x()), static_cast<float>(from.y()),
          static_cast<float>(from.z()), 0};
}

template <typename QuatType>
float32x4_t FromQuat(const QuatType& from) {
  return {static_cast<float>(from.x()), static_cast<float>(from.y()),
          static_cast<float>(from.z()), static_cast<float>(from.w())};
}

}  //  namespace

void AddPredictorPose(posepredictor::Predictor* predictor,
                      const posepredictor::vec3& start_t_head,
                      const posepredictor::quat& start_q_head,
                      int64_t pose_timestamp, DvrPoseAsync* out) {
  // Feed the predictor.
  predictor->Add(
      posepredictor::Pose{pose_timestamp, start_t_head, start_q_head});

  // Fill the output.
  out->timestamp_ns = pose_timestamp;

  out->translation = FromVec3(start_t_head);
  out->orientation = FromQuat(start_q_head);

  out->right_translation = out->translation;
  out->right_orientation = out->orientation;

  const auto velocity = predictor->PredictVelocity(pose_timestamp);

  out->velocity = FromVec3(velocity.linear);
  out->angular_velocity = FromVec3(velocity.angular);

  out->flags = DVR_POSE_FLAG_HEAD | DVR_POSE_FLAG_VALID;
  memset(out->pad, 0, sizeof(out->pad));
}

void PredictPose(const posepredictor::Predictor* predictor, int64_t left_ns,
                 int64_t right_ns, DvrPoseAsync* out) {
  const auto left_pose = predictor->Predict(left_ns);
  const auto right_pose = predictor->Predict(right_ns);
  const auto velocity = predictor->PredictVelocity((left_ns + right_ns) / 2);

  // Fill the output.
  out->timestamp_ns = left_ns;

  out->translation = FromVec3(left_pose.position);
  out->orientation = FromQuat(left_pose.orientation);

  out->right_translation = FromVec3(right_pose.position);
  out->right_orientation = FromQuat(right_pose.orientation);

  out->velocity = FromVec3(velocity.linear);
  out->angular_velocity = FromVec3(velocity.angular);

  out->flags = DVR_POSE_FLAG_HEAD | DVR_POSE_FLAG_VALID;
  memset(out->pad, 0, sizeof(out->pad));
}

}  //  dvr
}  //  android
