#include "include/private/dvr/lucid_pose_tracker.h"

#define LOG_TAG "LucidPoseTracker"
#include <cutils/log.h>

#include <private/dvr/clock_ns.h>

namespace android {
namespace dvr {

bool LucidPoseTracker::is_override_pose_ = false;
Posef LucidPoseTracker::override_pose_ = Posef();

void LucidPoseTracker::SetPoseOverride(const Posef& pose) {
  is_override_pose_ = true;
  override_pose_ = pose;
}

void LucidPoseTracker::ClearPoseOverride() {
  is_override_pose_ = false;
  override_pose_ = Posef();
}

LucidPoseTracker::LucidPoseTracker() : pose_client_(NULL) {}

LucidPoseTracker::~LucidPoseTracker() {
  if (pose_client_) {
    dvrPoseDestroy(pose_client_);
  }
}

Posef LucidPoseTracker::GetPose(uint64_t timestamp_ns) {
  if (is_override_pose_) {
    return override_pose_;
  }

  if (!pose_client_) {
    pose_client_ = dvrPoseCreate();

    if (!pose_client_) {
      ALOGE("No pose service, returning identity pose");
      return Posef();
    }
  }

  DvrPoseState state;
  dvrPosePoll(pose_client_, &state);

  const vec4 head_rotation_in_start_quat(
      state.head_from_start_rotation.x, state.head_from_start_rotation.y,
      state.head_from_start_rotation.z, state.head_from_start_rotation.w);

  // When the pose service hasn't computed a pose yet, it returns a zero
  // quaternion; just use the identity rotation in that case.
  // TODO(stefanus): Find a better way to signal and check this.
  if (head_rotation_in_start_quat.squaredNorm() < 0.5f) {
    latest_pose_.SetRotation(quat::Identity());
  } else {
    latest_pose_.SetRotation(
        quat(head_rotation_in_start_quat.w(), head_rotation_in_start_quat.x(),
             head_rotation_in_start_quat.y(), head_rotation_in_start_quat.z())
            .normalized());
  }

  const vec3 head_position_in_start(state.head_from_start_translation.x,
                                    state.head_from_start_translation.y,
                                    state.head_from_start_translation.z);
  latest_pose_.SetPosition(head_position_in_start);

  latest_timestamp_ns_ = GetSystemClockNs();

  // PoseState pose_state;
  // pose_state.timestamp_ns = latest_timestamp_ns_;
  // pose_state.sensor_from_start_rotation =
  //    ion::math::Rotationd::FromQuaternion(ion::math::Vector4d(
  //        state.head_from_start_rotation.x, state.head_from_start_rotation.y,
  //        state.head_from_start_rotation.z,
  //        state.head_from_start_rotation.w));
  //// TODO(stefanus): Determine the first derivative of the rotation and set it
  //// here.
  // pose_state.sensor_from_start_rotation_velocity =
  // ion::math::Vector3d::Zero();

  // TODO(stefanus): perform prediction.

  return latest_pose_;
}

}  // namespace dvr
}  // namespace android
