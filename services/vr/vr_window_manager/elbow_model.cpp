#include "elbow_model.h"

#include <cutils/log.h>

namespace android {
namespace dvr {
namespace {

const vec3 kControllerForearm(0.0f, 0.0f, -0.25f);
const vec3 kControllerPosition(0.0f, 0.0f, -0.05f);
const vec3 kLeftElbowPosition(-0.195f, -0.5f, 0.075f);
const vec3 kLeftArmExtension(0.13f, 0.14f, -0.08f);
const vec3 kRightElbowPosition(0.195f, -0.5f, 0.075f);
const vec3 kRightArmExtension(-0.13f, 0.14f, -0.08f);
constexpr float kElbowBendRatio = 0.4f;
constexpr float kCosMaxExtensionAngle =
    0.87f;  // Cos of 30 degrees (90-30 = 60)
constexpr float kCosMinExtensionAngle = 0.12f;  // Cos of 83 degrees (90-83 = 7)
constexpr float kYAxisExtensionFraction = 0.4f;
constexpr float kMinRotationSpeed = 0.61f;  // 35 degrees in radians
constexpr float kMinAngleDelta = 0.175f;    // 10 degrees in radians

float clamp(float v, float min, float max) {
  if (v < min)
    return min;
  if (v > max)
    return max;
  return v;
}

float NormalizeAngle(float angle) {
  if (angle > M_PI)
    angle = 2.0f * M_PI - angle;
  return angle;
}

}  // namespace

const vec3 ElbowModel::kDefaultNeckPosition = vec3(0, -0.075f, -0.080f);

ElbowModel::ElbowModel() {}
ElbowModel::~ElbowModel() {}

void ElbowModel::Enable(const vec3& neck_position, bool right_handed) {
  enabled_ = true;
  neck_position_ = neck_position;

  if (right_handed) {
    elbow_position_ = kRightElbowPosition;
    arm_extension_ = kRightArmExtension;
  } else {
    elbow_position_ = kLeftElbowPosition;
    arm_extension_ = kLeftArmExtension;
  }

  ResetRoot();
}

void ElbowModel::Disable() { enabled_ = false; }

vec3 ElbowModel::Update(float delta_t, const quat& hmd_orientation,
                        const quat& controller_orientation, bool recenter) {
  if (!enabled_)
    return vec3::Zero();

  float heading_rad = GetHeading(hmd_orientation);

  quat y_rotation;
  y_rotation = Eigen::AngleAxis<float>(heading_rad, vec3::UnitY());

  // If the controller's angular velocity is above a certain amount, we can
  // assume torso rotation and move the elbow joint relative to the
  // camera orientation.
  float angle_delta = last_controller_.angularDistance(controller_orientation);
  float rot_speed = angle_delta / delta_t;

  if (recenter) {
    root_rot_ = y_rotation;
  } else if (rot_speed > kMinRotationSpeed) {
    root_rot_.slerp(angle_delta / kMinAngleDelta, y_rotation);
  }

  // Calculate angle (or really, cos thereof) between controller forward vector
  // and Y axis to determine extension amount.
  vec3 controller_forward_rotated = controller_orientation * -vec3::UnitZ();
  float dot_y = controller_forward_rotated.y();
  float amt_extension = clamp(dot_y - kCosMinExtensionAngle, 0, 1);

  // Remove the root rotation from the orientation reading--we'll add it back in
  // later.
  quat controller_rot = root_rot_.inverse() * controller_orientation;
  controller_forward_rotated = controller_rot * -vec3::UnitZ();
  quat rot_xy;
  rot_xy.setFromTwoVectors(-vec3::UnitZ(), controller_forward_rotated);

  // Fixing polar singularity
  float total_angle = NormalizeAngle(atan2f(rot_xy.norm(), rot_xy.w()) * 2.0f);
  float lerp_amount = (1.0f - powf(total_angle / M_PI, 6.0f)) *
                      (1.0f - (kElbowBendRatio +
                               (1.0f - kElbowBendRatio) *
                                   (amt_extension + kYAxisExtensionFraction)));

  // Calculate the relative rotations of the elbow and wrist joints.
  quat wrist_rot = quat::Identity();
  wrist_rot.slerp(lerp_amount, rot_xy);
  quat elbow_rot = wrist_rot.inverse() * rot_xy;

  last_controller_ = controller_orientation;

  vec3 position =
      root_rot_ *
      ((controller_root_offset_ + arm_extension_ * amt_extension) +
       elbow_rot * (kControllerForearm + wrist_rot * kControllerPosition));

  return position;
}

float ElbowModel::GetHeading(const quat& orientation) {
  vec3 gaze = orientation * -vec3::UnitZ();

  if (gaze.y() > 0.99)
    gaze = orientation * -vec3::UnitY();
  else if (gaze.y() < -0.99)
    gaze = orientation * vec3::UnitY();

  return atan2f(-gaze.x(), -gaze.z());
}

void ElbowModel::ResetRoot() {
  controller_root_offset_ = elbow_position_ + neck_position_;
}

}  // namespace dvr
}  // namespace android
