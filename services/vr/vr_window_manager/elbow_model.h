#ifndef VR_WINDOW_MANAGER_ELBOW_MODEL_H_
#define VR_WINDOW_MANAGER_ELBOW_MODEL_H_

#include <private/dvr/types.h>

namespace android {
namespace dvr {

class ElbowModel {
 public:
  ElbowModel();
  ~ElbowModel();

  void Enable(const vec3& neck_position, bool right_handed);
  void Disable();

  vec3 Update(float delta_t, const quat& hmd_orientation,
              const quat& controller_orientation, bool recenter);

  static const vec3 kDefaultNeckPosition;

 private:
  ElbowModel(const ElbowModel&) = delete;
  void operator=(const ElbowModel&) = delete;

  void ResetRoot();

  float GetHeading(const quat& orientation);

  bool enabled_ = false;

  quat last_controller_ = quat::Identity();

  quat root_rot_ = quat::Identity();

  vec3 controller_root_offset_ = vec3::Zero();
  vec3 elbow_position_ = vec3::Zero();
  vec3 arm_extension_ = vec3::Zero();
  vec3 neck_position_ = vec3::Zero();
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_ELBOW_MODEL_H_
