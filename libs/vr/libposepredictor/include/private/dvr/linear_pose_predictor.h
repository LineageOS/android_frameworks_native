#ifndef ANDROID_DVR_POSE_PREDICTOR_H_
#define ANDROID_DVR_POSE_PREDICTOR_H_

#include <private/dvr/pose_predictor.h>

namespace android {
namespace dvr {

// This class makes a linear prediction using the last two samples we received.
class LinearPosePredictor : public PosePredictor {
 public:
  LinearPosePredictor() = default;

  // Add a new sample.
  void Add(const Sample& sample, DvrPoseAsync* out_pose) override;

  // Predict using the last two samples.
  void Predict(int64_t left_time_ns, int64_t right_time_ns,
               DvrPoseAsync* out_pose) const override;

 private:
  // The index of the last sample we received.
  size_t current_index_ = 0;

  // The previous two samples.
  Sample samples_[2];

  // Experimental
  bool forward_predict_angular_speed_ = false;

  // Transient variables updated when a sample is added.
  vec3d velocity_ = vec3d::Zero();
  vec3d rotational_velocity_ = vec3d::Zero();
  vec3d rotational_axis_ = vec3d::Zero();
  double last_angular_speed_ = 0;
  double angular_speed_ = 0;
  double angular_accel_ = 0;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_POSE_PREDICTOR_H_
