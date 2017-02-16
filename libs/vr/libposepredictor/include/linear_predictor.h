#ifndef POSEPREDICTOR_LINEAR_POSE_PREDICTOR_H_
#define POSEPREDICTOR_LINEAR_POSE_PREDICTOR_H_

#include "predictor.h"

namespace posepredictor {

// This class makes a linear prediction using the last two samples we received.
class LinearPosePredictor : public Predictor {
 public:
  LinearPosePredictor() = default;

  // Add a new sample.
  void Add(const Pose& sample) override;

  // Predict using the last two samples.
  Pose Predict(int64_t time_ns) const override;

  // Just copy the velocity over.
  Velocity PredictVelocity(int64_t time_ns) const override;

 private:
  // The index of the last sample we received.
  size_t current_index_ = 0;

  // The previous two samples.
  Pose samples_[2];

  // Experimental
  bool forward_predict_angular_speed_ = false;

  // Transient variables updated when a sample is added.
  vec3 velocity_ = vec3::Zero();
  vec3 rotational_velocity_ = vec3::Zero();
  vec3 rotational_axis_ = vec3::Zero();
  real last_angular_speed_ = 0;
  real angular_speed_ = 0;
  real angular_accel_ = 0;
};

}  // namespace posepredictor

#endif  // POSEPREDICTOR_LINEAR_POSE_PREDICTOR_H_
