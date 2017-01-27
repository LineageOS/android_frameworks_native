#ifndef ANDROID_DVR_LINEAR_POSE_PREDICTOR_H_
#define ANDROID_DVR_LINEAR_POSE_PREDICTOR_H_

#include <private/dvr/pose_client_internal.h>
#include <private/dvr/types.h>

namespace android {
namespace dvr {

// This is an abstract base class for prediction 6dof pose given
// a set of samples.
//
// TODO(okana): Create a framework for testing different subclasses for
// performance and accuracy.
class PosePredictor {
 public:
  PosePredictor() = default;
  virtual ~PosePredictor() = default;

  // Encapsulates a pose sample.
  struct Sample {
    vec3d position = vec3d::Zero();
    quatd orientation = quatd::Identity();
    int64_t time_ns = 0;
  };

  // Add a pose sample coming from the sensors.
  // Returns this sample as a dvr pose.
  //
  // We will use the returned pose if prediction is not enabled.
  virtual void Add(const Sample& sample, DvrPoseAsync* out_pose) = 0;

  // Make a pose prediction for the left and right eyes at specific times.
  virtual void Predict(int64_t left_time_ns, int64_t right_time_ns,
                       DvrPoseAsync* out_pose) const = 0;

  // Helpers
  static double NsToSeconds(int64_t time_ns) { return time_ns / 1e9; }
  static int64_t SecondsToNs(double seconds) {
    return static_cast<int64_t>(seconds * 1e9);
  }
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_LINEAR_POSE_PREDICTOR_H_
