#ifndef POSEPREDICTOR_POSE_PREDICTOR_H_
#define POSEPREDICTOR_POSE_PREDICTOR_H_

#include <Eigen/Core>
#include <Eigen/Geometry>

// This is the only file you need to include for pose prediction.

namespace posepredictor {

// The precision for the predictor.
// TODO(okana): double precision is probably not necessary.
typedef double real;

using vec3 = Eigen::Matrix<real, 3, 1>;
using quat = Eigen::Quaternion<real>;

// Encapsulates a pose sample.
struct Pose {
  int64_t time_ns = 0;
  vec3 position = vec3::Zero();
  quat orientation = quat::Identity();
};

// Encapsulates the derivative at a time.
struct Velocity {
  vec3 linear = vec3::Zero();
  vec3 angular = vec3::Zero();
};

// The preset types we support.
enum class PredictorType { Linear, Quadric, Cubic };

// This is an abstract base class for prediction 6dof pose given
// a set of samples.
class Predictor {
 public:
  Predictor() = default;
  virtual ~Predictor() = default;

  // The nanoseconds to use for finite differencing.
  static constexpr int64_t kFiniteDifferenceNs = 100;

  // Instantiate a new pose predictor for a type.
  static std::unique_ptr<Predictor> Create(PredictorType type);

  // Compute the angular velocity from orientation start_orientation to
  // end_orientation in delta_time.
  static vec3 AngularVelocity(const quat& start_orientation,
                              const quat& end_orientation, real delta_time);

  // Add a pose sample coming from the sensors.
  virtual void Add(const Pose& sample) = 0;

  // Make a pose prediction for at specific time.
  virtual Pose Predict(int64_t time_ns) const = 0;

  // Evaluate velocity at a particular time.
  // The default implementation uses finite differencing.
  virtual Velocity PredictVelocity(int64_t time_ns) const;

  // Helpers
  static real NsToSeconds(int64_t time_ns) {
    return static_cast<real>(time_ns / 1e9);
  }
  static int64_t SecondsToNs(real seconds) {
    return static_cast<int64_t>(seconds * 1e9);
  }
};

}  // namespace posepredictor

#endif  // POSEPREDICTOR_POSE_PREDICTOR_H_
