#include "sensor_fusion.h"

#include <algorithm>
#include <cmath>

#include <private/dvr/eigen.h>

namespace android {
namespace dvr {

namespace {

// --- start of added bits for porting to eigen

// In general, we prefer to add wrappers for things like Inverse() to minimize
// the changes to the imported code, so that merging in upstream changes becomes
// simpler.

inline Matrix3d Inverse(const Matrix3d& matrix) { return matrix.inverse(); }
inline Matrix3d Transpose(const Matrix3d& matrix) { return matrix.transpose(); }
inline Matrix3d RotationMatrixNH(const Rotationd& rotation) {
  return rotation.toRotationMatrix();
}
inline double Length(const Vector3d& vector) { return vector.norm(); }

using uint64 = uint64_t;

// --- end of added bits for porting to eigen

static const double kFiniteDifferencingEpsilon = 1e-7;
static const double kEpsilon = 1e-15;
// Default gyroscope frequency. This corresponds to 200 Hz.
static const double kDefaultGyroscopeTimestep_s = 0.005f;
// Maximum time between gyroscope before we start limiting the integration.
static const double kMaximumGyroscopeSampleDelay_s = 0.04f;
// Compute a first-order exponential moving average of changes in accel norm per
// frame.
static const double kSmoothingFactor = 0.5;
// Minimum and maximum values used for accelerometer noise covariance matrix.
// The smaller the sigma value, the more weight is given to the accelerometer
// signal.
static const double kMinAccelNoiseSigma = 0.75;
static const double kMaxAccelNoiseSigma = 7.0;
// Initial value for the diagonal elements of the different covariance matrices.
static const double kInitialStateCovarianceValue = 25.0;
static const double kInitialProcessCovarianceValue = 1.0;
// Maximum accelerometer norm change allowed before capping it covariance to a
// large value.
static const double kMaxAccelNormChange = 0.15;
// Timestep IIR filtering coefficient.
static const double kTimestepFilterCoeff = 0.95;
// Minimum number of sample for timestep filtering.
static const uint32_t kTimestepFilterMinSamples = 10;

// Z direction in start space.
static const Vector3d kCanonicalZDirection(0.0, 0.0, 1.0);

// Computes a axis angle rotation from the input vector.
// angle = norm(a)
// axis = a.normalized()
// If norm(a) == 0, it returns an identity rotation.
static Rotationd RotationFromVector(const Vector3d& a) {
  const double norm_a = Length(a);
  if (norm_a < kEpsilon) {
    return Rotationd::Identity();
  }
  return Rotationd(AngleAxisd(norm_a, a / norm_a));
}

// --- start of functions ported from pose_prediction.cc

namespace pose_prediction {

// Returns a rotation matrix based on the integration of the gyroscope_value
// over the timestep_s in seconds.
// TODO(pfg): Document the space better here.
//
// @param gyroscope_value gyroscope sensor values.
// @param timestep_s integration period in seconds.
// @return Integration of the gyroscope value the rotation is from Start to
//         Sensor Space.
Rotationd GetRotationFromGyroscope(const Vector3d& gyroscope_value,
                                   double timestep_s) {
  const double velocity = Length(gyroscope_value);

  // When there is no rotation data return an identity rotation.
  if (velocity < kEpsilon) {
    return Rotationd::Identity();
  }
  // Since the gyroscope_value is a start from sensor transformation we need to
  // invert it to have a sensor from start transformation, hence the minus sign.
  // For more info:
  // http://developer.android.com/guide/topics/sensors/sensors_motion.html#sensors-motion-gyro
  return Rotationd(AngleAxisd(-timestep_s * velocity,
                              gyroscope_value / velocity));
}

}  // namespace pose_prediction

// --- end of functions ported from pose_prediction.cc

}  // namespace

SensorFusion::SensorFusion()
    : execute_reset_with_next_accelerometer_sample_(false) {
  ResetState();
}

void SensorFusion::Reset() {
  execute_reset_with_next_accelerometer_sample_ = true;
}

void SensorFusion::ResetState() {
  current_state_.timestamp_ns = 0;
  current_state_.sensor_from_start_rotation = Rotationd::Identity();
  current_state_.sensor_from_start_rotation_velocity = Vector3d::Zero();

  current_accelerometer_timestamp_ns_ = 0;

  state_covariance_ = Matrix3d::Identity() * kInitialStateCovarianceValue;
  process_covariance_ = Matrix3d::Identity() * kInitialProcessCovarianceValue;
  accelerometer_measurement_covariance_ =
      Matrix3d::Identity() * kMinAccelNoiseSigma * kMinAccelNoiseSigma;
  innovation_covariance_.setIdentity();

  accelerometer_measurement_jacobian_ = Matrix3d::Zero();
  kalman_gain_ = Matrix3d::Zero();
  innovation_ = Vector3d::Zero();
  accelerometer_measurement_ = Vector3d::Zero();
  prediction_ = Vector3d::Zero();
  control_input_ = Vector3d::Zero();
  state_update_ = Vector3d::Zero();

  moving_average_accelerometer_norm_change_ = 0.0;

  is_timestep_filter_initialized_ = false;
  is_gyroscope_filter_valid_ = false;
  is_aligned_with_gravity_ = false;
}

// Here I am doing something wrong relative to time stamps. The state timestamps
// always correspond to the gyrostamps because it would require additional
// extrapolation if I wanted to do otherwise.
// TODO(pfg): investigate about published an updated pose after accelerometer
// data was used for filtering.
PoseState SensorFusion::GetLatestPoseState() const {
  std::unique_lock<std::mutex> lock(mutex_);
  return current_state_;
}

void SensorFusion::ProcessGyroscopeSample(float v_x, float v_y, float v_z,
                                          uint64 timestamp_ns) {
  std::unique_lock<std::mutex> lock(mutex_);

  // Don't accept gyroscope sample when waiting for a reset.
  if (execute_reset_with_next_accelerometer_sample_) {
    return;
  }

  // Discard outdated samples.
  if (current_state_.timestamp_ns >= timestamp_ns) {
    // TODO(pfg): Investigate why this happens.
    return;
  }

  // Checks that we received at least one gyroscope sample in the past.
  if (current_state_.timestamp_ns != 0) {
    // TODO(pfg): roll this in filter gyroscope timestep function.
    double current_timestep_s =
        static_cast<double>(timestamp_ns - current_state_.timestamp_ns) * 1e-9;
    if (current_timestep_s > kMaximumGyroscopeSampleDelay_s) {
      if (is_gyroscope_filter_valid_) {
        // Replaces the delta timestamp by the filtered estimates of the delta
        // time.
        current_timestep_s = filtered_gyroscope_timestep_s_;
      } else {
        current_timestep_s = kDefaultGyroscopeTimestep_s;
      }
    } else {
      FilterGyroscopeTimestep(current_timestep_s);
    }

    // Only integrate after receiving a accelerometer sample.
    if (is_aligned_with_gravity_) {
      const Rotationd rotation_from_gyroscope =
          pose_prediction::GetRotationFromGyroscope(Vector3d(v_x, v_y, v_z),
                                                    current_timestep_s);
      current_state_.sensor_from_start_rotation =
          rotation_from_gyroscope * current_state_.sensor_from_start_rotation;
      current_state_.sensor_from_start_rotation.normalize();
      UpdateStateCovariance(RotationMatrixNH(rotation_from_gyroscope));
      state_covariance_ =
          state_covariance_ +
          (process_covariance_ * (current_timestep_s * current_timestep_s));
    }
  }

  // Saves gyroscope event for future prediction.
  current_state_.timestamp_ns = timestamp_ns;
  current_state_.sensor_from_start_rotation_velocity = Vector3d(v_x, v_y, v_z);
}

// TODO(pfg): move to rotation object for the input.
Vector3d SensorFusion::ComputeInnovation(const Rotationd& pose) {
  const Vector3d predicted_down_direction =
      RotationMatrixNH(pose) * kCanonicalZDirection;

  const Rotationd rotation = Rotationd::FromTwoVectors(
      predicted_down_direction, accelerometer_measurement_);
  AngleAxisd angle_axis(rotation);
  return angle_axis.axis() * angle_axis.angle();
}

void SensorFusion::ComputeMeasurementJacobian() {
  for (int dof = 0; dof < 3; dof++) {
    // TODO(pfg): Create this delta rotation in the constructor and used unitX..
    Vector3d delta = Vector3d::Zero();
    delta[dof] = kFiniteDifferencingEpsilon;

    const Rotationd epsilon_rotation = RotationFromVector(delta);
    const Vector3d delta_rotation = ComputeInnovation(
        epsilon_rotation * current_state_.sensor_from_start_rotation);

    const Vector3d col =
        (innovation_ - delta_rotation) / kFiniteDifferencingEpsilon;
    accelerometer_measurement_jacobian_(0, dof) = col[0];
    accelerometer_measurement_jacobian_(1, dof) = col[1];
    accelerometer_measurement_jacobian_(2, dof) = col[2];
  }
}

void SensorFusion::ProcessAccelerometerSample(float acc_x, float acc_y,
                                              float acc_z,
                                              uint64 timestamp_ns) {
  std::unique_lock<std::mutex> lock(mutex_);

  // Discard outdated samples.
  if (current_accelerometer_timestamp_ns_ >= timestamp_ns) {
    // TODO(pfg): Investigate why this happens.
    return;
  }

  // Call reset state if required.
  if (execute_reset_with_next_accelerometer_sample_.exchange(false)) {
    ResetState();
  }

  accelerometer_measurement_ = Vector3d(acc_x, acc_y, acc_z);
  current_accelerometer_timestamp_ns_ = timestamp_ns;

  if (!is_aligned_with_gravity_) {
    // This is the first accelerometer measurement so it initializes the
    // orientation estimate.
    current_state_.sensor_from_start_rotation = Rotationd::FromTwoVectors(
        kCanonicalZDirection, accelerometer_measurement_);
    is_aligned_with_gravity_ = true;

    previous_accelerometer_norm_ = Length(accelerometer_measurement_);
    return;
  }

  UpdateMeasurementCovariance();

  innovation_ = ComputeInnovation(current_state_.sensor_from_start_rotation);
  ComputeMeasurementJacobian();

  // S = H * P * H' + R
  innovation_covariance_ = accelerometer_measurement_jacobian_ *
                               state_covariance_ *
                               Transpose(accelerometer_measurement_jacobian_) +
                           accelerometer_measurement_covariance_;

  // K = P * H' * S^-1
  kalman_gain_ = state_covariance_ *
                 Transpose(accelerometer_measurement_jacobian_) *
                 Inverse(innovation_covariance_);

  // x_update = K*nu
  state_update_ = kalman_gain_ * innovation_;

  // P = (I - K * H) * P;
  state_covariance_ = (Matrix3d::Identity() -
                       kalman_gain_ * accelerometer_measurement_jacobian_) *
                      state_covariance_;

  // Updates pose and associate covariance matrix.
  const Rotationd rotation_from_state_update =
      RotationFromVector(state_update_);

  current_state_.sensor_from_start_rotation =
      rotation_from_state_update * current_state_.sensor_from_start_rotation;
  UpdateStateCovariance(RotationMatrixNH(rotation_from_state_update));
}

void SensorFusion::UpdateStateCovariance(const Matrix3d& motion_update) {
  state_covariance_ =
      motion_update * state_covariance_ * Transpose(motion_update);
}

void SensorFusion::FilterGyroscopeTimestep(double gyroscope_timestep_s) {
  if (!is_timestep_filter_initialized_) {
    // Initializes the filter.
    filtered_gyroscope_timestep_s_ = gyroscope_timestep_s;
    num_gyroscope_timestep_samples_ = 1;
    is_timestep_filter_initialized_ = true;
    return;
  }

  // Computes the IIR filter response.
  filtered_gyroscope_timestep_s_ =
      kTimestepFilterCoeff * filtered_gyroscope_timestep_s_ +
      (1 - kTimestepFilterCoeff) * gyroscope_timestep_s;
  ++num_gyroscope_timestep_samples_;

  if (num_gyroscope_timestep_samples_ > kTimestepFilterMinSamples) {
    is_gyroscope_filter_valid_ = true;
  }
}

void SensorFusion::UpdateMeasurementCovariance() {
  const double current_accelerometer_norm = Length(accelerometer_measurement_);
  // Norm change between current and previous accel readings.
  const double current_accelerometer_norm_change =
      std::abs(current_accelerometer_norm - previous_accelerometer_norm_);
  previous_accelerometer_norm_ = current_accelerometer_norm;

  moving_average_accelerometer_norm_change_ =
      kSmoothingFactor * current_accelerometer_norm_change +
      (1. - kSmoothingFactor) * moving_average_accelerometer_norm_change_;

  // If we hit the accel norm change threshold, we use the maximum noise sigma
  // for the accel covariance. For anything below that, we use a linear
  // combination between min and max sigma values.
  const double norm_change_ratio =
      moving_average_accelerometer_norm_change_ / kMaxAccelNormChange;
  const double accelerometer_noise_sigma = std::min(
      kMaxAccelNoiseSigma,
      kMinAccelNoiseSigma +
          norm_change_ratio * (kMaxAccelNoiseSigma - kMinAccelNoiseSigma));

  // Updates the accel covariance matrix with the new sigma value.
  accelerometer_measurement_covariance_ = Matrix3d::Identity() *
                                          accelerometer_noise_sigma *
                                          accelerometer_noise_sigma;
}

}  // namespace dvr
}  // namespace android
