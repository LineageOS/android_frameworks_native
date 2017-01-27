#ifndef ANDROID_DVR_SENSORD_SENSOR_FUSION_H_
#define ANDROID_DVR_SENSORD_SENSOR_FUSION_H_

#include <atomic>
#include <cstdlib>
#include <mutex>

#include <private/dvr/types.h>

namespace android {
namespace dvr {

using Matrix3d = Eigen::Matrix<double, 3, 3>;
using Rotationd = quatd;
using Vector3d = vec3d;
using AngleAxisd = Eigen::AngleAxisd;

// Ported from GVR's pose_state.h.
// Stores a 3dof pose plus derivatives. This can be used for prediction.
struct PoseState {
  // Time in nanoseconds for the current pose.
  uint64_t timestamp_ns;

  // Rotation from Sensor Space to Start Space.
  Rotationd sensor_from_start_rotation;

  // First derivative of the rotation.
  // TODO(pfg): currently storing gyro data, switch to first derivative instead.
  Vector3d sensor_from_start_rotation_velocity;
};

// Sensor fusion class that implements an Extended Kalman Filter (EKF) to
// estimate a 3D rotation from a gyroscope and and accelerometer.
// This system only has one state, the pose. It does not estimate any velocity
// or acceleration.
//
// To learn more about Kalman filtering one can read this article which is a
// good introduction: http://en.wikipedia.org/wiki/Kalman_filter
//
// Start Space is :
// z is up.
// y is forward based on the first sensor data.
// x = y \times z
// Sensor Space follows the android specification {@link
// http://developer.android.com/guide/topics/sensors/sensors_overview.html#sensors-coords}
// See http://go/vr-coords for definitions of Start Space and Sensor Space.
//
// This is a port from GVR's SensorFusion code (See
// https://cs/vr/gvr/sensors/sensor_fusion.h)
// which in turn is a port from java of OrientationEKF (See
// https://cs/java/com/google/vr/cardboard/vrtoolkit/vrtoolkit/src/main/java/com/google/vrtoolkit/cardboard/sensors/internal/OrientationEKF.java)
class SensorFusion {
 public:
  SensorFusion();
  SensorFusion(const SensorFusion&) = delete;
  void operator=(const SensorFusion&) = delete;

  // Resets the state of the sensor fusion. It sets the velocity for
  // prediction to zero. The reset will happen with the next
  // accelerometer sample. Gyroscope sample will be discarded until a new
  // accelerometer sample arrives.
  void Reset();

  // Gets the PoseState representing the latest pose and  derivatives at a
  // particular timestamp as estimated by SensorFusion.
  PoseState GetLatestPoseState() const;

  // Processes one gyroscope sample event. This updates the pose of the system
  // and the prediction model. The gyroscope data is assumed to be in axis angle
  // form. Angle = ||v|| and Axis = v / ||v||, with v = [v_x, v_y, v_z]^T.
  //
  // @param v_x velocity in x.
  // @param v_y velocity in y.
  // @param v_z velocity in z.
  // @param timestamp_ns gyroscope event timestamp in nanosecond.
  void ProcessGyroscopeSample(float v_x, float v_y, float v_z,
                              uint64_t timestamp_ns);

  // Processes one accelerometer sample event. This updates the pose of the
  // system. If the Accelerometer norm changes too much between sample it is not
  // trusted as much.
  //
  // @param acc_x accelerometer data in x.
  // @param acc_y accelerometer data in y.
  // @param acc_z accelerometer data in z.
  // @param timestamp_ns accelerometer event timestamp in nanosecond.
  void ProcessAccelerometerSample(float acc_x, float acc_y, float acc_z,
                                  uint64_t timestamp_ns);

 private:
  // Estimates the average timestep between gyroscope event.
  void FilterGyroscopeTimestep(double gyroscope_timestep);

  // Updates the state covariance with an incremental motion. It changes the
  // space of the quadric.
  void UpdateStateCovariance(const Matrix3d& motion_update);

  // Computes the innovation vector of the Kalman based on the input pose.
  // It uses the latest measurement vector (i.e. accelerometer data), which must
  // be set prior to calling this function.
  Vector3d ComputeInnovation(const Rotationd& pose);

  // This computes the measurement_jacobian_ via numerical differentiation based
  // on the current value of sensor_from_start_rotation_.
  void ComputeMeasurementJacobian();

  // Updates the accelerometer covariance matrix.
  //
  // This looks at the norm of recent accelerometer readings. If it has changed
  // significantly, it means the phone receives additional acceleration than
  // just gravity, and so the down vector information gravity signal is noisier.
  //
  // TODO(dcoz,pfg): this function is very simple, we probably need something
  // more elaborated here once we have proper regression testing.
  void UpdateMeasurementCovariance();

  // Reset all internal states. This is not thread safe. Lock should be acquired
  // outside of it. This function is called in ProcessAccelerometerSample.
  void ResetState();

  // Current transformation from Sensor Space to Start Space.
  // x_sensor = sensor_from_start_rotation_ * x_start;
  PoseState current_state_;

  // Filtering of the gyroscope timestep started?
  bool is_timestep_filter_initialized_;
  // Filtered gyroscope timestep valid?
  bool is_gyroscope_filter_valid_;
  // Sensor fusion currently aligned with gravity? After initialization
  // it will requires a couple of accelerometer data for the system to get
  // aligned.
  bool is_aligned_with_gravity_;

  // Covariance of Kalman filter state (P in common formulation).
  Matrix3d state_covariance_;
  // Covariance of the process noise (Q in common formulation).
  Matrix3d process_covariance_;
  // Covariance of the accelerometer measurement (R in common formulation).
  Matrix3d accelerometer_measurement_covariance_;
  // Covariance of innovation (S in common formulation).
  Matrix3d innovation_covariance_;
  // Jacobian of the measurements (H in common formulation).
  Matrix3d accelerometer_measurement_jacobian_;
  // Gain of the Kalman filter (K in common formulation).
  Matrix3d kalman_gain_;
  // Parameter update a.k.a. innovation vector. (\nu in common formulation).
  Vector3d innovation_;
  // Measurement vector (z in common formulation).
  Vector3d accelerometer_measurement_;
  // Current prediction vector (g in common formulation).
  Vector3d prediction_;
  // Control input, currently this is only the gyroscope data (\mu in common
  // formulation).
  Vector3d control_input_;
  // Update of the state vector. (x in common formulation).
  Vector3d state_update_;

  // Time of the last accelerometer processed event.
  uint64_t current_accelerometer_timestamp_ns_;

  // Estimates of the timestep between gyroscope event in seconds.
  double filtered_gyroscope_timestep_s_;
  // Number of timestep samples processed so far by the filter.
  uint32_t num_gyroscope_timestep_samples_;
  // Norm of the accelerometer for the previous measurement.
  double previous_accelerometer_norm_;
  // Moving average of the accelerometer norm changes. It is computed for every
  // sensor datum.
  double moving_average_accelerometer_norm_change_;

  // Flag indicating if a state reset should be executed with the next
  // accelerometer sample.
  std::atomic<bool> execute_reset_with_next_accelerometer_sample_;

  mutable std::mutex mutex_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SENSORD_SENSOR_FUSION_H_
