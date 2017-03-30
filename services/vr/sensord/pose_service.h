#ifndef ANDROID_DVR_SENSORD_POSE_SERVICE_H_
#define ANDROID_DVR_SENSORD_POSE_SERVICE_H_

#include <condition_variable>
#include <forward_list>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <dvr/pose_client.h>
#include <pdx/service.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/pose_client_internal.h>
#include <private/dvr/dvr_pose_predictor.h>
#include <private/dvr/ring_buffer.h>

#include "sensor_fusion.h"
#include "sensor_thread.h"

namespace android {
namespace dvr {

// PoseService implements the HMD pose service over ServiceFS.
class PoseService : public pdx::ServiceBase<PoseService> {
 public:
  ~PoseService() override;

  bool IsInitialized() const override;
  int HandleMessage(pdx::Message& msg) override;
  std::string DumpState(size_t max_length) override;

  // Handle events from the sensor HAL.
  // Safe to call concurrently with any other public member functions.
  void HandleEvents(const sensors_event_t* begin_events,
                    const sensors_event_t* end_events);

 private:
  friend BASE;

  enum OrientationType {
    // Typical smartphone device (default).
    kOrientationTypePortrait = 1,
    // Landscape device.
    kOrientationTypeLandscape = 2,
    // 180 Landscape device.
    kOrientationTypeLandscape180 = 3,
  };

  // Initializes the service. Keeps a reference to sensor_thread, which must be
  // non-null.
  explicit PoseService(SensorThread* sensor_thread);

  // Kick the sensor watch dog thread which will robustly disable IMU usage
  // when there are no sensor data consumers.
  // The class mutex (mutex_) must be locked while calling this method.
  void KickSensorWatchDogThread();

  void UpdatePoseMode();

  // Update the async pose ring buffer with new pose data.
  // |start_t_head| Head position in start space.
  // |start_q_head| Head orientation quaternion in start space.
  // |pose_timestamp| System timestamp of pose data in seconds.
  // |pose_delta_time| Elapsed time in seconds between this pose and the last.
  void WriteAsyncPoses(const Eigen::Vector3<double>& start_t_head,
                       const Eigen::Quaternion<double>& start_q_head,
                       int64_t pose_timestamp);

  // Set the pose mode.
  void SetPoseMode(DvrPoseMode mode);

  // The abstraction around the sensor data.
  SensorThread* sensor_thread_;

  // Protects access to all member variables.
  std::mutex mutex_;

  // Watchdog thread data. The watchdog thread will ensure that sensor access
  // is disabled when nothing has been consuming it for a while.
  int64_t last_sensor_usage_time_ns_;
  std::thread watchdog_thread_;
  std::condition_variable watchdog_condition_;
  bool watchdog_shutdown_;
  bool sensors_on_;

  // Indices for the accelerometer and gyroscope sensors, or -1 if the sensor
  // wasn't present on construction.
  int accelerometer_index_;
  int gyroscope_index_;

  // The sensor fusion algorithm and its state.
  SensorFusion sensor_fusion_;

  // Current pose mode.
  DvrPoseMode pose_mode_;

  // State which is sent if pose_mode_ is DVR_POSE_MODE_MOCK_FROZEN.
  DvrPoseState frozen_state_;

  // Last known pose.
  DvrPoseAsync last_known_pose_;

  // If this flag is true, the pose published includes a small prediction of
  // where it'll be when it's consumed.
  bool enable_pose_prediction_;

  // Flag to turn on recording of raw sensor data
  bool enable_sensor_recording_;

  // Flag to log pose to a file
  bool enable_pose_recording_;

  // Flag to turn on playback from a saved dataset instead of using live data.
  bool enable_sensor_playback_;

  std::string sensor_playback_id_;

  // External pose generation.
  bool enable_external_pose_ = false;

  // The predictor to extrapolate pose samples.
  std::unique_ptr<posepredictor::Predictor> pose_predictor_;

  // Pose ring buffer.
  std::shared_ptr<BufferProducer> ring_buffer_;
  // Temporary mapped ring buffer.
  DvrPoseRingBuffer* mapped_pose_buffer_;
  // Current vsync info, updated by displayd.
  uint32_t vsync_count_;
  int64_t photon_timestamp_;
  int64_t display_period_ns_;
  int64_t right_eye_photon_offset_ns_ = 0;

  // Type for controlling pose orientation calculation.
  OrientationType device_orientation_type_;

  PoseService(const PoseService&) = delete;
  void operator=(const PoseService&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SENSORD_POSE_SERVICE_H_
