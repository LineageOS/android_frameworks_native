#define ATRACE_TAG ATRACE_TAG_INPUT
#include "pose_service.h"

#include <dlfcn.h>
#include <errno.h>
#include <time.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <type_traits>

#include <cutils/properties.h>
#include <cutils/trace.h>
#include <dvr/performance_client_api.h>
#include <dvr/pose_client.h>
#include <hardware/sensors.h>
#include <log/log.h>
#include <pdx/default_transport/service_endpoint.h>
#include <private/dvr/benchmark.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/platform_defines.h>
#include <private/dvr/pose-ipc.h>
#include <private/dvr/sensor_constants.h>
#include <utils/Trace.h>

using android::pdx::LocalChannelHandle;
using android::pdx::default_transport::Endpoint;
using android::pdx::Status;

namespace android {
namespace dvr {

using Vector3d = vec3d;
using Rotationd = quatd;
using AngleAxisd = Eigen::AngleAxis<double>;

namespace {
// Wait a few seconds before checking if we need to disable sensors.
static constexpr int64_t kSensorTimeoutNs = 5000000000ll;

static constexpr float kTwoPi = 2.0 * M_PI;
static constexpr float kDegToRad = M_PI / 180.f;

// Head model code data.
static constexpr float kDefaultNeckHorizontalOffset = 0.080f;  // meters
static constexpr float kDefaultNeckVerticalOffset = 0.075f;    // meters

static constexpr char kDisablePosePredictionProp[] =
    "persist.dvr.disable_predict";

// Device type property for controlling classes of behavior that differ
// between devices. If unset, defaults to kOrientationTypeSmartphone.
static constexpr char kOrientationTypeProp[] = "ro.dvr.orientation_type";
static constexpr char kEnableSensorRecordProp[] = "dvr.enable_6dof_recording";
static constexpr char kEnableSensorPlayProp[] = "dvr.enable_6dof_playback";
static constexpr char kEnableSensorPlayIdProp[] = "dvr.6dof_playback_id";
static constexpr char kEnablePoseRecordProp[] = "dvr.enable_pose_recording";
static constexpr char kPredictorTypeProp[] = "dvr.predictor_type";

// Persistent buffer names.
static constexpr char kPoseRingBufferName[] = "PoseService:RingBuffer";

static constexpr int kDatasetIdLength = 36;
static constexpr char kDatasetIdChars[] = "0123456789abcdef-";

static constexpr int kLatencyWindowSize = 200;

// These are the flags used by BufferProducer::CreatePersistentUncachedBlob,
// plus PRIVATE_ADSP_HEAP to allow access from the DSP.
static constexpr int kPoseRingBufferFlags =
    GRALLOC_USAGE_SW_READ_RARELY | GRALLOC_USAGE_SW_WRITE_RARELY |
    GRALLOC_USAGE_PRIVATE_UNCACHED | GRALLOC_USAGE_PRIVATE_ADSP_HEAP;

std::string GetPoseModeString(DvrPoseMode mode) {
  switch (mode) {
    case DVR_POSE_MODE_6DOF:
      return "DVR_POSE_MODE_6DOF";
    case DVR_POSE_MODE_3DOF:
      return "DVR_POSE_MODE_3DOF";
    case DVR_POSE_MODE_MOCK_FROZEN:
      return "DVR_POSE_MODE_MOCK_FROZEN";
    case DVR_POSE_MODE_MOCK_HEAD_TURN_SLOW:
      return "DVR_POSE_MODE_MOCK_HEAD_TURN_SLOW";
    case DVR_POSE_MODE_MOCK_HEAD_TURN_FAST:
      return "DVR_POSE_MODE_MOCK_HEAD_TURN_FAST";
    case DVR_POSE_MODE_MOCK_ROTATE_SLOW:
      return "DVR_POSE_MODE_MOCK_ROTATE_SLOW";
    case DVR_POSE_MODE_MOCK_ROTATE_MEDIUM:
      return "DVR_POSE_MODE_MOCK_ROTATE_MEDIUM";
    case DVR_POSE_MODE_MOCK_ROTATE_FAST:
      return "DVR_POSE_MODE_MOCK_ROTATE_FAST";
    case DVR_POSE_MODE_MOCK_CIRCLE_STRAFE:
      return "DVR_POSE_MODE_MOCK_CIRCLE_STRAFE";
    default:
      return "Unknown pose mode";
  }
}

}  // namespace

PoseService::PoseService(SensorThread* sensor_thread)
    : BASE("PoseService", Endpoint::Create(DVR_POSE_SERVICE_CLIENT)),
      sensor_thread_(sensor_thread),
      last_sensor_usage_time_ns_(0),
      watchdog_shutdown_(false),
      sensors_on_(false),
      accelerometer_index_(-1),
      gyroscope_index_(-1),
      pose_mode_(DVR_POSE_MODE_6DOF),
      mapped_pose_buffer_(nullptr),
      vsync_count_(0),
      photon_timestamp_(0),
      // Will be updated by external service, but start with a non-zero value:
      display_period_ns_(16000000),
      sensor_latency_(kLatencyWindowSize) {
  last_known_pose_ = {
      .orientation = {1.0f, 0.0f, 0.0f, 0.0f},
      .translation = {0.0f, 0.0f, 0.0f, 0.0f},
      .angular_velocity = {0.0f, 0.0f, 0.0f, 0.0f},
      .velocity = {0.0f, 0.0f, 0.0f, 0.0f},
      .timestamp_ns = 0,
      .flags = DVR_POSE_FLAG_HEAD,
      .pad = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  };

  switch (property_get_int32(kOrientationTypeProp, kOrientationTypePortrait)) {
    case kOrientationTypeLandscape:
      device_orientation_type_ = kOrientationTypeLandscape;
      break;
    default:
      device_orientation_type_ = kOrientationTypePortrait;
      break;
  }

  ring_buffer_ =
      BufferProducer::Create(kPoseRingBufferName, 0, 0, kPoseRingBufferFlags,
                             sizeof(DvrPoseRingBuffer));
  if (!ring_buffer_) {
    ALOGE("PoseService::PoseService: Failed to create/get pose ring buffer!");
    return;
  }

  void* addr = nullptr;
  int ret =
      ring_buffer_->GetBlobReadWritePointer(sizeof(DvrPoseRingBuffer), &addr);
  if (ret < 0) {
    ALOGE("PoseService::PoseService: Failed to map pose ring buffer: %s",
          strerror(-ret));
    return;
  }
  memset(addr, 0, sizeof(DvrPoseRingBuffer));
  mapped_pose_buffer_ = static_cast<DvrPoseRingBuffer*>(addr);
  addr = nullptr;

  for (int i = 0; i < sensor_thread->GetSensorCount(); ++i) {
    if (sensor_thread->GetSensorType(i) == SENSOR_TYPE_ACCELEROMETER)
      accelerometer_index_ = i;
    if (sensor_thread->GetSensorType(i) == SENSOR_TYPE_GYROSCOPE_UNCALIBRATED)
      gyroscope_index_ = i;
  }
  // If we failed to find the uncalibrated gyroscope, use the regular one.
  if (gyroscope_index_ < 0) {
    ALOGW("PoseService was unable to find uncalibrated gyroscope");
    for (int i = 0; i < sensor_thread->GetSensorCount(); ++i) {
      ALOGI("Type %d", sensor_thread->GetSensorType(i));
      if (sensor_thread->GetSensorType(i) == SENSOR_TYPE_GYROSCOPE)
        gyroscope_index_ = i;
    }
  }

  if (accelerometer_index_ < 0) {
    ALOGE("PoseService was unable to find accelerometer");
  }
  if (gyroscope_index_ < 0) {
    ALOGE("PoseService was unable to find gyroscope");
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    KickSensorWatchDogThread();
  }

  // Read the persistent dvr flags before using them in SetPoseMode.
  enable_pose_prediction_ =
      property_get_bool(kDisablePosePredictionProp, 0) == 0;

  enable_sensor_recording_ = property_get_bool(kEnableSensorRecordProp, 0) == 1;

  enable_sensor_playback_ = property_get_bool(kEnableSensorPlayProp, 0) == 1;

  if (enable_sensor_playback_) {
    char dataset_id[PROPERTY_VALUE_MAX];
    property_get(kEnableSensorPlayIdProp, dataset_id, "");
    sensor_playback_id_ = std::string(dataset_id);

    if (sensor_playback_id_.length() != kDatasetIdLength ||
        sensor_playback_id_.find_first_not_of(kDatasetIdChars) !=
            std::string::npos) {
      ALOGE("Error: invalid playback id %s", sensor_playback_id_.c_str());
      sensor_playback_id_ = "";
      enable_sensor_playback_ = false;
    } else {
      ALOGI("Playback id %s", sensor_playback_id_.c_str());
    }
  }

  switch (property_get_int32(kPredictorTypeProp, 0)) {
    case 1:
      pose_predictor_ = posepredictor::Predictor::Create(
          posepredictor::PredictorType::Quadric);
    default:
      pose_predictor_ = posepredictor::Predictor::Create(
          posepredictor::PredictorType::Linear);
  }

  enable_pose_recording_ = property_get_bool(kEnablePoseRecordProp, 0) == 1;

  SetPoseMode(DVR_POSE_MODE_6DOF);
}

PoseService::~PoseService() {
  if (watchdog_thread_.get_id() != std::thread::id()) {
    {
      std::lock_guard<std::mutex> guard(mutex_);
      watchdog_shutdown_ = true;
      watchdog_condition_.notify_one();
    }
    watchdog_thread_.join();
  }
}

void PoseService::KickSensorWatchDogThread() {
  // This method is called every frame while rendering so we want to make sure
  // it is very light weight with synchronization.
  // TODO(jbates) For better performance, we can consider a lock-free atomic
  // solution instead of locking this mutex.

  // Update the usage time. The watchdog thread will poll this value to know
  // when to disable sensors.
  last_sensor_usage_time_ns_ = GetSystemClockNs();

  // If sensors are still on, there's nothing else to do.
  if (sensors_on_)
    return;

  // Enable sensors.
  ALOGI("Start using sensors.");
  sensors_on_ = true;
  if (accelerometer_index_ >= 0) {
    sensor_thread_->StartUsingSensor(accelerometer_index_);
  }
  if (gyroscope_index_ >= 0) {
    sensor_thread_->StartUsingSensor(gyroscope_index_);
  }

  // Tell the thread to wake up to disable the sensors when no longer needed.
  watchdog_condition_.notify_one();

  if (watchdog_thread_.get_id() == std::thread::id()) {
    // The sensor watchdog thread runs while sensors are in use. When no APIs
    // have requested sensors beyond a threshold (5 seconds), sensors are
    // disabled.
    watchdog_thread_ = std::thread([this] {
      std::unique_lock<std::mutex> lock(mutex_);
      while (!watchdog_shutdown_) {
        int64_t remaining_sensor_time_ns =
            last_sensor_usage_time_ns_ + kSensorTimeoutNs - GetSystemClockNs();

        if (remaining_sensor_time_ns > 0) {
          // Wait for the remaining usage time before checking again.
          watchdog_condition_.wait_for(
              lock, std::chrono::nanoseconds(remaining_sensor_time_ns));
          continue;
        }

        if (sensors_on_) {
          // Disable sensors.
          ALOGI("Stop using sensors.");
          sensors_on_ = false;
          if (accelerometer_index_ >= 0) {
            sensor_thread_->StopUsingSensor(accelerometer_index_);
          }
          if (gyroscope_index_ >= 0) {
            sensor_thread_->StopUsingSensor(gyroscope_index_);
          }
        }

        // Wait for sensors to be enabled again.
        watchdog_condition_.wait(lock);
      }
    });
  }
}

bool PoseService::IsInitialized() const {
  return BASE::IsInitialized() && ring_buffer_ && mapped_pose_buffer_;
}

void PoseService::WriteAsyncPoses(const Vector3d& start_t_head,
                                  const Rotationd& start_q_head,
                                  int64_t pose_timestamp) {
  if (enable_external_pose_) {
    return;
  }

  // If playing back data, the timestamps are different enough from the
  // current time that prediction doesn't work. This hack pretends that
  // there was one nanosecond of latency between the sensors and here.
  if (enable_sensor_playback_)
    pose_timestamp = GetSystemClockNs() - 1;

  // Feed the sample to the predictor
  AddPredictorPose(pose_predictor_.get(), start_t_head, start_q_head,
                   pose_timestamp, &last_known_pose_);

  // Store one extra value, because the application is working on the next
  // frame and expects the minimum count from that frame on.
  for (uint32_t i = 0; i < kPoseAsyncBufferMinFutureCount + 1; ++i) {
    int64_t target_time = photon_timestamp_ + i * display_period_ns_;

    // TODO(jbates, cwolfe) For the DSP code, we may still want poses even when
    // the vsyncs are not ticking up. But it's important not to update the pose
    // data that's in the past so that applications have the most accurate
    // estimate of the last frame's *actual* pose, so that they can update
    // simulations and calculate collisions, etc.
    if (target_time < pose_timestamp) {
      // Already in the past, do not update this head pose slot.
      continue;
    }

    // Write to the actual shared memory ring buffer.
    uint32_t index = ((vsync_count_ + i) & kPoseAsyncBufferIndexMask);

    // Make a pose prediction
    if (enable_pose_prediction_) {
      PredictPose(pose_predictor_.get(), target_time,
                  target_time + right_eye_photon_offset_ns_,
                  mapped_pose_buffer_->ring + index);
    } else {
      mapped_pose_buffer_->ring[index] = last_known_pose_;
    }
  }
}

void PoseService::UpdatePoseMode() {
  ALOGI_IF(TRACE, "UpdatePoseMode: %f %f %f", last_known_pose_.translation[0],
           last_known_pose_.translation[1], last_known_pose_.translation[2]);

  const int64_t current_time_ns = GetSystemClockNs();

  const PoseState pose_state = sensor_fusion_.GetLatestPoseState();

  switch (pose_mode_) {
    case DVR_POSE_MODE_MOCK_HEAD_TURN_SLOW:
    case DVR_POSE_MODE_MOCK_HEAD_TURN_FAST:
    case DVR_POSE_MODE_MOCK_ROTATE_SLOW:
    case DVR_POSE_MODE_MOCK_ROTATE_MEDIUM:
    case DVR_POSE_MODE_MOCK_ROTATE_FAST:
    case DVR_POSE_MODE_MOCK_CIRCLE_STRAFE: {
      // Calculate a pose based on monotic system time.
      const Vector3d y_axis(0., 1., 0.);
      double time_s = current_time_ns / 1e9;

      // Generate fake yaw data.
      float yaw = 0.0f;
      Vector3d head_trans(0.0, 0.0, 0.0);
      switch (pose_mode_) {
        default:
        case DVR_POSE_MODE_MOCK_HEAD_TURN_SLOW:
          // Pan across 120 degrees in 15 seconds.
          yaw = std::cos(kTwoPi * time_s / 15.0) * 60.0 * kDegToRad;
          break;
        case DVR_POSE_MODE_MOCK_HEAD_TURN_FAST:
          // Pan across 120 degrees in 4 seconds.
          yaw = std::cos(kTwoPi * time_s / 4.0) * 60.0 * kDegToRad;
          break;
        case DVR_POSE_MODE_MOCK_ROTATE_SLOW:
          // Rotate 5 degrees per second.
          yaw = std::fmod(time_s * 5.0 * kDegToRad, kTwoPi);
          break;
        case DVR_POSE_MODE_MOCK_ROTATE_MEDIUM:
          // Rotate 30 degrees per second.
          yaw = std::fmod(time_s * 30.0 * kDegToRad, kTwoPi);
          break;
        case DVR_POSE_MODE_MOCK_ROTATE_FAST:
          // Rotate 90 degrees per second.
          yaw = std::fmod(time_s * 90.0 * kDegToRad, kTwoPi);
          break;
        case DVR_POSE_MODE_MOCK_CIRCLE_STRAFE:
          // Circle strafe around origin at distance of 3 meters.
          yaw = std::fmod(time_s * 30.0 * kDegToRad, kTwoPi);
          head_trans += 3.0 * Vector3d(sin(yaw), 0.0, cos(yaw));
          break;
      }

      // Calculate the simulated head rotation in an absolute "head" space.
      // This space is not related to start space and doesn't need a
      // reference.
      Rotationd head_rotation_in_head_space(AngleAxisd(yaw, y_axis));

      WriteAsyncPoses(head_trans, head_rotation_in_head_space, current_time_ns);
      break;
    }
    case DVR_POSE_MODE_MOCK_FROZEN: {
      // Even when frozen, we still provide a current timestamp, because
      // consumers may rely on it being monotonic.

      Rotationd start_from_head_rotation(
          frozen_state_.head_from_start_rotation.w,
          frozen_state_.head_from_start_rotation.x,
          frozen_state_.head_from_start_rotation.y,
          frozen_state_.head_from_start_rotation.z);
      Vector3d head_from_start_translation(
          frozen_state_.head_from_start_translation.x,
          frozen_state_.head_from_start_translation.y,
          frozen_state_.head_from_start_translation.z);

      WriteAsyncPoses(head_from_start_translation, start_from_head_rotation,
                      current_time_ns);
      break;
    }
    case DVR_POSE_MODE_3DOF: {
      // Sensor fusion provides IMU-space data, transform to world space.

      // Constants to perform IMU orientation adjustments. Note that these
      // calculations will be optimized out in a release build.
      constexpr double k90DegInRad = 90.0 * M_PI / 180.0;
      const Vector3d kVecAxisX(1.0, 0.0, 0.0);
      const Vector3d kVecAxisY(0.0, 1.0, 0.0);
      const Vector3d kVecAxisZ(0.0, 0.0, 1.0);
      const Rotationd kRotX90(AngleAxisd(k90DegInRad, kVecAxisX));

      Rotationd start_from_head_rotation;
      if (device_orientation_type_ == kOrientationTypeLandscape) {
        const Rotationd kPostRotation =
            kRotX90 * Rotationd(AngleAxisd(-k90DegInRad, kVecAxisY));
        start_from_head_rotation =
            (pose_state.sensor_from_start_rotation * kPostRotation).inverse();
      } else if (device_orientation_type_ == kOrientationTypeLandscape180) {
        const Rotationd kPreRotation =
            Rotationd(AngleAxisd(k90DegInRad * 2.0, kVecAxisY)) *
            Rotationd(AngleAxisd(k90DegInRad * 2.0, kVecAxisZ));
        const Rotationd kPostRotation = kRotX90;
        start_from_head_rotation =
            (kPreRotation *
             pose_state.sensor_from_start_rotation * kPostRotation)
                .inverse();
      } else {
        const Rotationd kPreRotation =
            Rotationd(AngleAxisd(k90DegInRad, kVecAxisZ));
        const Rotationd kPostRotation = kRotX90;
        start_from_head_rotation =
            (kPreRotation * pose_state.sensor_from_start_rotation *
             kPostRotation)
                .inverse();
      }
      start_from_head_rotation.normalize();

      // Neck / head model code procedure for when no 6dof is available.
      // To apply the neck model, first translate the head pose to the new
      // center of eyes, then rotate around the origin (the original head
      // pos).
      Vector3d position =
          start_from_head_rotation * Vector3d(0.0, kDefaultNeckVerticalOffset,
                                              -kDefaultNeckHorizontalOffset);

      // Update the current latency model.
      if (pose_state.timestamp_ns != 0) {
        sensor_latency_.AddLatency(GetSystemClockNs() -
                                   pose_state.timestamp_ns);
      }

      // Update the timestamp with the expected latency.
      WriteAsyncPoses(
          position, start_from_head_rotation,
          pose_state.timestamp_ns + sensor_latency_.CurrentLatencyEstimate());
      break;
    }
    default:
    case DVR_POSE_MODE_6DOF:
      ALOGE("ERROR: invalid pose mode");
      break;
  }
}

pdx::Status<void> PoseService::HandleMessage(pdx::Message& msg) {
  pdx::Status<void> ret;
  const pdx::MessageInfo& info = msg.GetInfo();
  switch (info.op) {
    case DVR_POSE_NOTIFY_VSYNC: {
      std::lock_guard<std::mutex> guard(mutex_);

      // Kick the sensor thread, because we are still rendering.
      KickSensorWatchDogThread();

      const struct iovec data[] = {
          {.iov_base = &vsync_count_, .iov_len = sizeof(vsync_count_)},
          {.iov_base = &photon_timestamp_,
           .iov_len = sizeof(photon_timestamp_)},
          {.iov_base = &display_period_ns_,
           .iov_len = sizeof(display_period_ns_)},
          {.iov_base = &right_eye_photon_offset_ns_,
           .iov_len = sizeof(right_eye_photon_offset_ns_)},
      };
      ret = msg.ReadVectorAll(data);
      if (ret && !enable_external_pose_) {
        mapped_pose_buffer_->vsync_count = vsync_count_;
      }

      // TODO(jbates, eieio): make this async, no need to reply.
      REPLY_MESSAGE(msg, ret, error);
    }
    case DVR_POSE_POLL: {
      ATRACE_NAME("pose_poll");
      std::lock_guard<std::mutex> guard(mutex_);

      DvrPoseState client_state;
      client_state = {
          .head_from_start_rotation = {last_known_pose_.orientation[0],
                                       last_known_pose_.orientation[1],
                                       last_known_pose_.orientation[2],
                                       last_known_pose_.orientation[3]},
          .head_from_start_translation = {last_known_pose_.translation[0],
                                          last_known_pose_.translation[1],
                                          last_known_pose_.translation[2]},
          .timestamp_ns = static_cast<uint64_t>(last_known_pose_.timestamp_ns),
          .sensor_from_start_rotation_velocity = {
              last_known_pose_.angular_velocity[0],
              last_known_pose_.angular_velocity[1],
              last_known_pose_.angular_velocity[2]}};

      Btrace("Sensor data received",
             static_cast<int64_t>(client_state.timestamp_ns));

      Btrace("Pose polled");

      ret = msg.WriteAll(&client_state, sizeof(client_state));
      REPLY_MESSAGE(msg, ret, error);
    }
    case DVR_POSE_FREEZE: {
      {
        std::lock_guard<std::mutex> guard(mutex_);

        DvrPoseState frozen_state;
        ret = msg.ReadAll(&frozen_state, sizeof(frozen_state));
        if (!ret) {
          REPLY_ERROR(msg, ret.error(), error);
        }
        frozen_state_ = frozen_state;
      }
      SetPoseMode(DVR_POSE_MODE_MOCK_FROZEN);
      REPLY_MESSAGE(msg, ret, error);
    }
    case DVR_POSE_SET_MODE: {
      int mode;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        ret = msg.ReadAll(&mode, sizeof(mode));
        if (!ret) {
          REPLY_ERROR(msg, ret.error(), error);
        }
        if (mode < 0 || mode >= DVR_POSE_MODE_COUNT) {
          REPLY_ERROR(msg, EINVAL, error);
        }
      }
      SetPoseMode(DvrPoseMode(mode));
      REPLY_MESSAGE(msg, ret, error);
    }
    case DVR_POSE_GET_MODE: {
      std::lock_guard<std::mutex> guard(mutex_);
      int mode = pose_mode_;
      ret = msg.WriteAll(&mode, sizeof(mode));
      REPLY_MESSAGE(msg, ret, error);
    }
    case DVR_POSE_GET_RING_BUFFER: {
      std::lock_guard<std::mutex> guard(mutex_);

      // Kick the sensor thread, because we have a new consumer.
      KickSensorWatchDogThread();

      Status<LocalChannelHandle> consumer_channel =
          ring_buffer_->CreateConsumer();
      REPLY_MESSAGE(msg, consumer_channel, error);
    }
    case DVR_POSE_GET_CONTROLLER_RING_BUFFER: {
      std::lock_guard<std::mutex> guard(mutex_);
      REPLY_ERROR(msg, EINVAL, error);
    }
    case DVR_POSE_LOG_CONTROLLER: {
      std::lock_guard<std::mutex> guard(mutex_);
      REPLY_ERROR(msg, EINVAL, error);
    }
    default:
      // Do not lock mutex_ here, because this may call the on*() handlers,
      // which will lock the mutex themselves.
      ret = Service::HandleMessage(msg);
      break;
  }
error:
  return ret;
}

std::string PoseService::DumpState(size_t /*max_length*/) {
  DvrPoseMode pose_mode;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    pose_mode = pose_mode_;
  }

  std::ostringstream stream;
  stream << "Pose mode: " << GetPoseModeString(pose_mode);
  return stream.str();
}

void PoseService::HandleEvents(const sensors_event_t* begin_events,
                               const sensors_event_t* end_events) {
  ATRACE_NAME("PoseService::HandleEvents");
  std::lock_guard<std::mutex> guard(mutex_);

  for (const sensors_event_t* event = begin_events; event != end_events;
       ++event) {
    if (event->type == SENSOR_TYPE_ACCELEROMETER) {
      sensor_fusion_.ProcessAccelerometerSample(
          event->acceleration.x, event->acceleration.y, event->acceleration.z,
          event->timestamp);
    } else if (event->type == SENSOR_TYPE_GYROSCOPE_UNCALIBRATED) {
      sensor_fusion_.ProcessGyroscopeSample(event->gyro.x, event->gyro.y,
                                            event->gyro.z, event->timestamp);
    }
  }

  UpdatePoseMode();
}

void PoseService::SetPoseMode(DvrPoseMode mode) {
  if (mode == DVR_POSE_MODE_6DOF) {
    // Only 3DoF is currently supported.
    mode = DVR_POSE_MODE_3DOF;
  }

  pose_mode_ = mode;

  sensor_thread_->SetPaused(false);
}

}  // namespace dvr
}  // namespace android
