#ifndef ANDROID_DVR_SENSORD_SENSOR_NDK_THREAD_H_
#define ANDROID_DVR_SENSORD_SENSOR_NDK_THREAD_H_

#include <android/sensor.h>
#include <hardware/sensors.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "sensor_thread.h"

namespace android {
namespace dvr {

// Manages initialization and polling of the sensor data. Polling is performed
// continuously on a thread that passes events along to an arbitrary consumer.
// All const member functions are thread-safe; otherwise, thread safety is noted
// for each function.
class SensorNdkThread : public SensorThread {
 public:
  // Initializes the sensor access, but does not yet start polling (see Start()
  // below). Sets *out_success to true on success; otherwise, sets *out_success
  // to false and logs an error.
  explicit SensorNdkThread(bool* out_success);

  // Tells the polling thread to shut down if it's running, and waits for it to
  // complete its polling loop.
  ~SensorNdkThread() override;

  // Begins polling on the thread. The provided consumer will be notified of
  // events. Event notification occurs on the polling thread.
  // Calling Start() more than once on an instance of SensorNdkThread is
  // invalid.
  void StartPolling(const EventConsumer& consumer) override;

  // Set whether the sensor polling thread is paused or not. This is useful
  // while we need to support both 3DoF and 6DoF codepaths. This 3DoF codepath
  // must be paused while the 6DoF codepath is using the IMU event stream.
  void SetPaused(bool is_paused) override;

  // Increase the number of users of the given sensor by one. Activates the
  // sensor if it wasn't already active.
  // Safe to call concurrently with any other functions in this class.
  void StartUsingSensor(int sensor_index) override;

  // Decrease the number of users of the given sensor by one. Deactivates the
  // sensor if its usage count has dropped to zero.
  // Safe to call concurrently with any other functions in this class.
  void StopUsingSensor(int sensor_index) override;

  // The number of sensors that are available. Returns a negative number if
  // initialization failed.
  int GetSensorCount() const override { return sensor_count_; }

  // The underlying sensor HAL data structure for the sensor at the given index.
  int GetSensorType(int index) const override {
    return ASensor_getType(sensor_list_[index]);
  }

 private:
  // Initialize ALooper and sensor access on the thread.
  // Returns true on success, false on failure.
  bool InitializeSensors();

  // Destroy sensor access.
  void DestroySensors();

  // Start or stop requested sensors from the thread. Class mutex must already
  // be locked.
  void UpdateSensorUse();

  // The actual thread on which we consume events.
  std::unique_ptr<std::thread> thread_;

  // Mutex for access to shutting_down_ and paused_ members.
  std::mutex mutex_;

  // Condition for signaling pause/unpause to the thread.
  std::condition_variable condition_;

  // Condition for signaling thread initialization.
  std::condition_variable init_condition_;

  // If this member is set to true, the thread will stop running at its next
  // iteration. Only set with the mutex held and signal condition_ when changed.
  bool shutting_down_;

  // If this member is set to true, the thread will pause at its next
  // iteration. Only set with the mutex held and signal condition_ when changed.
  bool paused_;

  // Thread start hand shake to verify that sensor initialization succeeded.
  bool thread_started_;

  // Initialization result (true for success).
  bool initialization_result_;

  // The callback.
  EventConsumer consumer_;

  // Sensor access
  ALooper* looper_;
  ASensorManager* sensor_manager_;
  ASensorEventQueue* event_queue_;

  // Sensor list from NDK.
  ASensorList sensor_list_;
  int sensor_count_;

  // Requests to the sensor thread to enable or disable given sensors.
  std::vector<int> enable_sensors_;
  std::vector<int> disable_sensors_;

  // A count of how many users each sensor has. Protected by user_count_mutex.
  std::vector<int> sensor_user_count_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SENSORD_SENSOR_NDK_THREAD_H_
