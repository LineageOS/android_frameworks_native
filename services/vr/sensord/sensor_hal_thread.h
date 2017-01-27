#ifndef ANDROID_DVR_SENSORD_SENSOR_HAL_THREAD_H_
#define ANDROID_DVR_SENSORD_SENSOR_HAL_THREAD_H_

#include <hardware/sensors.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "sensor_thread.h"

namespace android {
namespace dvr {

// Manages initialization and polling of the sensor HAL. Polling is performed
// continuously on a thread that passes events along to an arbitrary consumer.
// All const member functions are thread-safe; otherwise, thread safety is noted
// for each function.
class SensorHalThread : public SensorThread {
 public:
  // Initializes the sensor HAL, but does not yet start polling (see Start()
  // below). Sets *out_success to true on success; otherwise, sets *out_success
  // to false and logs an error.
  explicit SensorHalThread(bool* out_success);

  // Tells the polling thread to shut down if it's running, and waits for it to
  // complete its polling loop.
  ~SensorHalThread() override;

  // Begins polling on the thread. The provided consumer will be notified of
  // events. Event notification occurs on the polling thread.
  // Calling Start() more than once on an instance of SensorHalThread is
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
  int GetSensorCount() const override {
    return static_cast<int>(sensor_user_count_.size());
  }

  // The underlying sensor HAL data structure for the sensor at the given index.
  int GetSensorType(int index) const override {
    return sensor_list_[index].type;
  }

 private:
  // The actual thread on which we consume events.
  std::unique_ptr<std::thread> thread_;

  // Mutex for access to shutting_down_ and paused_ members.
  std::mutex mutex_;

  // Condition for signaling pause/unpause to the thread.
  std::condition_variable condition_;

  // If this member is set to true, the thread will stop running at its next
  // iteration. Only set with the mutex held and signal condition_ when changed.
  bool shutting_down_;

  // If this member is set to true, the thread will pause at its next
  // iteration. Only set with the mutex held and signal condition_ when changed.
  bool paused_;

  // HAL access
  struct sensors_module_t* sensor_module_;
  sensors_poll_device_1_t* sensor_device_;

  // Contiguous array of available sensors, owned by the sensor HAL.
  const sensor_t* sensor_list_;

  // Mutex that protects access to sensor_user_count_.data().
  std::mutex user_count_mutex_;

  // A count of how many users each sensor has. Protected by user_count_mutex.
  std::vector<int> sensor_user_count_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SENSORD_SENSOR_HAL_THREAD_H_
