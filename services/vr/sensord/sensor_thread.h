#ifndef ANDROID_DVR_SENSORD_SENSOR_THREAD_H_
#define ANDROID_DVR_SENSORD_SENSOR_THREAD_H_

#include <hardware/sensors.h>

#include <functional>

namespace android {
namespace dvr {

// Manages initialization and polling of the sensor data. Polling is performed
// continuously on a thread that passes events along to an arbitrary consumer.
// All const member functions are thread-safe; otherwise, thread safety is noted
// for each function.
class SensorThread {
 public:
  // A function type that can be called to provide it with new events.
  // [events_begin, events_end) forms a contiguous array of events.
  using EventConsumer = std::function<void(const sensors_event_t* events_begin,
                                           const sensors_event_t* events_end)>;

  // Tells the polling thread to shut down if it's running, and waits for it to
  // complete its polling loop.
  virtual ~SensorThread();

  // Begins polling on the thread. The provided consumer will be notified of
  // events. Event notification occurs on the polling thread.
  // Calling Start() more than once on an instance of SensorThread is
  // invalid.
  virtual void StartPolling(const EventConsumer& consumer) = 0;

  // Set whether the sensor polling thread is paused or not. This is useful
  // while we need to support both 3DoF and 6DoF codepaths. This 3DoF codepath
  // must be paused while the 6DoF codepath is using the IMU event stream.
  virtual void SetPaused(bool is_paused) = 0;

  // Increase the number of users of the given sensor by one. Activates the
  // sensor if it wasn't already active.
  // Safe to call concurrently with any other functions in this class.
  virtual void StartUsingSensor(int sensor_index) = 0;

  // Decrease the number of users of the given sensor by one. Deactivates the
  // sensor if its usage count has dropped to zero.
  // Safe to call concurrently with any other functions in this class.
  virtual void StopUsingSensor(int sensor_index) = 0;

  // The number of sensors that are available. Returns a negative number if
  // initialization failed.
  virtual int GetSensorCount() const = 0;

  // Get the sensor type for the sensor at the given index.
  virtual int GetSensorType(int index) const = 0;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SENSORD_SENSOR_THREAD_H_
