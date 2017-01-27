#include "sensor_hal_thread.h"

#include <cutils/log.h>
#include <dvr/performance_client_api.h>

namespace android {
namespace dvr {

SensorHalThread::SensorHalThread(bool* out_success)
    : shutting_down_(false),
      paused_(false),
      sensor_module_(nullptr),
      sensor_device_(nullptr),
      sensor_list_(nullptr) {
  // Assume failure; we will change this to true on success.
  *out_success = false;

  // TODO(segal): module & device should be singletons.
  int32_t err = hw_get_module_by_class(SENSORS_HARDWARE_MODULE_ID, "platform",
                                       (hw_module_t const**)&sensor_module_);

  if (err) {
    ALOGE("couldn't load %s module (%s)", SENSORS_HARDWARE_MODULE_ID,
          strerror(-err));
    return;
  }

  err = sensors_open_1(&sensor_module_->common, &sensor_device_);
  if (err) {
    ALOGE("couldn't open device for module %s (%s)", SENSORS_HARDWARE_MODULE_ID,
          strerror(-err));
    return;
  }

  const int sensor_count =
      sensor_module_->get_sensors_list(sensor_module_, &sensor_list_);

  // Deactivate all of the sensors initially.
  sensor_user_count_.resize(sensor_count, 0);
  for (int i = 0; i < sensor_count; ++i) {
    err = sensor_device_->activate(
        reinterpret_cast<struct sensors_poll_device_t*>(sensor_device_),
        sensor_list_[i].handle, 0);

    if (err) {
      ALOGE("failed to deactivate sensor %d (%s)", i, strerror(-err));
      return;
    }
  }

  // At this point, we've successfully initialized everything.
  *out_success = true;
}

SensorHalThread::~SensorHalThread() {
  {
    std::unique_lock<std::mutex> lock(mutex_);
    shutting_down_ = true;
    condition_.notify_one();
  }

  // Implicitly joins *thread_ if it's running.
}

void SensorHalThread::StartPolling(const EventConsumer& consumer) {
  if (thread_) {
    ALOGE("SensorHalThread::Start() called but thread is already running!");
    return;
  }

  thread_.reset(new std::thread([this, consumer] {
    const int priority_error = dvrSetSchedulerClass(0, "sensors:high");
    LOG_ALWAYS_FATAL_IF(
        priority_error < 0,
        "SensorHalTread::StartPolling: Failed to set scheduler class: %s",
        strerror(-priority_error));

    for (;;) {
      for (;;) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (shutting_down_)
          return;
        if (!paused_)
          break;
        condition_.wait(lock);
      }
      const int kMaxEvents = 100;
      sensors_event_t events[kMaxEvents];
      ssize_t event_count = 0;
      do {
        if (sensor_device_) {
          event_count = sensor_device_->poll(
              reinterpret_cast<struct sensors_poll_device_t*>(sensor_device_),
              events, kMaxEvents);
        } else {
          // When there is no sensor_device_, we still call the consumer at
          // regular intervals in case mock poses are in use. Note that this
          // will never be the case for production devices, but this helps
          // during bringup.
          usleep(5000);
        }
      } while (event_count == -EINTR);
      if (event_count == kMaxEvents)
        ALOGI("max events (%d) reached", kMaxEvents);

      if (event_count >= 0) {
        consumer(events, events + event_count);
      } else {
        ALOGE(
            "SensorHalThread::StartPolling: Error while polling sensor: %s "
            "(%zd)",
            strerror(-event_count), -event_count);
      }
    }
  }));
}

void SensorHalThread::SetPaused(bool is_paused) {
  std::unique_lock<std::mutex> lock(mutex_);
  paused_ = is_paused;
  condition_.notify_one();
}

void SensorHalThread::StartUsingSensor(const int sensor_index) {
  if (sensor_index < 0 || sensor_index >= GetSensorCount()) {
    ALOGE("StartUsingSensor(): sensor index %d out of range [0, %d)",
          sensor_index, GetSensorCount());
    return;
  }

  std::lock_guard<std::mutex> guard(user_count_mutex_);
  if (sensor_user_count_[sensor_index]++ == 0) {
    sensor_device_->activate(
        reinterpret_cast<struct sensors_poll_device_t*>(sensor_device_),
        sensor_list_[sensor_index].handle, 1);
    sensor_device_->setDelay(
        reinterpret_cast<struct sensors_poll_device_t*>(sensor_device_),
        sensor_list_[sensor_index].handle, 0);
  }
}

void SensorHalThread::StopUsingSensor(const int sensor_index) {
  if (sensor_index < 0 || sensor_index >= GetSensorCount()) {
    ALOGE("StopUsingSensor(): sensor index %d out of range [0, %d)",
          sensor_index, GetSensorCount());
    return;
  }

  std::lock_guard<std::mutex> guard(user_count_mutex_);
  if (--sensor_user_count_[sensor_index] == 0) {
    sensor_device_->activate(
        reinterpret_cast<struct sensors_poll_device_t*>(sensor_device_),
        sensor_list_[sensor_index].handle, 0);
  }
}

}  // namespace dvr
}  // namespace android
