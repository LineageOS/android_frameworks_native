#include "sensor_ndk_thread.h"

#include <dvr/performance_client_api.h>
#include <log/log.h>

namespace android {
namespace dvr {

namespace {
static constexpr int kLooperIdUser = 5;
}  // namespace

SensorNdkThread::SensorNdkThread(bool* out_success)
    : shutting_down_(false),
      paused_(true),
      thread_started_(false),
      initialization_result_(false),
      looper_(nullptr),
      sensor_manager_(nullptr),
      event_queue_(nullptr),
      sensor_list_(nullptr),
      sensor_count_(0) {
  // Assume failure; we will change this to true on success.
  *out_success = false;

  // These structs are the same, but sanity check the sizes.
  static_assert(sizeof(sensors_event_t) == sizeof(ASensorEvent),
                "Error: sizeof(sensors_event_t) != sizeof(ASensorEvent)");

  thread_.reset(new std::thread([this] {
    const int priority_error = dvrSetSchedulerClass(0, "sensors:high");
    LOG_ALWAYS_FATAL_IF(
        priority_error < 0,
        "SensorHalTread::StartPolling: Failed to set scheduler class: %s",
        strerror(-priority_error));

    // Start ALooper and initialize sensor access.
    {
      std::unique_lock<std::mutex> lock(mutex_);
      initialization_result_ = InitializeSensors();
      thread_started_ = true;
      init_condition_.notify_one();
      if (!initialization_result_)
        return;
    }

    EventConsumer consumer;
    for (;;) {
      for (;;) {
        std::unique_lock<std::mutex> lock(mutex_);
        UpdateSensorUse();
        if (!consumer)
          consumer = consumer_;
        if (shutting_down_)
          return;
        if (!paused_)
          break;
        condition_.wait(lock);
      }

      constexpr int kMaxEvents = 100;
      sensors_event_t events[kMaxEvents];
      ssize_t event_count = 0;
      if (looper_ && sensor_manager_) {
        int poll_fd, poll_events;
        void* poll_source;
        // Poll for events.
        int ident = ALooper_pollAll(-1, &poll_fd, &poll_events, &poll_source);

        if (ident != kLooperIdUser)
          continue;

        ASensorEvent* event = reinterpret_cast<ASensorEvent*>(&events[0]);
        event_count =
            ASensorEventQueue_getEvents(event_queue_, event, kMaxEvents);

        if (event_count == 0) {
          ALOGE("Detected sensor service failure, restarting sensors");
          // This happens when sensorservice has died and restarted. To avoid
          // spinning we need to restart the sensor access.
          DestroySensors();
          InitializeSensors();
        }
      } else {
        // When there is no sensor_device_, we still call the consumer at
        // regular intervals in case mock poses are in use. Note that this
        // will never be the case for production devices, but this helps
        // during bringup.
        usleep(5000);
      }
      if (event_count == kMaxEvents)
        ALOGI("max events (%d) reached", kMaxEvents);

      if (event_count >= 0) {
        consumer(events, events + event_count);
      } else {
        ALOGE(
            "SensorNdkThread::StartPolling: Error while polling sensor: %s "
            "(%zd)",
            strerror(-event_count), -event_count);
      }
    }

    // About to exit sensor thread, destroy sensor objects.
    DestroySensors();
  }));

  // Wait for thread to startup and initialize sensors so that we know whether
  // it succeeded.
  {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!thread_started_)
      init_condition_.wait(lock);
  }

  // At this point, we've successfully initialized everything.
  *out_success = initialization_result_;
}

SensorNdkThread::~SensorNdkThread() {
  {
    if (looper_)
      ALooper_wake(looper_);
    std::unique_lock<std::mutex> lock(mutex_);
    shutting_down_ = true;
    condition_.notify_one();
  }

  thread_->join();
}

bool SensorNdkThread::InitializeSensors() {
  looper_ = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
  if (!looper_) {
    ALOGE("Failed to create ALooper.");
    return false;
  }

  // Prepare to monitor accelerometer
  sensor_manager_ = ASensorManager_getInstanceForPackage(nullptr);
  if (!sensor_manager_) {
    ALOGE("Failed to create ASensorManager.");
    return false;
  }

  event_queue_ = ASensorManager_createEventQueue(
      sensor_manager_, looper_, kLooperIdUser, nullptr, nullptr);
  if (!event_queue_) {
    ALOGE("Failed to create sensor EventQueue.");
    return false;
  }

  sensor_count_ = ASensorManager_getSensorList(sensor_manager_, &sensor_list_);
  ALOGI("Sensor count %d", sensor_count_);

  sensor_user_count_.resize(sensor_count_, 0);

  // To recover from sensorservice restart, enable the sensors that are already
  // requested.
  for (size_t sensor_index = 0; sensor_index < sensor_user_count_.size();
       ++sensor_index) {
    if (sensor_user_count_[sensor_index] > 0) {
      int result = ASensorEventQueue_registerSensor(
          event_queue_, sensor_list_[sensor_index], 0, 0);
      ALOGE_IF(result < 0, "ASensorEventQueue_registerSensor failed: %d",
               result);
    }
  }

  return true;
}

void SensorNdkThread::DestroySensors() {
  for (size_t sensor_index = 0; sensor_index < sensor_user_count_.size();
       ++sensor_index) {
    if (sensor_user_count_[sensor_index] > 0) {
      ASensorEventQueue_disableSensor(event_queue_, sensor_list_[sensor_index]);
    }
  }
  ASensorManager_destroyEventQueue(sensor_manager_, event_queue_);
}

void SensorNdkThread::UpdateSensorUse() {
  if (!enable_sensors_.empty()) {
    for (int sensor_index : enable_sensors_) {
      if (sensor_user_count_[sensor_index]++ == 0) {
        int result = ASensorEventQueue_registerSensor(
            event_queue_, sensor_list_[sensor_index], 0, 0);
        ALOGE_IF(result < 0, "ASensorEventQueue_registerSensor failed: %d",
                 result);
      }
    }
    enable_sensors_.clear();
  }

  if (!disable_sensors_.empty()) {
    for (int sensor_index : disable_sensors_) {
      if (--sensor_user_count_[sensor_index] == 0) {
        int result = ASensorEventQueue_disableSensor(
            event_queue_, sensor_list_[sensor_index]);
        ALOGE_IF(result < 0, "ASensorEventQueue_disableSensor failed: %d",
                 result);
      }
    }
    disable_sensors_.clear();
  }
}

void SensorNdkThread::StartPolling(const EventConsumer& consumer) {
  {
    std::unique_lock<std::mutex> lock(mutex_);
    if (consumer_) {
      ALOGE("Already started sensor thread.");
      return;
    }
    consumer_ = consumer;
  }
  SetPaused(false);
}

void SensorNdkThread::SetPaused(bool is_paused) {
  std::unique_lock<std::mutex> lock(mutex_);
  // SetPaused may be called before we have StartPolling, make sure we have
  // an event consumer. Otherwise we defer until StartPolling is called.
  if (!consumer_)
    return;
  paused_ = is_paused;
  condition_.notify_one();
  ALooper_wake(looper_);
}

void SensorNdkThread::StartUsingSensor(const int sensor_index) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (sensor_index < 0 || sensor_index >= sensor_count_) {
    ALOGE("StartUsingSensor(): sensor index %d out of range [0, %d)",
          sensor_index, sensor_count_);
    return;
  }

  enable_sensors_.push_back(sensor_index);
  ALooper_wake(looper_);
}

void SensorNdkThread::StopUsingSensor(const int sensor_index) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (sensor_index < 0 || sensor_index >= sensor_count_) {
    ALOGE("StopUsingSensor(): sensor index %d out of range [0, %d)",
          sensor_index, sensor_count_);
    return;
  }

  disable_sensors_.push_back(sensor_index);
  ALooper_wake(looper_);
}

}  // namespace dvr
}  // namespace android
