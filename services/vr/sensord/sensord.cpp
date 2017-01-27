#define LOG_TAG "sensord"

#include <string.h>

#include <binder/ProcessState.h>

#include <dvr/performance_client_api.h>
#include <pdx/default_transport/service_dispatcher.h>
#include <private/dvr/pose-ipc.h>
#include <private/dvr/sensor-ipc.h>

#include "pose_service.h"
#include "sensor_hal_thread.h"
#include "sensor_ndk_thread.h"
#include "sensor_service.h"
#include "sensor_thread.h"

using android::dvr::PoseService;
using android::dvr::SensorHalThread;
using android::dvr::SensorNdkThread;
using android::dvr::SensorService;
using android::dvr::SensorThread;
using android::pdx::Service;
using android::pdx::ServiceDispatcher;

int main(int, char**) {
  ALOGI("Starting up...");

  // We need to be able to create endpoints with full perms.
  umask(0000);

  android::ProcessState::self()->startThreadPool();

  bool sensor_thread_succeeded = false;
#ifdef SENSORD_USES_HAL
  std::unique_ptr<SensorThread> sensor_thread(
      new SensorHalThread(&sensor_thread_succeeded));
#else
  std::unique_ptr<SensorThread> sensor_thread(
      new SensorNdkThread(&sensor_thread_succeeded));
#endif

  if (!sensor_thread_succeeded) {
    ALOGE("ERROR: Failed to initialize SensorThread! No 3DoF!\n");
  }

  if (sensor_thread->GetSensorCount() == 0)
    ALOGW("No sensors found\n");

  auto sensor_service = SensorService::Create(sensor_thread.get());
  if (!sensor_service) {
    ALOGE("TERMINATING: failed to create SensorService!!!\n");
    return -1;
  }

  auto pose_service = PoseService::Create(sensor_thread.get());
  if (!pose_service) {
    ALOGE("TERMINATING: failed to create PoseService!!!\n");
    return -1;
  }

  std::unique_ptr<ServiceDispatcher> dispatcher =
      android::pdx::default_transport::ServiceDispatcher::Create();
  if (!dispatcher) {
    ALOGE("TERMINATING: failed to create ServiceDispatcher!!!\n");
    return -1;
  }

  dispatcher->AddService(sensor_service);
  dispatcher->AddService(pose_service);

  sensor_thread->StartPolling([sensor_service, pose_service](
      const sensors_event_t* events_begin, const sensors_event_t* events_end) {
    sensor_service->EnqueueEvents(events_begin, events_end);
    pose_service->HandleEvents(events_begin, events_end);
  });

  const int priority_error = dvrSetSchedulerClass(0, "sensors:low");
  LOG_ALWAYS_FATAL_IF(priority_error < 0,
                      "SensorService: Failed to set scheduler class: %s",
                      strerror(-priority_error));

  int ret = dispatcher->EnterDispatchLoop();
  ALOGI("Dispatch loop exited because: %s\n", strerror(-ret));

  return ret;
}
