#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <log/log.h>

#include "VirtualTouchpadService.h"

int main() {
  ALOGI("Starting");
  android::dvr::VirtualTouchpad touchpad;
  android::dvr::VirtualTouchpadService touchpad_service(touchpad);
  const int touchpad_status = touchpad_service.Initialize();
  if (touchpad_status) {
    ALOGE("virtual touchpad initialization failed: %d", touchpad_status);
    exit(1);
  }

  signal(SIGPIPE, SIG_IGN);
  android::sp<android::ProcessState> ps(android::ProcessState::self());
  ps->setThreadPoolMaxThreadCount(4);
  ps->startThreadPool();
  ps->giveThreadPoolName();

  android::sp<android::IServiceManager> sm(android::defaultServiceManager());
  const android::status_t service_status =
      sm->addService(android::String16(touchpad_service.getServiceName()),
                     &touchpad_service, false /*allowIsolated*/);
  if (service_status != android::OK) {
    ALOGE("virtual touchpad service not added: %d",
          static_cast<int>(service_status));
    exit(2);
  }

  android::IPCThreadState::self()->joinThreadPool();
  return 0;
}
