#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <cutils/log.h>

#include "vr_window_manager_binder.h"

int main() {
  ALOGI("Starting");
  android::service::vr::VrWindowManagerBinder service;
  const int status = service.Initialize();
  LOG_ALWAYS_FATAL_IF(status != 0, "initialization failed: %d", status);

  signal(SIGPIPE, SIG_IGN);
  android::sp<android::ProcessState> ps(android::ProcessState::self());
  ps->setThreadPoolMaxThreadCount(4);
  ps->startThreadPool();
  ps->giveThreadPoolName();

  android::sp<android::IServiceManager> sm(android::defaultServiceManager());
  const android::status_t service_status = sm->addService(
      android::service::vr::VrWindowManagerBinder::SERVICE_NAME(), &service,
      false /*allowIsolated*/);
  LOG_ALWAYS_FATAL_IF(service_status != android::OK, "service not added: %d",
                      static_cast<int>(service_status));

  android::IPCThreadState::self()->joinThreadPool();
  return 0;
}
