#include <sched.h>
#include <unistd.h>

#include <log/log.h>

#include <dvr/performance_client_api.h>
#include <pdx/default_transport/service_dispatcher.h>

#include "buffer_hub.h"

int main(int, char**) {
  int ret = -1;
  std::shared_ptr<android::pdx::Service> service;
  std::unique_ptr<android::pdx::ServiceDispatcher> dispatcher;

  // We need to be able to create endpoints with full perms.
  umask(0000);

  dispatcher = android::pdx::default_transport::ServiceDispatcher::Create();
  CHECK_ERROR(!dispatcher, error, "Failed to create service dispatcher\n");

  service = android::dvr::BufferHubService::Create();
  CHECK_ERROR(!service, error, "Failed to create buffer hub service\n");
  dispatcher->AddService(service);

  ret = dvrSetSchedulerClass(0, "graphics");
  CHECK_ERROR(ret < 0, error, "Failed to set thread priority");

  ALOGI("Entering message loop.");

  ret = dispatcher->EnterDispatchLoop();
  CHECK_ERROR(ret < 0, error, "Dispatch loop exited because: %s\n",
              strerror(-ret));

error:
  return -ret;
}
