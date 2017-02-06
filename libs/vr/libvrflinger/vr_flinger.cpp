#include <dvr/vr_flinger.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <memory>

#include <binder/ProcessState.h>
#include <log/log.h>
#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <private/dvr/display_client.h>
#include <sys/resource.h>

#include <pdx/default_transport/service_dispatcher.h>

#include <functional>

#include "DisplayHardware/ComposerHal.h"
#include "display_manager_service.h"
#include "display_service.h"
#include "screenshot_service.h"
#include "vsync_service.h"

namespace android {
namespace dvr {

VrFlinger::VrFlinger() {}

int VrFlinger::Run(Hwc2::Composer* hidl) {
  if (!hidl)
    return EINVAL;

  std::shared_ptr<android::pdx::Service> service;

  ALOGI("Starting up VrFlinger...");

  setpriority(PRIO_PROCESS, 0, android::PRIORITY_URGENT_DISPLAY);
  set_sched_policy(0, SP_FOREGROUND);

  // We need to be able to create endpoints with full perms.
  umask(0000);

  android::ProcessState::self()->startThreadPool();

  std::shared_ptr<android::pdx::ServiceDispatcher> dispatcher =
      android::pdx::default_transport::ServiceDispatcher::Create();
  CHECK_ERROR(!dispatcher, error, "Failed to create service dispatcher.");

  display_service_ = android::dvr::DisplayService::Create(hidl);
  CHECK_ERROR(!display_service_, error, "Failed to create display service.");
  dispatcher->AddService(display_service_);

  service = android::dvr::DisplayManagerService::Create(display_service_);
  CHECK_ERROR(!service, error, "Failed to create display manager service.");
  dispatcher->AddService(service);

  service = android::dvr::ScreenshotService::Create();
  CHECK_ERROR(!service, error, "Failed to create screenshot service.");
  dispatcher->AddService(service);

  service = android::dvr::VSyncService::Create();
  CHECK_ERROR(!service, error, "Failed to create vsync service.");
  dispatcher->AddService(service);

  display_service_->SetVSyncCallback(
      std::bind(&android::dvr::VSyncService::VSyncEvent,
                std::static_pointer_cast<android::dvr::VSyncService>(service),
                std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3, std::placeholders::_4));

  displayd_thread_ = std::thread([this, dispatcher]() {
    ALOGI("Entering message loop.");

    int ret = dispatcher->EnterDispatchLoop();
    if (ret < 0) {
      ALOGE("Dispatch loop exited because: %s\n", strerror(-ret));
    }
  });

  return NO_ERROR;

error:
  display_service_.reset();

  return -1;
}

void VrFlinger::EnterVrMode() {
  if (display_service_) {
    display_service_->SetActive(true);
  } else {
    ALOGE("Failed to enter VR mode : Display service is not started.");
  }
}

void VrFlinger::ExitVrMode() {
  if (display_service_) {
    display_service_->SetActive(false);
  } else {
    ALOGE("Failed to exit VR mode : Display service is not started.");
  }
}

}  // namespace dvr
}  // namespace android
