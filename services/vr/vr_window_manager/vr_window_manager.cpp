#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <hwbinder/IPCThreadState.h>
#include <impl/vr_hwc.h>

#include "shell_view.h"
#include "vr_window_manager_binder.h"

using namespace android;
using namespace android::dvr;

int main(int /* argc */, char** /* argv */) {
  android::ProcessState::self()->startThreadPool();

  // ShellView needs to be created after vr_hwcomposer.
  android::dvr::ShellView app;
  const int app_status = app.Initialize();
  LOG_ALWAYS_FATAL_IF(app_status != 0, "failed to initialize: %d", app_status);

  // Create vr_wm_binder.
  android::sp<android::service::vr::VrWindowManagerBinder> vr_wm_binder =
      new android::service::vr::VrWindowManagerBinder(app);
  const int status = vr_wm_binder->Initialize();
  LOG_ALWAYS_FATAL_IF(status != 0, "initialization failed: %d", status);

  android::sp<android::IServiceManager> sm(android::defaultServiceManager());
  const android::status_t vr_wm_binder_status = sm->addService(
      android::service::vr::VrWindowManagerBinder::SERVICE_NAME(),
      vr_wm_binder, false /*allowIsolated*/);
  LOG_ALWAYS_FATAL_IF(vr_wm_binder_status != android::OK,
                      "vr_wm_binder service not added: %d",
                      static_cast<int>(vr_wm_binder_status));

  app.SetControllerDataProvider(vr_wm_binder.get());

  android::hardware::ProcessState::self()->startThreadPool();

  while (true) {
    app.DrawFrame();
  }

  android::hardware::IPCThreadState::self()->joinThreadPool();
  android::IPCThreadState::self()->joinThreadPool();

  return 0;
}
