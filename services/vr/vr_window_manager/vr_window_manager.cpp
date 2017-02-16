#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>

#include "shell_view.h"
#include "vr_window_manager_binder.h"

int main(int /* argc */, char** /* argv */) {
  android::dvr::ShellView app;
  const int app_status = app.Initialize();
  LOG_ALWAYS_FATAL_IF(app_status != 0, "failed to initialize: %d", app_status);

  android::service::vr::VrWindowManagerBinder service(app);
  const int status = service.Initialize();
  LOG_ALWAYS_FATAL_IF(status != 0, "initialization failed: %d", status);

  android::ProcessState::self()->startThreadPool();

  android::sp<android::IServiceManager> sm(android::defaultServiceManager());
  const android::status_t service_status = sm->addService(
      android::service::vr::VrWindowManagerBinder::SERVICE_NAME(), &service,
      false /*allowIsolated*/);
  LOG_ALWAYS_FATAL_IF(service_status != android::OK, "service not added: %d",
                      static_cast<int>(service_status));

  app.SetControllerDataProvider(&service);

  while (true)
    app.DrawFrame();

  android::IPCThreadState::self()->joinThreadPool();
  return 0;
}
