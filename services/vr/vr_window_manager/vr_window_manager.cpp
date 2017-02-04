#include <binder/ProcessState.h>

#include "shell_view.h"

int main(int /* argc */, char** /* argv */) {
  android::ProcessState::self()->startThreadPool();

  android::dvr::ShellView app;
  if (app.Initialize(nullptr, nullptr, nullptr)) {
    ALOGE("Failed to initialize");
    return 1;
  }

  while (true)
    app.DrawFrame();

  return 0;
}
