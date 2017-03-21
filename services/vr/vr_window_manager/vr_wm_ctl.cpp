#include <android/service/vr/BpVrWindowManager.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <inttypes.h>

void usage() { fprintf(stderr, "usage: vr_wm_ctl [enter|exit|debug N]\n"); }

int report(const android::binder::Status& status) {
  if (status.isOk()) {
    fprintf(stderr, "ok\n");
    return 0;
  }
  fprintf(stderr, "failed (%" PRId32 ") %s\n", status.exceptionCode(),
          status.exceptionMessage().string());
  return (int)status.exceptionCode();
}

int main(int argc, char* argv[]) {
  android::sp<android::IServiceManager> sm(android::defaultServiceManager());
  if (sm == nullptr) {
    fprintf(stderr, "service manager not found\n");
    exit(1);
  }

  android::sp<android::service::vr::IVrWindowManager> vrwm =
      android::interface_cast<android::service::vr::IVrWindowManager>(
          sm->getService(
              android::service::vr::IVrWindowManager::SERVICE_NAME()));
  if (vrwm == nullptr) {
    fprintf(stderr, "service not found\n");
    exit(1);
  }

  android::binder::Status status;
  if ((argc == 2) && (strcmp(argv[1], "enter") == 0)) {
    exit(report(vrwm->enterVrMode()));
  } else if ((argc == 2) && (strcmp(argv[1], "exit") == 0)) {
    exit(report(vrwm->exitVrMode()));
  } else if ((argc == 3) && (strcmp(argv[1], "debug") == 0)) {
    exit(report(vrwm->setDebugMode(atoi(argv[2]))));
  } else if ((argc == 3) && (strcmp(argv[1], "2d") == 0)) {
    exit(report(vrwm->set2DMode(atoi(argv[2]))));
  } else {
    usage();
    exit(2);
  }

  return 0;
}
