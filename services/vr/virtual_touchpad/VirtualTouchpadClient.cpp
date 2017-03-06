#include "VirtualTouchpadClient.h"

#include <android/dvr/IVirtualTouchpadService.h>
#include <binder/IServiceManager.h>

namespace android {
namespace dvr {

namespace {

class VirtualTouchpadClientImpl : public VirtualTouchpadClient {
 public:
  VirtualTouchpadClientImpl(sp<IVirtualTouchpadService> service)
      : service_(service) {}
  ~VirtualTouchpadClientImpl() override {}

  status_t Touch(int touchpad,
                 float x, float y, float pressure) override {
    if (service_ == nullptr) {
      return NO_INIT;
    }
    return service_->touch(touchpad, x, y, pressure).transactionError();
  }
  status_t ButtonState(int touchpad, int buttons) override {
    if (service_ == nullptr) {
      return NO_INIT;
    }
    return service_->buttonState(touchpad, buttons).transactionError();
  }

 private:
  sp<IVirtualTouchpadService> service_;
};

}  // anonymous namespace

sp<VirtualTouchpad> VirtualTouchpadClient::Create() {
  sp<IServiceManager> sm = defaultServiceManager();
  if (sm == nullptr) {
    ALOGE("no service manager");
    return sp<VirtualTouchpad>();
  }
  sp<IVirtualTouchpadService> service = interface_cast<IVirtualTouchpadService>(
      sm->getService(IVirtualTouchpadService::SERVICE_NAME()));
  if (service == nullptr) {
    ALOGE("failed to get service");
    return sp<VirtualTouchpad>();
  }
  return new VirtualTouchpadClientImpl(service);
}

}  // namespace dvr
}  // namespace android
