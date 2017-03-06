#ifndef ANDROID_DVR_VIRTUAL_TOUCHPAD_SERVICE_H
#define ANDROID_DVR_VIRTUAL_TOUCHPAD_SERVICE_H

#include <android/dvr/BnVirtualTouchpadService.h>

#include "VirtualTouchpad.h"

namespace android {
namespace dvr {

// VirtualTouchpadService implements the service side of
// the Binder interface defined in VirtualTouchpadService.aidl.
//
class VirtualTouchpadService : public BnVirtualTouchpadService {
 public:
  VirtualTouchpadService(sp<VirtualTouchpad> touchpad)
      : touchpad_(touchpad) {}
  ~VirtualTouchpadService() override {}

 protected:
  // Implements IVirtualTouchpadService.
  binder::Status touch(int touchpad, float x, float y, float pressure) override;
  binder::Status buttonState(int touchpad, int buttons) override;

 private:
  sp<VirtualTouchpad> touchpad_;

  VirtualTouchpadService(const VirtualTouchpadService&) = delete;
  void operator=(const VirtualTouchpadService&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_VIRTUAL_TOUCHPAD_SERVICE_H
