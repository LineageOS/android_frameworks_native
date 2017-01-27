#ifndef ANDROID_DVR_VIRTUAL_TOUCHPAD_SERVICE_H
#define ANDROID_DVR_VIRTUAL_TOUCHPAD_SERVICE_H

#include <android/dvr/BnVirtualTouchpadService.h>

#include "VirtualTouchpad.h"

namespace android {
namespace dvr {

class VirtualTouchpadService : public BnVirtualTouchpadService {
 public:
  VirtualTouchpadService(VirtualTouchpad& touchpad)
      : touchpad_(touchpad) {}

  // Must be called before clients can connect.
  // Returns 0 if initialization is successful.
  int Initialize();

  static char const* getServiceName() { return "virtual_touchpad"; }

 protected:
  // Implements IVirtualTouchpadService.
  ::android::binder::Status touch(float x, float y, float pressure) override;

 private:
  VirtualTouchpad& touchpad_;

  VirtualTouchpadService(const VirtualTouchpadService&) = delete;
  void operator=(const VirtualTouchpadService&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_VIRTUAL_TOUCHPAD_SERVICE_H
