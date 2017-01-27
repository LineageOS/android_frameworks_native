#ifndef ANDROID_DVR_VIRTUAL_TOUCHPAD_H
#define ANDROID_DVR_VIRTUAL_TOUCHPAD_H

#include <memory>

#include "EvdevInjector.h"

namespace android {
namespace dvr {

class EvdevInjector;

class VirtualTouchpad {
 public:
  VirtualTouchpad() {}
  int Initialize();
  int Touch(float x, float y, float pressure);

 protected:
  // Must be called only between construction and Initialize().
  inline void SetEvdevInjectorForTesting(EvdevInjector* injector) {
    injector_ = injector;
  }

 private:
  // Active pointer to |owned_injector_| or to a testing injector.
  EvdevInjector* injector_ = nullptr;
  std::unique_ptr<EvdevInjector> owned_injector_;

  // Previous (x,y) position to suppress redundant events.
  int32_t last_device_x_ = INT32_MIN;
  int32_t last_device_y_ = INT32_MIN;

  // Records current touch state in bit 0 and previous state in bit 1.
  int touches_ = 0;

  VirtualTouchpad(const VirtualTouchpad&) = delete;
  void operator=(const VirtualTouchpad&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_VIRTUAL_TOUCHPAD_H
