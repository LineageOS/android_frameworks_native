#ifndef ANDROID_DVR_VIRTUAL_TOUCHPAD_EVDEV_H
#define ANDROID_DVR_VIRTUAL_TOUCHPAD_EVDEV_H

#include <memory>

#include "VirtualTouchpad.h"
#include "EvdevInjector.h"

namespace android {
namespace dvr {

class EvdevInjector;

// VirtualTouchpadEvdev implements a VirtualTouchpad by injecting evdev events.
//
class VirtualTouchpadEvdev : public VirtualTouchpad {
 public:
  static sp<VirtualTouchpad> Create();

  // VirtualTouchpad implementation:
  status_t Attach() override;
  status_t Detach() override;
  status_t Touch(int touchpad, float x, float y, float pressure) override;
  status_t ButtonState(int touchpad, int buttons) override;
  void dumpInternal(String8& result) override;

 protected:
  VirtualTouchpadEvdev() {}
  ~VirtualTouchpadEvdev() override {}

  // Must be called only between construction and Attach().
  inline void SetEvdevInjectorForTesting(EvdevInjector* injector) {
    injector_ = injector;
  }

 private:
  // Except for testing, the |EvdevInjector| used to inject evdev events.
  std::unique_ptr<EvdevInjector> owned_injector_;

  // Active pointer to |owned_injector_| or to a testing injector.
  EvdevInjector* injector_ = nullptr;

  // Previous (x, y) position in device space, to suppress redundant events.
  int32_t last_device_x_ = INT32_MIN;
  int32_t last_device_y_ = INT32_MIN;

  // Records current touch state (0=up 1=down) in bit 0, and previous state
  // in bit 1, to track transitions.
  int touches_ = 0;

  // Previous injected button state, to detect changes.
  int32_t last_motion_event_buttons_ = 0;

  VirtualTouchpadEvdev(const VirtualTouchpadEvdev&) = delete;
  void operator=(const VirtualTouchpadEvdev&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_VIRTUAL_TOUCHPAD_EVDEV_H
