#ifndef ANDROID_DVR_VIRTUAL_TOUCHPAD_H
#define ANDROID_DVR_VIRTUAL_TOUCHPAD_H

#include <memory>

#include "EvdevInjector.h"

namespace android {
namespace dvr {

class EvdevInjector;

// Provides a virtual touchpad for injecting events into the input system.
//
class VirtualTouchpad {
 public:
  VirtualTouchpad() {}
  ~VirtualTouchpad() {}

  // |Intialize()| must be called once on a VirtualTouchpad before
  // and other public method. Returns zero on success.
  int Initialize();

  // Generate a simulated touch event.
  //
  // @param x Horizontal touch position.
  // @param y Vertical touch position.
  //            Values must be in the range [0.0, 1.0).
  // @param pressure Touch pressure.
  //            Positive values represent contact; use 1.0f if contact
  //            is binary. Use 0.0f for no contact.
  // @returns Zero on success.
  //
  int Touch(float x, float y, float pressure);

  // Generate a simulated touchpad button state.
  //
  // @param buttons A union of MotionEvent BUTTON_* values.
  // @returns Zero on success.
  //
  // Currently only BUTTON_BACK is supported, as the implementation
  // restricts itself to operations actually required by VrWindowManager.
  //
  int ButtonState(int buttons);

 protected:
  // Must be called only between construction and Initialize().
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

  VirtualTouchpad(const VirtualTouchpad&) = delete;
  void operator=(const VirtualTouchpad&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_VIRTUAL_TOUCHPAD_H
