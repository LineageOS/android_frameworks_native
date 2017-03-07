#include "VirtualTouchpadEvdev.h"

#include <android/input.h>
#include <inttypes.h>
#include <linux/input.h>
#include <log/log.h>

// References:
//  [0] Multi-touch (MT) Protocol,
//      https://www.kernel.org/doc/Documentation/input/multi-touch-protocol.txt

namespace android {
namespace dvr {

namespace {

// Virtual evdev device properties. The name is arbitrary, but Android can
// use it to look up device configuration, so it must be unique. Vendor and
// product values must be 0 to indicate an internal device and prevent a
// similar lookup that could conflict with a physical device.
static const char* const kDeviceName = "vr window manager virtual touchpad";
static constexpr int16_t kDeviceBusType = BUS_VIRTUAL;
static constexpr int16_t kDeviceVendor = 0;
static constexpr int16_t kDeviceProduct = 0;
static constexpr int16_t kDeviceVersion = 0x0001;

static constexpr int32_t kWidth = 0x10000;
static constexpr int32_t kHeight = 0x10000;
static constexpr int32_t kSlots = 2;

}  // anonymous namespace

sp<VirtualTouchpad> VirtualTouchpadEvdev::Create() {
  VirtualTouchpadEvdev* const touchpad = new VirtualTouchpadEvdev();
  return sp<VirtualTouchpad>(touchpad);
}

status_t VirtualTouchpadEvdev::Attach() {
  if (!injector_) {
    owned_injector_.reset(new EvdevInjector());
    injector_ = owned_injector_.get();
  }
  injector_->ConfigureBegin(kDeviceName, kDeviceBusType, kDeviceVendor,
                            kDeviceProduct, kDeviceVersion);
  injector_->ConfigureInputProperty(INPUT_PROP_DIRECT);
  injector_->ConfigureMultiTouchXY(0, 0, kWidth - 1, kHeight - 1);
  injector_->ConfigureAbsSlots(kSlots);
  injector_->ConfigureKey(BTN_TOUCH);
  injector_->ConfigureKey(BTN_BACK);
  injector_->ConfigureEnd();
  return injector_->GetError();
}

status_t VirtualTouchpadEvdev::Detach() {
  injector_->Close();
  injector_ = nullptr;
  owned_injector_.reset();
  last_device_x_ = INT32_MIN;
  last_device_y_ = INT32_MIN;
  touches_ = 0;
  last_motion_event_buttons_ = 0;
  return OK;
}

int VirtualTouchpadEvdev::Touch(int touchpad, float x, float y,
                                float pressure) {
  (void)touchpad;  // TODO(b/35992608) Support multiple touchpad devices.
  if ((x < 0.0f) || (x >= 1.0f) || (y < 0.0f) || (y >= 1.0f)) {
    return EINVAL;
  }
  int32_t device_x = x * kWidth;
  int32_t device_y = y * kHeight;
  touches_ = ((touches_ & 1) << 1) | (pressure > 0);
  ALOGV("(%f,%f) %f -> (%" PRId32 ",%" PRId32 ") %d", x, y, pressure, device_x,
        device_y, touches_);

  if (!injector_) {
    return EvdevInjector::ERROR_SEQUENCING;
  }
  injector_->ResetError();
  switch (touches_) {
    case 0b00:  // Hover continues.
      if (device_x != last_device_x_ || device_y != last_device_y_) {
        injector_->SendMultiTouchXY(0, 0, device_x, device_y);
        injector_->SendSynReport();
      }
      break;
    case 0b01:  // Touch begins.
      // Press.
      injector_->SendMultiTouchXY(0, 0, device_x, device_y);
      injector_->SendKey(BTN_TOUCH, EvdevInjector::KEY_PRESS);
      injector_->SendSynReport();
      break;
    case 0b10:  // Touch ends.
      injector_->SendKey(BTN_TOUCH, EvdevInjector::KEY_RELEASE);
      injector_->SendMultiTouchLift(0);
      injector_->SendSynReport();
      break;
    case 0b11:  // Touch continues.
      if (device_x != last_device_x_ || device_y != last_device_y_) {
        injector_->SendMultiTouchXY(0, 0, device_x, device_y);
        injector_->SendSynReport();
      }
      break;
  }
  last_device_x_ = device_x;
  last_device_y_ = device_y;

  return injector_->GetError();
}

int VirtualTouchpadEvdev::ButtonState(int touchpad, int buttons) {
  (void)touchpad;  // TODO(b/35992608) Support multiple touchpad devices.
  const int changes = last_motion_event_buttons_ ^ buttons;
  if (!changes) {
    return 0;
  }
  if (buttons & ~AMOTION_EVENT_BUTTON_BACK) {
    return ENOTSUP;
  }
  ALOGV("change %X from %X to %X", changes, last_motion_event_buttons_,
        buttons);

  if (!injector_) {
    return EvdevInjector::ERROR_SEQUENCING;
  }
  injector_->ResetError();
  if (changes & AMOTION_EVENT_BUTTON_BACK) {
    injector_->SendKey(BTN_BACK, (buttons & AMOTION_EVENT_BUTTON_BACK)
                                     ? EvdevInjector::KEY_PRESS
                                     : EvdevInjector::KEY_RELEASE);
    injector_->SendSynReport();
  }
  last_motion_event_buttons_ = buttons;
  return injector_->GetError();
}

void VirtualTouchpadEvdev::dumpInternal(String8& result) {
  result.append("[virtual touchpad]\n");
  if (!injector_) {
    result.append("injector = none\n");
    return;
  }
  result.appendFormat("injector = %s\n", owned_injector_ ? "normal" : "test");
  result.appendFormat("touches = %d\n", touches_);
  result.appendFormat("last_position = (%" PRId32 ", %" PRId32 ")\n",
                      last_device_x_, last_device_y_);
  result.appendFormat("last_buttons = 0x%" PRIX32 "\n\n",
                      last_motion_event_buttons_);
  injector_->dumpInternal(result);
}

}  // namespace dvr
}  // namespace android
