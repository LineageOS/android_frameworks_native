#include "VirtualTouchpad.h"

#include <cutils/log.h>
#include <inttypes.h>
#include <linux/input.h>

namespace android {
namespace dvr {

namespace {

// Virtual evdev device properties.
static const char* const kDeviceName = "vr window manager virtual touchpad";
static constexpr int16_t kDeviceBusType = BUS_VIRTUAL;
static constexpr int16_t kDeviceVendor = 0x18D1;   // Google USB vendor ID.
static constexpr int16_t kDeviceProduct = 0x5652;  // 'VR'
static constexpr int16_t kDeviceVersion = 0x0001;
static constexpr int32_t kWidth = 0x10000;
static constexpr int32_t kHeight = 0x10000;
static constexpr int32_t kSlots = 2;

}  // anonymous namespace

int VirtualTouchpad::Initialize() {
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
  injector_->ConfigureEnd();
  return injector_->GetError();
}

int VirtualTouchpad::Touch(float x, float y, float pressure) {
  int error = 0;
  int32_t device_x = x * kWidth;
  int32_t device_y = y * kHeight;
  touches_ = ((touches_ & 1) << 1) | (pressure > 0);
  ALOGV("(%f,%f) %f -> (%" PRId32 ",%" PRId32 ") %d",
        x, y, pressure, device_x, device_y, touches_);

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

}  // namespace dvr
}  // namespace android
