#include "VirtualTouchpadService.h"

#include <binder/Status.h>
#include <linux/input.h>
#include <log/log.h>
#include <utils/Errors.h>

namespace android {
namespace dvr {

binder::Status VirtualTouchpadService::touch(int touchpad,
                                             float x, float y, float pressure) {
  const status_t error = touchpad_->Touch(touchpad, x, y, pressure);
  return error ? binder::Status::fromStatusT(error) : binder::Status::ok();
}

binder::Status VirtualTouchpadService::buttonState(int touchpad, int buttons) {
  const status_t error = touchpad_->ButtonState(touchpad, buttons);
  return error ? binder::Status::fromStatusT(error) : binder::Status::ok();
}

}  // namespace dvr
}  // namespace android
