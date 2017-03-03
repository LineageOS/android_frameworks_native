#include "VirtualTouchpadService.h"

#include <binder/Status.h>
#include <linux/input.h>
#include <log/log.h>
#include <utils/Errors.h>

namespace android {
namespace dvr {

binder::Status VirtualTouchpadService::touch(float x, float y, float pressure) {
  const status_t error = touchpad_->Touch(x, y, pressure);
  return error ? binder::Status::fromStatusT(error)
               : binder::Status::ok();
}

binder::Status VirtualTouchpadService::buttonState(int buttons) {
  const status_t error = touchpad_->ButtonState(buttons);
  return error ? binder::Status::fromStatusT(error)
               : binder::Status::ok();
}

}  // namespace dvr
}  // namespace android
