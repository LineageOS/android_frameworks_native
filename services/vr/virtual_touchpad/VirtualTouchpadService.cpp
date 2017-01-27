#include "VirtualTouchpadService.h"

#include <binder/Status.h>
#include <cutils/log.h>
#include <linux/input.h>
#include <utils/Errors.h>

namespace android {
namespace dvr {

int VirtualTouchpadService::Initialize() {
  return touchpad_.Initialize();
}

binder::Status VirtualTouchpadService::touch(float x, float y, float pressure) {
  // Permissions check added and removed here :^)
  const int error = touchpad_.Touch(x, y, pressure);
  return error ? binder::Status::fromServiceSpecificError(error)
               : binder::Status::ok();
}

}  // namespace dvr
}  // namespace android
