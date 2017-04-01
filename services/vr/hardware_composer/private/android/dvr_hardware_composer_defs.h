#ifndef VR_HARDWARE_COMPOSER_PRIVATE_ANDROID_VR_HARDWARE_COMPOSER_DEFS_H
#define VR_HARDWARE_COMPOSER_PRIVATE_ANDROID_VR_HARDWARE_COMPOSER_DEFS_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// NOTE: These definitions must match the ones in
// //hardware/libhardware/include/hardware/hwcomposer2.h. They are used by the
// client side which does not have access to hwc2 headers.
enum BlendMode {
  BLEND_MODE_INVALID = 0,
  BLEND_MODE_NONE = 1,
  BLEND_MODE_PREMULTIPLIED = 2,
  BLEND_MODE_COVERAGE = 3,
};

enum Composition {
  COMPOSITION_INVALID = 0,
  COMPOSITION_CLIENT = 1,
  COMPOSITION_DEVICE = 2,
  COMPOSITION_SOLID_COLOR = 3,
  COMPOSITION_CURSOR = 4,
  COMPOSITION_SIDEBAND = 5,
};

typedef uint64_t Display;
typedef uint64_t Layer;

struct Recti {
  int32_t left;
  int32_t top;
  int32_t right;
  int32_t bottom;
};

struct Rectf {
  float left;
  float top;
  float right;
  float bottom;
};

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // VR_HARDWARE_COMPOSER_PRIVATE_ANDROID_DVR_HARDWARE_COMPOSER_DEFS_H
