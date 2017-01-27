#ifndef ANDROID_DVR_DISPLAY_TYPES_H_
#define ANDROID_DVR_DISPLAY_TYPES_H_

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#ifndef __FLOAT32X4T_86
#define __FLOAT32X4T_86
typedef float float32x4_t __attribute__ ((__vector_size__ (16)));
typedef struct float32x4x4_t { float32x4_t val[4]; };
#endif
#endif

#include <cutils/native_handle.h>

// DVR display-related data types.

enum dvr_display_surface_type {
  // Normal display surface meant to be used by applications' GL context to
  // render into.
  DVR_SURFACE_TYPE_NORMAL = 0,

  // VideoMeshSurface is used to composite video frames into the 3D world.
  DVR_SURFACE_TYPE_VIDEO_MESH,

  // System overlay surface type. This is not currently in use.
  DVR_SURFACE_TYPE_OVERLAY,
};

enum dvr_display_surface_flags {
  DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_EDS = (1 << 0),
  DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION = (1 << 1),
  DVR_DISPLAY_SURFACE_FLAGS_VERTICAL_FLIP = (1 << 2),
  DVR_DISPLAY_SURFACE_FLAGS_GEOMETRY_SEPARATE_2 = (1 << 3),
  DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_CAC = (1 << 4),
};

enum dvr_display_surface_item_flags {
  DVR_DISPLAY_SURFACE_ITEM_FLAGS_BUFFERS_CHANGED = (1 << 0),
};

enum dvr_display_surface_attribute {
  DVR_DISPLAY_SURFACE_ATTRIBUTE_Z_ORDER = (1<<0),
  DVR_DISPLAY_SURFACE_ATTRIBUTE_VISIBLE = (1<<1),
  DVR_DISPLAY_SURFACE_ATTRIBUTE_BLUR = (1<<2),
  DVR_DISPLAY_SURFACE_ATTRIBUTE_EXCLUDE_FROM_BLUR = (1<<3),
  DVR_DISPLAY_SURFACE_ATTRIBUTE_BLUR_BEHIND = (1<<4),
};

// Maximum number of buffers for a surface. Each buffer represents a single
// frame and may actually be a buffer array if multiview rendering is in use.
// Define so that it can be used in shader code.
#define kSurfaceBufferMaxCount 4

// Maximum number of views per surface. Each eye is a view, for example.
#define kSurfaceViewMaxCount 4

namespace android {
namespace dvr {

struct __attribute__((packed, aligned(16))) DisplaySurfaceMetadata {
  // Array of orientations and translations corresponding with surface buffers.
  // The index is associated with each allocated buffer by DisplaySurface and
  // communicated to clients.
  // The maximum number of buffers is hard coded here as 4 so that we can bind
  // this data structure in GPU shaders.
  float32x4_t orientation[kSurfaceBufferMaxCount];
  float32x4_t translation[kSurfaceBufferMaxCount];
};

struct __attribute__((packed, aligned(16))) VideoMeshSurfaceMetadata {
  // Array of transform matrices corresponding with surface buffers.
  // Note that The index is associated with each allocated buffer by
  // DisplaySurface instead of VideoMeshSurface due to the fact that the
  // metadata here is interpreted as video mesh's transformation in each
  // application's rendering frame.
  float32x4x4_t transform[4][2];
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DISPLAY_TYPES_H_
