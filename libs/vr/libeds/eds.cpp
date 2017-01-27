#include <dvr/eds.h>

#include <private/dvr/graphics/vr_gl_extensions.h>
#include <private/dvr/late_latch.h>
#include <private/dvr/types.h>

// TODO(jbates) delete this file and eds.h

extern "C" int dvrEdsInit(bool with_late_latch) { return 0; }

extern "C" void dvrEdsDeinit() {}

extern "C" int dvrEdsCapturePoseAsync(int eye, uint32_t target_vsync_count,
                                      const float* projection_matrix,
                                      const float* eye_from_head_matrix,
                                      const float* pose_offset_matrix) {
  return 0;
}

extern "C" int dvrEdsBindPose(int eye, uint32_t ubo_binding, intptr_t offset,
                              ssize_t size) {
  return 0;
}

extern "C" int dvrEdsBlitPose(int eye, int viewport_width,
                              int viewport_height) {
  return 0;
}

extern "C" int dvrEdsBlitPoseFromCpu(int eye, int viewport_width,
                                     int viewport_height,
                                     const float* pose_quaternion,
                                     const float* pose_position) {
  return 0;
}
