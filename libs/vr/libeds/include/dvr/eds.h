#ifndef ANDROID_DVR_EDS_H_
#define ANDROID_DVR_EDS_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

// This struct aligns with GLSL uniform blocks with std140 layout.
// std140 allows padding between certain types, so padding must be explicitly
// added as struct members.
struct __attribute__((__packed__)) DvrLateLatchData {
  // Column-major order.
  float view_proj_matrix[16];
  // Column-major order.
  float view_matrix[16];
  float pose_quaternion[4];
  float pose_position[4];
};

//
// These APIs are not thread safe and must be called on a single thread with an
// actively bound GL context corresponding to a display surface.
//

// Prepares EDS and Late Latching system. Idempotent if called more than once.
// The target GL context must be created and bound.
//
// If |with_late_latch| is true, a thread will be created that asynchronously
// updates the pose in memory.
//
// The following GL states are modified as follows:
// glBindBuffer(GL_ARRAY_BUFFER, 0);
// glBindBuffer(GL_UNIFORM_BUFFER, 0);
//
// Returns 0 on success, negative error code on failure.
// Check GL errors with glGetError for other error conditions.
int dvrEdsInit(bool with_late_latch);

// Stops and destroys the EDS Late Latching system.
void dvrEdsDeinit();

// Submits GL draw command that will capture the latest head pose into a uniform
// buffer object. This should be called twice per frame, before the app begins
// drawing for each eye.
// For each eye, a later call to dvrEdsBlitPose will write this pose into
// the application framebuffer corner so that the EDS service knows what pose
// the frame was rendered with.
//
// |eye| is 0 for left eye and 1 for right eye.
//
// The following GL states are modified as follows:
// glUseProgram(0);
// glBindBuffer(GL_UNIFORM_BUFFER, 0);
// glBindBufferBase(GL_TRANSFORM_FEEDBACK_BUFFER, 0, id);
// glDisable(GL_RASTERIZER_DISCARD);
//
// Returns 0 on success, negative error code on failure:
//   EPERM - dvrEdsInit(true) was not called.
// Check GL errors with glGetError for other error conditions.
int dvrEdsCapturePoseAsync(int eye, uint32_t target_vsync_count,
                           const float* projection_matrix,
                           const float* eye_from_head_matrix,
                           const float* pose_offset_matrix);

// Binds the late-latch output data as a GL_UNIFORM_BUFFER so that your vertex
// shaders can use the latest head pose. For example, to bind just the
// view_matrix from the output:
//
// dvrEdsBindPose(eye, BINDING,
//                       offsetof(DvrLateLatchData, view_matrix),
//                       sizeof(DvrLateLatchData::view_matrix));
//
// Or more commonly, bind the view projection matrix:
//
// dvrEdsBindPose(eye, BINDING,
//                       offsetof(DvrLateLatchData, view_proj_matrix),
//                       sizeof(DvrLateLatchData::view_proj_matrix));
//
// BINDING in the above examples is the binding location of the uniform
// interface block in the GLSL shader.
//
// Shader example (3 would be the |ubo_binding| passed to this function):
//  layout(binding = 3, std140) uniform LateLatchData {
//    mat4 uViewProjection;
//  };
//
// |eye| is 0 for left eye and 1 for right eye.
//
// The following GL states are modified as follows:
// glBindBuffer(GL_UNIFORM_BUFFER, ...);
// glBindBufferRange(GL_UNIFORM_BUFFER, ...);
//
// To clear the binding, call glBindBuffer(GL_UNIFORM_BUFFER, 0);
//
// Returns 0 on success, negative error code on failure:
//   EPERM - dvrEdsInit(true) was not called.
// Check GL errors with glGetError for other error conditions.
int dvrEdsBindPose(int eye, uint32_t ubo_binding, intptr_t offset,
                   ssize_t size);

// DEPRECATED
//
// Blits the pose captured previously into the currently bound framebuffer.
// The current framebuffer is assumed to be the default framebuffer 0, the
// surface that will be sent to the display and have EDS and lens warp applied
// to it.
//
// |eye| is 0 for left eye and 1 for right eye.
// |viewport_width| is the width of the viewport for this eye, which is
//                  usually half the width of the framebuffer.
// |viewport_height| is the height of the viewport for this eye, which is
//                   usually the height of the framebuffer.
//
// The following GL states are modified as follows:
// glUseProgram(0);
// glBindBuffer(GL_UNIFORM_BUFFER, 0);
// glBindBufferRange(GL_UNIFORM_BUFFER, 23, ...);
//
// Returns 0 on success, negative error code on failure:
//   EPERM - dvrEdsInit was not called.
// Check GL errors with glGetError for other error conditions.
int dvrEdsBlitPose(int eye, int viewport_width, int viewport_height);

// DEPRECATED
//
// Same as dvrEdsBlitPose except that the pose is provided as an
// parameter instead of getting it from dvrEdsBindPose. This is for
// applications that want EDS but do not want late-latching.
//
// |pose_quaternion| should point to 4 floats that represent a quaternion.
// |pose_position| should point to 3 floats that represent x,y,z position.
//
// GL states are modified as follows:
// glUseProgram(0);
// glBindBuffer(GL_UNIFORM_BUFFER, 0);
// glBindBufferBase(GL_UNIFORM_BUFFER, 23, ...);
//
// Returns 0 on success, negative error code on failure:
//   EPERM - dvrEdsInit was not called.
// Check GL errors with glGetError for other error conditions.
int dvrEdsBlitPoseFromCpu(int eye, int viewport_width, int viewport_height,
                          const float* pose_quaternion,
                          const float* pose_position);

__END_DECLS

#endif  // ANDROID_DVR_EDS_H_
