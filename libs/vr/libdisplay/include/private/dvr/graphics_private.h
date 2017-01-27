#ifndef ANDROID_DVR_GRAPHICS_PRIVATE_H_
#define ANDROID_DVR_GRAPHICS_PRIVATE_H_

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#ifndef __FLOAT32X4T_86
#define __FLOAT32X4T_86
typedef float float32x4_t __attribute__ ((__vector_size__ (16)));
typedef struct float32x4x4_t { float32x4_t val[4]; };
#endif
#endif

#include <sys/cdefs.h>

#include <dvr/graphics.h>

__BEGIN_DECLS

// Sets the pose used by the system for EDS. If dvrBeginRenderFrameEds() or
// dvrBeginRenderFrameLateLatch() are called instead of dvrBeginRenderFrame()
// it's not necessary to call this function. If this function is used, the call
// must be made after dvrBeginRenderFrame() and before dvrPresent().
//
// @param[in] graphics_context The DvrGraphicsContext.
// @param[in] render_pose_orientation Head pose orientation that rendering for
//            this frame will be based off of. This must be an unmodified value
//            from DvrPoseAsync, returned by dvrPoseGet.
// @param[in] render_pose_translation Head pose translation that rendering for
//            this frame will be based off of. This must be an unmodified value
//            from DvrPoseAsync, returned by dvrPoseGet.
// @return 0 on success or a negative error code on failure.
int dvrSetEdsPose(DvrGraphicsContext* graphics_context,
                  float32x4_t render_pose_orientation,
                  float32x4_t render_pose_translation);

__END_DECLS

#endif  // ANDROID_DVR_GRAPHICS_PRIVATE_H_
