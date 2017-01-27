#include <base/logging.h>
#include <vr/gvr/capi/include/gvr.h>
#include <vr/gvr/capi/include/gvr_ext.h>
#include <vr/gvr/capi/include/gvr_types.h>

gvr_frame_schedule* gvr_frame_schedule_create() { return NULL; }

void gvr_frame_schedule_destroy(gvr_frame_schedule** /* schedule */) {}

uint32_t gvr_frame_schedule_get_vsync_count(
    gvr_frame_schedule* /* schedule */) {
  return 0;
}

gvr_mat4f gvr_get_6dof_head_pose_in_start_space(gvr_context* gvr,
                                                uint32_t /* vsync_count */) {
  LOG(FATAL) << "gvr_get_6dof_head_pose_in_start_space is not implemented. "
             << "Use gvr_get_head_space_from_start_space_pose instead.";
  return gvr_mat4f({{{1.0f, 0.0f, 0.0f, 0.0f},
                     {0.0f, 1.0f, 0.0f, 0.0f},
                     {0.0f, 0.0f, 1.0f, 0.0f},
                     {0.0f, 0.0f, 0.0f, 1.0f}}});
}

void gvr_wait_next_frame(gvr_swap_chain* /* swap_chain */,
                         int64_t /* sched_offset_nanos */,
                         gvr_frame_schedule* /* out_next_frame_schedule */) {
  LOG(FATAL) << "gvr_wait_next_frame is not implemented.";
}
