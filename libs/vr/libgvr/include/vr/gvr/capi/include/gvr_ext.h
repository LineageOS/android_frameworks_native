/* Copyright 2016 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VR_GVR_CAPI_INCLUDE_GVR_EXT_H_
#define VR_GVR_CAPI_INCLUDE_GVR_EXT_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Constants that represent GVR error codes.
typedef enum {
  // TODO(steventhomas): All errors should be switched to something more
  // meaningful and this should eventually go away.
  GVR_ERROR_INTERNAL = 9000,
} gvr_error_ext;

typedef struct gvr_frame_schedule_ gvr_frame_schedule;

gvr_frame_schedule* gvr_frame_schedule_create();

void gvr_frame_schedule_destroy(gvr_frame_schedule** schedule);

uint32_t gvr_frame_schedule_get_vsync_count(gvr_frame_schedule* schedule);

gvr_clock_time_point gvr_frame_schedule_get_scheduled_finish(
    gvr_frame_schedule* schedule);

/// Sleep until it's time to render the next frame.
// |start_delay_ns| adjusts how long this function blocks the app from starting
// its next frame. If |start_delay_ns| is 0, the function waits until the
// scheduled frame finish time for the current frame, which gives the app one
// full vsync period to render the next frame. If the app needs less than a full
// vysnc period to render the frame, pass in a non-zero |start_delay_ns| to
// delay the start of frame rendering further. For example, if the vsync period
// is 11.1ms and the app takes 6ms to render a frame, consider setting this to
// 5ms (note that the value is in nanoseconds, so 5,000,000ns) so that the app
// finishes the frame closer to the scheduled frame finish time. Delaying the
// start of rendering allows the app to use a more up-to-date pose for
// rendering.
// |start_delay_ns| must be a positive value or 0. If you're unsure what to set
// for |start_delay_ns|, use 0.
/// |out_next_frame_schedule| is an output parameter that will contain the
/// schedule for the next frame. It can be null.
void gvr_wait_next_frame(gvr_swap_chain* swap_chain, int64_t start_delay_nanos,
                         gvr_frame_schedule* out_next_frame_schedule);

gvr_mat4f gvr_get_6dof_head_pose_in_start_space(gvr_context* gvr,
                                                uint32_t vsync_count);

gvr_mat4f gvr_get_head_space_from_start_space_pose(
    gvr_context* gvr, const gvr_clock_time_point time);

gvr_mat4f gvr_get_start_space_from_controller_space_pose(
    gvr_context* gvr, int controller_id, const gvr_clock_time_point time);

#ifdef __cplusplus
}  // extern "C"
#endif

#if defined(__cplusplus) && !defined(GVR_NO_CPP_WRAPPER)
#include <utility>

namespace gvr {

/// Convenience C++ wrapper for gvr_frame_schedule. Frees the underlying
/// gvr_frame_schedule on destruction.
class FrameSchedule {
 public:
  FrameSchedule() { schedule_ = gvr_frame_schedule_create(); }

  ~FrameSchedule() {
    if (schedule_)
      gvr_frame_schedule_destroy(&schedule_);
  }

  FrameSchedule(FrameSchedule&& other) {
    std::swap(schedule_, other.schedule_);
  }

  FrameSchedule& operator=(FrameSchedule&& other) {
    std::swap(schedule_, other.schedule_);
    return *this;
  }

  gvr_frame_schedule* cobj() { return schedule_; }
  const gvr_frame_schedule* cobj() const { return schedule_; }

  uint32_t GetVsyncCount() const {
    return gvr_frame_schedule_get_vsync_count(schedule_);
  }

  gvr_clock_time_point GetScheduledFinish() const {
    return gvr_frame_schedule_get_scheduled_finish(schedule_);
  }

 private:
  gvr_frame_schedule* schedule_;
};

}  // namespace gvr
#endif  // #if defined(__cplusplus) && !defined(GVR_NO_CPP_WRAPPER)

#endif  // VR_GVR_CAPI_INCLUDE_GVR_EXT_H_
