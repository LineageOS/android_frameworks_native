#ifndef ANDROID_DVR_INTERNAL_TYPES_H_
#define ANDROID_DVR_INTERNAL_TYPES_H_

#include <GLES2/gl2.h>
#include <atomic>
#include <memory>
#include <vector>
#include <unordered_map>

#include <dvr/graphics.h>
#include <dvr/pose_client.h>
#include <gui/Surface.h>
#include <private/dvr/buffer_hub_queue_core.h>
#include <private/dvr/display_client.h>
#include <vr/gvr/capi/include/gvr.h>
#include <vr/gvr/capi/include/gvr_types.h>
#include <vr/gvr/capi/src/gvr_types_experimental.h>

typedef struct gvr_user_prefs_ {
} gvr_user_prefs;

typedef struct gvr_context_ {
  int32_t last_error_;
  JNIEnv* jni_env_;
  DvrPose* pose_client_;
  std::unique_ptr<android::dvr::DisplayClient> display_client_;
  android::dvr::SystemDisplayMetrics display_metrics_;
  gvr_mat4f left_eye_viewport_transform_;
  gvr_mat4f right_eye_viewport_transform_;
  gvr_mat4f next_frame_6dof_pose_;
  gvr_mat4f next_frame_controller_pose_[2];
  gvr_user_prefs user_prefs_;
  bool force_6dof_;
  std::vector<gvr_swap_chain*> swap_chains_;

  gvr_context_() :
      last_error_(GVR_ERROR_NONE),
      jni_env_(nullptr),
      pose_client_(nullptr),
      force_6dof_(false) {}

  ~gvr_context_();
} gvr_context;

typedef struct gvr_buffer_spec_ {
  gvr_sizei size;
  int32_t msaa_samples;
  int32_t color_format;
  int32_t depth_stencil_format;
  bool blur_behind;
  bool initially_visible;
  int z_order;

  // The default values are configured to match SVR defaults
  gvr_buffer_spec_()
      : size{0, 0},
        msaa_samples(0),
        color_format(GVR_COLOR_FORMAT_RGBA_8888),
        depth_stencil_format(GVR_DEPTH_STENCIL_FORMAT_DEPTH_16),
        blur_behind(true),
        initially_visible(true),
        z_order(0) {}
} gvr_buffer_spec;

// This isn't a public gvr type
struct gvr_buffer {
  gvr_buffer_spec spec;
  GLuint frame_buffer;
  GLuint color_render_buffer;
  GLuint depth_stencil_render_buffer;

  // requested_size is used for resizing. It will be {-1, -1} when no resize is
  // requested. Any other value indicates the app changed the size.
  gvr_sizei requested_size;

  gvr_buffer();
  // If creation fails frame_buffer will be 0
  gvr_buffer(gvr_context* gvr, const gvr_buffer_spec& spec,
             GLuint texture_id, GLenum texture_target);
  ~gvr_buffer();

  gvr_buffer(gvr_buffer&& other);
  gvr_buffer& operator=(gvr_buffer&& other);
  gvr_buffer(const gvr_buffer& other) = delete;
  gvr_buffer& operator=(const gvr_buffer& other) = delete;

  // Set default values. Doesn't free GL resources first.
  void SetDefaults();

  // Frees all GL resources associated with the buffer
  void FreeGl();
};

typedef struct gvr_swap_chain_ {
  gvr_context* context;
  DvrGraphicsContext* graphics_context_;
  std::vector<gvr_buffer> buffers_;
  bool frame_acquired_;
  bool wait_next_frame_called_by_app_;
  std::atomic<int32_t> next_external_surface_id_;
  std::unordered_map<int32_t, gvr_external_surface*> external_surfaces_;

  explicit gvr_swap_chain_(gvr_context* context)
      : context(context),
        graphics_context_(nullptr),
        frame_acquired_(false),
        wait_next_frame_called_by_app_(false),
        next_external_surface_id_(0) {}
  ~gvr_swap_chain_();
} gvr_swap_chain;

typedef struct gvr_buffer_viewport_ {
  int32_t buffer_index;
  gvr_rectf uv;
  gvr_mat4f transform;
  int32_t eye;
  int32_t external_surface_id;
  gvr_reprojection reprojection;

  gvr_buffer_viewport_()
      : buffer_index(0),
        uv{0, 0, 0, 0},
        transform{{{1.f, 0.f, 0.f, 0.f},
                   {0.f, 1.f, 0.f, 0.f},
                   {0.f, 0.f, 1.f, 0.f},
                   {0.f, 0.f, 0.f, 1.f}}},
        eye(0),
        external_surface_id(-1),
        reprojection(GVR_REPROJECTION_FULL) {}

  gvr_buffer_viewport_(int32_t /* buffer_index */, gvr_rectf uv,
                       const gvr_mat4f& transform, int32_t eye,
                       int32_t external_surface_id,
                       gvr_reprojection reprojection)
      : buffer_index(0),
        uv(uv),
        transform(transform),
        eye(eye),
        external_surface_id(external_surface_id),
        reprojection(reprojection) {}

  bool operator==(const gvr_buffer_viewport_& other) const;

  bool operator!=(const gvr_buffer_viewport_& other) const {
    return !operator==(other);
  }
} gvr_buffer_viewport;

typedef struct gvr_buffer_viewport_list_ {
  std::vector<gvr_buffer_viewport> viewports;
} gvr_buffer_viewport_list;

typedef struct gvr_frame_schedule_ {
  uint32_t vsync_count;
  gvr_clock_time_point scheduled_finish;

  gvr_frame_schedule_() : vsync_count(0) {
    scheduled_finish.monotonic_system_time_nanos = 0;
  }
} gvr_frame_schedule;

typedef struct gvr_display_synchronizer_ {} gvr_display_synchronizer;

typedef struct gvr_external_surface_ {
  int32_t id;
  gvr_swap_chain* swap_chain;
  DvrVideoMeshSurface* video_surface;
} gvr_external_surface;

#endif  // ANDROID_DVR_INTERNAL_TYPES_H_
