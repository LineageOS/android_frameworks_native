#define LOG_TAG "libgvr_shim"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <GLES3/gl31.h>
#include <GLES3/gl3ext.h>
#include <algorithm>
#include <cmath>

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#ifndef __FLOAT32X4T_86
#define __FLOAT32X4T_86
typedef float float32x4_t __attribute__ ((__vector_size__ (16)));
typedef struct float32x4x4_t { float32x4_t val[4]; };
#endif
#endif

#include <dvr/graphics.h>
#include <dvr/performance_client_api.h>
#include <dvr/pose_client.h>
#include <log/log.h>
#include <private/dvr/buffer_hub_queue_core.h>
#include <private/dvr/buffer_hub_queue_producer.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/display_client.h>
#include <private/dvr/graphics_private.h>
#include <private/dvr/internal_types.h>
#include <private/dvr/numeric.h>
#include <private/dvr/types.h>
#include <private/dvr/video_mesh_surface_client.h>
#include <sys/system_properties.h>
#include <vr/gvr/capi/include/gvr.h>
#include <vr/gvr/capi/include/gvr_ext.h>
#include <vr/gvr/capi/include/gvr_util.h>
#include <vr/gvr/capi/src/gvr_experimental.h>
#include <vr/gvr/capi/src/gvr_private.h>

#include <android_runtime/android_view_Surface.h>
#include <gui/Surface.h>

using android::dvr::DisplayClient;
using android::dvr::EigenToGvrMatrix;
using android::dvr::FieldOfView;
using android::dvr::FovRadiansToDegrees;
using android::dvr::GetSystemClockNs;
using android::dvr::GvrIdentityMatrix;
using android::dvr::GvrMatrixToPosef;
using android::dvr::GvrToDvrFov;
using android::dvr::GvrToEigenMatrix;
using android::dvr::GvrToEigenRotation;
using android::dvr::GvrTranslationMatrix;
using android::dvr::IsEqual;
using android::dvr::PosefToGvrMatrix;
using android::dvr::mat3;
using android::dvr::mat4;
using android::dvr::Posef;
using android::dvr::quat;
using android::dvr::vec3;

namespace {

constexpr static int32_t GVR_SDK_MAJOR_VERSION = 2;
constexpr static int32_t GVR_SDK_MINOR_VERSION = 0;
constexpr static int32_t GVR_SDK_PATCH_VERSION = 0;

// The "DaydreamOS" part has been appended to make easier to see when VrCore
// dynamic GVR API loading is effectively working.
static const char* kVersionString = "2.0.0 DaydreamOS";
static const char* kViewerVendor = "Google";
static const char* kViewerModel = "Lucid";

// Experimental system property used to provide 6DoF information on 3DoF APIs.
static const char* kForce6DofProp = "experimental.force_6dof";

static constexpr int kControllerCount = 2;

gvr_frame* GetFrameFromSwapChain(gvr_swap_chain* swap_chain) {
  return reinterpret_cast<gvr_frame*>(swap_chain);
}

gvr_swap_chain* GetSwapChainForFrame(gvr_frame* frame) {
  return reinterpret_cast<gvr_swap_chain*>(frame);
}

const gvr_swap_chain* GetSwapChainForFrame(const gvr_frame* frame) {
  return reinterpret_cast<const gvr_swap_chain*>(frame);
}

// Returns the world to head transform as a Posef.
Posef ToPosef(const DvrPoseAsync& pose) {
  return Posef(
      quat(pose.orientation[3], pose.orientation[0], pose.orientation[1],
           pose.orientation[2]),
      vec3(pose.translation[0], pose.translation[1], pose.translation[2]));
}

// Returns the world to head transform, with 0 position, as a gvr matrix
gvr_mat4f Gvr6dofTo3dof(const gvr_mat4f& pose) {
  gvr_mat4f ret = pose;
  ret.m[0][3] = 0;
  ret.m[1][3] = 0;
  ret.m[2][3] = 0;
  return ret;
}

void GvrToDvrPose(gvr_mat4f world_to_head_transform,
                  /*out*/ float32x4_t* orientation,
                  /*out */ float32x4_t* translation) {
  Posef pose = GvrMatrixToPosef(world_to_head_transform);
  (*orientation)[0] = pose.GetRotation().x();
  (*orientation)[1] = pose.GetRotation().y();
  (*orientation)[2] = pose.GetRotation().z();
  (*orientation)[3] = pose.GetRotation().w();
  (*translation)[0] = pose.GetPosition().x();
  (*translation)[1] = pose.GetPosition().y();
  (*translation)[2] = pose.GetPosition().z();
  (*translation)[3] = 0;
}

bool MatricesAlmostEqual(const gvr_mat4f& m1, const gvr_mat4f& m2,
                         float tolerance) {
  for (int row = 0; row < 4; ++row) {
    for (int col = 0; col < 4; ++col) {
      if (!IsEqual(m1.m[row][col], m2.m[row][col], tolerance))
        return false;
    }
  }
  return true;
}

gvr_mat4f FovToViewportTransform(const gvr_rectf& fov) {
  // Depth range (1 1000) is chosen to match gvr impl in google3, which is
  // chosen to match Unity integration.
  return EigenToGvrMatrix(
      GvrToDvrFov(fov).GetProjectionMatrix(1.f, 1000.f).inverse());
}

gvr_rectf ViewportTransformToFov(const gvr_mat4f& transform) {
  return DvrToGvrFov(
      FieldOfView::FromProjectionMatrix(GvrToEigenMatrix(transform).inverse()));
}

bool GetGlColorFormat(int32_t gvr_color_format,
                      /*out*/ GLenum* gl_color_format) {
  switch (gvr_color_format) {
    case GVR_COLOR_FORMAT_RGBA_8888:
      *gl_color_format = GL_RGBA8;
      break;
    case GVR_COLOR_FORMAT_RGB_565:
      *gl_color_format = GL_RGB565;
      break;
    default:
      return false;
  }
  return true;
}

bool GetGlDepthFormat(int32_t gvr_depth_format,
                      /*out*/ GLenum* gl_depth_format) {
  switch (gvr_depth_format) {
    case GVR_DEPTH_STENCIL_FORMAT_DEPTH_16:
      *gl_depth_format = GL_DEPTH_COMPONENT16;
      break;
    case GVR_DEPTH_STENCIL_FORMAT_DEPTH_24:
      *gl_depth_format = GL_DEPTH_COMPONENT24;
      break;
    case GVR_DEPTH_STENCIL_FORMAT_DEPTH_24_STENCIL_8:
      *gl_depth_format = GL_DEPTH24_STENCIL8;
      break;
    case GVR_DEPTH_STENCIL_FORMAT_DEPTH_32_F:
      *gl_depth_format = GL_DEPTH_COMPONENT32F;
      break;
    case GVR_DEPTH_STENCIL_FORMAT_DEPTH_32_F_STENCIL_8:
      *gl_depth_format = GL_DEPTH32F_STENCIL8;
      break;
    default:
      return false;
  }
  return true;
}

// Returns true on success, false on failure. If the swap_chain already has a
// DvrGraphicsContext and gvr buffer, they'll be freed first. If creation fails,
// the DvrGraphicsContext in the swap_chain will be set to null and the
// corresponding gvr buffer will be freed.
bool CreateDvrGraphicsContextAndGvrBuffer(gvr_swap_chain* swap_chain) {
  if (swap_chain->buffers_.empty()) {
    ALOGE("Can't create a graphics context for an empty swap chain");
    return false;
  }

  // We currently only render the first gvr buffer. Create a DvrGraphicsContext
  // for the first buffer only.
  gvr_buffer& buf = swap_chain->buffers_[0];
  buf.FreeGl();

  bool visible;
  int z_order;
  if (swap_chain->graphics_context_ != nullptr) {
    visible = dvrGraphicsSurfaceGetVisible(swap_chain->graphics_context_);
    z_order = dvrGraphicsSurfaceGetZOrder(swap_chain->graphics_context_);
    dvrGraphicsContextDestroy(swap_chain->graphics_context_);
    swap_chain->graphics_context_ = nullptr;
  } else {
    visible = buf.spec.initially_visible;
    z_order = buf.spec.z_order;
  }

  int width = 0, height = 0;
  GLuint texture_id = 0;
  GLenum texture_target = 0;
  DvrSurfaceParameter surface_params[] = {
      DVR_SURFACE_PARAMETER_IN(DISABLE_DISTORTION, false),
      DVR_SURFACE_PARAMETER_IN(CREATE_GL_CONTEXT, 0),
      DVR_SURFACE_PARAMETER_IN(WIDTH, buf.spec.size.width),
      DVR_SURFACE_PARAMETER_IN(HEIGHT, buf.spec.size.height),
      DVR_SURFACE_PARAMETER_IN(BLUR_BEHIND, buf.spec.blur_behind),
      DVR_SURFACE_PARAMETER_IN(VISIBLE, visible),
      DVR_SURFACE_PARAMETER_IN(Z_ORDER, z_order),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_WIDTH, &width),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_HEIGHT, &height),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_TEXTURE_TARGET_TYPE, &texture_target),
      DVR_SURFACE_PARAMETER_OUT(SURFACE_TEXTURE_TARGET_ID, &texture_id),
      DVR_SURFACE_PARAMETER_LIST_END,
  };

  DvrGraphicsContext* graphics_context;
  int ret = dvrGraphicsContextCreate(surface_params, &graphics_context);
  if (ret < 0) {
    ALOGE("dvrGraphicsContextCreate failed: %d (%s)", ret, strerror(-ret));
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    return false;
  }

  // Sanity check that the size of the buffer we allocated from the system is
  // what we expect
  if (buf.spec.size != gvr_sizei{width, height}) {
    ALOGE(
        "The created surface is the wrong size."
        " Should be %dx%d, instead got %dx%d.",
        buf.spec.size.width, buf.spec.size.height, width, height);
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    dvrGraphicsContextDestroy(graphics_context);
    return false;
  }

  buf = gvr_buffer(swap_chain->context, buf.spec, texture_id, texture_target);
  if (buf.frame_buffer == 0) {
    dvrGraphicsContextDestroy(graphics_context);
    return false;
  }

  swap_chain->graphics_context_ = graphics_context;
  return true;
}

bool SwapChainResizeBuffer(gvr_swap_chain* swap_chain, int buffer_index) {
  gvr_buffer& buf = swap_chain->buffers_[buffer_index];
  buf.FreeGl();
  gvr_sizei orig_size = buf.spec.size;
  buf.spec.size = buf.requested_size;
  bool resize_successful = false;
  if (buffer_index == 0) {
    resize_successful = CreateDvrGraphicsContextAndGvrBuffer(swap_chain);
  } else {
    buf = gvr_buffer(swap_chain->context, buf.spec, 0, GL_TEXTURE_2D);
    resize_successful = buf.frame_buffer != 0;
  }

  if (resize_successful) {
    // The resize was successful, so clear the resize request
    buf.requested_size = {-1, -1};
  } else {
    ALOGE("Failed to resize buffer. orig_size=%dx%d requested_size=%dx%d.",
          orig_size.width, orig_size.height, buf.requested_size.width,
          buf.requested_size.height);
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    buf.spec.size = orig_size;
  }

  return resize_successful;
}

void WaitNextFrame(gvr_swap_chain* swap_chain, int64_t start_delay_nanos,
                   gvr_frame_schedule* out_next_frame_schedule,
                   bool called_by_app) {
  if (called_by_app)
    swap_chain->wait_next_frame_called_by_app_ = true;

  DvrFrameSchedule dvr_schedule;
  int ret = dvrGraphicsWaitNextFrame(swap_chain->graphics_context_,
                                     start_delay_nanos, &dvr_schedule);
  if (ret < 0) {
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    return;
  }
  if (out_next_frame_schedule) {
    out_next_frame_schedule->vsync_count = dvr_schedule.vsync_count;
    out_next_frame_schedule->scheduled_finish.monotonic_system_time_nanos =
        dvr_schedule.scheduled_frame_finish_ns;
  }

  DvrPoseAsync pose;
  ret = dvrPoseGet(swap_chain->context->pose_client_, dvr_schedule.vsync_count,
                   &pose);
  if (ret < 0) {
    ALOGW("dvrPoseGet failed: %d", ret);
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    return;
  }

  swap_chain->context->next_frame_6dof_pose_ = PosefToGvrMatrix(ToPosef(pose));

  for (int i = 0; i < kControllerCount; ++i) {
    ret = dvrPoseGetController(swap_chain->context->pose_client_, i,
                               dvr_schedule.vsync_count, &pose);
    if (ret == 0) {
      // Silently fail when there are no controllers.
      swap_chain->context->next_frame_controller_pose_[i] =
          PosefToGvrMatrix(ToPosef(pose).Inverse());
    }
  }
}

bool VerifyBufferIndex(const std::string& function_name,
                       const gvr_swap_chain* swap_chain, int index) {
  if (index > static_cast<int32_t>(swap_chain->buffers_.size())) {
    ALOGE("%s out of range buffer index. index=%d num_buffers=%zu.",
          function_name.c_str(), index, swap_chain->buffers_.size());
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    return false;
  }
  return true;
}

}  // anonymous namespace

gvr_context* gvr_create(JNIEnv* env, jobject /* app_context */,
                        jobject /* class_loader */) {
  std::unique_ptr<gvr_context> context(new gvr_context);

  // Set cpu set to avoid default scheduling randomness.
  dvrSetCpuPartition(0, "/application/performance");

  context->jni_env_ = env;
  context->pose_client_ = dvrPoseCreate();
  if (!context->pose_client_) {
    ALOGE("Failed to create pose client");
    return nullptr;
  }

  context->display_client_ = DisplayClient::Create();
  if (!context->display_client_) {
    ALOGE("Failed to create display client");
    return nullptr;
  }

  int ret =
      context->display_client_->GetDisplayMetrics(&context->display_metrics_);
  if (ret < 0) {
    ALOGE("Failed to get display metrics: %d (%s)", ret, strerror(-ret));
    return nullptr;
  }

  const float* left_fov = context->display_metrics_.left_fov_lrbt.data();
  context->left_eye_viewport_transform_ =
      FovToViewportTransform(FovRadiansToDegrees(
          gvr_rectf{left_fov[0], left_fov[1], left_fov[2], left_fov[3]}));

  const float* right_fov = context->display_metrics_.right_fov_lrbt.data();
  context->right_eye_viewport_transform_ =
      FovToViewportTransform(FovRadiansToDegrees(
          gvr_rectf{right_fov[0], right_fov[1], right_fov[2], right_fov[3]}));

  context->next_frame_6dof_pose_ = GvrIdentityMatrix();

  for (int i = 0; i < kControllerCount; ++i) {
    context->next_frame_controller_pose_[i] = GvrIdentityMatrix();
  }

  // Check the system property to force 6DoF when requested 3DoF.
  char prop_buffer[PROP_VALUE_MAX];
  if (__system_property_get(kForce6DofProp, prop_buffer) &&
      (!strncasecmp("1", prop_buffer, PROP_VALUE_MAX) ||
       !strncasecmp("true", prop_buffer, PROP_VALUE_MAX))) {
    context->force_6dof_ = true;
  }

  return context.release();
}

gvr_version gvr_get_version() {
  gvr_version version = {};
  version.major = GVR_SDK_MAJOR_VERSION;
  version.minor = GVR_SDK_MINOR_VERSION;
  version.patch = GVR_SDK_PATCH_VERSION;
  return version;
}

const char* gvr_get_version_string() { return kVersionString; }

int32_t gvr_get_error(gvr_context* gvr) { return gvr->last_error_; }

int32_t gvr_clear_error(gvr_context* gvr) {
  int32_t last_error = gvr->last_error_;
  gvr->last_error_ = GVR_ERROR_NONE;
  return last_error;
}

const char* gvr_get_error_string(int32_t error_code) {
  switch (error_code) {
    case GVR_ERROR_NONE:
      return "No error";
    case GVR_ERROR_CONTROLLER_CREATE_FAILED:
      return "Creation of GVR controller context failed";
    case GVR_ERROR_NO_FRAME_AVAILABLE:
      return "No frame available in swap chain";
    case GVR_ERROR_INTERNAL:
      return "Internal error";
    default:
      return "(Internal error: unknown error code)";
  }
}

const gvr_user_prefs* gvr_get_user_prefs(gvr_context* gvr) {
  return &gvr->user_prefs_;
}

int32_t gvr_user_prefs_get_controller_handedness(
    const gvr_user_prefs* /* user_prefs */) {
  return GVR_CONTROLLER_RIGHT_HANDED;
}

gvr_context_::~gvr_context_() {
  for (gvr_swap_chain* swap_chain : swap_chains_)
    swap_chain->context = nullptr;
  if (pose_client_)
    dvrPoseDestroy(pose_client_);
}

void gvr_destroy(gvr_context** gvr) {
  if (!gvr || !(*gvr)) {
    ALOGW("gvr_destroy: Invalid gvr_context pointer.");
    return;
  }
  delete *gvr;
  *gvr = nullptr;
}

void gvr_initialize_gl(gvr_context* /* gvr */) {}

bool gvr_get_async_reprojection_enabled(const gvr_context* /* gvr */) {
  return true;
}

void gvr_get_recommended_buffer_viewports(
    const gvr_context* gvr, gvr_buffer_viewport_list* viewport_list) {
  gvr_buffer_viewport left(
      /*buffer_index*/ 0,
      /*uv*/ {0, .5f, 0, 1}, gvr->left_eye_viewport_transform_, GVR_LEFT_EYE,
      GVR_EXTERNAL_SURFACE_ID_NONE, GVR_REPROJECTION_FULL);

  gvr_buffer_viewport right(
      /*buffer_index*/ 0,
      /*uv*/ {.5f, 1, 0, 1}, gvr->right_eye_viewport_transform_, GVR_RIGHT_EYE,
      GVR_EXTERNAL_SURFACE_ID_NONE, GVR_REPROJECTION_FULL);

  viewport_list->viewports.resize(2);
  viewport_list->viewports[0] = left;
  viewport_list->viewports[1] = right;
}

void gvr_get_screen_buffer_viewports(const gvr_context* gvr,
                                     gvr_buffer_viewport_list* viewport_list) {
  gvr_get_recommended_buffer_viewports(gvr, viewport_list);
}

gvr_sizei gvr_get_maximum_effective_render_target_size(const gvr_context* gvr) {
  return gvr_sizei{
      static_cast<int32_t>(gvr->display_metrics_.distorted_width),
      static_cast<int32_t>(gvr->display_metrics_.distorted_height)};
}

gvr_sizei gvr_get_screen_target_size(const gvr_context* gvr) {
  // DisplayMetrics returns native_width and native_height for the display in
  // portrait orientation, which our device is never in. Swap the width and
  // height to account for this.
  return gvr_sizei{
      static_cast<int32_t>(gvr->display_metrics_.display_native_height),
      static_cast<int32_t>(gvr->display_metrics_.display_native_width)};
}

void gvr_set_surface_size(gvr_context* gvr,
                          gvr_sizei /* surface_size_pixels */) {
  // TODO(leandrogracia): this needs to be properly implemented.
  ALOGE("gvr_set_surface_size not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
}

void gvr_distort_to_screen(
    gvr_context* gvr, int32_t /* texture_id */,
    const gvr_buffer_viewport_list* /* viewport_list */,
    gvr_mat4f /* head_space_from_start_space */,
    gvr_clock_time_point /* target_presentation_time */) {
  // TODO(leandrogracia): this needs to be properly implemented.
  ALOGE("gvr_distort_to_screen not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
}

bool gvr_is_feature_supported(const gvr_context* /*gvr*/, int32_t feature) {
  return feature == GVR_FEATURE_ASYNC_REPROJECTION ||
      feature == GVR_FEATURE_HEAD_POSE_6DOF;
}

/////////////////////////////////////////////////////////////////////////////
// Viewports and viewport lists
/////////////////////////////////////////////////////////////////////////////

bool gvr_buffer_viewport::operator==(const gvr_buffer_viewport_& other) const {
  return buffer_index == other.buffer_index && uv == other.uv &&
         eye == other.eye && external_surface_id == other.external_surface_id &&
         reprojection == other.reprojection &&
         MatricesAlmostEqual(transform, other.transform, 1e-5f);
}

gvr_buffer_viewport* gvr_buffer_viewport_create(gvr_context* /* gvr */) {
  return new gvr_buffer_viewport;
}

void gvr_buffer_viewport_destroy(gvr_buffer_viewport** viewport) {
  if (viewport) {
    delete *viewport;
    *viewport = nullptr;
  }
}

gvr_rectf gvr_buffer_viewport_get_source_uv(
    const gvr_buffer_viewport* viewport) {
  return viewport->uv;
}

void gvr_buffer_viewport_set_source_uv(gvr_buffer_viewport* viewport,
                                       gvr_rectf uv) {
  viewport->uv = uv;
}

gvr_rectf gvr_buffer_viewport_get_source_fov(
    const gvr_buffer_viewport* viewport) {
  return ViewportTransformToFov(viewport->transform);
}

void gvr_buffer_viewport_set_source_fov(gvr_buffer_viewport* viewport,
                                        gvr_rectf fov) {
  viewport->transform = FovToViewportTransform(fov);
}

gvr_mat4f gvr_buffer_viewport_get_transform(
    const gvr_buffer_viewport* viewport) {
  return viewport->transform;
}

void gvr_buffer_viewport_set_transform(gvr_buffer_viewport* viewport,
                                       gvr_mat4f transform) {
  viewport->transform = transform;
}

int32_t gvr_buffer_viewport_get_target_eye(
    const gvr_buffer_viewport* viewport) {
  return viewport->eye;
}

void gvr_buffer_viewport_set_target_eye(gvr_buffer_viewport* viewport,
                                        int32_t index) {
  viewport->eye = index;
}

int32_t gvr_buffer_viewport_get_source_buffer_index(
    const gvr_buffer_viewport* viewport) {
  return viewport->buffer_index;
}

void gvr_buffer_viewport_set_source_buffer_index(gvr_buffer_viewport* viewport,
                                                 int32_t buffer_index) {
  viewport->buffer_index = buffer_index;
}

int32_t gvr_buffer_viewport_get_external_surface_id(
    const gvr_buffer_viewport* viewport) {
  return viewport->external_surface_id;
}

void gvr_buffer_viewport_set_external_surface_id(gvr_buffer_viewport* viewport,
                                                 int32_t external_surface_id) {
  viewport->external_surface_id = external_surface_id;
}

int32_t gvr_buffer_viewport_get_reprojection(
    const gvr_buffer_viewport* viewport) {
  return viewport->reprojection;
}

void gvr_buffer_viewport_set_reprojection(gvr_buffer_viewport* viewport,
                                          int32_t reprojection) {
  viewport->reprojection = static_cast<gvr_reprojection>(reprojection);
}

bool gvr_buffer_viewport_equal(const gvr_buffer_viewport* a,
                               const gvr_buffer_viewport* b) {
  return *a == *b;
}

gvr_buffer_viewport_list* gvr_buffer_viewport_list_create(
    const gvr_context* /* gvr */) {
  return new gvr_buffer_viewport_list;
}

void gvr_buffer_viewport_list_destroy(
    gvr_buffer_viewport_list** viewport_list) {
  if (!viewport_list || !(*viewport_list)) {
    ALOGW("gvr_buffer_viewport_list_destroy: Invalid list pointer.");
    return;
  }
  delete *viewport_list;
  *viewport_list = nullptr;
}

size_t gvr_buffer_viewport_list_get_size(
    const gvr_buffer_viewport_list* viewport_list) {
  return viewport_list->viewports.size();
}

void gvr_buffer_viewport_list_get_item(
    const gvr_buffer_viewport_list* viewport_list, size_t index,
    gvr_buffer_viewport* viewport) {
  *viewport = viewport_list->viewports[index];
}

void gvr_buffer_viewport_list_set_item(gvr_buffer_viewport_list* viewport_list,
                                       size_t index,
                                       const gvr_buffer_viewport* viewport) {
  if (index < viewport_list->viewports.size())
    viewport_list->viewports[index] = *viewport;
  else
    viewport_list->viewports.push_back(*viewport);
}

/////////////////////////////////////////////////////////////////////////////
// Swapchains and frames
/////////////////////////////////////////////////////////////////////////////

gvr_buffer_spec* gvr_buffer_spec_create(gvr_context* /* gvr */) {
  return new gvr_buffer_spec;
}

void gvr_buffer_spec_destroy(gvr_buffer_spec** spec) {
  if (spec) {
    delete *spec;
    *spec = nullptr;
  }
}

gvr_sizei gvr_buffer_spec_get_size(const gvr_buffer_spec* spec) {
  return spec->size;
}

void gvr_buffer_spec_set_size(gvr_buffer_spec* spec, gvr_sizei size) {
  spec->size = size;
}

int32_t gvr_buffer_spec_get_samples(const gvr_buffer_spec* spec) {
  return spec->msaa_samples;
}

void gvr_buffer_spec_set_samples(gvr_buffer_spec* spec, int32_t num_samples) {
  spec->msaa_samples = num_samples;
}

void gvr_buffer_spec_set_color_format(gvr_buffer_spec* spec,
                                      int32_t color_format) {
  spec->color_format = color_format;
}

void gvr_buffer_spec_set_depth_stencil_format(gvr_buffer_spec* spec,
                                              int32_t depth_stencil_format) {
  spec->depth_stencil_format = depth_stencil_format;
}

void gvr_buffer_spec_set_z_order(gvr_buffer_spec* spec, int z_order) {
  spec->z_order = z_order;
}

void gvr_buffer_spec_set_visibility(gvr_buffer_spec* spec,
                                    int32_t visibility) {
  spec->initially_visible = (visibility != GVR_INVISIBLE);
}

void gvr_buffer_spec_set_blur_behind(gvr_buffer_spec* spec,
                                     int32_t blur_behind) {
  spec->blur_behind = (blur_behind != GVR_BLUR_BEHIND_FALSE);
}

void gvr_buffer::SetDefaults() {
  spec = gvr_buffer_spec();
  frame_buffer = 0;
  color_render_buffer = 0;
  depth_stencil_render_buffer = 0;
  requested_size = {-1, -1};
}

gvr_buffer::gvr_buffer() { SetDefaults(); }

gvr_buffer::gvr_buffer(gvr_context* gvr, const gvr_buffer_spec& spec_in,
                       GLuint texture_id, GLenum texture_target) {
  SetDefaults();
  spec = spec_in;

  glGetError();  // Clear error state
  glGenFramebuffers(1, &frame_buffer);
  glBindFramebuffer(GL_FRAMEBUFFER, frame_buffer);

  if (texture_id == 0) {
    GLenum gl_color_format;
    if (!GetGlColorFormat(spec.color_format, &gl_color_format)) {
      ALOGE("Unknown color format: %d", spec.color_format);
      gvr_set_error(gvr, GVR_ERROR_INTERNAL);
      FreeGl();
      return;
    }

    glGenRenderbuffers(1, &color_render_buffer);
    glBindRenderbuffer(GL_RENDERBUFFER, color_render_buffer);
    if (spec.msaa_samples < 2) {
      glRenderbufferStorage(GL_RENDERBUFFER, gl_color_format, spec.size.width,
                            spec.size.height);
    } else {
      glRenderbufferStorageMultisample(GL_RENDERBUFFER, spec.msaa_samples,
                                       gl_color_format, spec.size.width,
                                       spec.size.height);
    }
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                              GL_RENDERBUFFER, color_render_buffer);
  } else {
    if (spec.msaa_samples < 2) {
      glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                             texture_target, texture_id, 0);
    } else {
      glFramebufferTexture2DMultisampleEXT(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                           texture_target, texture_id, 0,
                                           spec.msaa_samples);
    }
  }

  if (spec.depth_stencil_format != GVR_DEPTH_STENCIL_FORMAT_NONE) {
    GLenum gl_depth_format;
    if (!GetGlDepthFormat(spec.depth_stencil_format, &gl_depth_format)) {
      ALOGE("Unknown depth/stencil format: %d", spec.depth_stencil_format);
      gvr_set_error(gvr, GVR_ERROR_INTERNAL);
      FreeGl();
      return;
    }

    glGenRenderbuffers(1, &depth_stencil_render_buffer);
    glBindRenderbuffer(GL_RENDERBUFFER, depth_stencil_render_buffer);
    if (spec.msaa_samples < 2) {
      glRenderbufferStorage(GL_RENDERBUFFER, gl_depth_format, spec.size.width,
                            spec.size.height);
    } else {
      glRenderbufferStorageMultisample(GL_RENDERBUFFER, spec.msaa_samples,
                                       gl_depth_format, spec.size.width,
                                       spec.size.height);
    }
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT,
                              GL_RENDERBUFFER, depth_stencil_render_buffer);
  }

  GLenum gl_error = glGetError();
  if (gl_error != GL_NO_ERROR) {
    ALOGE("GL error after creating framebuffer: %d", gl_error);
    gvr_set_error(gvr, GVR_ERROR_INTERNAL);
    FreeGl();
    return;
  }

  GLenum framebuffer_complete_result = glCheckFramebufferStatus(GL_FRAMEBUFFER);
  if (framebuffer_complete_result != GL_FRAMEBUFFER_COMPLETE) {
    ALOGE("Framebuffer setup failed. glCheckFramebufferStatus returned %d",
          framebuffer_complete_result);
    gvr_set_error(gvr, GVR_ERROR_INTERNAL);
    FreeGl();
    return;
  }
}

void gvr_buffer::FreeGl() {
  if (frame_buffer != 0) {
    glDeleteFramebuffers(1, &frame_buffer);
    frame_buffer = 0;
  }
  if (color_render_buffer != 0) {
    glDeleteRenderbuffers(1, &color_render_buffer);
    color_render_buffer = 0;
  }
  if (depth_stencil_render_buffer != 0) {
    glDeleteRenderbuffers(1, &depth_stencil_render_buffer);
    depth_stencil_render_buffer = 0;
  }
}

gvr_buffer::~gvr_buffer() { FreeGl(); }

gvr_buffer::gvr_buffer(gvr_buffer&& other) {
  spec = other.spec;
  frame_buffer = other.frame_buffer;
  color_render_buffer = other.color_render_buffer;
  depth_stencil_render_buffer = other.depth_stencil_render_buffer;
  requested_size = other.requested_size;
  other.SetDefaults();
}

gvr_buffer& gvr_buffer::operator=(gvr_buffer&& other) {
  if (this == &other)
    return *this;
  spec = other.spec;
  frame_buffer = other.frame_buffer;
  color_render_buffer = other.color_render_buffer;
  depth_stencil_render_buffer = other.depth_stencil_render_buffer;
  requested_size = other.requested_size;
  other.SetDefaults();
  return *this;
}

gvr_swap_chain* gvr_swap_chain_create(gvr_context* gvr,
                                      const gvr_buffer_spec** buffers,
                                      int32_t count) {
  if (count == 0) {
    ALOGE("At least one buffer must be requested");
    gvr_set_error(gvr, GVR_ERROR_INTERNAL);
    return nullptr;
  }

  // We only support one buffer, but it's common for gvr apps to use more than
  // one. Print an error to the log if the app requests more than one buffer,
  // but continue on. We'll only render the first buffer in that case.
  if (count > 1) {
    ALOGE(
        "Only one buffer is supported but the app requested %d."
        " Only the first buffer will be rendered.",
        count);
  }

  std::unique_ptr<gvr_swap_chain> swap_chain(new gvr_swap_chain(gvr));

  // The first buffer gets a DvrGraphicsContext, which contains the surface we
  // pass to displayd for rendering.
  swap_chain->buffers_.push_back(gvr_buffer());
  swap_chain->buffers_.back().spec = *buffers[0];
  if (!CreateDvrGraphicsContextAndGvrBuffer(swap_chain.get()))
    return nullptr;

  // The rest of the buffers, which we don't render for now, get color render
  // buffers.
  for (int i = 1; i < count; ++i) {
    swap_chain->buffers_.push_back(
        gvr_buffer(gvr, *buffers[i], 0, GL_TEXTURE_2D));
    if (swap_chain->buffers_.back().frame_buffer == 0)
      return nullptr;
  }

  gvr->swap_chains_.push_back(swap_chain.get());
  return swap_chain.release();
}

gvr_swap_chain_::~gvr_swap_chain_() {
  if (context) {
    auto iter = std::find(std::begin(context->swap_chains_),
                          std::end(context->swap_chains_), this);
    if (iter != context->swap_chains_.end())
      context->swap_chains_.erase(iter);
  }
  buffers_.clear();
  if (graphics_context_ != nullptr)
    dvrGraphicsContextDestroy(graphics_context_);
}

void gvr_swap_chain_destroy(gvr_swap_chain** swap_chain) {
  if (!swap_chain || !(*swap_chain)) {
    ALOGW("gvr_swap_chain_destroy: Invalid swap chain pointer.");
    return;
  }
  delete *swap_chain;
  *swap_chain = nullptr;
}

int32_t gvr_swap_chain_get_buffer_count(const gvr_swap_chain* swap_chain) {
  return swap_chain ? static_cast<int32_t>(swap_chain->buffers_.size()) : 0;
}

gvr_sizei gvr_swap_chain_get_buffer_size(gvr_swap_chain* swap_chain,
                                         int32_t index) {
  if (!VerifyBufferIndex("gvr_swap_chain_get_buffer_size", swap_chain, index))
    return gvr_sizei{0, 0};

  gvr_buffer& buf = swap_chain->buffers_[index];
  if (buf.requested_size != gvr_sizei{-1, -1})
    return buf.requested_size;
  else
    return buf.spec.size;
}

void gvr_swap_chain_resize_buffer(gvr_swap_chain* swap_chain, int32_t index,
                                  gvr_sizei size) {
  if (!VerifyBufferIndex("gvr_swap_chain_resize_buffer", swap_chain, index))
    return;

  gvr_buffer& buf = swap_chain->buffers_[index];
  if (size != buf.spec.size)
    buf.requested_size = size;
  else
    buf.requested_size = {-1, -1};
}

gvr_frame* gvr_swap_chain_acquire_frame(gvr_swap_chain* swap_chain) {
  if (!swap_chain)
    return nullptr;

  if (swap_chain->frame_acquired_) {
    gvr_set_error(swap_chain->context, GVR_ERROR_NO_FRAME_AVAILABLE);
    return nullptr;
  }

  // Resize buffers if necessary
  for (int i = 0; i < static_cast<int>(swap_chain->buffers_.size()); ++i) {
    gvr_buffer& buf = swap_chain->buffers_[i];
    if (buf.requested_size != gvr_sizei{-1, -1}) {
      if (!SwapChainResizeBuffer(swap_chain, i))
        return nullptr;
    }
  }

  // Only call gvr_wait_next_frame() if the app didn't call it already.
  if (!swap_chain->wait_next_frame_called_by_app_)
    WaitNextFrame(swap_chain, 0, nullptr, /*called_by_app*/ false);

  int ret = dvrBeginRenderFrame(swap_chain->graphics_context_);
  if (ret < 0) {
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    return nullptr;
  }

  swap_chain->frame_acquired_ = true;
  return GetFrameFromSwapChain(swap_chain);
}

void gvr_frame_bind_buffer(gvr_frame* frame, int32_t index) {
  gvr_swap_chain* swap_chain = GetSwapChainForFrame(frame);
  if (!VerifyBufferIndex("gvr_frame_bind_buffer", swap_chain, index))
    return;
  glBindFramebuffer(GL_FRAMEBUFFER, swap_chain->buffers_[index].frame_buffer);
}

void gvr_frame_unbind(gvr_frame* /* frame */) {
  glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

gvr_sizei gvr_frame_get_buffer_size(const gvr_frame* frame, int32_t index) {
  const gvr_swap_chain* swap_chain = GetSwapChainForFrame(frame);
  if (!VerifyBufferIndex("gvr_frame_get_buffer_size", swap_chain, index))
    return gvr_sizei{0, 0};
  return swap_chain->buffers_[index].spec.size;
}

int32_t gvr_frame_get_framebuffer_object(const gvr_frame* frame,
                                         int32_t index) {
  const gvr_swap_chain* swap_chain = GetSwapChainForFrame(frame);
  if (!VerifyBufferIndex("gvr_frame_get_framebuffer_object", swap_chain, index))
    return 0;
  return swap_chain->buffers_[index].frame_buffer;
}

void gvr_frame_submit(gvr_frame** frame, const gvr_buffer_viewport_list* list,
                      gvr_mat4f head_space_from_start_space) {
  if (!frame)
    return;

  gvr_swap_chain* swap_chain = GetSwapChainForFrame(*frame);

  if (!swap_chain->frame_acquired_) {
    ALOGE("Frame was never acquired before being submitted");
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    return;
  }

  *frame = nullptr;
  swap_chain->frame_acquired_ = false;

  // Currently, support for arbitrary buffer viewport configs is very limited.
  // We assume that the first two viewports have to be the recommended color
  // buffer viewports, followed by pairs of external external buffer viewports
  // for video rendering.
  gvr_buffer_viewport_list supported_viewports;
  gvr_get_recommended_buffer_viewports(swap_chain->context,
                                       &supported_viewports);
  for (size_t i = 0; i < supported_viewports.viewports.size(); ++i) {
    if (i >= list->viewports.size() ||
        supported_viewports.viewports[i] != list->viewports[i]) {
      ALOGE("Custom viewport configurations are not fully supported.");
      gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
      return;
    }
  }

  for (size_t i = supported_viewports.viewports.size();
       i < list->viewports.size(); ++i) {
    int32_t external_surface_id = list->viewports[i].external_surface_id;
    // Ignore additional custom buffer viewport for now, only those buffer
    // viewports backed by external surfaces are supported.
    // TODO(b/31442094, b/31771861, 28954457) Add full GVR buffer viewport
    // support.
    if (external_surface_id == GVR_EXTERNAL_SURFACE_ID_NONE)
      continue;

    auto surface_it = swap_chain->external_surfaces_.find(external_surface_id);
    if (surface_it == swap_chain->external_surfaces_.end()) {
      ALOGE("Cannot find external_surface by id: %d.", external_surface_id);
      gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
      return;
    }

    // Pass the transfrom matrix of video mesh to displayd.
    dvrGraphicsVideoMeshSurfacePresent(
        swap_chain->graphics_context_, surface_it->second->video_surface,
        list->viewports[i].eye,
        GvrToEigenMatrix(list->viewports[i].transform).data());
  }

  float32x4_t pose_orientation, pose_translation;
  GvrToDvrPose(head_space_from_start_space, &pose_orientation,
               &pose_translation);
  int ret = dvrSetEdsPose(swap_chain->graphics_context_, pose_orientation,
                          pose_translation);
  if (ret < 0)
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);

  ret = dvrPresent(swap_chain->graphics_context_);
  if (ret < 0) {
    gvr_set_error(swap_chain->context, GVR_ERROR_INTERNAL);
    return;
  }
}

void gvr_bind_default_framebuffer(gvr_context* /* gvr */) {
  glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

/////////////////////////////////////////////////////////////////////////////
// Head tracking
/////////////////////////////////////////////////////////////////////////////

gvr_clock_time_point gvr_get_time_point_now() {
  return gvr_clock_time_point{GetSystemClockNs()};
}

gvr_mat4f gvr_get_head_space_from_start_space_rotation(
    const gvr_context* gvr, const gvr_clock_time_point /* time */) {
  // TODO(steventhomas): Implement prediction according to the supplied time
  // value.
  return gvr->force_6dof_ ? gvr->next_frame_6dof_pose_
                          : Gvr6dofTo3dof(gvr->next_frame_6dof_pose_);
}

gvr_mat4f gvr_apply_neck_model(const gvr_context* /* gvr */,
                               gvr_mat4f head_space_from_start_space_rotation,
                               float /* factor */) {
  // TODO(leandrogracia): this needs to be properly implemented.
  ALOGE("gvr_apply_neck_model not implemented.");
  return head_space_from_start_space_rotation;
}

// This is used to turn off sensors to save power. Not relevant for our all in
// one device.
void gvr_pause_tracking(gvr_context* /* gvr */) {}

// This is used to turn on sensors. Not relevant for our all in one device.
void gvr_resume_tracking(gvr_context* /* gvr */) {}

void gvr_reset_tracking(gvr_context* gvr) {
  // TODO(leandrogracia): this needs to be properly implemented.
  ALOGE("gvr_reset_tracking not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
}

void gvr_recenter_tracking(gvr_context* gvr) {
  // TODO(leandrogracia): this needs to be properly implemented.
  ALOGE("gvr_recenter_tracking not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
}

/////////////////////////////////////////////////////////////////////////////
// Head mounted display
/////////////////////////////////////////////////////////////////////////////

bool gvr_set_default_viewer_profile(gvr_context* gvr,
                                    const char* /* viewer_profile_uri */) {
  // TODO(leandrogracia): this needs to be properly implemented.
  ALOGE("gvr_set_default_viewer_profile not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
  return false;
}

void gvr_refresh_viewer_profile(gvr_context* /* gvr */) {}

const char* gvr_get_viewer_vendor(const gvr_context* /* gvr */) {
  return kViewerVendor;
}

const char* gvr_get_viewer_model(const gvr_context* /* gvr */) {
  return kViewerModel;
}

int32_t gvr_get_viewer_type(const gvr_context* /* gvr */) {
  // TODO(leandrogracia): this needs to be properly implemented.
  // In this case, we will probably need to define a new viewer type that
  // has 6DoF support.
  return GVR_VIEWER_TYPE_DAYDREAM;
}

gvr_mat4f gvr_get_eye_from_head_matrix(const gvr_context* gvr,
                                       const int32_t eye) {
  float eye_mult = eye == GVR_LEFT_EYE ? 1 : -1;
  return GvrTranslationMatrix(
      .5f * eye_mult * gvr->display_metrics_.inter_lens_distance_m, 0, 0);
}

gvr_recti gvr_get_window_bounds(const gvr_context* gvr) {
  // Our app windows are always full screen
  gvr_sizei screen_size = gvr_get_screen_target_size(gvr);
  return gvr_recti{0, screen_size.width, 0, screen_size.height};
}

void gvr_compute_distorted_point(const gvr_context* /* gvr */,
                                 const int32_t /* eye */,
                                 const gvr_vec2f /* uv_in */,
                                 gvr_vec2f /* uv_out */[3]) {
  // TODO(leandrogracia): this needs to be properly implemented.
  ALOGE("gvr_compute_distorted_point not implemented.");
}

/////////////////////////////////////////////////////////////////////////////
// GVR API extension (from gvr_ext.h)
/////////////////////////////////////////////////////////////////////////////

gvr_frame_schedule* gvr_frame_schedule_create() {
  return new gvr_frame_schedule;
}

void gvr_frame_schedule_destroy(gvr_frame_schedule** schedule) {
  if (!schedule || !(*schedule)) {
    ALOGW("gvr_frame_schedule_destroy: Invalid frame schedule pointer.");
    return;
  }
  delete *schedule;
  *schedule = nullptr;
}

uint32_t gvr_frame_schedule_get_vsync_count(gvr_frame_schedule* schedule) {
  return schedule->vsync_count;
}

gvr_clock_time_point gvr_frame_schedule_get_scheduled_finish(
    gvr_frame_schedule* schedule) {
  return schedule->scheduled_finish;
}

void gvr_wait_next_frame(gvr_swap_chain* swap_chain, int64_t start_delay_nanos,
                         gvr_frame_schedule* out_next_frame_schedule) {
  WaitNextFrame(swap_chain, start_delay_nanos, out_next_frame_schedule,
                /*called_by_app*/ true);
}

gvr_mat4f gvr_get_6dof_head_pose_in_start_space(gvr_context* gvr,
                                                uint32_t vsync_count) {
  DvrPoseAsync pose;
  int ret = dvrPoseGet(gvr->pose_client_, vsync_count, &pose);
  if (ret < 0) {
    ALOGW("dvrPoseGet failed: %d", ret);
    gvr_set_error(gvr, GVR_ERROR_INTERNAL);
    return GvrIdentityMatrix();
  }

  return PosefToGvrMatrix(ToPosef(pose));
}

gvr_mat4f gvr_get_head_space_from_start_space_pose(
    gvr_context* gvr, const gvr_clock_time_point /* time */) {
  // TODO(leandrogracia): implement prediction based on the provided time.
  // We need to do the same for the 3dof version too.
  return gvr->next_frame_6dof_pose_;
}

void gvr_swap_chain_set_z_order(const gvr_swap_chain* swap_chain, int z_order) {
  dvrGraphicsSurfaceSetZOrder(swap_chain->graphics_context_, z_order);
}

bool gvr_experimental_register_perf_event_callback(
    gvr_context* gvr, int* /* out_handle */, void* /* user_data */,
    void (* /* event_callback */)(void*, int, float)) {
  ALOGE("gvr_experimental_register_perf_event_callback not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
  return false;
}

bool gvr_experimental_unregister_perf_event_callback(gvr_context* gvr,
                                                     int /* handle */) {
  ALOGE("gvr_experimental_unregister_perf_event_callback not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
  return false;
}

const gvr_analytics* gvr_get_analytics(gvr_context* gvr) {
  ALOGE("gvr_get_analytics not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
  return nullptr;
}

const gvr_analytics_sample* gvr_analytics_create_sample(
    const gvr_analytics* analytics) {
  ALOGE("gvr_analytics_create_sample not implemented.");
  return nullptr;
}

const char* gvr_analytics_sample_get_buffer(const gvr_analytics_sample* sample) {
  ALOGE("gvr_analytics_sample_get_buffer not implemented.");
  return nullptr;
}

size_t gvr_analytics_sample_get_buffer_length(
    const gvr_analytics_sample* sample) {
  ALOGE("gvr_analytics_sample_get_buffer_length not implemented.");
  return 0;
}

void gvr_analytics_destroy_sample(const gvr_analytics_sample** sample) {
  ALOGE("gvr_analytics_destroy_sample not implemented.");
}

bool gvr_user_prefs_get_performance_monitoring_enabled(
    const gvr_user_prefs* /* user_prefs */) {
  ALOGW("gvr_user_prefs_get_performance_monitoring_enabled not implemented.");
  return false;
}

void gvr_enable_context_sharing(gvr_context* gvr,
                                gvr_egl_context_listener /* handler */,
                                void* /* user_data */) {
  ALOGW("gvr_enable_context_sharing not implemented.");
  gvr_set_error(gvr, GVR_ERROR_INTERNAL);
}

gvr_mat4f gvr_get_start_space_from_controller_space_pose(
    gvr_context* gvr, int controller_id,
    const gvr_clock_time_point /* time */) {
  if (controller_id < 0 || controller_id >= kControllerCount) {
    return GvrIdentityMatrix();
  }

  // TODO(leandrogracia): implement prediction based on the provided time.
  // We need to do the same for the 3dof version too.
  return gvr->next_frame_controller_pose_[controller_id];
}

gvr_external_surface* gvr_external_surface_create(gvr_context* context) {
  // A |gvr_external_surface| is bound to a DVR Graphics context at the
  // moment, which means we need an |gvr_swap_chain| created prior to the call
  // of |gvr_external_surface_create|. Check whether the current GVR context
  // has |gvr_swap_chain| created. Fail if there is no swap chain created
  // already.
  if (context->swap_chains_.empty()) {
    ALOGE("gvr_external_surface_create: No swapchain has been created yet.");
    return nullptr;
  }

  // In case there are multiple swap chains in the context, the first is
  // implicitly chosen. Actually, this should not happen as current scanline
  // racing based GVR implementation only supports single swap chain per GVR
  // context.
  if (context->swap_chains_.size() > 1) {
    ALOGW("gvr_external_surface_create: Multiple swap chains detected. "
          "Choosing the first one but this may yield unexpected results.");
  }
  gvr_swap_chain* swap_chain = context->swap_chains_[0];
  DvrVideoMeshSurface* video_surface = dvrGraphicsVideoMeshSurfaceCreate(
      swap_chain->graphics_context_);

  if (video_surface == nullptr) {
    ALOGE("gvr_external_surface_create: Failed to create video mesh surface.");
    return nullptr;
  }

  gvr_external_surface* surface = new gvr_external_surface;
  surface->id = swap_chain->next_external_surface_id_++;
  surface->swap_chain = swap_chain;
  surface->video_surface = video_surface;

  // Insert the surface into a lookup table in swap_chain. This will be
  // needed to by the external_surface_id in |gvr_buffer_viewport|.
  swap_chain->external_surfaces_.insert({surface->id, surface});
  return surface;
}

void gvr_external_surface_destroy(gvr_external_surface** surface) {
  if (!surface || !(*surface)) {
    ALOGW("gvr_external_surface_destroy: Invalid external surface pointer.");
    return;
  }

  (*surface)->swap_chain->external_surfaces_.erase((*surface)->id);
  if ((*surface)->video_surface != nullptr) {
    dvrGraphicsVideoMeshSurfaceDestroy((*surface)->video_surface);
  }

  delete *surface;
  *surface = nullptr;
}

void* gvr_external_surface_get_surface(const gvr_external_surface* surface) {
  LOG_ALWAYS_FATAL_IF(surface->swap_chain == nullptr ||
                          surface->swap_chain->context == nullptr ||
                          surface->swap_chain->context->jni_env_ == nullptr,
                      "gvr_external_surface_get_surface: Surface must be "
                      "constructed within a JNIEnv. Check |gvr_create| call.");

  LOG_ALWAYS_FATAL_IF(surface->video_surface == nullptr,
                      "gvr_external_surface_get_surface: Invalid surface.");

  std::shared_ptr<android::dvr::ProducerQueue> producer_queue =
      surface->video_surface->client->GetProducerQueue();
  std::shared_ptr<android::dvr::BufferHubQueueCore> core =
      android::dvr::BufferHubQueueCore::Create(producer_queue);

  return android_view_Surface_createFromIGraphicBufferProducer(
      surface->swap_chain->context->jni_env_,
      new android::dvr::BufferHubQueueProducer(core));
}

int32_t gvr_external_surface_get_surface_id(
    const gvr_external_surface* surface) {
  return surface->id;
}
