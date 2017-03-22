#include <dvr/graphics.h>

#include <inttypes.h>
#include <sys/timerfd.h>
#include <array>
#include <vector>

#include <log/log.h>
#include <utils/Trace.h>

#ifndef VK_USE_PLATFORM_ANDROID_KHR
#define VK_USE_PLATFORM_ANDROID_KHR 1
#endif
#include <vulkan/vulkan.h>

#include <pdx/file_handle.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/debug.h>
#include <private/dvr/display_types.h>
#include <private/dvr/frame_history.h>
#include <private/dvr/gl_fenced_flush.h>
#include <private/dvr/graphics/vr_gl_extensions.h>
#include <private/dvr/graphics_private.h>
#include <private/dvr/late_latch.h>
#include <private/dvr/native_buffer_queue.h>
#include <private/dvr/sensor_constants.h>
#include <private/dvr/video_mesh_surface_client.h>
#include <private/dvr/vsync_client.h>
#include <private/dvr/platform_defines.h>

#include <android/native_window.h>

#ifndef EGL_CONTEXT_MAJOR_VERSION
#define EGL_CONTEXT_MAJOR_VERSION 0x3098
#define EGL_CONTEXT_MINOR_VERSION 0x30FB
#endif

using android::pdx::LocalHandle;
using android::pdx::LocalChannelHandle;

using android::dvr::DisplaySurfaceAttributeEnum;
using android::dvr::DisplaySurfaceAttributeValue;

namespace {

// TODO(urbanus): revisit once we have per-platform usage config in place.
constexpr int kDefaultDisplaySurfaceUsage =
    GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE |
    GRALLOC_USAGE_QCOM_FRAMEBUFFER_COMPRESSION;
constexpr int kDefaultDisplaySurfaceFormat = HAL_PIXEL_FORMAT_RGBA_8888;
// TODO(alexst): revisit this count when HW encode is available for casting.
constexpr int kDefaultBufferCount = 4;

// Use with dvrBeginRenderFrame to disable EDS for the current frame.
constexpr float32x4_t DVR_POSE_NO_EDS = {10.0f, 0.0f, 0.0f, 0.0f};

// Use with dvrBeginRenderFrame to indicate that GPU late-latching is being used
// for determining the render pose.
constexpr float32x4_t DVR_POSE_LATE_LATCH = {20.0f, 0.0f, 0.0f, 0.0f};

#ifndef NDEBUG

static const char* GetGlCallbackType(GLenum type) {
  switch (type) {
    case GL_DEBUG_TYPE_ERROR_KHR:
      return "ERROR";
    case GL_DEBUG_TYPE_DEPRECATED_BEHAVIOR_KHR:
      return "DEPRECATED_BEHAVIOR";
    case GL_DEBUG_TYPE_UNDEFINED_BEHAVIOR_KHR:
      return "UNDEFINED_BEHAVIOR";
    case GL_DEBUG_TYPE_PORTABILITY_KHR:
      return "PORTABILITY";
    case GL_DEBUG_TYPE_PERFORMANCE_KHR:
      return "PERFORMANCE";
    case GL_DEBUG_TYPE_OTHER_KHR:
      return "OTHER";
    default:
      return "UNKNOWN";
  }
}

static void on_gl_error(GLenum /*source*/, GLenum type, GLuint /*id*/,
                        GLenum severity, GLsizei /*length*/,
                        const char* message, const void* /*user_param*/) {
  char msg[400];
  snprintf(msg, sizeof(msg), "[" __FILE__ ":%u] GL %s: %s", __LINE__,
           GetGlCallbackType(type), message);
  switch (severity) {
    case GL_DEBUG_SEVERITY_LOW_KHR:
      ALOGI("%s", msg);
      break;
    case GL_DEBUG_SEVERITY_MEDIUM_KHR:
      ALOGW("%s", msg);
      break;
    case GL_DEBUG_SEVERITY_HIGH_KHR:
      ALOGE("%s", msg);
      break;
  }
  fprintf(stderr, "%s\n", msg);
}

#endif

int DvrToHalSurfaceFormat(int dvr_surface_format) {
  switch (dvr_surface_format) {
    case DVR_SURFACE_FORMAT_RGBA_8888:
      return HAL_PIXEL_FORMAT_RGBA_8888;
    case DVR_SURFACE_FORMAT_RGB_565:
      return HAL_PIXEL_FORMAT_RGB_565;
    default:
      return HAL_PIXEL_FORMAT_RGBA_8888;
  }
}

int SelectEGLConfig(EGLDisplay dpy, EGLint* attr, unsigned format,
                    EGLConfig* config) {
  std::array<EGLint, 4> desired_rgba;
  switch (format) {
    case HAL_PIXEL_FORMAT_RGBA_8888:
    case HAL_PIXEL_FORMAT_BGRA_8888:
      desired_rgba = {{8, 8, 8, 8}};
      break;
    case HAL_PIXEL_FORMAT_RGB_565:
      desired_rgba = {{5, 6, 5, 0}};
      break;
    default:
      ALOGE("Unsupported framebuffer pixel format %d", format);
      return -1;
  }

  EGLint max_configs = 0;
  if (eglGetConfigs(dpy, NULL, 0, &max_configs) == EGL_FALSE) {
    ALOGE("No EGL configurations available?!");
    return -1;
  }

  std::vector<EGLConfig> configs(max_configs);

  EGLint num_configs;
  if (eglChooseConfig(dpy, attr, &configs[0], max_configs, &num_configs) ==
      EGL_FALSE) {
    ALOGE("eglChooseConfig failed");
    return -1;
  }

  std::array<EGLint, 4> config_rgba;
  for (int i = 0; i < num_configs; i++) {
    eglGetConfigAttrib(dpy, configs[i], EGL_RED_SIZE, &config_rgba[0]);
    eglGetConfigAttrib(dpy, configs[i], EGL_GREEN_SIZE, &config_rgba[1]);
    eglGetConfigAttrib(dpy, configs[i], EGL_BLUE_SIZE, &config_rgba[2]);
    eglGetConfigAttrib(dpy, configs[i], EGL_ALPHA_SIZE, &config_rgba[3]);
    if (config_rgba == desired_rgba) {
      *config = configs[i];
      return 0;
    }
  }

  ALOGE("Cannot find a matching EGL config");
  return -1;
}

void DestroyEglContext(EGLDisplay egl_display, EGLContext* egl_context) {
  if (*egl_context != EGL_NO_CONTEXT) {
    eglDestroyContext(egl_display, *egl_context);
    *egl_context = EGL_NO_CONTEXT;
  }
}

// Perform internal initialization. A GL context must be bound to the current
// thread.
// @param internally_created_context True if we created and own the GL context,
//        false if it was supplied by the application.
// @return 0 if init was successful, or a negative error code on failure.
int InitGl(bool internally_created_context) {
  EGLDisplay egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (egl_display == EGL_NO_DISPLAY) {
    ALOGE("eglGetDisplay failed");
    return -EINVAL;
  }

  EGLContext egl_context = eglGetCurrentContext();
  if (egl_context == EGL_NO_CONTEXT) {
    ALOGE("No GL context bound");
    return -EINVAL;
  }

  glGetError();  // Clear the error state
  GLint major_version, minor_version;
  glGetIntegerv(GL_MAJOR_VERSION, &major_version);
  glGetIntegerv(GL_MINOR_VERSION, &minor_version);
  if (glGetError() != GL_NO_ERROR) {
    // GL_MAJOR_VERSION and GL_MINOR_VERSION were added in GLES 3. If we get an
    // error querying them it's almost certainly because it's GLES 1 or 2.
    ALOGE("Error getting GL version. Must be GLES 3.2 or greater.");
    return -EINVAL;
  }

  if (major_version < 3 || (major_version == 3 && minor_version < 2)) {
    ALOGE("Invalid GL version: %d.%d. Must be GLES 3.2 or greater.",
          major_version, minor_version);
    return -EINVAL;
  }

#ifndef NDEBUG
  if (internally_created_context) {
    // Enable verbose GL debug output.
    glEnable(GL_DEBUG_OUTPUT_SYNCHRONOUS_KHR);
    glDebugMessageCallbackKHR(on_gl_error, NULL);
    GLuint unused_ids = 0;
    glDebugMessageControlKHR(GL_DONT_CARE, GL_DONT_CARE, GL_DONT_CARE, 0,
                             &unused_ids, GL_TRUE);
  }
#else
  (void)internally_created_context;
#endif

  load_gl_extensions();
  return 0;
}

int CreateEglContext(EGLDisplay egl_display, DvrSurfaceParameter* parameters,
                     EGLContext* egl_context) {
  *egl_context = EGL_NO_CONTEXT;

  EGLint major, minor;
  if (!eglInitialize(egl_display, &major, &minor)) {
    ALOGE("Failed to initialize EGL");
    return -ENXIO;
  }

  ALOGI("EGL version: %d.%d\n", major, minor);

  int buffer_format = kDefaultDisplaySurfaceFormat;

  for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
    switch (p->key) {
      case DVR_SURFACE_PARAMETER_FORMAT_IN:
        buffer_format = DvrToHalSurfaceFormat(p->value);
        break;
    }
  }

  EGLint config_attrs[] = {EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
                           EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE};
  EGLConfig config = {0};

  int ret = SelectEGLConfig(egl_display, config_attrs, buffer_format, &config);
  if (ret < 0)
    return ret;

  ALOGI("EGL SelectEGLConfig ok.\n");

  EGLint context_attrs[] = {EGL_CONTEXT_MAJOR_VERSION,
                            3,
                            EGL_CONTEXT_MINOR_VERSION,
                            2,
#ifndef NDEBUG
                            EGL_CONTEXT_FLAGS_KHR,
                            EGL_CONTEXT_OPENGL_DEBUG_BIT_KHR,
#endif
                            EGL_NONE};

  *egl_context =
      eglCreateContext(egl_display, config, EGL_NO_CONTEXT, context_attrs);
  if (*egl_context == EGL_NO_CONTEXT) {
    ALOGE("eglCreateContext failed");
    return -ENXIO;
  }

  ALOGI("eglCreateContext ok.\n");

  if (!eglMakeCurrent(egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE,
                      *egl_context)) {
    ALOGE("eglMakeCurrent failed");
    DestroyEglContext(egl_display, egl_context);
    return -EINVAL;
  }

  return 0;
}

}  // anonymous namespace

// TODO(hendrikw): When we remove the calls to this in native_window.cpp, move
// this back into the anonymous namespace
std::shared_ptr<android::dvr::DisplaySurfaceClient> CreateDisplaySurfaceClient(
    struct DvrSurfaceParameter* parameters,
    /*out*/ android::dvr::SystemDisplayMetrics* metrics) {
  auto client = android::dvr::DisplayClient::Create();
  if (!client) {
    ALOGE("Failed to create display client!");
    return nullptr;
  }

  const int ret = client->GetDisplayMetrics(metrics);
  if (ret < 0) {
    ALOGE("Failed to get display metrics: %s", strerror(-ret));
    return nullptr;
  }

  // Parameters that may be modified by the parameters array. Some of these are
  // here for future expansion.
  int request_width = -1;
  int request_height = -1;
  int request_flags = 0;
  bool disable_distortion = false;
  bool disable_stabilization = false;
  bool disable_cac = false;
  bool request_visible = true;
  bool vertical_flip = false;
  int request_z_order = 0;
  bool request_exclude_from_blur = false;
  bool request_blur_behind = true;
  int request_format = kDefaultDisplaySurfaceFormat;
  int request_usage = kDefaultDisplaySurfaceUsage;
  int geometry_type = DVR_SURFACE_GEOMETRY_SINGLE;

  // Handle parameter inputs.
  for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
    switch (p->key) {
      case DVR_SURFACE_PARAMETER_WIDTH_IN:
        request_width = p->value;
        break;
      case DVR_SURFACE_PARAMETER_HEIGHT_IN:
        request_height = p->value;
        break;
      case DVR_SURFACE_PARAMETER_DISABLE_DISTORTION_IN:
        disable_distortion = !!p->value;
        break;
      case DVR_SURFACE_PARAMETER_DISABLE_STABILIZATION_IN:
        disable_stabilization = !!p->value;
        break;
      case DVR_SURFACE_PARAMETER_DISABLE_CAC_IN:
        disable_cac = !!p->value;
        break;
      case DVR_SURFACE_PARAMETER_VISIBLE_IN:
        request_visible = !!p->value;
        break;
      case DVR_SURFACE_PARAMETER_Z_ORDER_IN:
        request_z_order = p->value;
        break;
      case DVR_SURFACE_PARAMETER_EXCLUDE_FROM_BLUR_IN:
        request_exclude_from_blur = !!p->value;
        break;
      case DVR_SURFACE_PARAMETER_BLUR_BEHIND_IN:
        request_blur_behind = !!p->value;
        break;
      case DVR_SURFACE_PARAMETER_VERTICAL_FLIP_IN:
        vertical_flip = !!p->value;
        break;
      case DVR_SURFACE_PARAMETER_GEOMETRY_IN:
        geometry_type = p->value;
        break;
      case DVR_SURFACE_PARAMETER_FORMAT_IN:
        request_format = DvrToHalSurfaceFormat(p->value);
        break;
      case DVR_SURFACE_PARAMETER_ENABLE_LATE_LATCH_IN:
      case DVR_SURFACE_PARAMETER_CREATE_GL_CONTEXT_IN:
      case DVR_SURFACE_PARAMETER_DISPLAY_WIDTH_OUT:
      case DVR_SURFACE_PARAMETER_DISPLAY_HEIGHT_OUT:
      case DVR_SURFACE_PARAMETER_SURFACE_WIDTH_OUT:
      case DVR_SURFACE_PARAMETER_SURFACE_HEIGHT_OUT:
      case DVR_SURFACE_PARAMETER_INTER_LENS_METERS_OUT:
      case DVR_SURFACE_PARAMETER_LEFT_FOV_LRBT_OUT:
      case DVR_SURFACE_PARAMETER_RIGHT_FOV_LRBT_OUT:
      case DVR_SURFACE_PARAMETER_VSYNC_PERIOD_OUT:
      case DVR_SURFACE_PARAMETER_SURFACE_TEXTURE_TARGET_TYPE_OUT:
      case DVR_SURFACE_PARAMETER_SURFACE_TEXTURE_TARGET_ID_OUT:
      case DVR_SURFACE_PARAMETER_GRAPHICS_API_IN:
      case DVR_SURFACE_PARAMETER_VK_INSTANCE_IN:
      case DVR_SURFACE_PARAMETER_VK_PHYSICAL_DEVICE_IN:
      case DVR_SURFACE_PARAMETER_VK_DEVICE_IN:
      case DVR_SURFACE_PARAMETER_VK_PRESENT_QUEUE_IN:
      case DVR_SURFACE_PARAMETER_VK_PRESENT_QUEUE_FAMILY_IN:
      case DVR_SURFACE_PARAMETER_VK_SWAPCHAIN_IMAGE_COUNT_OUT:
      case DVR_SURFACE_PARAMETER_VK_SWAPCHAIN_IMAGE_FORMAT_OUT:
        break;
      default:
        ALOGE("Invalid display surface parameter: key=%d value=%" PRId64,
              p->key, p->value);
        return nullptr;
    }
  }

  request_flags |= disable_distortion
                       ? DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION
                       : 0;
  request_flags |=
      disable_stabilization ? DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_EDS : 0;
  request_flags |=
      disable_cac ? DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_CAC : 0;
  request_flags |= vertical_flip ? DVR_DISPLAY_SURFACE_FLAGS_VERTICAL_FLIP : 0;
  request_flags |= (geometry_type == DVR_SURFACE_GEOMETRY_SEPARATE_2)
                       ? DVR_DISPLAY_SURFACE_FLAGS_GEOMETRY_SEPARATE_2
                       : 0;

  if (request_width == -1) {
    request_width = disable_distortion ? metrics->display_native_width
                                       : metrics->distorted_width;
    if (!disable_distortion &&
        geometry_type == DVR_SURFACE_GEOMETRY_SEPARATE_2) {
      // The metrics always return the single wide buffer resolution.
      // When split between eyes, we need to halve the width of the surface.
      request_width /= 2;
    }
  }
  if (request_height == -1) {
    request_height = disable_distortion ? metrics->display_native_height
                                        : metrics->distorted_height;
  }

  std::shared_ptr<android::dvr::DisplaySurfaceClient> surface =
      client->CreateDisplaySurface(request_width, request_height,
                                   request_format, request_usage,
                                   request_flags);
  surface->SetAttributes(
      {{DisplaySurfaceAttributeEnum::Visible,
        DisplaySurfaceAttributeValue{request_visible}},
       {DisplaySurfaceAttributeEnum::ZOrder,
        DisplaySurfaceAttributeValue{request_z_order}},
       {DisplaySurfaceAttributeEnum::ExcludeFromBlur,
        DisplaySurfaceAttributeValue{request_exclude_from_blur}},
       {DisplaySurfaceAttributeEnum::BlurBehind,
        DisplaySurfaceAttributeValue{request_blur_behind}}});

  // Handle parameter output requests down here so we can return surface info.
  for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
    switch (p->key) {
      case DVR_SURFACE_PARAMETER_DISPLAY_WIDTH_OUT:
        *static_cast<int32_t*>(p->value_out) = metrics->display_native_width;
        break;
      case DVR_SURFACE_PARAMETER_DISPLAY_HEIGHT_OUT:
        *static_cast<int32_t*>(p->value_out) = metrics->display_native_height;
        break;
      case DVR_SURFACE_PARAMETER_SURFACE_WIDTH_OUT:
        *static_cast<int32_t*>(p->value_out) = surface->width();
        break;
      case DVR_SURFACE_PARAMETER_SURFACE_HEIGHT_OUT:
        *static_cast<int32_t*>(p->value_out) = surface->height();
        break;
      case DVR_SURFACE_PARAMETER_INTER_LENS_METERS_OUT:
        *static_cast<float*>(p->value_out) = metrics->inter_lens_distance_m;
        break;
      case DVR_SURFACE_PARAMETER_LEFT_FOV_LRBT_OUT:
        for (int i = 0; i < 4; ++i) {
          float* float_values_out = static_cast<float*>(p->value_out);
          float_values_out[i] = metrics->left_fov_lrbt[i];
        }
        break;
      case DVR_SURFACE_PARAMETER_RIGHT_FOV_LRBT_OUT:
        for (int i = 0; i < 4; ++i) {
          float* float_values_out = static_cast<float*>(p->value_out);
          float_values_out[i] = metrics->right_fov_lrbt[i];
        }
        break;
      case DVR_SURFACE_PARAMETER_VSYNC_PERIOD_OUT:
        *static_cast<uint64_t*>(p->value_out) = metrics->vsync_period_ns;
        break;
      default:
        break;
    }
  }

  return surface;
}

extern "C" int dvrGetNativeDisplayDimensions(int* native_width,
                                             int* native_height) {
  int error = 0;
  auto client = android::dvr::DisplayClient::Create(&error);
  if (!client) {
    ALOGE("Failed to create display client!");
    return error;
  }

  android::dvr::SystemDisplayMetrics metrics;
  const int ret = client->GetDisplayMetrics(&metrics);

  if (ret != 0) {
    ALOGE("Failed to get display metrics!");
    return ret;
  }

  *native_width = static_cast<int>(metrics.display_native_width);
  *native_height = static_cast<int>(metrics.display_native_height);
  return 0;
}

struct DvrGraphicsContext : public android::ANativeObjectBase<
                                ANativeWindow, DvrGraphicsContext,
                                android::LightRefBase<DvrGraphicsContext>> {
 public:
  DvrGraphicsContext();
  ~DvrGraphicsContext();

  int graphics_api;  // DVR_SURFACE_GRAPHICS_API_*

  // GL specific members.
  struct {
    EGLDisplay egl_display;
    EGLContext egl_context;
    bool owns_egl_context;
    GLuint texture_id[kSurfaceViewMaxCount];
    int texture_count;
    GLenum texture_target_type;
  } gl;

  // VK specific members
  struct {
    // These objects are passed in by the application, and are NOT owned
    // by the context.
    VkInstance instance;
    VkPhysicalDevice physical_device;
    VkDevice device;
    VkQueue present_queue;
    uint32_t present_queue_family;
    const VkAllocationCallbacks* allocation_callbacks;
    // These objects are owned by the context.
    ANativeWindow* window;
    VkSurfaceKHR surface;
    VkSwapchainKHR swapchain;
    std::vector<VkImage> swapchain_images;
    std::vector<VkImageView> swapchain_image_views;
  } vk;

  // Display surface, metrics, and buffer management members.
  std::shared_ptr<android::dvr::DisplaySurfaceClient> display_surface;
  android::dvr::SystemDisplayMetrics display_metrics;
  std::unique_ptr<android::dvr::NativeBufferQueue> buffer_queue;
  android::dvr::NativeBufferProducer* current_buffer;
  bool buffer_already_posted;

  // Synchronization members.
  std::unique_ptr<android::dvr::VSyncClient> vsync_client;
  LocalHandle timerfd;

  android::dvr::FrameHistory frame_history;

  // Mapped surface metadata (ie: for pose delivery with presented frames).
  volatile android::dvr::DisplaySurfaceMetadata* surface_metadata;

  // LateLatch support.
  std::unique_ptr<android::dvr::LateLatch> late_latch;

  // Video mesh support.
  std::vector<std::shared_ptr<android::dvr::VideoMeshSurfaceClient>>
      video_mesh_surfaces;

 private:
  // ANativeWindow function implementations
  std::mutex lock_;
  int Post(android::dvr::NativeBufferProducer* buffer, int fence_fd);
  static int SetSwapInterval(ANativeWindow* window, int interval);
  static int DequeueBuffer(ANativeWindow* window, ANativeWindowBuffer** buffer,
                           int* fence_fd);
  static int QueueBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer,
                         int fence_fd);
  static int CancelBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer,
                          int fence_fd);
  static int Query(const ANativeWindow* window, int what, int* value);
  static int Perform(ANativeWindow* window, int operation, ...);
  static int DequeueBuffer_DEPRECATED(ANativeWindow* window,
                                      ANativeWindowBuffer** buffer);
  static int CancelBuffer_DEPRECATED(ANativeWindow* window,
                                     ANativeWindowBuffer* buffer);
  static int QueueBuffer_DEPRECATED(ANativeWindow* window,
                                    ANativeWindowBuffer* buffer);
  static int LockBuffer_DEPRECATED(ANativeWindow* window,
                                   ANativeWindowBuffer* buffer);

  DvrGraphicsContext(const DvrGraphicsContext&) = delete;
  void operator=(const DvrGraphicsContext&) = delete;
};

DvrGraphicsContext::DvrGraphicsContext()
    : graphics_api(DVR_GRAPHICS_API_GLES),
      gl{},
      vk{},
      current_buffer(nullptr),
      buffer_already_posted(false),
      surface_metadata(nullptr) {
  gl.egl_display = EGL_NO_DISPLAY;
  gl.egl_context = EGL_NO_CONTEXT;
  gl.owns_egl_context = true;
  gl.texture_target_type = GL_TEXTURE_2D;

  ANativeWindow::setSwapInterval = SetSwapInterval;
  ANativeWindow::dequeueBuffer = DequeueBuffer;
  ANativeWindow::cancelBuffer = CancelBuffer;
  ANativeWindow::queueBuffer = QueueBuffer;
  ANativeWindow::query = Query;
  ANativeWindow::perform = Perform;

  ANativeWindow::dequeueBuffer_DEPRECATED = DequeueBuffer_DEPRECATED;
  ANativeWindow::cancelBuffer_DEPRECATED = CancelBuffer_DEPRECATED;
  ANativeWindow::lockBuffer_DEPRECATED = LockBuffer_DEPRECATED;
  ANativeWindow::queueBuffer_DEPRECATED = QueueBuffer_DEPRECATED;
}

DvrGraphicsContext::~DvrGraphicsContext() {
  if (graphics_api == DVR_GRAPHICS_API_GLES) {
    glDeleteTextures(gl.texture_count, gl.texture_id);
    if (gl.owns_egl_context)
      DestroyEglContext(gl.egl_display, &gl.egl_context);
  } else if (graphics_api == DVR_GRAPHICS_API_VULKAN) {
    if (vk.swapchain != VK_NULL_HANDLE) {
      for (auto view : vk.swapchain_image_views) {
        vkDestroyImageView(vk.device, view, vk.allocation_callbacks);
      }
      vkDestroySwapchainKHR(vk.device, vk.swapchain, vk.allocation_callbacks);
      vkDestroySurfaceKHR(vk.instance, vk.surface, vk.allocation_callbacks);
      delete vk.window;
    }
  }
}

int dvrGraphicsContextCreate(struct DvrSurfaceParameter* parameters,
                             DvrGraphicsContext** return_graphics_context) {
  std::unique_ptr<DvrGraphicsContext> context(new DvrGraphicsContext);

  // See whether we're using GL or Vulkan
  for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
    switch (p->key) {
      case DVR_SURFACE_PARAMETER_GRAPHICS_API_IN:
        context->graphics_api = p->value;
        break;
    }
  }

  if (context->graphics_api == DVR_GRAPHICS_API_GLES) {
    context->gl.egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (context->gl.egl_display == EGL_NO_DISPLAY) {
      ALOGE("eglGetDisplay failed");
      return -ENXIO;
    }

    // See if we should create a GL context
    for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
      switch (p->key) {
        case DVR_SURFACE_PARAMETER_CREATE_GL_CONTEXT_IN:
          context->gl.owns_egl_context = p->value != 0;
          break;
      }
    }

    if (context->gl.owns_egl_context) {
      int ret = CreateEglContext(context->gl.egl_display, parameters,
                                 &context->gl.egl_context);
      if (ret < 0)
        return ret;
    } else {
      context->gl.egl_context = eglGetCurrentContext();
    }

    int ret = InitGl(context->gl.owns_egl_context);
    if (ret < 0)
      return ret;
  } else if (context->graphics_api == DVR_GRAPHICS_API_VULKAN) {
    for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
      switch (p->key) {
        case DVR_SURFACE_PARAMETER_VK_INSTANCE_IN:
          context->vk.instance = reinterpret_cast<VkInstance>(p->value);
          break;
        case DVR_SURFACE_PARAMETER_VK_PHYSICAL_DEVICE_IN:
          context->vk.physical_device =
              reinterpret_cast<VkPhysicalDevice>(p->value);
          break;
        case DVR_SURFACE_PARAMETER_VK_DEVICE_IN:
          context->vk.device = reinterpret_cast<VkDevice>(p->value);
          break;
        case DVR_SURFACE_PARAMETER_VK_PRESENT_QUEUE_IN:
          context->vk.present_queue = reinterpret_cast<VkQueue>(p->value);
          break;
        case DVR_SURFACE_PARAMETER_VK_PRESENT_QUEUE_FAMILY_IN:
          context->vk.present_queue_family = static_cast<uint32_t>(p->value);
          break;
      }
    }
  } else {
    ALOGE("Error: invalid graphics API type");
    return -EINVAL;
  }

  context->display_surface =
      CreateDisplaySurfaceClient(parameters, &context->display_metrics);
  if (!context->display_surface) {
    ALOGE("Error: failed to create display surface client");
    return -ECOMM;
  }

  context->buffer_queue.reset(new android::dvr::NativeBufferQueue(
      context->gl.egl_display, context->display_surface, kDefaultBufferCount));

  // The way the call sequence works we need 1 more than the buffer queue
  // capacity to store data for all pending frames
  context->frame_history.Reset(context->buffer_queue->GetQueueCapacity() + 1);

  context->vsync_client = android::dvr::VSyncClient::Create();
  if (!context->vsync_client) {
    ALOGE("Error: failed to create vsync client");
    return -ECOMM;
  }

  context->timerfd.Reset(timerfd_create(CLOCK_MONOTONIC, 0));
  if (!context->timerfd) {
    ALOGE("Error: timerfd_create failed because: %s", strerror(errno));
    return -EPERM;
  }

  context->surface_metadata = context->display_surface->GetMetadataBufferPtr();
  if (!context->surface_metadata) {
    ALOGE("Error: surface metadata allocation failed");
    return -ENOMEM;
  }

  ALOGI("buffer: %d x %d\n", context->display_surface->width(),
        context->display_surface->height());

  if (context->graphics_api == DVR_GRAPHICS_API_GLES) {
    context->gl.texture_count = (context->display_surface->flags() &
                                 DVR_DISPLAY_SURFACE_FLAGS_GEOMETRY_SEPARATE_2)
                                    ? 2
                                    : 1;

    // Create the GL textures.
    glGenTextures(context->gl.texture_count, context->gl.texture_id);

    // We must make sure that we have at least one buffer allocated at this time
    // so that anyone who tries to bind an FBO to context->texture_id
    // will not get an incomplete buffer.
    context->current_buffer = context->buffer_queue->Dequeue();
    LOG_ALWAYS_FATAL_IF(context->gl.texture_count !=
                        context->current_buffer->buffer()->slice_count());
    for (int i = 0; i < context->gl.texture_count; ++i) {
      glBindTexture(context->gl.texture_target_type, context->gl.texture_id[i]);
      glEGLImageTargetTexture2DOES(context->gl.texture_target_type,
                                   context->current_buffer->image_khr(i));
    }
    glBindTexture(context->gl.texture_target_type, 0);
    CHECK_GL();

    bool is_late_latch = false;

    // Pass back the texture target type and id.
    for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
      switch (p->key) {
        case DVR_SURFACE_PARAMETER_ENABLE_LATE_LATCH_IN:
          is_late_latch = !!p->value;
          break;
        case DVR_SURFACE_PARAMETER_SURFACE_TEXTURE_TARGET_TYPE_OUT:
          *static_cast<GLenum*>(p->value_out) = context->gl.texture_target_type;
          break;
        case DVR_SURFACE_PARAMETER_SURFACE_TEXTURE_TARGET_ID_OUT:
          for (int i = 0; i < context->gl.texture_count; ++i) {
            *(static_cast<GLuint*>(p->value_out) + i) =
                context->gl.texture_id[i];
          }
          break;
      }
    }

    // Initialize late latch.
    if (is_late_latch) {
      LocalHandle fd;
      int ret = context->display_surface->GetMetadataBufferFd(&fd);
      if (ret == 0) {
        context->late_latch.reset(
            new android::dvr::LateLatch(true, std::move(fd)));
      } else {
        ALOGE("Error: failed to get surface metadata buffer fd for late latch");
      }
    }
  } else if (context->graphics_api == DVR_GRAPHICS_API_VULKAN) {
    VkResult result = VK_SUCCESS;
    // Create a VkSurfaceKHR from the ANativeWindow.
    VkAndroidSurfaceCreateInfoKHR android_surface_ci = {};
    android_surface_ci.sType =
        VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR;
    android_surface_ci.window = context.get();
    result = vkCreateAndroidSurfaceKHR(
        context->vk.instance, &android_surface_ci,
        context->vk.allocation_callbacks, &context->vk.surface);
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    VkBool32 surface_supports_present = VK_FALSE;
    result = vkGetPhysicalDeviceSurfaceSupportKHR(
        context->vk.physical_device, context->vk.present_queue_family,
        context->vk.surface, &surface_supports_present);
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    if (!surface_supports_present) {
      ALOGE("Error: provided queue family (%u) does not support presentation",
            context->vk.present_queue_family);
      return -EPERM;
    }
    VkSurfaceCapabilitiesKHR surface_capabilities = {};
    result = vkGetPhysicalDeviceSurfaceCapabilitiesKHR(
        context->vk.physical_device, context->vk.surface,
        &surface_capabilities);
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    // Determine the swapchain image format.
    uint32_t device_surface_format_count = 0;
    result = vkGetPhysicalDeviceSurfaceFormatsKHR(
        context->vk.physical_device, context->vk.surface,
        &device_surface_format_count, nullptr);
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    std::vector<VkSurfaceFormatKHR> device_surface_formats(
        device_surface_format_count);
    result = vkGetPhysicalDeviceSurfaceFormatsKHR(
        context->vk.physical_device, context->vk.surface,
        &device_surface_format_count, device_surface_formats.data());
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    LOG_ALWAYS_FATAL_IF(device_surface_format_count == 0U);
    LOG_ALWAYS_FATAL_IF(device_surface_formats[0].format ==
                        VK_FORMAT_UNDEFINED);
    VkSurfaceFormatKHR present_surface_format = device_surface_formats[0];
    // Determine the swapchain present mode.
    // TODO(cort): query device_present_modes to make sure MAILBOX is supported.
    // But according to libvulkan, it is.
    uint32_t device_present_mode_count = 0;
    result = vkGetPhysicalDeviceSurfacePresentModesKHR(
        context->vk.physical_device, context->vk.surface,
        &device_present_mode_count, nullptr);
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    std::vector<VkPresentModeKHR> device_present_modes(
        device_present_mode_count);
    result = vkGetPhysicalDeviceSurfacePresentModesKHR(
        context->vk.physical_device, context->vk.surface,
        &device_present_mode_count, device_present_modes.data());
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    VkPresentModeKHR present_mode = VK_PRESENT_MODE_MAILBOX_KHR;
    // Extract presentation surface extents, image count, transform, usages,
    // etc.
    LOG_ALWAYS_FATAL_IF(
        static_cast<int>(surface_capabilities.currentExtent.width) == -1 ||
        static_cast<int>(surface_capabilities.currentExtent.height) == -1);
    VkExtent2D swapchain_extent = surface_capabilities.currentExtent;

    uint32_t desired_image_count = surface_capabilities.minImageCount;
    if (surface_capabilities.maxImageCount > 0 &&
        desired_image_count > surface_capabilities.maxImageCount) {
      desired_image_count = surface_capabilities.maxImageCount;
    }
    VkSurfaceTransformFlagBitsKHR surface_transform =
        surface_capabilities.currentTransform;
    VkImageUsageFlags image_usage_flags =
        surface_capabilities.supportedUsageFlags;
    LOG_ALWAYS_FATAL_IF(surface_capabilities.supportedCompositeAlpha ==
                        static_cast<VkFlags>(0));
    VkCompositeAlphaFlagBitsKHR composite_alpha =
        VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    if (!(surface_capabilities.supportedCompositeAlpha &
          VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR)) {
      composite_alpha = VkCompositeAlphaFlagBitsKHR(
          static_cast<int>(surface_capabilities.supportedCompositeAlpha) &
          -static_cast<int>(surface_capabilities.supportedCompositeAlpha));
    }
    // Create VkSwapchainKHR
    VkSwapchainCreateInfoKHR swapchain_ci = {};
    swapchain_ci.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    swapchain_ci.pNext = nullptr;
    swapchain_ci.surface = context->vk.surface;
    swapchain_ci.minImageCount = desired_image_count;
    swapchain_ci.imageFormat = present_surface_format.format;
    swapchain_ci.imageColorSpace = present_surface_format.colorSpace;
    swapchain_ci.imageExtent.width = swapchain_extent.width;
    swapchain_ci.imageExtent.height = swapchain_extent.height;
    swapchain_ci.imageUsage = image_usage_flags;
    swapchain_ci.preTransform = surface_transform;
    swapchain_ci.compositeAlpha = composite_alpha;
    swapchain_ci.imageArrayLayers = 1;
    swapchain_ci.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    swapchain_ci.queueFamilyIndexCount = 0;
    swapchain_ci.pQueueFamilyIndices = nullptr;
    swapchain_ci.presentMode = present_mode;
    swapchain_ci.clipped = VK_TRUE;
    swapchain_ci.oldSwapchain = VK_NULL_HANDLE;
    result = vkCreateSwapchainKHR(context->vk.device, &swapchain_ci,
                                  context->vk.allocation_callbacks,
                                  &context->vk.swapchain);
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    // Create swapchain image views
    uint32_t image_count = 0;
    result = vkGetSwapchainImagesKHR(context->vk.device, context->vk.swapchain,
                                     &image_count, nullptr);
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    LOG_ALWAYS_FATAL_IF(image_count == 0U);
    context->vk.swapchain_images.resize(image_count);
    result = vkGetSwapchainImagesKHR(context->vk.device, context->vk.swapchain,
                                     &image_count,
                                     context->vk.swapchain_images.data());
    LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    context->vk.swapchain_image_views.resize(image_count);
    VkImageViewCreateInfo image_view_ci = {};
    image_view_ci.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    image_view_ci.pNext = nullptr;
    image_view_ci.flags = 0;
    image_view_ci.format = swapchain_ci.imageFormat;
    image_view_ci.components.r = VK_COMPONENT_SWIZZLE_IDENTITY;
    image_view_ci.components.g = VK_COMPONENT_SWIZZLE_IDENTITY;
    image_view_ci.components.b = VK_COMPONENT_SWIZZLE_IDENTITY;
    image_view_ci.components.a = VK_COMPONENT_SWIZZLE_IDENTITY;
    image_view_ci.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    image_view_ci.subresourceRange.baseMipLevel = 0;
    image_view_ci.subresourceRange.levelCount = 1;
    image_view_ci.subresourceRange.baseArrayLayer = 0;
    image_view_ci.subresourceRange.layerCount = 1;
    image_view_ci.viewType = VK_IMAGE_VIEW_TYPE_2D;
    image_view_ci.image = VK_NULL_HANDLE;  // filled in below
    for (uint32_t i = 0; i < image_count; ++i) {
      image_view_ci.image = context->vk.swapchain_images[i];
      result = vkCreateImageView(context->vk.device, &image_view_ci,
                                 context->vk.allocation_callbacks,
                                 &context->vk.swapchain_image_views[i]);
      LOG_ALWAYS_FATAL_IF(result != VK_SUCCESS);
    }
    // Fill in any requested output parameters.
    for (auto p = parameters; p && p->key != DVR_SURFACE_PARAMETER_NONE; ++p) {
      switch (p->key) {
        case DVR_SURFACE_PARAMETER_VK_SWAPCHAIN_IMAGE_COUNT_OUT:
          *static_cast<uint32_t*>(p->value_out) = image_count;
          break;
        case DVR_SURFACE_PARAMETER_VK_SWAPCHAIN_IMAGE_FORMAT_OUT:
          *static_cast<VkFormat*>(p->value_out) = swapchain_ci.imageFormat;
          break;
      }
    }
  }

  *return_graphics_context = context.release();
  return 0;
}

void dvrGraphicsContextDestroy(DvrGraphicsContext* graphics_context) {
  delete graphics_context;
}

// ANativeWindow function implementations. These should only be used
// by the Vulkan path.
int DvrGraphicsContext::Post(android::dvr::NativeBufferProducer* buffer,
                             int fence_fd) {
  LOG_ALWAYS_FATAL_IF(graphics_api != DVR_GRAPHICS_API_VULKAN);
  ATRACE_NAME(__PRETTY_FUNCTION__);
  ALOGI_IF(TRACE, "DvrGraphicsContext::Post: buffer_id=%d, fence_fd=%d",
           buffer->buffer()->id(), fence_fd);
  ALOGW_IF(!display_surface->visible(),
           "DvrGraphicsContext::Post: Posting buffer on invisible surface!!!");
  // The NativeBufferProducer closes the fence fd, so dup it for tracking in the
  // frame history.
  frame_history.OnFrameSubmit(LocalHandle::AsDuplicate(fence_fd));
  int result = buffer->Post(fence_fd, 0);
  return result;
}

int DvrGraphicsContext::SetSwapInterval(ANativeWindow* window, int interval) {
  ALOGI_IF(TRACE, "SetSwapInterval: window=%p interval=%d", window, interval);
  DvrGraphicsContext* self = getSelf(window);
  (void)self;
  LOG_ALWAYS_FATAL_IF(self->graphics_api != DVR_GRAPHICS_API_VULKAN);
  return android::NO_ERROR;
}

int DvrGraphicsContext::DequeueBuffer(ANativeWindow* window,
                                      ANativeWindowBuffer** buffer,
                                      int* fence_fd) {
  ATRACE_NAME(__PRETTY_FUNCTION__);

  DvrGraphicsContext* self = getSelf(window);
  LOG_ALWAYS_FATAL_IF(self->graphics_api != DVR_GRAPHICS_API_VULKAN);
  std::lock_guard<std::mutex> autolock(self->lock_);

  if (!self->current_buffer) {
    self->current_buffer = self->buffer_queue.get()->Dequeue();
  }
  ATRACE_ASYNC_BEGIN("BufferDraw", self->current_buffer->buffer()->id());
  *fence_fd = self->current_buffer->ClaimReleaseFence().Release();
  *buffer = self->current_buffer;

  ALOGI_IF(TRACE, "DvrGraphicsContext::DequeueBuffer: fence_fd=%d", *fence_fd);
  return android::NO_ERROR;
}

int DvrGraphicsContext::QueueBuffer(ANativeWindow* window,
                                    ANativeWindowBuffer* buffer, int fence_fd) {
  ATRACE_NAME("NativeWindow::QueueBuffer");
  ALOGI_IF(TRACE, "NativeWindow::QueueBuffer: fence_fd=%d", fence_fd);

  DvrGraphicsContext* self = getSelf(window);
  LOG_ALWAYS_FATAL_IF(self->graphics_api != DVR_GRAPHICS_API_VULKAN);
  std::lock_guard<std::mutex> autolock(self->lock_);

  android::dvr::NativeBufferProducer* native_buffer =
      static_cast<android::dvr::NativeBufferProducer*>(buffer);
  ATRACE_ASYNC_END("BufferDraw", native_buffer->buffer()->id());
  bool do_post = true;
  if (self->buffer_already_posted) {
    // Check that the buffer is the one we expect, but handle it if this happens
    // in production by allowing this buffer to post on top of the previous one.
    LOG_FATAL_IF(native_buffer != self->current_buffer);
    if (native_buffer == self->current_buffer) {
      do_post = false;
      if (fence_fd >= 0)
        close(fence_fd);
    }
  }
  if (do_post) {
    ATRACE_ASYNC_BEGIN("BufferPost", native_buffer->buffer()->id());
    self->Post(native_buffer, fence_fd);
  }
  self->buffer_already_posted = false;
  self->current_buffer = nullptr;

  return android::NO_ERROR;
}

int DvrGraphicsContext::CancelBuffer(ANativeWindow* window,
                                     ANativeWindowBuffer* buffer,
                                     int fence_fd) {
  ATRACE_NAME("DvrGraphicsContext::CancelBuffer");
  ALOGI_IF(TRACE, "DvrGraphicsContext::CancelBuffer: fence_fd: %d", fence_fd);

  DvrGraphicsContext* self = getSelf(window);
  LOG_ALWAYS_FATAL_IF(self->graphics_api != DVR_GRAPHICS_API_VULKAN);
  std::lock_guard<std::mutex> autolock(self->lock_);

  android::dvr::NativeBufferProducer* native_buffer =
      static_cast<android::dvr::NativeBufferProducer*>(buffer);
  ATRACE_ASYNC_END("BufferDraw", native_buffer->buffer()->id());
  ATRACE_INT("CancelBuffer", native_buffer->buffer()->id());
  bool do_enqueue = true;
  if (self->buffer_already_posted) {
    // Check that the buffer is the one we expect, but handle it if this happens
    // in production by returning this buffer to the buffer queue.
    LOG_FATAL_IF(native_buffer != self->current_buffer);
    if (native_buffer == self->current_buffer) {
      do_enqueue = false;
    }
  }
  if (do_enqueue) {
    self->buffer_queue.get()->Enqueue(native_buffer);
  }
  if (fence_fd >= 0)
    close(fence_fd);
  self->buffer_already_posted = false;
  self->current_buffer = nullptr;

  return android::NO_ERROR;
}

int DvrGraphicsContext::Query(const ANativeWindow* window, int what,
                              int* value) {
  DvrGraphicsContext* self = getSelf(const_cast<ANativeWindow*>(window));
  LOG_ALWAYS_FATAL_IF(self->graphics_api != DVR_GRAPHICS_API_VULKAN);
  std::lock_guard<std::mutex> autolock(self->lock_);

  switch (what) {
    case NATIVE_WINDOW_WIDTH:
      *value = self->display_surface->width();
      return android::NO_ERROR;
    case NATIVE_WINDOW_HEIGHT:
      *value = self->display_surface->height();
      return android::NO_ERROR;
    case NATIVE_WINDOW_FORMAT:
      *value = self->display_surface->format();
      return android::NO_ERROR;
    case NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS:
      *value = 1;
      return android::NO_ERROR;
    case NATIVE_WINDOW_CONCRETE_TYPE:
      *value = NATIVE_WINDOW_SURFACE;
      return android::NO_ERROR;
    case NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER:
      *value = 1;
      return android::NO_ERROR;
    case NATIVE_WINDOW_DEFAULT_WIDTH:
      *value = self->display_surface->width();
      return android::NO_ERROR;
    case NATIVE_WINDOW_DEFAULT_HEIGHT:
      *value = self->display_surface->height();
      return android::NO_ERROR;
    case NATIVE_WINDOW_TRANSFORM_HINT:
      *value = 0;
      return android::NO_ERROR;
  }

  *value = 0;
  return android::BAD_VALUE;
}

int DvrGraphicsContext::Perform(ANativeWindow* window, int operation, ...) {
  DvrGraphicsContext* self = getSelf(window);
  LOG_ALWAYS_FATAL_IF(self->graphics_api != DVR_GRAPHICS_API_VULKAN);
  std::lock_guard<std::mutex> autolock(self->lock_);

  va_list args;
  va_start(args, operation);

  // TODO(eieio): The following operations are not used at this time. They are
  // included here to help document which operations may be useful and what
  // parameters they take.
  switch (operation) {
    case NATIVE_WINDOW_SET_BUFFERS_DIMENSIONS: {
      int w = va_arg(args, int);
      int h = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_DIMENSIONS: w=%d h=%d", w, h);
      return android::NO_ERROR;
    }

    case NATIVE_WINDOW_SET_BUFFERS_FORMAT: {
      int format = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_FORMAT: format=%d", format);
      return android::NO_ERROR;
    }

    case NATIVE_WINDOW_SET_BUFFERS_TRANSFORM: {
      int transform = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_TRANSFORM: transform=%d",
               transform);
      return android::NO_ERROR;
    }

    case NATIVE_WINDOW_SET_USAGE: {
      int usage = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_USAGE: usage=%d", usage);
      return android::NO_ERROR;
    }

    case NATIVE_WINDOW_CONNECT:
    case NATIVE_WINDOW_DISCONNECT:
    case NATIVE_WINDOW_SET_BUFFERS_GEOMETRY:
    case NATIVE_WINDOW_API_CONNECT:
    case NATIVE_WINDOW_API_DISCONNECT:
      // TODO(eieio): we should implement these
      return android::NO_ERROR;

    case NATIVE_WINDOW_SET_BUFFER_COUNT: {
      int buffer_count = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFER_COUNT: bufferCount=%d",
               buffer_count);
      return android::NO_ERROR;
    }
    case NATIVE_WINDOW_SET_BUFFERS_DATASPACE: {
      android_dataspace_t data_space =
          static_cast<android_dataspace_t>(va_arg(args, int));
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_BUFFERS_DATASPACE: dataSpace=%d",
               data_space);
      return android::NO_ERROR;
    }
    case NATIVE_WINDOW_SET_SCALING_MODE: {
      int mode = va_arg(args, int);
      ALOGD_IF(TRACE, "NATIVE_WINDOW_SET_SCALING_MODE: mode=%d", mode);
      return android::NO_ERROR;
    }

    case NATIVE_WINDOW_LOCK:
    case NATIVE_WINDOW_UNLOCK_AND_POST:
    case NATIVE_WINDOW_SET_CROP:
    case NATIVE_WINDOW_SET_BUFFERS_TIMESTAMP:
      return android::INVALID_OPERATION;
  }

  return android::NAME_NOT_FOUND;
}

int DvrGraphicsContext::DequeueBuffer_DEPRECATED(ANativeWindow* window,
                                                 ANativeWindowBuffer** buffer) {
  int fence_fd = -1;
  int ret = DequeueBuffer(window, buffer, &fence_fd);

  // wait for fence
  if (ret == android::NO_ERROR && fence_fd != -1)
    close(fence_fd);

  return ret;
}

int DvrGraphicsContext::CancelBuffer_DEPRECATED(ANativeWindow* window,
                                                ANativeWindowBuffer* buffer) {
  return CancelBuffer(window, buffer, -1);
}

int DvrGraphicsContext::QueueBuffer_DEPRECATED(ANativeWindow* window,
                                               ANativeWindowBuffer* buffer) {
  return QueueBuffer(window, buffer, -1);
}

int DvrGraphicsContext::LockBuffer_DEPRECATED(ANativeWindow* /*window*/,
                                              ANativeWindowBuffer* /*buffer*/) {
  return android::NO_ERROR;
}
// End ANativeWindow implementation

int dvrSetEdsPose(DvrGraphicsContext* graphics_context,
                  float32x4_t render_pose_orientation,
                  float32x4_t render_pose_translation) {
  ATRACE_NAME("dvrSetEdsPose");
  if (!graphics_context->current_buffer) {
    ALOGE("dvrBeginRenderFrame must be called before dvrSetEdsPose");
    return -EPERM;
  }

  // When late-latching is enabled, the pose buffer is written by the GPU, so
  // we don't touch it here.
  float32x4_t is_late_latch = DVR_POSE_LATE_LATCH;
  if (render_pose_orientation[0] != is_late_latch[0]) {
    volatile android::dvr::DisplaySurfaceMetadata* data =
        graphics_context->surface_metadata;
    uint32_t buffer_index =
        graphics_context->current_buffer->surface_buffer_index();
    ALOGE_IF(TRACE, "write pose index %d %f %f", buffer_index,
             render_pose_orientation[0], render_pose_orientation[1]);
    data->orientation[buffer_index] = render_pose_orientation;
    data->translation[buffer_index] = render_pose_translation;
  }

  return 0;
}

int dvrBeginRenderFrameEds(DvrGraphicsContext* graphics_context,
                           float32x4_t render_pose_orientation,
                           float32x4_t render_pose_translation) {
  ATRACE_NAME("dvrBeginRenderFrameEds");
  LOG_ALWAYS_FATAL_IF(graphics_context->graphics_api != DVR_GRAPHICS_API_GLES);
  CHECK_GL();
  // Grab a buffer from the queue and set its pose.
  if (!graphics_context->current_buffer) {
    graphics_context->current_buffer =
        graphics_context->buffer_queue->Dequeue();
  }

  int ret = dvrSetEdsPose(graphics_context, render_pose_orientation,
                          render_pose_translation);
  if (ret < 0)
    return ret;

  ATRACE_ASYNC_BEGIN("BufferDraw",
                     graphics_context->current_buffer->buffer()->id());

  {
    ATRACE_NAME("glEGLImageTargetTexture2DOES");
    // Bind the texture to the latest buffer in the queue.
    for (int i = 0; i < graphics_context->gl.texture_count; ++i) {
      glBindTexture(graphics_context->gl.texture_target_type,
                    graphics_context->gl.texture_id[i]);
      glEGLImageTargetTexture2DOES(
          graphics_context->gl.texture_target_type,
          graphics_context->current_buffer->image_khr(i));
    }
    glBindTexture(graphics_context->gl.texture_target_type, 0);
  }
  CHECK_GL();
  return 0;
}
int dvrBeginRenderFrameEdsVk(DvrGraphicsContext* graphics_context,
                             float32x4_t render_pose_orientation,
                             float32x4_t render_pose_translation,
                             VkSemaphore acquire_semaphore,
                             VkFence acquire_fence,
                             uint32_t* swapchain_image_index,
                             VkImageView* swapchain_image_view) {
  ATRACE_NAME("dvrBeginRenderFrameEds");
  LOG_ALWAYS_FATAL_IF(graphics_context->graphics_api !=
                      DVR_GRAPHICS_API_VULKAN);

  // Acquire a swapchain image. This calls Dequeue() internally.
  VkResult result = vkAcquireNextImageKHR(
      graphics_context->vk.device, graphics_context->vk.swapchain, UINT64_MAX,
      acquire_semaphore, acquire_fence, swapchain_image_index);
  if (result != VK_SUCCESS)
    return -EINVAL;

  // Set the pose pose.
  int ret = dvrSetEdsPose(graphics_context, render_pose_orientation,
                          render_pose_translation);
  if (ret < 0)
    return ret;
  *swapchain_image_view =
      graphics_context->vk.swapchain_image_views[*swapchain_image_index];
  return 0;
}

int dvrBeginRenderFrame(DvrGraphicsContext* graphics_context) {
  return dvrBeginRenderFrameEds(graphics_context, DVR_POSE_NO_EDS,
                                DVR_POSE_NO_EDS);
}
int dvrBeginRenderFrameVk(DvrGraphicsContext* graphics_context,
                          VkSemaphore acquire_semaphore, VkFence acquire_fence,
                          uint32_t* swapchain_image_index,
                          VkImageView* swapchain_image_view) {
  return dvrBeginRenderFrameEdsVk(
      graphics_context, DVR_POSE_NO_EDS, DVR_POSE_NO_EDS, acquire_semaphore,
      acquire_fence, swapchain_image_index, swapchain_image_view);
}

int dvrBeginRenderFrameLateLatch(DvrGraphicsContext* graphics_context,
                                 uint32_t /*flags*/,
                                 uint32_t target_vsync_count, int num_views,
                                 const float** projection_matrices,
                                 const float** eye_from_head_matrices,
                                 const float** pose_offset_matrices,
                                 uint32_t* out_late_latch_buffer_id) {
  if (!graphics_context->late_latch) {
    return -EPERM;
  }
  if (num_views > DVR_GRAPHICS_SURFACE_MAX_VIEWS) {
    ALOGE("dvrBeginRenderFrameLateLatch called with too many views.");
    return -EINVAL;
  }
  dvrBeginRenderFrameEds(graphics_context, DVR_POSE_LATE_LATCH,
                         DVR_POSE_LATE_LATCH);
  auto& ll = graphics_context->late_latch;
  // TODO(jbates) Need to change this shader so that it dumps the single
  // captured pose for both eyes into the display surface metadata buffer at
  // the right index.
  android::dvr::LateLatchInput input;
  memset(&input, 0, sizeof(input));
  for (int i = 0; i < num_views; ++i) {
    memcpy(input.proj_mat + i, *(projection_matrices + i), 16 * sizeof(float));
    memcpy(input.eye_from_head_mat + i, *(eye_from_head_matrices + i),
           16 * sizeof(float));
    memcpy(input.pose_offset + i, *(pose_offset_matrices + i),
           16 * sizeof(float));
  }
  input.pose_index =
      target_vsync_count & android::dvr::kPoseAsyncBufferIndexMask;
  input.render_pose_index =
      graphics_context->current_buffer->surface_buffer_index();
  ll->AddLateLatch(input);
  *out_late_latch_buffer_id = ll->output_buffer_id();
  return 0;
}

extern "C" int dvrGraphicsWaitNextFrame(
    DvrGraphicsContext* graphics_context, int64_t start_delay_ns,
    DvrFrameSchedule* out_next_frame_schedule) {
  start_delay_ns = std::max(start_delay_ns, static_cast<int64_t>(0));

  // We only do one-shot timers:
  int64_t wake_time_ns = 0;

  uint32_t current_frame_vsync;
  int64_t current_frame_scheduled_finish_ns;
  int64_t vsync_period_ns;

  int fetch_schedule_result = graphics_context->vsync_client->GetSchedInfo(
      &vsync_period_ns, &current_frame_scheduled_finish_ns,
      &current_frame_vsync);
  if (fetch_schedule_result == 0) {
    wake_time_ns = current_frame_scheduled_finish_ns + start_delay_ns;
    // If the last wakeup time is still in the future, use it instead to avoid
    // major schedule jumps when applications call WaitNextFrame with
    // aggressive offsets.
    int64_t now = android::dvr::GetSystemClockNs();
    if (android::dvr::TimestampGT(wake_time_ns - vsync_period_ns, now)) {
      wake_time_ns -= vsync_period_ns;
      --current_frame_vsync;
    }
    // If the next wakeup time is in the past, add a vsync period to keep the
    // application on schedule.
    if (android::dvr::TimestampLT(wake_time_ns, now)) {
      wake_time_ns += vsync_period_ns;
      ++current_frame_vsync;
    }
  } else {
    ALOGE("Error getting frame schedule because: %s",
          strerror(-fetch_schedule_result));
    // Sleep for a vsync period to avoid cascading failure.
    wake_time_ns = android::dvr::GetSystemClockNs() +
                   graphics_context->display_metrics.vsync_period_ns;
  }

  // Adjust nsec to [0..999,999,999].
  struct itimerspec wake_time;
  wake_time.it_interval.tv_sec = 0;
  wake_time.it_interval.tv_nsec = 0;
  wake_time.it_value = android::dvr::NsToTimespec(wake_time_ns);
  bool sleep_result =
      timerfd_settime(graphics_context->timerfd.Get(), TFD_TIMER_ABSTIME,
                      &wake_time, nullptr) == 0;
  if (sleep_result) {
    ATRACE_NAME("sleep");
    uint64_t expirations = 0;
    sleep_result = read(graphics_context->timerfd.Get(), &expirations,
                        sizeof(uint64_t)) == sizeof(uint64_t);
    if (!sleep_result) {
      ALOGE("Error: timerfd read failed");
    }
  } else {
    ALOGE("Error: timerfd_settime failed because: %s", strerror(errno));
  }

  auto& frame_history = graphics_context->frame_history;
  frame_history.CheckForFinishedFrames();
  if (fetch_schedule_result == 0) {
    uint32_t next_frame_vsync =
        current_frame_vsync +
        frame_history.PredictNextFrameVsyncInterval(vsync_period_ns);
    int64_t next_frame_scheduled_finish =
        (wake_time_ns - start_delay_ns) + vsync_period_ns;
    frame_history.OnFrameStart(next_frame_vsync, next_frame_scheduled_finish);
    if (out_next_frame_schedule) {
      out_next_frame_schedule->vsync_count = next_frame_vsync;
      out_next_frame_schedule->scheduled_frame_finish_ns =
          next_frame_scheduled_finish;
    }
  } else {
    frame_history.OnFrameStart(UINT32_MAX, -1);
  }

  return (fetch_schedule_result == 0 && sleep_result) ? 0 : -1;
}

extern "C" void dvrGraphicsPostEarly(DvrGraphicsContext* graphics_context) {
  ATRACE_NAME("dvrGraphicsPostEarly");
  ALOGI_IF(TRACE, "dvrGraphicsPostEarly");

  LOG_ALWAYS_FATAL_IF(graphics_context->graphics_api != DVR_GRAPHICS_API_GLES);

  // Note that this function can be called before or after
  // dvrBeginRenderFrame.
  if (!graphics_context->buffer_already_posted) {
    graphics_context->buffer_already_posted = true;

    if (!graphics_context->current_buffer) {
      graphics_context->current_buffer =
          graphics_context->buffer_queue->Dequeue();
    }

    auto buffer = graphics_context->current_buffer->buffer().get();
    ATRACE_ASYNC_BEGIN("BufferPost", buffer->id());
    int result = buffer->Post<uint64_t>(LocalHandle(), 0);
    if (result < 0)
      ALOGE("Buffer post failed: %d (%s)", result, strerror(-result));
  }
}

int dvrPresent(DvrGraphicsContext* graphics_context) {
  LOG_ALWAYS_FATAL_IF(graphics_context->graphics_api != DVR_GRAPHICS_API_GLES);

  std::array<char, 128> buf;
  snprintf(buf.data(), buf.size(), "dvrPresent|vsync=%d|",
           graphics_context->frame_history.GetCurrentFrameVsync());
  ATRACE_NAME(buf.data());

  if (!graphics_context->current_buffer) {
    ALOGE("Error: dvrPresent called without dvrBeginRenderFrame");
    return -EPERM;
  }

  LocalHandle fence_fd =
      android::dvr::CreateGLSyncAndFlush(graphics_context->gl.egl_display);

  ALOGI_IF(TRACE, "PostBuffer: buffer_id=%d, fence_fd=%d",
           graphics_context->current_buffer->buffer()->id(), fence_fd.Get());
  ALOGW_IF(!graphics_context->display_surface->visible(),
           "PostBuffer: Posting buffer on invisible surface!!!");

  auto buffer = graphics_context->current_buffer->buffer().get();
  ATRACE_ASYNC_END("BufferDraw", buffer->id());
  if (!graphics_context->buffer_already_posted) {
    ATRACE_ASYNC_BEGIN("BufferPost", buffer->id());
    int result = buffer->Post<uint64_t>(fence_fd, 0);
    if (result < 0)
      ALOGE("Buffer post failed: %d (%s)", result, strerror(-result));
  }

  graphics_context->frame_history.OnFrameSubmit(std::move(fence_fd));
  graphics_context->buffer_already_posted = false;
  graphics_context->current_buffer = nullptr;
  return 0;
}

int dvrPresentVk(DvrGraphicsContext* graphics_context,
                 VkSemaphore submit_semaphore, uint32_t swapchain_image_index) {
  LOG_ALWAYS_FATAL_IF(graphics_context->graphics_api !=
                      DVR_GRAPHICS_API_VULKAN);

  std::array<char, 128> buf;
  snprintf(buf.data(), buf.size(), "dvrPresent|vsync=%d|",
           graphics_context->frame_history.GetCurrentFrameVsync());
  ATRACE_NAME(buf.data());

  if (!graphics_context->current_buffer) {
    ALOGE("Error: dvrPresentVk called without dvrBeginRenderFrameVk");
    return -EPERM;
  }

  // Present the specified image. Internally, this gets a fence from the
  // Vulkan driver and passes it to DvrGraphicsContext::Post(),
  // which in turn passes it to buffer->Post() and adds it to frame_history.
  VkPresentInfoKHR present_info = {};
  present_info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
  present_info.swapchainCount = 1;
  present_info.pSwapchains = &graphics_context->vk.swapchain;
  present_info.pImageIndices = &swapchain_image_index;
  present_info.waitSemaphoreCount =
      (submit_semaphore != VK_NULL_HANDLE) ? 1 : 0;
  present_info.pWaitSemaphores = &submit_semaphore;
  VkResult result =
      vkQueuePresentKHR(graphics_context->vk.present_queue, &present_info);
  if (result != VK_SUCCESS) {
    return -EINVAL;
  }

  return 0;
}

extern "C" int dvrGetFrameScheduleResults(DvrGraphicsContext* context,
                                          DvrFrameScheduleResult* results,
                                          int in_result_count) {
  if (!context || !results)
    return -EINVAL;

  return context->frame_history.GetPreviousFrameResults(results,
                                                        in_result_count);
}

extern "C" void dvrGraphicsSurfaceSetVisible(
    DvrGraphicsContext* graphics_context, int visible) {
  graphics_context->display_surface->SetVisible(visible);
}

extern "C" int dvrGraphicsSurfaceGetVisible(
    DvrGraphicsContext* graphics_context) {
  return graphics_context->display_surface->visible() ? 1 : 0;
}

extern "C" void dvrGraphicsSurfaceSetZOrder(
    DvrGraphicsContext* graphics_context, int z_order) {
  graphics_context->display_surface->SetZOrder(z_order);
}

extern "C" int dvrGraphicsSurfaceGetZOrder(
    DvrGraphicsContext* graphics_context) {
  return graphics_context->display_surface->z_order();
}

extern "C" DvrVideoMeshSurface* dvrGraphicsVideoMeshSurfaceCreate(
    DvrGraphicsContext* graphics_context) {
  auto display_surface = graphics_context->display_surface;
  // A DisplaySurface must be created prior to the creation of a
  // VideoMeshSurface.
  LOG_ALWAYS_FATAL_IF(display_surface == nullptr);

  LocalChannelHandle surface_handle = display_surface->CreateVideoMeshSurface();
  if (!surface_handle.valid()) {
    return nullptr;
  }

  std::unique_ptr<DvrVideoMeshSurface> surface(new DvrVideoMeshSurface);
  surface->client =
      android::dvr::VideoMeshSurfaceClient::Import(std::move(surface_handle));

  // TODO(jwcai) The next line is not needed...
  auto producer_queue = surface->client->GetProducerQueue();
  return surface.release();
}

extern "C" void dvrGraphicsVideoMeshSurfaceDestroy(
    DvrVideoMeshSurface* surface) {
  delete surface;
}

extern "C" void dvrGraphicsVideoMeshSurfacePresent(
    DvrGraphicsContext* graphics_context, DvrVideoMeshSurface* surface,
    const int eye, const float* transform) {
  volatile android::dvr::VideoMeshSurfaceMetadata* metadata =
      surface->client->GetMetadataBufferPtr();

  const uint32_t graphics_buffer_index =
      graphics_context->current_buffer->surface_buffer_index();

  for (int i = 0; i < 4; ++i) {
    metadata->transform[graphics_buffer_index][eye].val[i] = {
        transform[i + 0], transform[i + 4], transform[i + 8], transform[i + 12],
    };
  }
}
