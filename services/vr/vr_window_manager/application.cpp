#include "application.h"

#include <binder/IServiceManager.h>
#include <cutils/log.h>
#include <dvr/graphics.h>
#include <dvr/performance_client_api.h>
#include <dvr/pose_client.h>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <gui/ISurfaceComposer.h>
#include <hardware/hwcomposer_defs.h>
#include <private/dvr/graphics/vr_gl_extensions.h>

#include <vector>

namespace android {
namespace dvr {

Application::Application()
    : controller_api_status_logged_(false),
      controller_connection_state_logged_(false) {}

Application::~Application() {
}

int Application::Initialize(JNIEnv* env, jobject app_context,
                            jobject class_loader) {
  dvrSetCpuPartition(0, "/application/performance");

  bool is_right_handed = true;  // TODO: retrieve setting from system
  elbow_model_.Enable(ElbowModel::kDefaultNeckPosition, is_right_handed);
  last_frame_time_ = std::chrono::system_clock::now();

  java_env_ = env;
  app_context_ = app_context;
  class_loader_ = class_loader;

  return 0;
}

int Application::AllocateResources() {
  int surface_width = 0, surface_height = 0;
  DvrLensInfo lens_info = {};
  GLuint texture_id = 0;
  GLenum texture_target = 0;
  std::vector<DvrSurfaceParameter> surface_params = {
    DVR_SURFACE_PARAMETER_OUT(SURFACE_WIDTH, &surface_width),
    DVR_SURFACE_PARAMETER_OUT(SURFACE_HEIGHT, &surface_height),
    DVR_SURFACE_PARAMETER_OUT(INTER_LENS_METERS, &lens_info.inter_lens_meters),
    DVR_SURFACE_PARAMETER_OUT(LEFT_FOV_LRBT, &lens_info.left_fov),
    DVR_SURFACE_PARAMETER_OUT(RIGHT_FOV_LRBT, &lens_info.right_fov),
    DVR_SURFACE_PARAMETER_OUT(SURFACE_TEXTURE_TARGET_TYPE, &texture_target),
    DVR_SURFACE_PARAMETER_OUT(SURFACE_TEXTURE_TARGET_ID, &texture_id),
    DVR_SURFACE_PARAMETER_IN(VISIBLE, 0),
    DVR_SURFACE_PARAMETER_IN(Z_ORDER, 1),
    DVR_SURFACE_PARAMETER_IN(GEOMETRY, DVR_SURFACE_GEOMETRY_SINGLE),
    DVR_SURFACE_PARAMETER_IN(ENABLE_LATE_LATCH, 0),
    DVR_SURFACE_PARAMETER_IN(DISABLE_DISTORTION, 0),
    DVR_SURFACE_PARAMETER_LIST_END,
  };

  int ret = dvrGraphicsContextCreate(surface_params.data(), &graphics_context_);
  if (ret)
    return ret;

  GLuint fbo = 0;
  GLuint depth_stencil_buffer = 0;
  GLuint samples = 1;
  glGenFramebuffers(1, &fbo);
  glBindFramebuffer(GL_FRAMEBUFFER, fbo);
  glFramebufferTexture2DMultisampleEXT(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                       texture_target, texture_id, 0, samples);

  glGenRenderbuffers(1, &depth_stencil_buffer);
  glBindRenderbuffer(GL_RENDERBUFFER, depth_stencil_buffer);
  glRenderbufferStorageMultisample(GL_RENDERBUFFER, samples,
                                   GL_DEPTH_COMPONENT24, surface_width,
                                   surface_height);

  glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT,
                            GL_RENDERBUFFER, depth_stencil_buffer);

  ALOGI("Surface size=%dx%d", surface_width, surface_height);
  pose_client_ = dvrPoseCreate();
  if (!pose_client_)
    return 1;

  vec2i eye_size(surface_width / 2, surface_height);

  eye_viewport_[0] = Range2i::FromSize(vec2i(0, 0), eye_size);
  eye_viewport_[1] = Range2i::FromSize(vec2i(surface_width / 2, 0), eye_size);

  eye_from_head_[0] = Eigen::Translation3f(
      vec3(lens_info.inter_lens_meters * 0.5f, 0.0f, 0.0f));
  eye_from_head_[1] = Eigen::Translation3f(
      vec3(-lens_info.inter_lens_meters * 0.5f, 0.0f, 0.0f));

  fov_[0] = FieldOfView(lens_info.left_fov[0], lens_info.left_fov[1],
                        lens_info.left_fov[2], lens_info.left_fov[3]);
  fov_[1] = FieldOfView(lens_info.right_fov[0], lens_info.right_fov[1],
                        lens_info.right_fov[2], lens_info.right_fov[3]);

  gvr_context_ = gvr::GvrApi::Create(java_env_, app_context_, class_loader_);
  if (gvr_context_ == nullptr) {
    ALOGE("Gvr context creation failed");
    return 1;
  }

  int32_t options = gvr_controller_get_default_options();
  options |= GVR_CONTROLLER_ENABLE_GYRO | GVR_CONTROLLER_ENABLE_ACCEL;

  controller_.reset(new gvr::ControllerApi);
  if (!controller_->Init(java_env_, app_context_, class_loader_, options,
                         gvr_context_->cobj())) {
    ALOGE("Gvr controller init failed");
    return 1;
  }

  controller_state_.reset(new gvr::ControllerState);

  return 0;
}

void Application::DeallocateResources() {
  gvr_context_.reset();
  controller_.reset();
  controller_state_.reset();

  if (graphics_context_)
    dvrGraphicsContextDestroy(graphics_context_);

  if (pose_client_)
    dvrPoseDestroy(pose_client_);

  initialized_ = false;
}

void Application::ProcessTasks(const std::vector<MainThreadTask>& tasks) {
  for (auto task : tasks) {
    switch (task) {
      case MainThreadTask::EnableDebugMode:
        if (!debug_mode_) {
          debug_mode_ = true;
          SetVisibility(debug_mode_);
        }
        break;
      case MainThreadTask::DisableDebugMode:
        if (debug_mode_) {
          debug_mode_ = false;
          SetVisibility(debug_mode_);
        }
        break;
      case MainThreadTask::EnteringVrMode:
        if (!initialized_)
          AllocateResources();
        break;
      case MainThreadTask::ExitingVrMode:
        if (initialized_)
          DeallocateResources();
        break;
      case MainThreadTask::Show:
        if (!is_visible_)
          SetVisibility(true);
        break;
    }
  }
}

void Application::DrawFrame() {
  // Thread should block if we are invisible or not fully initialized.
  std::unique_lock<std::mutex> lock(mutex_);
  wake_up_init_and_render_.wait(lock, [this]() {
    return is_visible_ && initialized_ || !main_thread_tasks_.empty();
  });

  // Process main thread tasks if there are any.
  std::vector<MainThreadTask> tasks;
  tasks.swap(main_thread_tasks_);
  lock.unlock();

  if (!tasks.empty())
    ProcessTasks(tasks);

  if (!initialized_)
    return;

  // TODO(steventhomas): If we're not visible, block until we are. For now we
  // throttle by calling dvrGraphicsWaitNextFrame.
  DvrFrameSchedule schedule;
  dvrGraphicsWaitNextFrame(graphics_context_, 0, &schedule);

  OnDrawFrame();

  if (is_visible_) {
    ProcessControllerInput();

    DvrPoseAsync pose;
    dvrPoseGet(pose_client_, schedule.vsync_count, &pose);
    last_pose_ = Posef(
        quat(pose.orientation[3], pose.orientation[0], pose.orientation[1],
             pose.orientation[2]),
        vec3(pose.translation[0], pose.translation[1], pose.translation[2]));

    std::chrono::time_point<std::chrono::system_clock> now =
        std::chrono::system_clock::now();
    double delta =
        std::chrono::duration<double>(now - last_frame_time_).count();
    last_frame_time_ = now;

    if (delta > 1.0f)
      delta = 0.05f;

    fade_value_ += delta / 0.25f;
    if (fade_value_ > 1.0f)
      fade_value_ = 1.0f;

    quat controller_quat(controller_orientation_.qw, controller_orientation_.qx,
        controller_orientation_.qy, controller_orientation_.qz);
    controller_position_ = elbow_model_.Update(
        delta, last_pose_.GetRotation(), controller_quat, false);

    dvrBeginRenderFrameEds(graphics_context_, pose.orientation,
                           pose.translation);

    glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    mat4 head_matrix = last_pose_.GetObjectFromReferenceMatrix();
    glViewport(eye_viewport_[kLeftEye].GetMinPoint()[0],
               eye_viewport_[kLeftEye].GetMinPoint()[1],
               eye_viewport_[kLeftEye].GetSize()[0],
               eye_viewport_[kLeftEye].GetSize()[1]);
    DrawEye(kLeftEye, fov_[kLeftEye].GetProjectionMatrix(0.1f, 500.0f),
            eye_from_head_[kLeftEye], head_matrix);

    glViewport(eye_viewport_[kRightEye].GetMinPoint()[0],
               eye_viewport_[kRightEye].GetMinPoint()[1],
               eye_viewport_[kRightEye].GetSize()[0],
               eye_viewport_[kRightEye].GetSize()[1]);
    DrawEye(kRightEye, fov_[kRightEye].GetProjectionMatrix(0.1f, 500.0f),
            eye_from_head_[kRightEye], head_matrix);

    dvrPresent(graphics_context_);
  }
}

void Application::ProcessControllerInput() {
  controller_state_->Update(*controller_);
  gvr::ControllerApiStatus new_api_status = controller_state_->GetApiStatus();
  gvr::ControllerConnectionState new_connection_state =
      controller_state_->GetConnectionState();

  if (!controller_api_status_logged_) {
    controller_api_status_logged_ = true;
    ALOGI("Controller api status: %s",
          gvr::ControllerApi::ToString(new_api_status));
  } else if (new_api_status != controller_api_status_) {
    ALOGI("Controller api status changed: %s --> %s",
          gvr::ControllerApi::ToString(controller_api_status_),
          gvr::ControllerApi::ToString(new_api_status));
  }

  if (new_api_status == gvr::kControllerApiOk) {
    if (!controller_connection_state_logged_) {
      controller_connection_state_logged_ = true;
      ALOGI("Controller connection state: %s",
            gvr::ControllerApi::ToString(new_connection_state));
    } else if (new_connection_state != controller_connection_state_) {
      ALOGI("Controller connection state changed: %s --> %s",
            gvr::ControllerApi::ToString(controller_connection_state_),
            gvr::ControllerApi::ToString(new_connection_state));
    }
  } else {
    controller_connection_state_logged_ = false;
  }

  if (new_api_status == gvr::kControllerApiOk)
    controller_orientation_ = controller_state_->GetOrientation();

  controller_api_status_ = new_api_status;
  controller_connection_state_ = new_connection_state;
}

void Application::SetVisibility(bool visible) {
  bool changed = is_visible_ != visible;
  if (changed) {
    is_visible_ = visible;
    dvrGraphicsSurfaceSetVisible(graphics_context_, is_visible_);
    if (is_visible_)
      controller_->Resume();
    else
      controller_->Pause();
    OnVisibilityChanged(is_visible_);
  }
}

void Application::OnVisibilityChanged(bool visible) {
  if (visible) {
    fade_value_ = 0;
    // We have been sleeping so to ensure correct deltas, reset the time.
    last_frame_time_ = std::chrono::system_clock::now();
  }
}

void Application::QueueTask(MainThreadTask task) {
  std::unique_lock<std::mutex> lock(mutex_);
  main_thread_tasks_.push_back(task);
  wake_up_init_and_render_.notify_one();
}

}  // namespace dvr
}  // namespace android
