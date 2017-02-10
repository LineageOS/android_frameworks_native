#ifndef VR_WINDOW_MANAGER_APPLICATION_H_
#define VR_WINDOW_MANAGER_APPLICATION_H_

#include <memory>
#include <private/dvr/types.h>
#include <stdint.h>

#include <chrono>
#include <mutex>
#include <vector>

#include "controller_data_provider.h"
#include "elbow_model.h"

struct DvrGraphicsContext;
struct DvrPose;

namespace android {
namespace dvr {

class Application {
 public:
  Application();
  virtual ~Application();

  virtual int Initialize();

  virtual int AllocateResources();
  virtual void DeallocateResources();

  void DrawFrame();

  void SetControllerDataProvider(ControllerDataProvider* provider) {
    controller_data_provider_ = provider;
  }

 protected:
  enum class MainThreadTask {
    EnteringVrMode,
    ExitingVrMode,
    EnableDebugMode,
    DisableDebugMode,
    Show,
  };

  virtual void OnDrawFrame() = 0;
  virtual void DrawEye(EyeType eye, const mat4& perspective,
                       const mat4& eye_matrix, const mat4& head_matrix) = 0;

  void SetVisibility(bool visible);
  virtual void OnVisibilityChanged(bool visible);

  void ProcessControllerInput();

  void ProcessTasks(const std::vector<MainThreadTask>& tasks);

  void QueueTask(MainThreadTask task);

  DvrGraphicsContext* graphics_context_ = nullptr;
  DvrPose* pose_client_ = nullptr;

  Range2i eye_viewport_[2];
  mat4 eye_from_head_[2];
  FieldOfView fov_[2];
  Posef last_pose_;

  quat controller_orientation_;
  bool shmem_controller_active_ = false;
  uint64_t shmem_controller_buttons_;

  bool is_visible_ = false;
  std::chrono::time_point<std::chrono::system_clock> visibility_button_press_;
  bool debug_mode_ = false;

  std::chrono::time_point<std::chrono::system_clock> last_frame_time_;
  vec3 controller_position_;
  ElbowModel elbow_model_;

  float fade_value_ = 0;

  std::mutex mutex_;
  std::condition_variable wake_up_init_and_render_;
  bool initialized_ = false;
  std::vector<MainThreadTask> main_thread_tasks_;

  // Controller data provider from shared memory buffer.
  ControllerDataProvider* controller_data_provider_ = nullptr;

  Application(const Application&) = delete;
  void operator=(const Application&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_APPLICATION_H_
