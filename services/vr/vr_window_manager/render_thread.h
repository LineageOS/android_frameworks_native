#ifndef VR_WINDOW_MANAGER_RENDER_THREAD_H_
#define VR_WINDOW_MANAGER_RENDER_THREAD_H_

#include <atomic>
#include <future>
#include <jni.h>
#include <thread>

#include "shell_view.h"

namespace android {
namespace dvr {

class RenderThread {
 public:
  RenderThread(JNIEnv* env, jobject class_loader, jobject android_context);
  ~RenderThread();
  void Quit();
  void EnableDebug(bool debug);
  void VrMode(bool mode);

  RenderThread(const RenderThread&) = delete;
  void operator=(const RenderThread&) = delete;

 private:
  // Called by both the main thread and render thread. Will return the correct
  // JNIEnv for the current thread.
  JNIEnv* GetJniEnv();

  void RunRenderLoop(std::promise<int>* init_result_promise);

  // Accessed only by the main thread.
  std::thread thread_;

  // The vars below are accessed by both the main thread and the render thread.
  JavaVM* jvm_;
  jobject class_loader_global_ref_;
  jobject android_context_global_ref_;
  std::atomic_bool quit_;

  ShellView shell_view_;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_RENDER_THREAD_H_
