#include <jni.h>
#include <log/log.h>
#include <future>

#include "render_thread.h"
#include "shell_view.h"

namespace android {
namespace dvr {

RenderThread::RenderThread(JNIEnv* env, jobject class_loader,
                           jobject android_context)
    : jvm_(nullptr),
      class_loader_global_ref_(0),
      android_context_global_ref_(0),
      quit_(false) {
  env->GetJavaVM(&jvm_);

  // Create global references so we can access these objects on the render
  // thread
  class_loader_global_ref_ = env->NewGlobalRef(class_loader);
  android_context_global_ref_ = env->NewGlobalRef(android_context);

  std::promise<int> render_thread_init_result_promise;
  thread_ = std::thread([this, &render_thread_init_result_promise] {
    JNIEnv* render_thread_jni_env = nullptr;
    jvm_->AttachCurrentThread(&render_thread_jni_env, nullptr);
    RunRenderLoop(&render_thread_init_result_promise);
    jvm_->DetachCurrentThread();
  });

  // Wait to see if the render thread started successfully. If not bail.
  int render_thread_init_result =
      render_thread_init_result_promise.get_future().get();
  LOG_ALWAYS_FATAL_IF(render_thread_init_result != 0,
                      "Failed initializing render thread. result=%d",
                      render_thread_init_result);
}

RenderThread::~RenderThread() { Quit(); }

void RenderThread::Quit() {
  if (thread_.joinable()) {
    quit_ = true;
    thread_.join();
  }

  JNIEnv* env = GetJniEnv();
  if (class_loader_global_ref_ != 0) {
    env->DeleteGlobalRef(class_loader_global_ref_);
    class_loader_global_ref_ = 0;
  }
  if (android_context_global_ref_ != 0) {
    env->DeleteGlobalRef(android_context_global_ref_);
    android_context_global_ref_ = 0;
  }
}

void RenderThread::EnableDebug(bool debug) { shell_view_.EnableDebug(debug); }

void RenderThread::VrMode(bool mode) { shell_view_.VrMode(mode); }

JNIEnv* RenderThread::GetJniEnv() {
  JNIEnv* env;
  jvm_->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
  return env;
}

void RenderThread::RunRenderLoop(
    std::promise<int>* init_result_promise) {
  // TODO(steventhomas): Create local refs to work around b/33251144. Remove
  // once that bug is fixed.
  JNIEnv* env = GetJniEnv();
  jobject class_loader = env->NewLocalRef(class_loader_global_ref_);
  jobject android_context = env->NewLocalRef(android_context_global_ref_);

  int init_result = shell_view_.Initialize(env, android_context, class_loader);
  init_result_promise->set_value(init_result);
  if (init_result == 0) {
    while (!quit_)
      shell_view_.DrawFrame();
  } else {
    ALOGE("Failed to initialize ShellView");
  }

  env->DeleteLocalRef(class_loader);
  env->DeleteLocalRef(android_context);
}

}  // namespace dvr
}  // namespace android
