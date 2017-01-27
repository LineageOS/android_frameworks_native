#include <cutils/log.h>
#include <jni.h>

#include <memory>

#include "render_thread.h"

#define JNI_METHOD(return_type, method_name) \
  JNIEXPORT return_type JNICALL              \
      Java_com_google_vr_windowmanager_VrWindowManagerService_##method_name

namespace {

inline jlong jptr(android::dvr::RenderThread* native_vr_window_manager) {
  return reinterpret_cast<intptr_t>(native_vr_window_manager);
}

inline android::dvr::RenderThread* native(jlong ptr) {
  return reinterpret_cast<android::dvr::RenderThread*>(ptr);
}

}  // namespace

extern "C" {

JNI_METHOD(jlong, nativeCreate)(JNIEnv* env, jclass /*clazz*/,
                                jobject class_loader,
                                jobject android_context) {
  return jptr(new android::dvr::RenderThread(
      env, class_loader, android_context));
}

JNI_METHOD(void, nativeDestroy)
(JNIEnv* /*env*/, jclass /*clazz*/, jlong native_render_thread) {
  delete native(native_render_thread);
}

JNI_METHOD(void, nativeEnableDebug)
(JNIEnv* /*env*/, jclass /*clazz*/, jlong native_render_thread) {
  native(native_render_thread)->EnableDebug(true);
}

JNI_METHOD(void, nativeDisableDebug)
(JNIEnv* /*env*/, jclass /*clazz*/, jlong native_render_thread) {
  native(native_render_thread)->EnableDebug(false);
}

JNI_METHOD(void, nativeEnterVrMode)
(JNIEnv* /*env*/, jclass /*clazz*/, jlong native_render_thread) {
  native(native_render_thread)->VrMode(true);
}

JNI_METHOD(void, nativeExitVrMode)
(JNIEnv* /*env*/, jclass /*clazz*/, jlong native_render_thread) {
  native(native_render_thread)->VrMode(false);
}

}  // extern "C"
