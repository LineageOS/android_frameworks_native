#ifndef ANDROID_DVR_DUMMY_NATIVE_WINDOW_H_
#define ANDROID_DVR_DUMMY_NATIVE_WINDOW_H_

#include <android/native_window.h>
#include <ui/ANativeObjectBase.h>

namespace android {
namespace dvr {

// DummyNativeWindow is an implementation of ANativeWindow that is
// essentially empty and is used as a surface placeholder during context
// creation for contexts that we don't intend to call eglSwapBuffers on.
class DummyNativeWindow
    : public ANativeObjectBase<ANativeWindow, DummyNativeWindow,
                               LightRefBase<DummyNativeWindow> > {
 public:
  DummyNativeWindow();

 private:
  static int Query(const ANativeWindow* window, int what, int* value);
  static int Perform(ANativeWindow* window, int operation, ...);

  DummyNativeWindow(const DummyNativeWindow&) = delete;
  void operator=(DummyNativeWindow&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DUMMY_NATIVE_WINDOW_H_
