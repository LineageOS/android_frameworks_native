#include <private/dvr/dummy_native_window.h>
#include <gtest/gtest.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2.h>

class DummyNativeWindowTests : public ::testing::Test {
 public:
  EGLDisplay display_;
  bool initialized_;

  DummyNativeWindowTests()
      : display_(nullptr)
      , initialized_(false)
  {
  }

  virtual void SetUp() {
    display_ = eglGetDisplay(EGL_DEFAULT_DISPLAY);

    ASSERT_NE(nullptr, display_);
    initialized_ = eglInitialize(display_, nullptr, nullptr);

    ASSERT_TRUE(initialized_);
  }

  virtual void TearDown() {
    if (display_ && initialized_) {
      eglTerminate(display_);
    }
  }
};

// Test that eglCreateWindowSurface works with DummyNativeWindow
TEST_F(DummyNativeWindowTests, TryCreateEglWindow) {
  EGLint attribs[] = {
      EGL_NONE,
  };

  EGLint num_configs;
  EGLConfig config;
  ASSERT_TRUE(eglChooseConfig(display_, attribs, &config, 1, &num_configs));

  std::unique_ptr<android::dvr::DummyNativeWindow> dummy_window(
      new android::dvr::DummyNativeWindow());

  EGLint context_attribs[] = {
    EGL_NONE,
  };

  EGLSurface surface = eglCreateWindowSurface(display_, config,
                                              dummy_window.get(),
                                              context_attribs);

  EXPECT_NE(nullptr, surface);

  bool destroyed = eglDestroySurface(display_, surface);

  EXPECT_TRUE(destroyed);
}

