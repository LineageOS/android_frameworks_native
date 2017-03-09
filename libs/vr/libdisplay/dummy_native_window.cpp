#include "include/private/dvr/dummy_native_window.h"

#include <utils/Errors.h>

namespace {
// Dummy functions required for an ANativeWindow Implementation.
int F1(struct ANativeWindow*, int) { return 0; }
int F2(struct ANativeWindow*, struct ANativeWindowBuffer**) { return 0; }
int F3(struct ANativeWindow*, struct ANativeWindowBuffer*) { return 0; }
int F4(struct ANativeWindow*, struct ANativeWindowBuffer**, int*) { return 0; }
int F5(struct ANativeWindow*, struct ANativeWindowBuffer*, int) { return 0; }
}  // anonymous namespace

namespace android {
namespace dvr {

DummyNativeWindow::DummyNativeWindow() {
  ANativeWindow::setSwapInterval = F1;
  ANativeWindow::dequeueBuffer = F4;
  ANativeWindow::cancelBuffer = F5;
  ANativeWindow::queueBuffer = F5;
  ANativeWindow::query = Query;
  ANativeWindow::perform = Perform;

  ANativeWindow::dequeueBuffer_DEPRECATED = F2;
  ANativeWindow::cancelBuffer_DEPRECATED = F3;
  ANativeWindow::lockBuffer_DEPRECATED = F3;
  ANativeWindow::queueBuffer_DEPRECATED = F3;
}

int DummyNativeWindow::Query(const ANativeWindow*, int what, int* value) {
  switch (what) {
    // This must be 1 in order for eglCreateWindowSurface to not trigger an
    // error
    case NATIVE_WINDOW_IS_VALID:
      *value = 1;
      return NO_ERROR;
    case NATIVE_WINDOW_WIDTH:
    case NATIVE_WINDOW_HEIGHT:
    case NATIVE_WINDOW_FORMAT:
    case NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS:
    case NATIVE_WINDOW_CONCRETE_TYPE:
    case NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER:
    case NATIVE_WINDOW_DEFAULT_WIDTH:
    case NATIVE_WINDOW_DEFAULT_HEIGHT:
    case NATIVE_WINDOW_TRANSFORM_HINT:
      *value = 0;
      return NO_ERROR;
  }

  *value = 0;
  return BAD_VALUE;
}

int DummyNativeWindow::Perform(ANativeWindow*, int operation, ...) {
  switch (operation) {
    case NATIVE_WINDOW_SET_BUFFERS_DIMENSIONS:
    case NATIVE_WINDOW_SET_BUFFERS_FORMAT:
    case NATIVE_WINDOW_SET_BUFFERS_TRANSFORM:
    case NATIVE_WINDOW_SET_USAGE:
    case NATIVE_WINDOW_CONNECT:
    case NATIVE_WINDOW_DISCONNECT:
    case NATIVE_WINDOW_SET_BUFFERS_GEOMETRY:
    case NATIVE_WINDOW_API_CONNECT:
    case NATIVE_WINDOW_API_DISCONNECT:
    case NATIVE_WINDOW_SET_BUFFER_COUNT:
    case NATIVE_WINDOW_SET_BUFFERS_DATASPACE:
    case NATIVE_WINDOW_SET_SCALING_MODE:
      return NO_ERROR;
    case NATIVE_WINDOW_LOCK:
    case NATIVE_WINDOW_UNLOCK_AND_POST:
    case NATIVE_WINDOW_SET_CROP:
    case NATIVE_WINDOW_SET_BUFFERS_TIMESTAMP:
      return INVALID_OPERATION;
  }
  return NAME_NOT_FOUND;
}

}  // namespace dvr
}  // namespace android
