// This file has a big hack, it "mocks" the actual IonBuffer by redefining
// it with mock methods and using the same header guard to prevent the original
// definition from being included in the same context.
#ifndef LIB_LIBBUFFERHUB_PRIVATE_DVR_ION_BUFFER_H_  // NOLINT
#define LIB_LIBBUFFERHUB_PRIVATE_DVR_ION_BUFFER_H_
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <hardware/gralloc.h>

namespace android {
namespace dvr {

// IonBuffer is an abstraction of Ion/Gralloc buffers.
class IonBufferMock {
 public:
  IonBufferMock() {}
  MOCK_METHOD0(GetGrallocModuleImpl, gralloc_module_t const*());
  MOCK_METHOD6(Import, int(buffer_handle_t handle, int width, int height,
                           int layer_count, int stride, int format, int usage));
  MOCK_METHOD9(Import,
               int(const int* fd_array, int fd_count, const int* int_array,
                   int int_count, int width, int height, int layer_count,
                   int stride, int format, int usage));
  MOCK_METHOD6(Lock, int(int usage, int x, int y, int width, int height,
                         void** address));
  MOCK_METHOD0(Unlock, int());
  MOCK_CONST_METHOD0(handle, buffer_handle_t());
  MOCK_CONST_METHOD0(width, int());
  MOCK_CONST_METHOD0(height, int());
  MOCK_CONST_METHOD0(layer_count, int());
  MOCK_CONST_METHOD0(stride, int());
  MOCK_CONST_METHOD0(format, int());
  MOCK_CONST_METHOD0(usage, int());
};

// IonBuffer is an abstraction of Ion/Gralloc buffers.
class IonBuffer {
 public:
  IonBuffer() : mock_(new IonBufferMock) {
    if (initializer) {
      initializer(mock_.get());
    }
  }
  IonBuffer(IonBuffer&& other) = default;
  static gralloc_module_t const* GetGrallocModule() {
    return staticObject->GetGrallocModuleImpl();
  }
  int Import(buffer_handle_t handle, int width, int height, int layer_count,
             int stride, int format, int usage) {
    return mock_->Import(handle, width, height, layer_count, stride, format,
                         usage);
  }
  int Import(const int* fd_array, int fd_count, const int* int_array,
             int int_count, int width, int height, int layer_count, int stride,
             int format, int usage) {
    return mock_->Import(fd_array, fd_count, int_array, int_count, width,
                         height, layer_count, stride, format, usage);
  }
  int Lock(int usage, int x, int y, int width, int height, void** address) {
    return mock_->Lock(usage, x, y, width, height, address);
  }
  int Unlock() { return mock_->Unlock(); }
  buffer_handle_t handle() const { return mock_->handle(); }
  int width() const { return mock_->width(); }
  int height() const { return mock_->height(); }
  int layer_count() const { return mock_->layer_count(); }
  int stride() const { return mock_->stride(); }
  int format() const { return mock_->format(); }
  int usage() const { return mock_->usage(); }
  std::unique_ptr<IonBufferMock> mock_;
  static IonBufferMock* staticObject;
  static void (*initializer)(IonBufferMock* target);
};

}  // namespace dvr
}  // namespace android
#endif  // LIB_LIBBUFFERHUB_PRIVATE_DVR_ION_BUFFER_H_ - NOLINT
