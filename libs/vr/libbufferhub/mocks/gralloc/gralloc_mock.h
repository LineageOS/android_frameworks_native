#ifndef LIB_LIBBUFFERHUB_MOCKS_GRALLOC_GRALLOC_MOCK_H_
#define LIB_LIBBUFFERHUB_MOCKS_GRALLOC_GRALLOC_MOCK_H_
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hardware/gralloc.h>

// IonBuffer is an abstraction of Ion/Gralloc buffers.
class GrallocMock {
 public:
  // Add methods here.
  MOCK_METHOD1(native_handle_close, int(const native_handle_t*));
  MOCK_METHOD1(native_handle_delete, int(native_handle_t*));
  MOCK_METHOD2(native_handle_create, native_handle_t*(int, int));
  MOCK_METHOD1(registerBuffer, int(buffer_handle_t));
  MOCK_METHOD1(unregisterBuffer, int(buffer_handle_t));
  MOCK_METHOD7(lock, int(buffer_handle_t, int, int, int, int, int, void**));
  MOCK_METHOD1(unlock, int(buffer_handle_t));
  MOCK_METHOD6(alloc, int(int, int, int, int, buffer_handle_t*, int*));
  MOCK_METHOD1(free, int(buffer_handle_t));
  static GrallocMock* staticObject;
};

#endif  // LIB_LIBBUFFERHUB_MOCKS_GRALLOC_GRALLOC_MOCK_H_
