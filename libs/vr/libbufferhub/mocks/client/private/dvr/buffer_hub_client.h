#ifndef LIB_LIBBUFFERHUB_PRIVATE_DVR_BUFFER_HUB_CLIENT_H_  // NOLINT
#define LIB_LIBBUFFERHUB_PRIVATE_DVR_BUFFER_HUB_CLIENT_H_
#include <gmock/gmock.h>
#include <gtest/gtest.h>

// TODO(jwcai) mock not need for now
class native_handle_t;

namespace android {
namespace dvr {

// TODO(jwcai) mock not need for now
class IonBuffer;

class BufferHubBuffer {
 public:
  MOCK_METHOD1(Poll, int(int timeout_ms));
  MOCK_METHOD6(Lock, bool(int usage, int x, int y, int width, int height,
                          void** addr));
  MOCK_METHOD0(Unlock, int());

  MOCK_METHOD0(native_handle, native_handle_t*());
  MOCK_METHOD0(buffer, IonBuffer*());
  MOCK_METHOD0(event_fd, int());

  MOCK_METHOD0(id, int());
  MOCK_METHOD0(width, int());
  MOCK_METHOD0(height, int());
  MOCK_METHOD0(stride, int());
  MOCK_METHOD0(format, int());
  MOCK_METHOD0(usage, int());
};

class BufferProducer : public BufferHubBuffer {
 public:
  // Note that static method |CreateBuffer| and |Import| are not mocked
  // here, they are just implementation details and thus not needed.
  MOCK_METHOD2(Post, int(int ready_fence, uint64_t sequence));
  MOCK_METHOD1(Gain, int(int* release_fence));

  static BufferProducer* staticObject;
};

class BufferConsumer : public BufferHubBuffer {
 public:
  MOCK_METHOD2(Acquire, int(int* ready_fence, uint64_t* sequence));
  MOCK_METHOD1(Release, int(int release_fence));
  MOCK_METHOD0(Discard, int());
  MOCK_METHOD3(DoAcquire,
               int(int* ready_fence, void* meta, size_t meta_size_bytes));

  static BufferConsumer* staticObject;
};

}  // namespace dvr
}  // namespace android
#endif  // LIB_LIBBUFFERHUB_PRIVATE_DVR_BUFFER_HUB_CLIENT_H_  //NOLINT
