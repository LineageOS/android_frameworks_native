#ifndef ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_
#define ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_

#include <private/dvr/ion_buffer.h>

namespace android {
namespace dvr {

class BufferNode {
 public:
  // Creates a BufferNode from existing IonBuffers, i.e. creating from an
  // existing ProducerChannel.
  BufferNode(IonBuffer buffer, IonBuffer metadata_buffer,
             size_t user_metadata_size);

  // Allocates a new BufferNode.
  BufferNode(uint32_t width, uint32_t height, uint32_t layer_count,
             uint32_t format, uint64_t usage, size_t user_metadata_size);

  // Returns whether the object holds a valid graphic buffer.
  bool IsValid() const {
    return buffer_.IsValid() && metadata_buffer_.IsValid();
  }

  size_t user_metadata_size() const { return user_metadata_size_; }
  uint64_t active_buffer_bit_mask() const { return active_buffer_bit_mask_; }
  void set_buffer_state_bit(uint64_t buffer_state_bit) {
    active_buffer_bit_mask_ |= buffer_state_bit;
  }

  // Used to take out IonBuffers.
  IonBuffer& buffer() { return buffer_; }
  IonBuffer& metadata_buffer() { return metadata_buffer_; }

  // Used to access IonBuffers.
  const IonBuffer& buffer() const { return buffer_; }
  const IonBuffer& metadata_buffer() const { return metadata_buffer_; }

 private:
  // Gralloc buffer handles.
  IonBuffer buffer_;
  IonBuffer metadata_buffer_;

  // Size of user requested metadata.
  const size_t user_metadata_size_;

  // All active buffer bits. Valid bits are the lower 63 bits, while the
  // highest bit is reserved for the exclusive writing and should not be set.
  uint64_t active_buffer_bit_mask_ = 0ULL;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_
