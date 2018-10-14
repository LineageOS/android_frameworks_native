#ifndef ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_
#define ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_

#include <private/dvr/ion_buffer.h>
#include <ui/BufferHubMetadata.h>

namespace android {
namespace dvr {

class BufferNode {
 public:
  // Creates a BufferNode from existing IonBuffers, i.e. creating from an
  // existing ProducerChannel.
  BufferNode(IonBuffer buffer, size_t user_metadata_size);

  // Allocates a new BufferNode.
  BufferNode(uint32_t width, uint32_t height, uint32_t layer_count,
             uint32_t format, uint64_t usage, size_t user_metadata_size);

  // Returns whether the object holds a valid graphic buffer.
  bool IsValid() const { return buffer_.IsValid() && metadata_.IsValid(); }

  size_t user_metadata_size() const { return metadata_.user_metadata_size(); }
  uint64_t active_buffer_bit_mask() const { return active_buffer_bit_mask_; }
  void set_buffer_state_bit(uint64_t buffer_state_bit) {
    active_buffer_bit_mask_ |= buffer_state_bit;
  }

  // Accessor of the IonBuffer.
  IonBuffer& buffer() { return buffer_; }
  const IonBuffer& buffer() const { return buffer_; }

  // Accessor of the metadata.
  const BufferHubMetadata& metadata() const { return metadata_; }

 private:
  // Gralloc buffer handles.
  IonBuffer buffer_;
  BufferHubMetadata metadata_;

  // All active buffer bits. Valid bits are the lower 63 bits, while the
  // highest bit is reserved for the exclusive writing and should not be set.
  uint64_t active_buffer_bit_mask_ = 0ULL;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_
