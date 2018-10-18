#ifndef ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_
#define ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_

#include <private/dvr/ion_buffer.h>
#include <ui/BufferHubMetadata.h>

namespace android {
namespace dvr {

class BufferNode {
 public:
  // Creates a BufferNode from existing IonBuffers, i.e. creating from an
  // existing ProducerChannel. Allocate a new BufferHubMetadata.
  BufferNode(IonBuffer buffer, size_t user_metadata_size);

  // Allocates a new BufferNode.
  BufferNode(uint32_t width, uint32_t height, uint32_t layer_count,
             uint32_t format, uint64_t usage, size_t user_metadata_size);

  // Returns whether the object holds a valid graphic buffer.
  bool IsValid() const { return buffer_.IsValid() && metadata_.IsValid(); }

  size_t user_metadata_size() const { return metadata_.user_metadata_size(); }

  // Accessors of the IonBuffer.
  IonBuffer& buffer() { return buffer_; }
  const IonBuffer& buffer() const { return buffer_; }

  // Accessors of metadata.
  const BufferHubMetadata& metadata() const { return metadata_; }

  // Gets the current value of active_clients_bit_mask in metadata_ with
  // std::memory_order_acquire, so that all previous releases of
  // active_clients_bit_mask from all threads will be returned here.
  uint64_t GetActiveClientsBitMask() const;

  // Find and add a new buffer_state_bit to active_clients_bit_mask in
  // metadata_.
  // Return the new buffer_state_bit that is added to active_clients_bit_mask.
  // Return 0ULL if there are already 32 bp clients of the buffer.
  uint64_t AddNewActiveClientsBitToMask();

  // Removes the value from active_clients_bit_mask in metadata_ with
  // std::memory_order_release, so that the change will be visible to any
  // acquire of active_clients_bit_mask_ in any threads after the succeed of
  // this operation.
  void RemoveClientsBitFromMask(const uint64_t& value);

 private:
  // Helper method for constructors to initialize atomic metadata header
  // variables in shared memory.
  void InitializeMetadata();

  // Gralloc buffer handles.
  IonBuffer buffer_;

  // Metadata in shared memory.
  BufferHubMetadata metadata_;

  // The following variables are atomic variables in metadata_ that are visible
  // to Bn object and Bp objects. Please find more info in
  // BufferHubDefs::MetadataHeader.

  // buffer_state_ tracks the state of the buffer. Buffer can be in one of these
  // four states: gained, posted, acquired, released.
  std::atomic<uint64_t>* buffer_state_ = nullptr;

  // TODO(b/112012161): add comments to fence_state_.
  std::atomic<uint64_t>* fence_state_ = nullptr;

  // active_clients_bit_mask_ tracks all the bp clients of the buffer. It is the
  // union of all buffer_state_bit of all bp clients.
  std::atomic<uint64_t>* active_clients_bit_mask_ = nullptr;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFERHUBD_BUFFER_NODE_H_
