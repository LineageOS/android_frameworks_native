#ifndef ANDROID_FRAMEWORKS_BUFFERHUB_V1_0_BUFFER_NODE_H_
#define ANDROID_FRAMEWORKS_BUFFERHUB_V1_0_BUFFER_NODE_H_

#include <android/hardware_buffer.h>
#include <ui/BufferHubMetadata.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

class BufferNode {
public:
    // Allocates a new BufferNode.
    BufferNode(uint32_t width, uint32_t height, uint32_t layer_count, uint32_t format,
               uint64_t usage, size_t user_metadata_size);

    ~BufferNode();

    // Returns whether the object holds a valid metadata.
    bool IsValid() const { return metadata_.IsValid(); }

    size_t user_metadata_size() const { return metadata_.user_metadata_size(); }

    // Accessors of the buffer description and handle
    const native_handle_t* buffer_handle() const { return buffer_handle_; }
    const AHardwareBuffer_Desc& buffer_desc() const { return buffer_desc_; }

    // Accessors of metadata.
    const BufferHubMetadata& metadata() const { return metadata_; }

    // Gets the current value of active_clients_bit_mask in metadata_ with
    // std::memory_order_acquire, so that all previous releases of
    // active_clients_bit_mask from all threads will be returned here.
    uint64_t GetActiveClientsBitMask() const;

    // Find and add a new client_state_mask to active_clients_bit_mask in
    // metadata_.
    // Return the new client_state_mask that is added to active_clients_bit_mask.
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
    native_handle_t* buffer_handle_;
    AHardwareBuffer_Desc buffer_desc_;

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
    // union of all client_state_mask of all bp clients.
    std::atomic<uint64_t>* active_clients_bit_mask_ = nullptr;
};

} // namespace implementation
} // namespace V1_0
} // namespace bufferhub
} // namespace frameworks
} // namespace android

#endif // ANDROID_FRAMEWORKS_BUFFERHUB_V1_0_BUFFER_NODE_H_
