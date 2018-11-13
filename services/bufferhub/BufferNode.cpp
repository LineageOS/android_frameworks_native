#include <errno.h>

#include <bufferhub/BufferNode.h>
#include <private/dvr/buffer_hub_defs.h>
#include <ui/GraphicBufferAllocator.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

void BufferNode::InitializeMetadata() {
    // Using placement new here to reuse shared memory instead of new allocation
    // Initialize the atomic variables to zero.
    dvr::BufferHubDefs::MetadataHeader* metadata_header = metadata_.metadata_header();
    buffer_state_ = new (&metadata_header->buffer_state) std::atomic<uint64_t>(0);
    fence_state_ = new (&metadata_header->fence_state) std::atomic<uint64_t>(0);
    active_clients_bit_mask_ =
            new (&metadata_header->active_clients_bit_mask) std::atomic<uint64_t>(0);
}

// Allocates a new BufferNode.
BufferNode::BufferNode(uint32_t width, uint32_t height, uint32_t layer_count, uint32_t format,
                       uint64_t usage, size_t user_metadata_size) {
    uint32_t out_stride = 0;
    // graphicBufferId is not used in GraphicBufferAllocator::allocate
    // TODO(b/112338294) After move to the service folder, stop using the
    // hardcoded service name "bufferhub".
    int ret = GraphicBufferAllocator::get().allocate(width, height, format, layer_count, usage,
                                                     const_cast<const native_handle_t**>(
                                                             &buffer_handle_),
                                                     &out_stride,
                                                     /*graphicBufferId=*/0,
                                                     /*requestor=*/"bufferhub");

    if (ret != OK || buffer_handle_ == nullptr) {
        ALOGE("%s: Failed to allocate buffer: %s", __FUNCTION__, strerror(-ret));
        return;
    }

    buffer_desc_.width = width;
    buffer_desc_.height = height;
    buffer_desc_.layers = layer_count;
    buffer_desc_.format = format;
    buffer_desc_.usage = usage;
    buffer_desc_.stride = out_stride;

    metadata_ = BufferHubMetadata::Create(user_metadata_size);
    if (!metadata_.IsValid()) {
        ALOGE("%s: Failed to allocate metadata.", __FUNCTION__);
        return;
    }
    InitializeMetadata();
}

// Free the handle
BufferNode::~BufferNode() {
    if (buffer_handle_ != nullptr) {
        status_t ret = GraphicBufferAllocator::get().free(buffer_handle_);
        if (ret != OK) {
            ALOGE("%s: Failed to free handle; Got error: %d", __FUNCTION__, ret);
        }
    }
}

uint64_t BufferNode::GetActiveClientsBitMask() const {
    return active_clients_bit_mask_->load(std::memory_order_acquire);
}

uint64_t BufferNode::AddNewActiveClientsBitToMask() {
    uint64_t current_active_clients_bit_mask = GetActiveClientsBitMask();
    uint64_t client_state_mask = 0ULL;
    uint64_t updated_active_clients_bit_mask = 0ULL;
    do {
        client_state_mask = dvr::BufferHubDefs::FindNextAvailableClientStateMask(
                current_active_clients_bit_mask);
        if (client_state_mask == 0ULL) {
            ALOGE("%s: reached the maximum number of channels per buffer node: 32.", __FUNCTION__);
            errno = E2BIG;
            return 0ULL;
        }
        updated_active_clients_bit_mask = current_active_clients_bit_mask | client_state_mask;
    } while (!(active_clients_bit_mask_->compare_exchange_weak(current_active_clients_bit_mask,
                                                               updated_active_clients_bit_mask,
                                                               std::memory_order_acq_rel,
                                                               std::memory_order_acquire)));
    return client_state_mask;
}

void BufferNode::RemoveClientsBitFromMask(const uint64_t& value) {
    active_clients_bit_mask_->fetch_and(~value);
}

} // namespace implementation
} // namespace V1_0
} // namespace bufferhub
} // namespace frameworks
} // namespace android
