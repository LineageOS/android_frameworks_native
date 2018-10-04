#include <private/dvr/buffer_hub_defs.h>
#include <private/dvr/buffer_node.h>

namespace android {
namespace dvr {

BufferNode::BufferNode(IonBuffer buffer, size_t user_metadata_size)
    : buffer_(std::move(buffer)) {
  metadata_ = BufferHubMetadata::Create(user_metadata_size);
}

// Allocates a new BufferNode.
BufferNode::BufferNode(uint32_t width, uint32_t height, uint32_t layer_count,
                       uint32_t format, uint64_t usage,
                       size_t user_metadata_size) {
  if (int ret = buffer_.Alloc(width, height, layer_count, format, usage)) {
    ALOGE(
        "DetachedBufferChannel::DetachedBufferChannel: Failed to allocate "
        "buffer: %s",
        strerror(-ret));
    return;
  }

  metadata_ = BufferHubMetadata::Create(user_metadata_size);
}

}  // namespace dvr
}  // namespace android
