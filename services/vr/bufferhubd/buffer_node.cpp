#include "buffer_node.h"

#include <private/dvr/buffer_hub_defs.h>

namespace android {
namespace dvr {

BufferNode::BufferNode(IonBuffer buffer, IonBuffer metadata_buffer,
                       size_t user_metadata_size)
    : buffer_(std::move(buffer)),
      metadata_buffer_(std::move(metadata_buffer)),
      user_metadata_size_(user_metadata_size) {}

// Allocates a new BufferNode.
BufferNode::BufferNode(uint32_t width, uint32_t height, uint32_t layer_count,
                       uint32_t format, uint64_t usage,
                       size_t user_metadata_size)
    : user_metadata_size_(user_metadata_size) {
  // The size the of metadata buffer is used as the "width" parameter during
  // allocation. Thus it cannot overflow uint32_t.
  if (user_metadata_size_ >= (std::numeric_limits<uint32_t>::max() -
                              BufferHubDefs::kMetadataHeaderSize)) {
    ALOGE(
        "DetachedBufferChannel::DetachedBufferChannel: metadata size too big.");
    return;
  }

  if (int ret = buffer_.Alloc(width, height, layer_count, format, usage)) {
    ALOGE(
        "DetachedBufferChannel::DetachedBufferChannel: Failed to allocate "
        "buffer: %s",
        strerror(-ret));
    return;
  }

  // Buffer metadata has two parts: 1) a fixed sized metadata header; and 2)
  // user requested metadata.
  const size_t size = BufferHubDefs::kMetadataHeaderSize + user_metadata_size_;
  if (int ret = metadata_buffer_.Alloc(size,
                                       /*height=*/1,
                                       /*layer_count=*/1,
                                       BufferHubDefs::kMetadataFormat,
                                       BufferHubDefs::kMetadataUsage)) {
    ALOGE(
        "DetachedBufferChannel::DetachedBufferChannel: Failed to allocate "
        "metadata: %s",
        strerror(-ret));
    return;
  }
}

}  // namespace dvr
}  // namespace android
