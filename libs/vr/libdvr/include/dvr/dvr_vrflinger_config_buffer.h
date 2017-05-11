#ifndef ANDROID_DVR_VRFLINGER_CONFIG_BUFFER_H
#define ANDROID_DVR_VRFLINGER_CONFIG_BUFFER_H

#include <libbroadcastring/broadcast_ring.h>

// This header is shared by VrCore and Android and must be kept in sync.

namespace android {
namespace dvr {

// Increment when the layout for the buffers change.
constexpr uint32_t kSharedConfigBufferLayoutVersion = 1;

// This is a shared memory buffer for passing config data from VrCore to
// libvrflinger in SurfaceFlinger.
struct DvrVrFlingerConfigBuffer {
  // Offset before vsync to submit frames to hardware composer.
  int frame_post_offset_ns{4000000};

  // If the number of pending fences goes over this count at the point when we
  // are about to submit a new frame to HWC, we will drop the frame. This
  // should be a signal that the display driver has begun queuing frames. Note
  // that with smart displays (with RAM), the fence is signaled earlier than
  // the next vsync, at the point when the DMA to the display completes.
  // Currently we use a smart display and the EDS timing coincides with zero
  // pending fences, so this is 0.
  size_t allowed_pending_fence_count{0};

  // New fields should always be added to the end for backwards compat.
};

class DvrVrFlingerConfigBufferTraits {
 public:
  using Record = DvrVrFlingerConfigBuffer;
  static constexpr bool kUseStaticRecordSize = false;
  static constexpr uint32_t kStaticRecordCount = 2;
  static constexpr int kMaxReservedRecords = 1;
  static constexpr int kMinAvailableRecords = 1;
};

// The broadcast ring classes that will expose the data.
using DvrVrFlingerConfigRing =
    BroadcastRing<DvrVrFlingerConfigBuffer, DvrVrFlingerConfigBufferTraits>;

// Common buffers.
constexpr int kVrFlingerConfigBufferKey = 5;

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_VRFLINGER_CONFIG_BUFFER_H
