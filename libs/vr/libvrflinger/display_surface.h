#ifndef ANDROID_DVR_SERVICES_DISPLAYD_DISPLAY_SURFACE_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_DISPLAY_SURFACE_H_

#include <pdx/file_handle.h>
#include <pdx/service.h>
#include <private/dvr/display_rpc.h>
#include <private/dvr/ring_buffer.h>

#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "acquired_buffer.h"
#include "surface_channel.h"
#include "video_mesh_surface.h"

namespace android {
namespace dvr {

class DisplayService;

// DisplaySurface is the service-side notion of a client display context. It is
// responsible for managing display buffer format, geometry, and state, and
// maintains the buffer consumers connected to the client.
class DisplaySurface : public SurfaceChannel {
 public:
  DisplaySurface(DisplayService* service, int surface_id, int process_id,
                 int width, int height, int format, int usage, int flags);
  ~DisplaySurface() override;

  int process_id() const { return process_id_; }
  int width() const { return width_; }
  int height() const { return height_; }
  int format() const { return format_; }
  int usage() const { return usage_; }
  int flags() const { return flags_; }

  bool client_visible() const { return client_visible_; }
  int client_z_order() const { return client_z_order_; }
  bool client_exclude_from_blur() const { return client_exclude_from_blur_; }
  bool client_blur_behind() const { return client_blur_behind_; }

  bool manager_visible() const { return manager_visible_; }
  int manager_z_order() const { return manager_z_order_; }
  float manager_blur() const { return manager_blur_; }

  bool video_mesh_surfaces_updated() const {
    return video_mesh_surfaces_updated_;
  }

  volatile const DisplaySurfaceMetadata* GetMetadataBufferPtr() {
    if (EnsureMetadataBuffer()) {
      void* addr = nullptr;
      metadata_buffer_->GetBlobReadWritePointer(metadata_size(), &addr);
      return static_cast<const volatile DisplaySurfaceMetadata*>(addr);
    } else {
      return nullptr;
    }
  }

  uint32_t GetRenderBufferIndex(int buffer_id) {
    return buffer_id_to_index_[buffer_id];
  }

  bool IsBufferAvailable();
  bool IsBufferPosted();
  AcquiredBuffer AcquireCurrentBuffer();

  // Get the newest buffer. Up to one buffer will be skipped. If a buffer is
  // skipped, it will be stored in skipped_buffer if non null.
  AcquiredBuffer AcquireNewestAvailableBuffer(AcquiredBuffer* skipped_buffer);

  // Display manager interface to control visibility and z order.
  void ManagerSetVisible(bool visible);
  void ManagerSetZOrder(int z_order);
  void ManagerSetBlur(float blur);

  // A surface must be set visible by both the client and the display manager to
  // be visible on screen.
  bool IsVisible() const { return client_visible_ && manager_visible_; }

  // A surface is blurred if the display manager requests it.
  bool IsBlurred() const { return manager_blur_ > 0.0f; }

  // Set by HardwareComposer to the current logical layer order of this surface.
  void SetLayerOrder(int layer_order) { layer_order_ = layer_order; }
  // Gets the unique z-order index of this surface among other visible surfaces.
  // This is not the same as the hardware layer index, as not all display
  // surfaces map directly to hardware layers. Lower layer orders should be
  // composited underneath higher layer orders.
  int layer_order() const { return layer_order_; }

  // Lock all video mesh surfaces so that VideoMeshCompositor can access them.
  std::vector<std::shared_ptr<VideoMeshSurface>> GetVideoMeshSurfaces();

 private:
  friend class DisplayService;

  // The capacity of the pending buffer queue. Should be enough to hold all the
  // buffers of this DisplaySurface, although in practice only 1 or 2 frames
  // will be pending at a time.
  static constexpr int kMaxPostedBuffers =
      kSurfaceBufferMaxCount * kSurfaceViewMaxCount;

  // Returns whether a frame is available without locking the mutex.
  bool IsFrameAvailableNoLock() const;

  // Dispatches display surface messages to the appropriate handlers. This
  // handler runs on the displayd message dispatch thread.
  int HandleMessage(pdx::Message& message) override;

  // Sets display surface's client-controlled attributes.
  int OnClientSetAttributes(pdx::Message& message,
                            const DisplaySurfaceAttributes& attributes);

  // Creates a BufferHubQueue associated with this surface and returns the PDX
  // handle of its producer side to the client.
  pdx::LocalChannelHandle OnCreateBufferQueue(pdx::Message& message);

  // Creates a video mesh surface associated with this surface and returns its
  // PDX handle to the client.
  pdx::RemoteChannelHandle OnCreateVideoMeshSurface(pdx::Message& message);

  // Client interface (called through IPC) to set visibility and z order.
  void ClientSetVisible(bool visible);
  void ClientSetZOrder(int z_order);
  void ClientSetExcludeFromBlur(bool exclude_from_blur);
  void ClientSetBlurBehind(bool blur_behind);

  // Dequeue all available buffers from the consumer queue.
  void DequeueBuffersLocked();

  DisplaySurface(const DisplaySurface&) = delete;
  void operator=(const DisplaySurface&) = delete;

  int process_id_;

  // Synchronizes access to mutable state below between message dispatch thread,
  // epoll event thread, and frame post thread.
  mutable std::mutex lock_;

  // The consumer end of a BufferHubQueue. VrFlinger allocates and controls the
  // buffer queue and pass producer end to the app and the consumer end to
  // compositor.
  // TODO(jwcai) Add support for multiple buffer queues per display surface.
  std::shared_ptr<ConsumerQueue> consumer_queue_;

  // In a triple-buffered surface, up to kMaxPostedBuffers buffers may be
  // posted and pending.
  RingBuffer<AcquiredBuffer> acquired_buffers_;

  // Provides access to VideoMeshSurface. Here we don't want to increase
  // the reference count immediately on allocation, will leave it into
  // compositor's hand.
  std::vector<std::weak_ptr<VideoMeshSurface>> pending_video_mesh_surfaces_;
  volatile bool video_mesh_surfaces_updated_;

  // Surface parameters.
  int width_;
  int height_;
  int format_;
  int usage_;
  int flags_;
  bool client_visible_;
  int client_z_order_;
  bool client_exclude_from_blur_;
  bool client_blur_behind_;
  bool manager_visible_;
  int manager_z_order_;
  float manager_blur_;
  int layer_order_;

  // Maps from the buffer id to the corresponding allocated buffer index.
  std::unordered_map<int, uint32_t> buffer_id_to_index_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_DISPLAY_SURFACE_H_
