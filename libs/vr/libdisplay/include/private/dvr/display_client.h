#ifndef ANDROID_DVR_DISPLAY_CLIENT_H_
#define ANDROID_DVR_DISPLAY_CLIENT_H_

#include <hardware/hwcomposer.h>
#include <pdx/client.h>
#include <pdx/file_handle.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/buffer_hub_queue_client.h>
#include <private/dvr/display_rpc.h>

namespace android {
namespace dvr {

struct LateLatchOutput;

// Abstract base class for all surface types maintained in DVR's display
// service.
// TODO(jwcai) Explain more, surface is a channel...
class SurfaceClient : public pdx::Client {
 public:
  using LocalChannelHandle = pdx::LocalChannelHandle;
  SurfaceType type() const { return type_; }

  // Get the shared memory metadata buffer fd for this display surface. If it is
  // not yet allocated, this will allocate it.
  int GetMetadataBufferFd(pdx::LocalHandle* out_fd);

  // Allocate the single metadata buffer for providing metadata associated with
  // posted buffers for this surface. This can be used to provide rendered poses
  // for EDS, for example. The buffer format is defined by the struct
  // DisplaySurfaceMetadata.
  // The first call to this method will allocate the buffer in via IPC to the
  // display surface.
  std::shared_ptr<BufferProducer> GetMetadataBuffer();

 protected:
  SurfaceClient(LocalChannelHandle channel_handle, SurfaceType type);
  SurfaceClient(const std::string& endpoint_path, SurfaceType type);

 private:
  SurfaceType type_;
  std::shared_ptr<BufferProducer> metadata_buffer_;
};

// DisplaySurfaceClient represents the client interface to a displayd display
// surface.
class DisplaySurfaceClient
    : public pdx::ClientBase<DisplaySurfaceClient, SurfaceClient> {
 public:
  using LocalHandle = pdx::LocalHandle;

  int width() const { return width_; }
  int height() const { return height_; }
  int format() const { return format_; }
  int usage() const { return usage_; }
  int flags() const { return flags_; }
  int z_order() const { return z_order_; }
  bool visible() const { return visible_; }

  void SetVisible(bool visible);
  void SetZOrder(int z_order);
  void SetExcludeFromBlur(bool exclude_from_blur);
  void SetBlurBehind(bool blur_behind);
  void SetAttributes(const DisplaySurfaceAttributes& attributes);

  // Get the producer end of the buffer queue that transports graphics buffer
  // from the application side to the compositor side.
  std::shared_ptr<ProducerQueue> GetProducerQueue();

  // Get the shared memory metadata buffer for this display surface. If it is
  // not yet allocated, this will allocate it.
  volatile DisplaySurfaceMetadata* GetMetadataBufferPtr();

  // Create a VideoMeshSurface that is attached to the display sruface.
  LocalChannelHandle CreateVideoMeshSurface();

 private:
  friend BASE;

  DisplaySurfaceClient(int width, int height, int format, int usage, int flags);

  int width_;
  int height_;
  int format_;
  int usage_;
  int flags_;
  int z_order_;
  bool visible_;
  bool exclude_from_blur_;
  bool blur_behind_;
  DisplaySurfaceMetadata* mapped_metadata_buffer_;

  // TODO(jwcai) Add support for multiple queues.
  std::shared_ptr<ProducerQueue> producer_queue_;

  DisplaySurfaceClient(const DisplaySurfaceClient&) = delete;
  void operator=(const DisplaySurfaceClient&) = delete;
};

class DisplayClient : public pdx::ClientBase<DisplayClient> {
 public:
  int GetDisplayMetrics(SystemDisplayMetrics* metrics);
  pdx::Status<void> SetViewerParams(const ViewerParams& viewer_params);

  // Pull the latest eds pose data from the display service renderer
  int GetLastFrameEdsTransform(LateLatchOutput* ll_out);

  std::unique_ptr<DisplaySurfaceClient> CreateDisplaySurface(
      int width, int height, int format, int usage, int flags);

  std::unique_ptr<IonBuffer> GetNamedBuffer(const std::string& name);

  // Temporary query for current VR status. Will be removed later.
  bool IsVrAppRunning();

 private:
  friend BASE;

  explicit DisplayClient(int* error = nullptr);

  DisplayClient(const DisplayClient&) = delete;
  void operator=(const DisplayClient&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DISPLAY_CLIENT_H_
