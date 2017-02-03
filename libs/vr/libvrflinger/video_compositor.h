#ifndef ANDROID_DVR_SERVICES_DISPLAYD_VIDEO_COMPOSITOR_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_VIDEO_COMPOSITOR_H_

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <private/dvr/buffer_hub_queue_core.h>
#include <private/dvr/types.h>

#include <vector>

#include "display_surface.h"
#include "video_mesh_surface.h"

namespace android {
namespace dvr {

using pdx::LocalHandle;

// Manages video buffer consumers, texture mapping, and playback timing.
class VideoCompositor {
 public:
  VideoCompositor(
      const std::shared_ptr<VideoMeshSurface>& surface,
      const volatile DisplaySurfaceMetadata* display_surface_metadata);

  int surface_id() const { return surface_ ? surface_->surface_id() : -1; }

  // Returns a GL texture id that should be composited by displayd during the
  // current rendering loop. Note that this function must be called in
  // displayd's GL context.
  GLuint GetActiveTextureId(EGLDisplay display);

  // Returns a basic video mesh tranform.
  mat4 GetTransform(int eye, size_t render_buffer_index);

 private:
  class Texture {
   public:
    Texture(EGLDisplay display,
            const std::shared_ptr<BufferConsumer>& buffer_consumer);
    ~Texture();

    // Returns the |event_fd| of the underlying buffer consumer. Caller can use
    // this to decided whether the Texture need to be recreated for a different
    // buffer consumer.
    int event_fd() const { return buffer_consumer_->event_fd(); }

    // Method to map a dvr::BufferConsumer to a GL texture within the current GL
    // context. If the current Texture object's |image_| hasn't been
    // initialized, the method will do so based on the |buffer_consumer| and a
    // new GL texture will be generated, cached, and returned. Otherwise, the
    // cached |texture_id_| will be returned directly.
    GLuint EnsureTextureReady();

    // Signal bufferhub that the texture is done rendering so that the buffer
    // can be re-gained by the producer for future use.
    void Release();

   private:
    using NativeBuffer = BufferHubQueueCore::NativeBuffer;

    EGLDisplay display_;
    EGLImageKHR image_;
    GLuint texture_id_;
    sp<NativeBuffer> native_buffer_;
    std::shared_ptr<BufferConsumer> buffer_consumer_;
  };

  std::shared_ptr<VideoMeshSurface> surface_;
  std::shared_ptr<ConsumerQueue> consumer_queue_;
  std::array<std::unique_ptr<Texture>, BufferHubQueue::kMaxQueueCapacity>
      textures_;

  const volatile DisplaySurfaceMetadata* transform_metadata_;
  int active_texture_slot_;

  VideoCompositor(const VideoCompositor&) = delete;
  void operator=(const VideoCompositor&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_VIDEO_COMPOSITOR_H_
