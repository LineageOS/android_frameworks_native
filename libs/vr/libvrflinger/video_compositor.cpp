#include "video_compositor.h"

#include <EGL/eglext.h>
#include <GLES2/gl2ext.h>

#include <private/dvr/debug.h>
#include <private/dvr/display_rpc.h>

namespace android {
namespace dvr {

VideoCompositor::Texture::Texture(
    EGLDisplay display, const std::shared_ptr<BufferConsumer>& buffer_consumer)
    : display_(display),
      image_(EGL_NO_IMAGE_KHR),
      texture_id_(0),
      buffer_consumer_(buffer_consumer) {}

VideoCompositor::Texture::~Texture() {
  if (image_ != EGL_NO_IMAGE_KHR)
    eglDestroyImageKHR(display_, image_);
  if (texture_id_ != 0)
    glDeleteTextures(1, &texture_id_);
}

GLuint VideoCompositor::Texture::EnsureTextureReady() {
  if (!image_) {
    native_buffer_ = new NativeBuffer(buffer_consumer_);
    CHECK_GL();

    image_ = eglCreateImageKHR(
        display_, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
        static_cast<ANativeWindowBuffer*>(native_buffer_.get()), nullptr);
    if (!image_) {
      ALOGE("Failed to create EGLImage.");
      return 0;
    }

    glGenTextures(1, &texture_id_);
    glBindTexture(GL_TEXTURE_EXTERNAL_OES, texture_id_);
    glEGLImageTargetTexture2DOES(GL_TEXTURE_EXTERNAL_OES, image_);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_S,
                    GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_T,
                    GL_CLAMP_TO_EDGE);
    CHECK_GL();
  }

  return texture_id_;
}

void VideoCompositor::Texture::Release() {
  const int ret = buffer_consumer_->Release({});
  if (ret < 0) {
    ALOGE(
        "VideoCompositor::Texture::Release: Failed to release buffer, error: "
        "%s",
        strerror(-ret));
  }
}

VideoCompositor::VideoCompositor(
    const std::shared_ptr<VideoMeshSurface>& surface,
    const volatile DisplaySurfaceMetadata* display_surface_metadata)
    : surface_(surface),
      consumer_queue_(surface->GetConsumerQueue()),
      transform_metadata_(display_surface_metadata),
      active_texture_slot_(-1) {}

GLuint VideoCompositor::GetActiveTextureId(EGLDisplay display) {
  size_t slot;
  BufferHubQueueCore::NativeBufferMetadata metadata;

  while (true) {
    // A native way to pick the active texture: always dequeue all buffers from
    // the queue until it's empty. This works well as long as video frames are
    // queued in order from the producer side.
    // TODO(jwcai) Use |metadata.timestamp_ns| to schedule video frames
    // accurately.
    LocalHandle acquire_fence;
    auto buffer_consumer =
        consumer_queue_->Dequeue(0, &slot, &metadata, &acquire_fence);

    if (buffer_consumer) {
      // Create a new texture if it hasn't been created yet, or the same slot
      // has a new |buffer_consumer|.
      if (textures_[slot] == nullptr ||
          textures_[slot]->event_fd() != buffer_consumer->event_fd()) {
        textures_[slot] =
            std::unique_ptr<Texture>(new Texture(display, buffer_consumer));
      }

      if (active_texture_slot_ != static_cast<int>(slot)) {
        if (active_texture_slot_ >= 0) {
          // Release the last active texture and move on to use the new one.
          textures_[active_texture_slot_]->Release();
        }
        active_texture_slot_ = slot;
      }
    } else {
      break;
    }
  }

  if (active_texture_slot_ < 0) {
    // No texture is active yet.
    return 0;
  }

  return textures_[active_texture_slot_]->EnsureTextureReady();
}

mat4 VideoCompositor::GetTransform(int eye, size_t render_buffer_index) {
  volatile const VideoMeshSurfaceMetadata* transform_metadata =
      surface_->GetMetadataBufferPtr();

  mat4 screen_transform;
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      screen_transform(i, j) =
          transform_metadata->transform[render_buffer_index][eye].val[i][j];
    }
  }

  return screen_transform;
}

}  // namespace dvr
}  // namespace android
