#ifndef ANDROID_DVR_GRAPHICS_BLUR_H_
#define ANDROID_DVR_GRAPHICS_BLUR_H_

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>

#include <algorithm>
#include <vector>

#include <private/dvr/ring_buffer.h>

namespace android {
namespace dvr {

class Blur {
 public:
  // Construct a blur kernel for GL that works on source textures of the given
  // size. The given source_texture is configured for linear filtering.
  // |source_texture_target| is for |source_texture| while
  // |target_texture_target| is used for all the intermediate and output
  // buffers.
  // |num_blur_outputs| determines how many blurs this instance can be used for
  // in a single frame.
  Blur(int w, int h, GLuint source_texture, GLint source_texture_target,
       GLint target_texture_target, bool is_external, EGLDisplay display,
       int num_blur_outputs);
  ~Blur();

  // Place all output textures back into the FBO pool for a new frame.
  // Call this at the start of each frame before doing one or more blurs.
  void StartFrame();

  // Draw a multipass blur from the given source_texture. The resulting texture
  // is returned. The given source_texture is configured for linear filtering.
  // A segfault will occur if the application calls DrawBlur more times than
  // |num_blur_outputs| without calling StartFrame.
  // It is up to the calling code to change the framebuffer after this method.
  GLuint DrawBlur(GLuint source_texture);

  float width() const { return width_; }
  float height() const { return height_; }
  float scale() const { return scale_; }

  // Set the scale of the blur, usually between 0 and 1. This is only useful for
  // animation.
  // At the steady state, the scale should be set to 1. To change the steady
  // state blur appearance, the kernel patterns in DrawBlur should be modified
  // instead of using scale.
  void set_scale(float scale) { scale_ = scale; }

  // Animate the blur by |delta|. Clamp the result between |low| and |high|.
  // Recommended range is between 0 and 1, but other values will also work.
  void animate(float delta, float low, float high) {
    scale_ += delta;
    scale_ = std::min(high, std::max(low, scale_));
  }

 private:
  struct Fbo {
    Fbo() : fbo(0), renderbuffer(0), texture(0), egl_image(0) {}
    GLuint fbo;
    GLuint renderbuffer;
    GLuint texture;
    EGLImageKHR egl_image;
  };

  Fbo CreateFbo(int w, int h, GLuint source_texture, GLint tex_target,
                bool is_external);

  // EGL display for when target texture format is EGL image.
  EGLDisplay display_;
  GLint target_texture_target_;
  int width_;
  int height_;
  Fbo source_fbo_;
  Fbo fbo_half_;
  std::vector<Fbo> fbo_q_;
  RingBuffer<Fbo> fbo_q_free_;
  float scale_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GRAPHICS_BLUR_H_
