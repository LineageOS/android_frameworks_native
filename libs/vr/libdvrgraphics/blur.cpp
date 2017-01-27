#include "include/private/dvr/graphics/blur.h"

// clang-format off
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2.h>
// clang-format on
#include <hardware/gralloc.h>

#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <private/dvr/debug.h>
#include <private/dvr/graphics/egl_image.h>
#include <private/dvr/graphics/shader_program.h>
#include <private/dvr/types.h>

#define POSITION_ATTR 0
#define OFFSET_BINDING 0
#define SAMPLER_BINDING 1

namespace {

std::string screen_space_vert_shader = SHADER0([]() {  // NOLINT
  layout(location = 0) in vec4 position_uv;
  out vec2 texCoords;

  void main() {
    gl_Position = vec4(position_uv.xy, 0.0, 1.0);
    texCoords = position_uv.zw;
  }
});

std::string kawase_blur_frag_shader = SHADER0([]() {  // NOLINT
  precision mediump float;
  layout(location = 0) uniform vec2 uSampleOffsets[4];
  layout(binding = 1) uniform APP_SAMPLER_2D uTexture;
  in vec2 texCoords;
  out vec4 color;

  void main() {
    vec2 tc = texCoords;
    color = texture(uTexture, tc + uSampleOffsets[0]);
    color += texture(uTexture, tc + uSampleOffsets[1]);
    color += texture(uTexture, tc + uSampleOffsets[2]);
    color += texture(uTexture, tc + uSampleOffsets[3]);
    color *= (1.0 / 4.0);
  }
});

constexpr int g_num_samples = 4;

// Modified kernel patterns originally based on:
// https://software.intel.com/en-us/blogs/2014/07/15/an-investigation-of-fast-real-time-gpu-based-image-blur-algorithms
// The modification is left and right rotations of the 3rd and 4th patterns.
const android::dvr::vec2 g_blur_samples[][g_num_samples] = {
    {{0.5f, 0.5f}, {-0.5f, 0.5f}, {0.5f, -0.5f}, {-0.5f, -0.5f}},
    {{1.5f, 1.5f}, {-1.5f, 1.5f}, {1.5f, -1.5f}, {-1.5f, -1.5f}},
    {{2.5f, 1.5f}, {-1.5f, 2.5f}, {1.5f, -2.5f}, {-2.5f, -1.5f}},
    {{2.5f, 3.5f}, {-3.5f, 2.5f}, {3.5f, -2.5f}, {-2.5f, -3.5f}},
    // Last pass disabled, because it is more blur than we need.
    // {{3.5f, 3.5f}, {-3.5f, 3.5f}, {3.5f, -3.5f}, {-3.5f, -3.5f}},
};

}  // namespace

namespace android {
namespace dvr {

Blur::Blur(int w, int h, GLuint source_texture, GLint source_texture_target,
           GLint target_texture_target, bool is_external, EGLDisplay display,
           int num_blur_outputs)
    : display_(display),
      target_texture_target_(target_texture_target),
      width_(w),
      height_(h),
      fbo_q_free_(1 + num_blur_outputs) {
  CHECK(num_blur_outputs > 0);
  source_fbo_ =
      CreateFbo(w, h, source_texture, source_texture_target, is_external);
  fbo_half_ = CreateFbo(w / 2, h / 2, 0, target_texture_target, is_external);
  // Create the quarter res fbos.
  for (size_t i = 0; i < fbo_q_free_.GetCapacity(); ++i)
    fbo_q_.push_back(
        CreateFbo(w / 4, h / 4, 0, target_texture_target, is_external));
  scale_ = 1.0f;
}

Blur::~Blur() {
  glFinish();
  glDeleteFramebuffers(1, &source_fbo_.fbo);
  glDeleteFramebuffers(1, &fbo_half_.fbo);
  // Note: source_fbo_.texture is not deleted because it was created externally.
  glDeleteTextures(1, &fbo_half_.texture);
  if (fbo_half_.egl_image)
    eglDestroyImageKHR(display_, fbo_half_.egl_image);
  for (const auto& fbo : fbo_q_) {
    glDeleteFramebuffers(1, &fbo.fbo);
    glDeleteTextures(1, &fbo.texture);
    if (fbo.egl_image)
      eglDestroyImageKHR(display_, fbo.egl_image);
  }
  CHECK_GL();
}

void Blur::StartFrame() {
  fbo_q_free_.Clear();
  for (const auto& fbo : fbo_q_)
    fbo_q_free_.Append(fbo);
}

GLuint Blur::DrawBlur(GLuint source_texture) {
  CHECK(fbo_q_free_.GetSize() >= 2);

  // Downsample to half w x half h.
  glBindFramebuffer(GL_READ_FRAMEBUFFER, source_fbo_.fbo);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, fbo_half_.fbo);
  glFramebufferTexture2D(GL_READ_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                         target_texture_target_, source_texture, 0);
  glBlitFramebuffer(0, 0, width_, height_, 0, 0, width_ / 2, height_ / 2,
                    GL_COLOR_BUFFER_BIT, GL_LINEAR);
  CHECK_GL();

  // Downsample to quarter w x quarter h.
  glBindFramebuffer(GL_READ_FRAMEBUFFER, fbo_half_.fbo);
  Fbo fbo_out = fbo_q_free_.Front();
  fbo_q_free_.PopFront();
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, fbo_out.fbo);
  glBlitFramebuffer(0, 0, width_ / 2, height_ / 2, 0, 0, width_ / 4,
                    height_ / 4, GL_COLOR_BUFFER_BIT, GL_LINEAR);
  glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
  CHECK_GL();

  // Blur shader is initialized statically to share between multiple blur
  // instances.
  static ShaderProgram kawase_prog[2];
  int prog_index = (target_texture_target_ == GL_TEXTURE_EXTERNAL_OES) ? 1 : 0;
  if (!kawase_prog[prog_index].IsUsable()) {
    std::string prefix = "#version 310 es\n";
    if (target_texture_target_ == GL_TEXTURE_EXTERNAL_OES) {
      prefix += "#extension GL_OES_EGL_image_external_essl3 : require\n";
      prefix += "#define APP_SAMPLER_2D samplerExternalOES\n";
    } else {
      prefix += "#define APP_SAMPLER_2D sampler2D\n";
    }
    std::string vert = prefix + screen_space_vert_shader;
    std::string frag = prefix + kawase_blur_frag_shader;
    kawase_prog[prog_index].Link(vert, frag);
    CHECK_GL();
  }

  int blur_w = width_ / 4;
  int blur_h = height_ / 4;
  float pix_w = 1.0f / static_cast<float>(blur_w);
  float pix_h = 1.0f / static_cast<float>(blur_h);
  vec2 pixel_size(pix_w, pix_h);
  constexpr int num_passes = sizeof(g_blur_samples) / sizeof(g_blur_samples[0]);
  vec2 blur_offsets[num_passes][g_num_samples];
  for (int i = 0; i < num_passes; ++i) {
    for (int dir = 0; dir < g_num_samples; ++dir) {
      blur_offsets[i][dir] = pixel_size.array() *
          g_blur_samples[i][dir].array() * scale_;
    }
  }

  kawase_prog[prog_index].Use();

  vec4 screen_tri_strip[4] = {vec4(-1, 1, 0, 1), vec4(-1, -1, 0, 0),
                              vec4(1, 1, 1, 1), vec4(1, -1, 1, 0)};

  glViewport(0, 0, blur_w, blur_h);
  glVertexAttribPointer(POSITION_ATTR, 4, GL_FLOAT, GL_FALSE, sizeof(vec4),
                        screen_tri_strip);
  glEnableVertexAttribArray(POSITION_ATTR);
  CHECK_GL();

  // Ping-pong between fbos from fbo_q_free_ to compute the passes.
  Fbo fbo_in = fbo_out;
  for (int i = 0; i < num_passes; ++i) {
    fbo_out = fbo_q_free_.Front();
    fbo_q_free_.PopFront();
    glBindFramebuffer(GL_FRAMEBUFFER, fbo_out.fbo);
    glActiveTexture(GL_TEXTURE0 + SAMPLER_BINDING);
    glBindTexture(target_texture_target_, fbo_in.texture);
    glUniform2fv(OFFSET_BINDING, 4, &blur_offsets[i][0][0]);
    glClear(GL_COLOR_BUFFER_BIT);
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
    CHECK_GL();
    // Put fbo_in back into the free fbo pool.
    fbo_q_free_.Append(fbo_in);
    // Next iteration's in buffer is this iteration's out buffer.
    fbo_in = fbo_out;
  }
  glDisableVertexAttribArray(POSITION_ATTR);
  glBindTexture(target_texture_target_, 0);
  glUseProgram(0);
  glActiveTexture(GL_TEXTURE0);
  CHECK_GL();
  // fbo_out remains out of the fbo_q_free_ list, since the application will be
  // using it as a texture.
  return fbo_out.texture;
}

Blur::Fbo Blur::CreateFbo(int w, int h, GLuint source_texture, GLint tex_target,
                          bool is_external) {
  Fbo fbo;
  glGenFramebuffers(1, &fbo.fbo);
  if (source_texture) {
    fbo.texture = source_texture;
  } else {
    glGenTextures(1, &fbo.texture);
  }

  glBindFramebuffer(GL_FRAMEBUFFER, fbo.fbo);
  CHECK_GL();

  if (!source_texture) {
    glBindTexture(tex_target, fbo.texture);
    glTexParameteri(tex_target, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(tex_target, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(tex_target, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(tex_target, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    if (is_external) {
      fbo.egl_image =
          CreateEglImage(display_, w, h, HAL_PIXEL_FORMAT_RGBA_8888,
                         GRALLOC_USAGE_HW_FB | GRALLOC_USAGE_HW_RENDER);
      glEGLImageTargetTexture2DOES(tex_target, fbo.egl_image);
    } else {
      glTexImage2D(tex_target, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE,
                   nullptr);
    }
  }
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, tex_target,
                         fbo.texture, 0);
  CHECK_GL();
  CHECK_GL_FBO();

  glBindFramebuffer(GL_FRAMEBUFFER, 0);
  return fbo;
}

}  // namespace dvr
}  // namespace android
