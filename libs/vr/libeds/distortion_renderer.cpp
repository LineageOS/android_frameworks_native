#include "include/private/dvr/distortion_renderer.h"

#include <float.h>

#include <string>

#include <utils/Log.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <utils/Trace.h>

#include <base/logging.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/composite_hmd.h>
#include <private/dvr/debug.h>
#include <private/dvr/graphics/gpu_profiler.h>
#include <private/dvr/ortho.h>
#include <private/dvr/sensor_constants.h>

#define STRINGIFY2(s) #s
#define STRINGIFY(s) STRINGIFY2(s)

#define POSITION_ATTR 0
#define VIEWPORT_COORD_R_ATTR 1
#define VIEWPORT_COORD_G_ATTR 2
#define VIEWPORT_COORD_B_ATTR 3

// Pose data uniform buffer bindings. Must be sequential.
#define POSE_BINDING 0
#define POSE_BINDING2 1

// Texture unit bindings. Must be sequential.
// Things break if we start at binding 0 (samples come back black).
#define SAMPLER_BINDING 1
#define SAMPLER_BINDING2 2

#define GLSL_VIGNETTE_FUNC                                       \
  "float vignette(vec2 texCoords) {\n"                           \
  "  const float fadeDist = 0.01;\n"                             \
  "  const float fadeDistInv = 1.0 / fadeDist;\n"                \
  "  const float inset = 0.02;\n"                                \
  "  vec2 lowEdge = vec2(inset - fadeDist);\n"                   \
  "  vec2 highEdge = vec2(1.0 - inset + fadeDist);\n"            \
  "  vec2 vignetteMin = "                                        \
  "    clamp(-fadeDistInv * (lowEdge - texCoords), 0.0, 1.0);\n" \
  "  vec2 vignetteMax = "                                        \
  "    clamp(fadeDistInv * (highEdge - texCoords), 0.0, 1.0);\n" \
  "  vec2 vignette = vignetteMin * vignetteMax;\n"               \
  "  return vignette.x * vignette.y;\n"                          \
  "}\n"

namespace {

// If enabled, the pixel shader will blend by reading back the current pixel
// from the framebuffer.
// TODO(jbates) With framebuffer read coherency disabled, this seems to perform
//   well enough. That requires a GL extension, so for now we disable this path.
constexpr bool kUseFramebufferReadback = false;

static const char* kVertexShaderChromaticAberrationString =
    "uniform mat4 uProjectionMatrix;\n"
    "layout(binding = " STRINGIFY(POSE_BINDING) ", std140)\n"
    "uniform LateLatchData {\n"
    "  mat4 uTexFromRecommendedViewportMatrix;\n"
    "};\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "layout(binding = " STRINGIFY(POSE_BINDING2) ", std140)\n"
    "uniform LateLatchData2 {\n"
    "  mat4 uTexFromRecommendedViewportMatrix2;\n"
    "};\n"
    "#endif\n"
    "uniform vec4 uTexXMinMax;\n"
    "layout(location = " STRINGIFY(POSITION_ATTR) ") in vec2 aPosition;\n"
    "layout(location = " STRINGIFY(VIEWPORT_COORD_R_ATTR)
           ") in vec2 aViewportCoordsR;\n"
    "layout(location = " STRINGIFY(VIEWPORT_COORD_G_ATTR)
           ") in vec2 aViewportCoordsG;\n"
    "layout(location = " STRINGIFY(VIEWPORT_COORD_B_ATTR)
           ") in vec2 aViewportCoordsB;\n"
    "mediump out vec4 vTexCoordsRG;\n"
    "mediump out vec2 vTexCoordsB;\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "mediump out vec4 vTexCoordsRG2;\n"
    "mediump out vec2 vTexCoordsB2;\n"
    "#endif\n"
    "mediump out vec3 vVignette;\n"
    "\n" GLSL_VIGNETTE_FUNC
    "void main(void) {\n"
    "  vVignette.r = vignette(aViewportCoordsR);\n"
    "  vVignette.g = vignette(aViewportCoordsG);\n"
    "  vVignette.b = vignette(aViewportCoordsB);\n"
    "  vec4 redTexCoords = (uTexFromRecommendedViewportMatrix * \n"
    "                       vec4(aViewportCoordsR, 0., 1.));\n"
    "  vec4 greenTexCoords = (uTexFromRecommendedViewportMatrix * \n"
    "                         vec4(aViewportCoordsG, 0., 1.));\n"
    "  vec4 blueTexCoords = (uTexFromRecommendedViewportMatrix * \n"
    "                        vec4(aViewportCoordsB, 0., 1.));\n"
    "  vTexCoordsRG.xy = redTexCoords.xy / redTexCoords.w;\n"
    "  vTexCoordsRG.zw = greenTexCoords.xy / greenTexCoords.w;\n"
    "  vTexCoordsB = blueTexCoords.xy / blueTexCoords.w;\n"
    "  vTexCoordsRG.x = clamp(vTexCoordsRG.x, uTexXMinMax.x, uTexXMinMax.y);\n"
    "  vTexCoordsRG.z = clamp(vTexCoordsRG.z, uTexXMinMax.x, uTexXMinMax.y);\n"
    "  vTexCoordsB.x = clamp(vTexCoordsB.x, uTexXMinMax.x, uTexXMinMax.y);\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "  redTexCoords = (uTexFromRecommendedViewportMatrix2 * \n"
    "                  vec4(aViewportCoordsR, 0., 1.));\n"
    "  greenTexCoords = (uTexFromRecommendedViewportMatrix2 * \n"
    "                    vec4(aViewportCoordsG, 0., 1.));\n"
    "  blueTexCoords = (uTexFromRecommendedViewportMatrix2 * \n"
    "                   vec4(aViewportCoordsB, 0., 1.));\n"
    "  vTexCoordsRG2.xy = redTexCoords.xy / redTexCoords.w;\n"
    "  vTexCoordsRG2.zw = greenTexCoords.xy / greenTexCoords.w;\n"
    "  vTexCoordsB2 = blueTexCoords.xy / blueTexCoords.w;\n"
    "  vTexCoordsRG2.x = clamp(vTexCoordsRG2.x,\n"
    "                          uTexXMinMax.z, uTexXMinMax.w);\n"
    "  vTexCoordsRG2.z = clamp(vTexCoordsRG2.z, uTexXMinMax.z,\n"
    "                          uTexXMinMax.w);\n"
    "  vTexCoordsB2.x = clamp(vTexCoordsB2.x, uTexXMinMax.z, uTexXMinMax.w);\n"
    "#endif\n"
    "  gl_Position = uProjectionMatrix * vec4(aPosition, 0., 1.);\n"
    "}\n";

static const char* kFragmentShaderChromaticAberrationString =
    "#ifdef GL_ES\n"
    "precision mediump float;\n"
    "#endif\n"
    " \n"
    "layout(binding = " STRINGIFY(SAMPLER_BINDING) ")\n"
    "uniform sampler2D uDistortionTexture; \n"
    "mediump in vec4 vTexCoordsRG;\n"
    "mediump in vec2 vTexCoordsB;\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "layout(binding = " STRINGIFY(SAMPLER_BINDING2) ")\n"
    "uniform sampler2D uDistortionTexture2; \n"
    "mediump in vec4 vTexCoordsRG2;\n"
    "mediump in vec2 vTexCoordsB2;\n"
    "#endif\n"
    "mediump in vec3 vVignette;\n"
    "#ifdef BLEND_WITH_PREVIOUS_LAYER \n"
    "inout vec4 fragColor; \n"
    "#else \n"
    "out vec4 fragColor; \n"
    "#endif \n"
    " \n"
    "void main(void) { \n"
    "  vec4 ra = texture(uDistortionTexture, vTexCoordsRG.xy); \n"
    "  vec4 ga = texture(uDistortionTexture, vTexCoordsRG.zw); \n"
    "  vec4 ba = texture(uDistortionTexture, vTexCoordsB); \n"
    "#ifdef BLEND_WITH_PREVIOUS_LAYER \n"
    "  vec3 alpha1 = vec3(ra.a, ga.a, ba.a); \n"
    "  vec3 color = (vec3(1.0) - alpha1) * fragColor.rgb + \n"
    "               alpha1 * vec3(ra.r, ga.g, ba.b); \n"
    "#else // BLEND_WITH_PREVIOUS_LAYER \n"
    "  vec3 color = vec3(ra.r, ga.g, ba.b); \n"
    "#endif // BLEND_WITH_PREVIOUS_LAYER \n"
    "#ifdef COMPOSITE_LAYER_2 \n"
    "  // Alpha blend layer 2 onto layer 1. \n"
    "  vec4 ra2 = texture(uDistortionTexture2, vTexCoordsRG2.xy); \n"
    "  vec4 ga2 = texture(uDistortionTexture2, vTexCoordsRG2.zw); \n"
    "  vec4 ba2 = texture(uDistortionTexture2, vTexCoordsB2); \n"
    "  vec3 color2 = vec3(ra2.r, ga2.g, ba2.b); \n"
    "  vec3 alpha2 = vec3(ra2.a, ga2.a, ba2.a); \n"
    "  color = (vec3(1.0) - alpha2) * color + alpha2 * color2; \n"
    "#endif \n"
    "#ifdef ALPHA_VIGNETTE\n"
    "  fragColor = vec4(color, vVignette.b * ga.a); \n"
    "#else // ALPHA_VIGNETTE\n"
    "  fragColor = vec4(vVignette.rgb * color, ga.a); \n"
    "#endif // ALPHA_VIGNETTE\n"
    "} \n";

static const char* kVertexShaderNoChromaticAberrationString =
    "uniform mat4 uProjectionMatrix;\n"
    "layout(binding = " STRINGIFY(POSE_BINDING) ", std140)\n"
    "uniform LateLatchData {\n"
    "  mat4 uTexFromRecommendedViewportMatrix;\n"
    "};\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "layout(binding = " STRINGIFY(POSE_BINDING2) ", std140)\n"
    "uniform LateLatchData2 {\n"
    "  mat4 uTexFromRecommendedViewportMatrix2;\n"
    "};\n"
    "#endif\n"
    "uniform vec4 uTexXMinMax;\n"
    "layout(location = " STRINGIFY(POSITION_ATTR) ") in vec2 aPosition;\n"
    "layout(location = " STRINGIFY(VIEWPORT_COORD_G_ATTR)
           ") in vec2 aViewportCoords;\n"
    "mediump out vec2 vTexCoords;\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "mediump out vec2 vTexCoords2;\n"
    "#endif\n"
    "mediump out vec3 vVignette;\n"
    "\n" GLSL_VIGNETTE_FUNC
    "void main(void) {\n"
    "  float fVignette = vignette(aViewportCoords);\n"
    "  vVignette = vec3(fVignette, fVignette, fVignette);\n"
    "  vec4 texCoords = (uTexFromRecommendedViewportMatrix * \n"
    "                    vec4(aViewportCoords, 0., 1.));\n"
    "  vTexCoords = texCoords.xy / texCoords.w;\n"
    "  vTexCoords.x = clamp(vTexCoords.x, uTexXMinMax.x, uTexXMinMax.y);\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "  texCoords = (uTexFromRecommendedViewportMatrix2 * \n"
    "               vec4(aViewportCoords, 0., 1.));\n"
    "  vTexCoords2 = texCoords.xy / texCoords.w;\n"
    "  vTexCoords2.x = clamp(vTexCoords2.x, uTexXMinMax.z, uTexXMinMax.w);\n"
    "#endif\n"
    "  gl_Position = uProjectionMatrix * vec4(aPosition, 0., 1.);\n"
    "}\n";

static const char* kFragmentShaderNoChromaticAberrationString =
    "#ifdef GL_ES\n"
    "precision mediump float;\n"
    "#endif\n"
    " \n"
    "layout(binding = " STRINGIFY(SAMPLER_BINDING) ")\n"
    "uniform sampler2D uDistortionTexture; \n"
    "mediump in vec2 vTexCoords;\n"
    "#ifdef COMPOSITE_LAYER_2\n"
    "layout(binding = " STRINGIFY(SAMPLER_BINDING2) ")\n"
    "uniform sampler2D uDistortionTexture2; \n"
    "mediump in vec2 vTexCoords2;\n"
    "#endif\n"
    "mediump in vec3 vVignette;\n"
    "out vec4 fragColor;\n"
    " \n"
    "void main(void) { \n"
    "  vec4 color = texture(uDistortionTexture, vTexCoords); \n"
    "#ifdef COMPOSITE_LAYER_2 \n"
    "  // Alpha blend layer 2 onto layer 1. \n"
    "  vec4 color2 = texture(uDistortionTexture2, vTexCoords2); \n"
    "  float alpha2 = color2.a; \n"
    "  color.rgb = (1.0 - alpha2) * color.rgb + alpha2 * color2.rgb; \n"
    "#endif \n"
    "  fragColor = vec4(vVignette * color.rgb, color.a); \n"
    "} \n";

static const char* kVertexShaderSimpleVideoQuadString =
    "uniform mat4 uProjectionMatrix;\n"
    "layout(binding = " STRINGIFY(POSE_BINDING) ", std140)\n"
    "uniform LateLatchData {\n"
    "  mat4 uEdsCorrection;\n"
    "};\n"
    "uniform mat4 uTexFromEyeMatrix;\n"
    "uniform mat4 uEyeFromViewportMatrix;\n"
    "layout(location = " STRINGIFY(POSITION_ATTR) ") in vec2 aPosition;\n"
    "layout(location = " STRINGIFY(VIEWPORT_COORD_G_ATTR)
           ") in vec2 aViewportCoords;\n"
    "mediump out vec2 vTexCoords;\n"
    "void main(void) {\n"
    "  mat4 m = uTexFromEyeMatrix * inverse(uEdsCorrection) * uEyeFromViewportMatrix;\n"
    "  mat3 uTexFromViewportMatrix = inverse(mat3(m[0].xyw, m[1].xyw, m[3].xyw)); \n"
    "  vec3 texCoords = uTexFromViewportMatrix * vec3(aViewportCoords, 1.0);\n"
    "  vTexCoords = texCoords.xy / texCoords.z;\n"
    "  gl_Position = uProjectionMatrix * vec4(aPosition, 0.0, 1.0);\n"
    "}\n";

static const char* kFragmentShaderSimpleVideoQuadString =
    "#extension GL_OES_EGL_image_external_essl3 : enable\n"
    " \n"
    "#ifdef GL_ES\n"
    "precision mediump float;\n"
    "#endif\n"
    " \n"
    "layout(binding = " STRINGIFY(SAMPLER_BINDING) ")\n"
    "uniform samplerExternalOES uDistortionTexture; \n"
    "mediump in vec2 vTexCoords;\n"
    "out vec4 fragColor;\n"
    " \n"
    "void main(void) { \n"
    "  if (clamp(vTexCoords, 0.0, 1.0) != vTexCoords) { \n"
    "    fragColor = vec4(0.0, 0.0, 0.0, 0.0); \n"
    "  } else { \n"
    "    fragColor = texture(uDistortionTexture, vTexCoords); \n"
    "  } \n"
    "} \n";

}  // anonymous namespace

namespace android {
namespace dvr {

// Note that converting from Clip Space ([-1,1]^3) to Viewport Space
// for one eye ([0,1]x[0,1]) requires dividing by 2 in x and y.
const mat4 DistortionRenderer::kViewportFromClipMatrix =
    Eigen::Translation3f(vec3(0.5f, 0.5f, 0)) *
    Eigen::DiagonalMatrix<float, 3>(vec3(0.5f, 0.5f, 1.0f));

const mat4 DistortionRenderer::kClipFromViewportMatrix =
    Eigen::DiagonalMatrix<float, 3>(vec3(2.0f, 2.0f, 1.0f)) *
    Eigen::Translation3f(vec3(-0.5f, -0.5f, 0));

void DistortionRenderer::EdsShader::load(const char* vertex,
                                         const char* fragment, int num_layers,
                                         bool use_alpha_vignette,
                                         float rotation, bool flip_vertical,
                                         bool blend_with_previous_layer) {
  std::string vert_builder = "#version 310 es\n";
  std::string frag_builder = "#version 310 es\n";
  if (blend_with_previous_layer && kUseFramebufferReadback) {
    frag_builder += "#extension GL_EXT_shader_framebuffer_fetch : require\n";
  }

  if (num_layers == 2) {
    vert_builder += "#define COMPOSITE_LAYER_2\n";
    frag_builder += "#define COMPOSITE_LAYER_2\n";
  } else {
    CHECK_EQ(num_layers, 1);
  }
  if (blend_with_previous_layer) {
    // Check for unsupported shader combinations:
    CHECK_EQ(num_layers, 1);
    CHECK_EQ(use_alpha_vignette, false);
    if (kUseFramebufferReadback)
      frag_builder += "#define BLEND_WITH_PREVIOUS_LAYER\n";
  }
  if (use_alpha_vignette) {
    vert_builder += "#define ALPHA_VIGNETTE\n";
    frag_builder += "#define ALPHA_VIGNETTE\n";
  }

  vert_builder += vertex;
  frag_builder += fragment;
  pgm.Link(vert_builder, frag_builder);
  CHECK(pgm.IsUsable());

  pgm.Use();

  uProjectionMatrix =
      glGetUniformLocation(pgm.GetProgram(), "uProjectionMatrix");
  uTexFromEyeMatrix =
      glGetUniformLocation(pgm.GetProgram(), "uTexFromEyeMatrix");
  uEyeFromViewportMatrix =
      glGetUniformLocation(pgm.GetProgram(), "uEyeFromViewportMatrix");
  uTexXMinMax = glGetUniformLocation(pgm.GetProgram(), "uTexXMinMax");
  CHECK_GL();

  float vertical_multiply = flip_vertical ? -1.0 : 1.0;
  mat4 projectionMatrix = OrthoMatrix(-0.5f, 0.5f, vertical_multiply * -0.5f,
                                      vertical_multiply * 0.5f, -1.0f, 1.0f);

  // Rotate the mesh into the screen's orientation.
  // TODO(hendrikw): Once the display is finalized, and perhaps not portrait,
  //                 look into removing this matrix altogether.
  projectionMatrix =
      projectionMatrix * Eigen::AngleAxisf(rotation, vec3::UnitZ());

  CHECK(sizeof(mat4) == 4 * 4 * 4);
  glUniformMatrix4fv(uProjectionMatrix, 1, false, projectionMatrix.data());
}

DistortionRenderer::DistortionRenderer(
    const CompositeHmd& hmd, vec2i display_size, int distortion_mesh_resolution,
    bool flip_texture_horizontally, bool flip_texture_vertically,
    bool separated_eye_buffers, bool eds_enabled, bool late_latch_enabled)
    : shader_type_(kChromaticAberrationCorrection),
      eds_enabled_(eds_enabled),
      chromatic_aberration_correction_enabled_(true),
      use_alpha_vignette_(false),
      distortion_mesh_resolution_(distortion_mesh_resolution),
      last_distortion_texture_id_(0),
      app_texture_target_(GL_TEXTURE_2D),
      display_size_(display_size),
      separated_eye_buffers_(separated_eye_buffers) {
  ATRACE_NAME("DistortionRenderer::DistortionRenderer");

  float device_rotation = 0.0;

  if (eds_enabled_) {
    // Late latch must be on if eds_enabled_ is true.
    if (!late_latch_enabled) {
      LOG(ERROR) << "Cannot enable EDS without late latch. "
                 << "Force enabling late latch.";
      late_latch_enabled = true;
    }
  }

  // TODO(hendrikw): Look into moving this logic into DisplayMetrics.
  if (hmd.GetDisplayMetrics().IsPortrait()) {
    device_rotation = -M_PI / 2.0f;
  }

  // Create shader programs.
  shaders_[kNoChromaticAberrationCorrection].load(
      kVertexShaderNoChromaticAberrationString,
      kFragmentShaderNoChromaticAberrationString, 1, false, device_rotation,
      flip_texture_horizontally, false);
  shaders_[kNoChromaticAberrationCorrectionTwoLayers].load(
      kVertexShaderNoChromaticAberrationString,
      kFragmentShaderNoChromaticAberrationString, 2, false, device_rotation,
      flip_texture_horizontally, false);
  shaders_[kChromaticAberrationCorrection].load(
      kVertexShaderChromaticAberrationString,
      kFragmentShaderChromaticAberrationString, 1, false, device_rotation,
      flip_texture_horizontally, false);
  shaders_[kChromaticAberrationCorrectionTwoLayers].load(
      kVertexShaderChromaticAberrationString,
      kFragmentShaderChromaticAberrationString, 2, false, device_rotation,
      flip_texture_horizontally, false);
  shaders_[kChromaticAberrationCorrectionAlphaVignette].load(
      kVertexShaderChromaticAberrationString,
      kFragmentShaderChromaticAberrationString, 1, true, device_rotation,
      flip_texture_horizontally, false);
  shaders_[kChromaticAberrationCorrectionAlphaVignetteTwoLayers].load(
      kVertexShaderChromaticAberrationString,
      kFragmentShaderChromaticAberrationString, 2, true, device_rotation,
      flip_texture_horizontally, false);
  shaders_[kChromaticAberrationCorrectionWithBlend].load(
      kVertexShaderChromaticAberrationString,
      kFragmentShaderChromaticAberrationString, 1, false, device_rotation,
      flip_texture_horizontally, true);
  shaders_[kSimpleVideoQuad].load(
      kVertexShaderSimpleVideoQuadString,
      kFragmentShaderSimpleVideoQuadString, 1, false, device_rotation,
      flip_texture_horizontally, true);
  CHECK_GL();

  mat4 tex_from_recommended_viewport_matrix[2][2][2];
  for (int eye = 0; eye < 2; ++eye) {
    // Near and far plane don't actually matter for the clip_from_eye_matrix
    // below since it is only used (for EDS) to transform coordinates for
    // which the Z has been dropped.
    static const float kNear = 0.1f, kFar = 100.0f;
    const FieldOfView& fov =
        (eye == kLeftEye ? hmd.GetEyeFov(kLeftEye) : hmd.GetEyeFov(kRightEye));
    mat4 c_clip_from_eye_matrix = fov.GetProjectionMatrix(kNear, kFar);
    mat4 c_eye_from_clip_matrix = c_clip_from_eye_matrix.inverse();

    // Compute tex_from_recommended_viewport_matrix.

    // flip_texture_vertically defines the default flip behavior.
    // do_flip[0] should be the default, while do_flip[1] should be the
    // inverse of the default.
    int do_flip[2] = {flip_texture_vertically ? 1 : 0,
                      flip_texture_vertically ? 0 : 1};
    for (int flip = 0; flip < 2; ++flip) {
      vec2 flip_scale(1.0f, do_flip[flip] ? -1.0f : 1.0f);
      vec2 flip_offset(0.0f, do_flip[flip] ? 1.0f : 0.0f);

      for (int separate_eye = 0; separate_eye < 2; ++separate_eye) {
        vec2 viewport_corner_offset = (eye == kLeftEye || separate_eye)
                                          ? vec2(0.0f, 0.0f)
                                          : vec2(0.5f, 0.0f);
        const vec2 txy = viewport_corner_offset + flip_offset;
        const vec2 scalexy = vec2(separate_eye ? 1.0f : 0.5f, 1.0f);
        tex_from_recommended_viewport_matrix[eye][flip][separate_eye] =
            Eigen::Translation3f(vec3(txy.x(), txy.y(), 0.0f)) *
            Eigen::DiagonalMatrix<float, 3>(vec3(flip_scale.x() * scalexy.x(),
                                                 flip_scale.y(), scalexy.y()));

        tex_from_eye_matrix_[eye][flip][separate_eye] =
            tex_from_recommended_viewport_matrix[eye][flip][separate_eye] *
            kViewportFromClipMatrix * c_clip_from_eye_matrix;
      }
    }

    eye_from_viewport_matrix_[eye] =
        c_eye_from_clip_matrix * kClipFromViewportMatrix;
  }

  // Create UBO for setting the EDS matrix to identity when EDS is disabled.
  glGenBuffers(2 * 2 * 2, &uTexFromRecommendedViewportMatrix[0][0][0]);
  for (int eye = 0; eye < 2; ++eye) {
    for (int flip = 0; flip < 2; ++flip) {
      for (int separate_eye = 0; separate_eye < 2; ++separate_eye) {
        glBindBuffer(
            GL_UNIFORM_BUFFER,
            uTexFromRecommendedViewportMatrix[eye][flip][separate_eye]);
        glBufferData(GL_UNIFORM_BUFFER, sizeof(mat4), 0, GL_STATIC_DRAW);
        CHECK_GL();
        mat4* mat = static_cast<mat4*>(glMapBufferRange(
            GL_UNIFORM_BUFFER, 0, sizeof(mat4), GL_MAP_WRITE_BIT));
        CHECK_GL();
        *mat = tex_from_recommended_viewport_matrix[eye][flip][separate_eye];
        glUnmapBuffer(GL_UNIFORM_BUFFER);
      }
    }
  }
  glBindBuffer(GL_UNIFORM_BUFFER, 0);

  // Create distortion meshes and associated GL resources.
  glGenBuffers(2, mesh_vbo_);
  glGenVertexArrays(2, mesh_vao_);
  glGenBuffers(2, mesh_ibo_);
  RecomputeDistortion(hmd);

  SetDisplaySize(display_size);

  if (hmd.GetDisplayMetrics().IsPortrait()) {
    eye_viewport_origin_[0] =
        vec2i(0, flip_texture_horizontally ? 0 : display_size_[1] / 2);
    eye_viewport_origin_[1] =
        vec2i(0, flip_texture_horizontally ? display_size_[1] / 2 : 0);
    eye_viewport_size_ = vec2i(display_size_[0], display_size_[1] / 2);
  } else {
    eye_viewport_origin_[0] = vec2i(0, 0);
    eye_viewport_origin_[1] = vec2i(display_size_[0] / 2, 0);
    eye_viewport_size_ = vec2i(display_size_[0] / 2, display_size_[1]);
  }

  CHECK_GL();
}

DistortionRenderer::~DistortionRenderer() {
  glDeleteBuffers(2 * 2 * 2, &uTexFromRecommendedViewportMatrix[0][0][0]);
  glDeleteBuffers(2, mesh_vbo_);
  glDeleteVertexArrays(2, mesh_vao_);
  glDeleteBuffers(2, mesh_ibo_);
}

void DistortionRenderer::ApplyDistortionCorrectionToTexture(
    EyeType eye, const GLuint* texture_ids, const bool* vertical_flip,
    const bool* separate_eye, const int* late_latch_layer, int num_textures,
    bool blend_with_previous_layer, bool do_gl_state_prep) {
  ATRACE_NAME(__PRETTY_FUNCTION__);

  bool use_gl_blend = use_alpha_vignette_ ||
                      (blend_with_previous_layer && !kUseFramebufferReadback);
  if (use_gl_blend) {
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
  }
  DrawEye(eye, texture_ids, vertical_flip, separate_eye, late_latch_layer,
          num_textures, blend_with_previous_layer, do_gl_state_prep);
  if (use_gl_blend) {
    glDisable(GL_BLEND);
  }
  CHECK_GL();
}

void DistortionRenderer::DrawVideoQuad(EyeType eye, int layer_i,
                                       GLuint texture_id,
                                       const mat4& transform) {
  shaders_[kSimpleVideoQuad].use();

  shaders_[kSimpleVideoQuad].SetTexFromEyeTransform(
      tex_from_eye_matrix_[eye][0][1]);
  shaders_[kSimpleVideoQuad].SetEyeFromViewportTransform(
      transform * kClipFromViewportMatrix);

  if (eds_enabled_) {
    // Bind late latch view-projection UBO that is produced by AddEdsLateLatch.
    late_latch_[layer_i]->BindUniformBuffer(
        POSE_BINDING, LateLatch::kViewMatrix, eye);
    CHECK_GL();
  } else {
    // When EDS is disabled we just set the matrix here with no pose offset.
    glBindBufferBase(GL_UNIFORM_BUFFER, POSE_BINDING + layer_i,
                     uTexFromRecommendedViewportMatrix[eye][0][1]);
    CHECK_GL();
  }

  glActiveTexture(GL_TEXTURE0 + SAMPLER_BINDING);
  glBindTexture(GL_TEXTURE_EXTERNAL_OES, texture_id);
  CHECK_GL();

  glDrawElements(GL_TRIANGLE_STRIP, mesh_node_[eye].indices.size(),
                 GL_UNSIGNED_SHORT, nullptr);

  CHECK_GL();
}

void DistortionRenderer::DoLateLatch(uint32_t target_vsync_count,
                                     const uint32_t* render_buffer_index,
                                     const GLuint* render_pose_buffer_objects,
                                     const bool* vertical_flip,
                                     const bool* separate_eye,
                                     int num_textures) {
  if (eds_enabled_) {
    LateLatchInput data;
    memset(&data, 0, sizeof(data));
    for (int ti = 0; ti < num_textures; ++ti) {
      if (late_latch_[ti] == nullptr)
        late_latch_[ti].reset(new LateLatch(false));

      int flip_index = vertical_flip[ti] ? 1 : 0;
      int separate_eye_i = separate_eye[ti] ? 1 : 0;
      // Copy data into late latch input struct.
      for (int eye = 0; eye < 2; ++eye) {
        data.eds_mat1[eye] =
            tex_from_eye_matrix_[eye][flip_index][separate_eye_i];
        data.eds_mat2[eye] = eye_from_viewport_matrix_[eye];
      }
      data.pose_index = target_vsync_count & kPoseAsyncBufferIndexMask;
      data.render_pose_index = render_buffer_index[ti];

      late_latch_[ti]->AddEdsLateLatch(data, render_pose_buffer_objects[ti]);
    }
  }
}

void DistortionRenderer::PrepGlState(EyeType eye) {
  glViewport(eye_viewport_origin_[eye].x(), eye_viewport_origin_[eye].y(),
             eye_viewport_size_.x(), eye_viewport_size_.y());

  glBindVertexArray(mesh_vao_[eye]);
  CHECK_GL();

  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mesh_ibo_[eye]);
  CHECK_GL();

  if (!eds_enabled_) {
    glMemoryBarrier(GL_UNIFORM_BARRIER_BIT);
  }
}

void DistortionRenderer::ResetGlState(int num_textures) {
  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
  glBindBuffer(GL_ARRAY_BUFFER, 0);
  glBindVertexArray(0);
  if (eds_enabled_) {
    for (int ti = 0; ti < num_textures; ++ti)
      glBindBufferBase(GL_UNIFORM_BUFFER, POSE_BINDING + ti, 0);
  } else {
    glBindBuffer(GL_UNIFORM_BUFFER, 0);
  }

  CHECK_GL();

  // Unbind all texture inputs.
  for (int ti = 0; ti < num_textures; ++ti) {
    glActiveTexture(GL_TEXTURE0 + SAMPLER_BINDING + ti);
    glBindTexture(app_texture_target_, 0);
  }
  glActiveTexture(GL_TEXTURE0);
}

void DistortionRenderer::DrawEye(EyeType eye, const GLuint* texture_ids,
                                 const bool* vertical_flip,
                                 const bool* separate_eye,
                                 const int* late_latch_layer, int num_textures,
                                 bool blend_with_previous_layer,
                                 bool do_gl_state_prep) {
  if (do_gl_state_prep)
    PrepGlState(eye);

  if (num_textures > kMaxLayers) {
    LOG(ERROR) << "Too many textures for DistortionRenderer";
    num_textures = kMaxLayers;
  }

  CHECK(num_textures == 1 || num_textures == 2);

  if (num_textures == 2) {
    if (chromatic_aberration_correction_enabled_) {
      if (use_alpha_vignette_) {
        shader_type_ = kChromaticAberrationCorrectionAlphaVignetteTwoLayers;
      } else {
        shader_type_ = kChromaticAberrationCorrectionTwoLayers;
      }
    } else {
      shader_type_ = kNoChromaticAberrationCorrectionTwoLayers;
    }
  } else {
    if (chromatic_aberration_correction_enabled_) {
      if (blend_with_previous_layer) {
        shader_type_ = kChromaticAberrationCorrectionWithBlend;
      } else if (use_alpha_vignette_) {
        shader_type_ = kChromaticAberrationCorrectionAlphaVignette;
      } else {
        shader_type_ = kChromaticAberrationCorrection;
      }
    } else {
      shader_type_ = kNoChromaticAberrationCorrection;
    }
  }
  shaders_[shader_type_].use();

  for (int ti = 0; ti < num_textures; ++ti) {
    int flip_index = vertical_flip[ti] ? 1 : 0;
    if (eds_enabled_) {
      // Bind late latch view-projection UBO that is produced by
      // AddEdsLateLatch.
      late_latch_[late_latch_layer[ti]]->BindUniformBuffer(
          POSE_BINDING + ti, LateLatch::kViewProjMatrix, eye);
      CHECK_GL();
    } else {
      // When EDS is disabled we just set the matrix here with no pose offset.
      // With app late-latching, we can't know the pose that the app used
      // because it's in the app's framebuffer.
      int separate_eye_i = separate_eye[ti] ? 1 : 0;
      glBindBufferBase(
          GL_UNIFORM_BUFFER, POSE_BINDING + ti,
          uTexFromRecommendedViewportMatrix[eye][flip_index][separate_eye_i]);
      CHECK_GL();
    }

    glActiveTexture(GL_TEXTURE0 + SAMPLER_BINDING + ti);
    glBindTexture(app_texture_target_, texture_ids[ti]);
    CHECK_GL();
  }

  // Prevents left eye data from bleeding into right eye and vice-versa.
  vec2 layer_min_max[kMaxLayers];
  for (int i = 0; i < kMaxLayers; ++i)
    layer_min_max[i] = vec2(0.0f, 0.0f);
  for (int ti = 0; ti < num_textures; ++ti) {
    if (separate_eye[ti]) {
      layer_min_max[ti] = vec2(0.0f, 1.0f);  // Use the whole texture.
    } else if (eye == kLeftEye) {
      layer_min_max[ti] = vec2(0.0f, 0.499f);
    } else {
      layer_min_max[ti] = vec2(0.501f, 1.0f);
    }
  }
  // The second layer stores its x min and max in the z,w slots of the vec4.
  vec4 xTexMinMax(layer_min_max[0].x(), layer_min_max[0].y(),
                  layer_min_max[1].x(), layer_min_max[1].y());

  glUniform4fv(shaders_[shader_type_].uTexXMinMax, 1, &xTexMinMax[0]);
  CHECK_GL();

  glDrawElements(GL_TRIANGLE_STRIP, mesh_node_[eye].indices.size(),
                 GL_UNSIGNED_SHORT, nullptr);
  CHECK_GL();
  if (do_gl_state_prep)
    ResetGlState(num_textures);
}

void DistortionRenderer::SetDisplaySize(vec2i display_size) {
  display_size_ = display_size;
}

void DistortionRenderer::SetEdsEnabled(bool enabled) { eds_enabled_ = enabled; }

void DistortionRenderer::RecomputeDistortion(const CompositeHmd& hmd) {
  using std::placeholders::_1;
  using std::placeholders::_2;
  using std::placeholders::_3;
  using std::placeholders::_4;
  DistortionFunction distortion_function =
      std::bind(&CompositeHmd::ComputeDistortedVertex, &hmd, _1, _2, _3, _4);

  for (int i = 0; i < 2; ++i) {
    mesh_node_[i] =
        BuildDistortionMesh(static_cast<EyeType>(i),
                            distortion_mesh_resolution_, distortion_function);

    glBindVertexArray(mesh_vao_[i]);

    glBindBuffer(GL_ARRAY_BUFFER, mesh_vbo_[i]);
    glBufferData(GL_ARRAY_BUFFER,
                 sizeof(EdsVertex) * mesh_node_[i].vertices.size(),
                 &mesh_node_[i].vertices.front(), GL_STATIC_DRAW);

    glEnableVertexAttribArray(POSITION_ATTR);
    glEnableVertexAttribArray(VIEWPORT_COORD_R_ATTR);
    glEnableVertexAttribArray(VIEWPORT_COORD_G_ATTR);
    glEnableVertexAttribArray(VIEWPORT_COORD_B_ATTR);

    glVertexAttribPointer(
        POSITION_ATTR, 2, GL_FLOAT, GL_FALSE, sizeof(EdsVertex),
        reinterpret_cast<void*>(offsetof(EdsVertex, position)));

    glVertexAttribPointer(
        VIEWPORT_COORD_R_ATTR, 2, GL_FLOAT, GL_FALSE, sizeof(EdsVertex),
        reinterpret_cast<void*>(offsetof(EdsVertex, red_viewport_coords)));

    glVertexAttribPointer(
        VIEWPORT_COORD_G_ATTR, 2, GL_FLOAT, GL_FALSE, sizeof(EdsVertex),
        reinterpret_cast<void*>(offsetof(EdsVertex, green_viewport_coords)));

    glVertexAttribPointer(
        VIEWPORT_COORD_B_ATTR, 2, GL_FLOAT, GL_FALSE, sizeof(EdsVertex),
        reinterpret_cast<void*>(offsetof(EdsVertex, blue_viewport_coords)));

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mesh_ibo_[i]);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER,
                 sizeof(uint16_t) * mesh_node_[i].indices.size(),
                 &mesh_node_[i].indices.front(), GL_STATIC_DRAW);
    CHECK_GL();
  }
  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
  glBindBuffer(GL_ARRAY_BUFFER, 0);

  glBindVertexArray(0);
}

bool DistortionRenderer::GetLastEdsPose(LateLatchOutput* out_data, int layer_id) const {
  if (layer_id >= kMaxLayers) {
    LOG(ERROR) << "Accessing invalid layer " << layer_id << std::endl;
    return false;
  }

  if (late_latch_[layer_id] != nullptr) {
    late_latch_[layer_id]->CaptureOutputData(out_data);
    return true;
  } else {
    LOG(ERROR) << "Late latch shader not enabled." << std::endl;
    return false;
  }
}

}  // namespace dvr
}  // namespace android
