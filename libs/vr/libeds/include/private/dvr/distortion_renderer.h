#ifndef ANDROID_DVR_DISTORTION_RENDERER_H_
#define ANDROID_DVR_DISTORTION_RENDERER_H_

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <array>
#include <functional>

#include <private/dvr/eds_mesh.h>
#include <private/dvr/graphics/shader_program.h>
#include <private/dvr/late_latch.h>
#include <private/dvr/render_texture_params.h>
#include <private/dvr/types.h>

namespace android {
namespace dvr {

class CompositeHmd;

// Encapsulates the rendering operations to correct for the HMD's lens
// distortion.
class DistortionRenderer {
 public:
  static constexpr int kMaxLayers = 2;
  static constexpr int kMaxLatchedLayers = 4;

  static const mat4 kViewportFromClipMatrix;
  static const mat4 kClipFromViewportMatrix;

  // Creates a distortion renderer for distortion function.
  //
  // distortion_function the black-box distortion function to apply.
  // display_size the resolution of the output of the distortion renderer.
  // distortion_mesh_resolution the amount of subdivision in the
  //     distortion mesh.
  DistortionRenderer(const CompositeHmd& hmd, vec2i display_size,
                     int distortion_mesh_resolution,
                     bool flip_texture_horizontally,
                     bool flip_texture_vertically, bool separated_eye_buffers,
                     bool eds_enabled, bool late_latch_enabled);
  ~DistortionRenderer();

  // Returns the distortion factor array for the distortion function that was
  // passed in at creation time. The distortion factor array contains the
  // magnification factor induced by the distortion mesh at every vertex. There
  // is one entry per vertex, and entries are ordered in row-major major. The
  // array contains the magnification for both eyes averaged.
  const std::vector<float>& GetDistortionFactorArray();

  // |render_pose_buffer_object| is the per-texture pose array buffer object.
  // |render_buffer_index| is the per-texture index into the pose array buffer
  //                       object. This selects which pose was rendered into the
  //                       corresponding texture.
  void DoLateLatch(uint32_t target_vsync_count,
                   const uint32_t* render_buffer_index,
                   const GLuint* render_pose_buffer_objects,
                   const bool* vertical_flip, const bool* separate_eye,
                   int num_textures);

  // Convenience method that does no flipping.
  void DoLateLatch(uint32_t target_vsync_count,
                   const uint32_t* render_buffer_index,
                   const GLuint* render_pose_buffer_objects, int num_textures) {
    bool flip[kMaxLayers] = {false};
    bool separate[kMaxLayers] = {separated_eye_buffers_};
    DoLateLatch(target_vsync_count, render_buffer_index,
                render_pose_buffer_objects, flip, separate, num_textures);
  }

  void PrepGlState(EyeType eye);
  void ResetGlState(int num_textures);

  // Applies distortion correction to the given textures by rendering into the
  // current output target.
  //
  // eye Which eye is being corrected.
  // texture_ids The OpenGL texture IDs of the texture layers.
  // texture_sizes Dimensions of the corresponding textures.
  // vertical_flip Whether to flip each input texture vertically.
  // separate_eye Whether the correspending texture is a separate texture for
  //              left and right eyes. If false, it is a shared texture with
  //              the left view on the left half and right on the right half.
  // late_latch_layer Which late latch layer index to use for each texture.
  //     Typically this is just {0, 1} unless blend_with_previous_layer is used.
  // num_textures Number of textures in texture_ids and texture_sizes.
  // blend_with_previous_layer If enabled, blend this single layer with the
  //     existing framebuffer contents.
  void ApplyDistortionCorrectionToTexture(
      EyeType eye, const GLuint* texture_ids, const bool* vertical_flip,
      const bool* separate_eye, const int* late_latch_layer, int num_textures,
      bool blend_with_previous_layer, bool do_gl_state_prep);

  // Convenience method that does no flipping.
  void ApplyDistortionCorrectionToTexture(EyeType eye,
                                          const GLuint* texture_ids,
                                          int num_textures) {
    bool flip[kMaxLayers] = {false};
    bool separate[kMaxLayers] = {separated_eye_buffers_,
                                 separated_eye_buffers_};
    int latch_layer[kMaxLayers] = {0, 1};
    ApplyDistortionCorrectionToTexture(eye, texture_ids, flip, separate,
                                       latch_layer, num_textures, false, true);
  }

  // Draw a video quad based on the given video texture by rendering into the
  // current output target.
  //
  // eye Which eye is being corrected.
  // layer_id Which compositor layer the video mesh should be drawn into.
  // texture_ids The OpenGL texture IDs of the texture layers.
  // transform The transformation matrix that transforms the video mesh to its
  //           desired eye space position for the target eye.
  void DrawVideoQuad(EyeType eye, int layer_id, GLuint texture_id,
                     const mat4& transform);

  // Modifies the size of the output display. This is the number of physical
  // pixels per dimension covered by the display on the output device. Calling
  // this method is cheap; it only updates the state table of the two
  // eye-specific mesh nodes.
  void SetDisplaySize(vec2i size);

  void SetEdsEnabled(bool enabled);
  void SetChromaticAberrationCorrectionEnabled(bool enabled) {
    chromatic_aberration_correction_enabled_ = enabled;
  }
  void SetUseAlphaVignette(bool enabled) { use_alpha_vignette_ = enabled; }

  bool GetLastEdsPose(LateLatchOutput* out_data, int layer_id = 0) const;

 private:
  enum ShaderProgramType {
    kNoChromaticAberrationCorrection,
    kNoChromaticAberrationCorrectionTwoLayers,
    kChromaticAberrationCorrection,
    kChromaticAberrationCorrectionTwoLayers,
    kChromaticAberrationCorrectionAlphaVignette,
    kChromaticAberrationCorrectionAlphaVignetteTwoLayers,
    kChromaticAberrationCorrectionWithBlend,
    kSimpleVideoQuad,
    kNumShaderPrograms,
  };

  struct EdsShader {
    EdsShader() {}
    ~EdsShader() {
    }

    void load(const char* vertex, const char* fragment, int num_layers,
              bool use_alpha_vignette, float rotation, bool flip_vertical,
              bool blend_with_previous_layer);
    void use() { pgm.Use(); }

    // Update uTexFromEyeMatrix and uEyeFromViewportMatrix by the distortion
    // renderer with the transform matrix.
    void SetTexFromEyeTransform(const mat4& transform) {
      glUniformMatrix4fv(uTexFromEyeMatrix, 1, false, transform.data());
    }

    void SetEyeFromViewportTransform(const mat4& transform) {
      glUniformMatrix4fv(uEyeFromViewportMatrix, 1, false, transform.data());
    }

    ShaderProgram pgm;

    // Texture variables, named to match shader strings for convenience.
    GLint uProjectionMatrix;
    GLint uTexFromEyeMatrix;
    GLint uEyeFromViewportMatrix;
    GLint uTexXMinMax;
  };

  void DrawEye(EyeType eye, const GLuint* texture_ids,
               const bool* vertical_flip, const bool* separate_eye,
               const int* late_latch_layer, int num_textures,
               bool blend_with_previous_layer, bool do_gl_state_prep);

  // This function is called when there is an update on Hmd and distortion mesh
  // vertices and factor array will be updated.
  void RecomputeDistortion(const CompositeHmd& hmd);

  // Per-eye, per flip, per separate eye mode buffers for setting EDS matrix
  // when EDS is disabled.
  GLuint uTexFromRecommendedViewportMatrix[2][2][2];

  // Distortion mesh for the each eye.
  EdsMesh mesh_node_[2];
  // VBO (vertex buffer object) for distortion mesh vertices.
  GLuint mesh_vbo_[2];
  // VAO (vertex array object) for distortion mesh vertex array data.
  GLuint mesh_vao_[2];
  // IBO (index buffer object) for distortion mesh indices.
  GLuint mesh_ibo_[2];

  EdsShader shaders_[kNumShaderPrograms];

  // Enum to indicate which shader program is being used.
  ShaderProgramType shader_type_;

  bool eds_enabled_;
  bool chromatic_aberration_correction_enabled_;
  bool use_alpha_vignette_;

  // This keeps track of what distortion mesh resolution we are using currently.
  // When there is an update on Hmd, the distortion mesh vertices/factor array
  // will be re-computed with the old resolution that is stored here.
  int distortion_mesh_resolution_;

  // The OpenGL ID of the last texture passed to
  // ApplyDistortionCorrectionToTexture().
  GLuint last_distortion_texture_id_;

  // GL texture 2D target for application texture.
  GLint app_texture_target_;

  // Precomputed matrices for EDS and viewport transforms.
  mat4 tex_from_eye_matrix_[2][2][2];
  mat4 eye_from_viewport_matrix_[2];

  // Eye viewport locations.
  vec2i eye_viewport_origin_[2];
  vec2i eye_viewport_size_;

  vec2i display_size_;

  std::unique_ptr<LateLatch> late_latch_[kMaxLatchedLayers];
  bool separated_eye_buffers_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DISTORTION_RENDERER_H_
