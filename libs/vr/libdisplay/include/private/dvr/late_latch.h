#ifndef ANDROID_DVR_LATE_LATCH_H_
#define ANDROID_DVR_LATE_LATCH_H_

#include <atomic>
#include <thread>
#include <vector>

#include <dvr/pose_client.h>
#include <pdx/file_handle.h>
#include <private/dvr/display_types.h>
#include <private/dvr/graphics/shader_program.h>
#include <private/dvr/graphics/vr_gl_extensions.h>
#include <private/dvr/types.h>

struct DvrPose;

namespace android {
namespace dvr {

// Input data for late latch compute shader.
struct LateLatchInput {
  // For app late latch:
  mat4 eye_from_head_mat[kSurfaceViewMaxCount];
  mat4 proj_mat[kSurfaceViewMaxCount];
  mat4 pose_offset[kSurfaceViewMaxCount];
  // For EDS late latch only:
  mat4 eds_mat1[kSurfaceViewMaxCount];
  mat4 eds_mat2[kSurfaceViewMaxCount];
  // For both app and EDS late latch:
  uint32_t pose_index;
  uint32_t render_pose_index;
};

// Output data for late latch shader. The application can use all or part of
// this data by calling LateLatch::BindUniformBuffer.
// This struct matches the layout of DvrGraphicsLateLatchData.
struct LateLatchOutput {
  mat4 view_proj_matrix[kSurfaceViewMaxCount];
  mat4 view_matrix[kSurfaceViewMaxCount];
  vec4 pose_quaternion;
  vec4 pose_translation;
};

// LateLatch provides a facility for GL workloads to acquire a late-adjusted
// model-view projection matrix, adjusted based on the position/quaternion pose
// read from a buffer that is being written to asynchronously. The adjusted
// MVP matrix is written to a GL buffer object via GL transform feedback.
class LateLatch {
 public:
  enum BufferType {
    kViewProjMatrix,
    kViewMatrix,
    kPoseQuaternion,
    kPoseTranslation,
    // Max transform feedback count is 4, so no more buffers can go here.
    kNumBuffers,
  };

  static size_t GetBufferSize(BufferType type) {
    switch (type) {
      default:
      case kViewProjMatrix:
      case kViewMatrix:
        return 4 * 4 * sizeof(float);
      case kPoseQuaternion:
      case kPoseTranslation:
        return 4 * sizeof(float);
    }
  }

  static size_t GetBufferOffset(BufferType type, int view) {
    switch (type) {
      default:
      case kViewProjMatrix:
        return offsetof(LateLatchOutput, view_proj_matrix) +
               GetBufferSize(type) * view;
      case kViewMatrix:
        return offsetof(LateLatchOutput, view_matrix) +
               GetBufferSize(type) * view;
      case kPoseQuaternion:
        return offsetof(LateLatchOutput, pose_quaternion);
      case kPoseTranslation:
        return offsetof(LateLatchOutput, pose_translation);
    }
  }

  explicit LateLatch(bool is_app_late_latch);
  LateLatch(bool is_app_late_latch, pdx::LocalHandle&& surface_metadata_fd);
  ~LateLatch();

  // Bind the late-latch output data as a GL_UNIFORM_BUFFER. For example,
  // to bind just the view_matrix from the output:
  // BindUniformBuffer(BINDING, offsetof(LateLatchOutput, view_matrix),
  //                   sizeof(mat4));
  // buffer_index is the index of one of the output buffers if more than 1 were
  // requested in the constructor.
  void BindUniformBuffer(GLuint ubo_binding, size_t offset, size_t size) const {
    glBindBufferRange(GL_UNIFORM_BUFFER, ubo_binding, output_buffer_id_, offset,
                      size);
  }

  void BindUniformBuffer(GLuint ubo_binding, BufferType type, int view) const {
    glBindBufferRange(GL_UNIFORM_BUFFER, ubo_binding, output_buffer_id_,
                      GetBufferOffset(type, view), GetBufferSize(type));
  }

  GLuint output_buffer_id() const { return output_buffer_id_; }

  void UnbindUniformBuffer(GLuint ubo_binding) const {
    glBindBufferBase(GL_UNIFORM_BUFFER, ubo_binding, 0);
  }

  void CaptureOutputData(LateLatchOutput* data) const;

  // Add the late latch GL commands for this frame. This should be done just
  // before the first application draw calls that are dependent on the head
  // latest head pose.
  //
  // For efficiency, the application projection and eye_from_head matrices are
  // passed through the late latch shader and output in various combinations to
  // allow for both simple application vertex shaders that can take the view-
  // projection matrix as-is and shaders that need to access the view matrix
  // separately.
  //
  // GL state must be reset to default for this call.
  void AddLateLatch(const LateLatchInput& data) const;

  // After calling AddEdsLateLatch one or more times, this method must be called
  // to add the necessary GL memory barrier to ensure late latch outputs are
  // written before the EDS and warp shaders read them.
  void PostEdsLateLatchBarrier() const {
    // The transform feedback buffer is going to be read as a uniform by EDS,
    // so we need a uniform memory barrier.
    glMemoryBarrier(GL_UNIFORM_BARRIER_BIT);
  }

  // Typically not for use by application code. This method adds the EDS late
  // latch that will adjust the application framebuffer with the latest head
  // pose.
  // buffer_index is the index of one of the output buffers if more than 1 were
  // requested in the constructor.
  void AddEdsLateLatch(const LateLatchInput& data,
                       GLuint render_pose_buffer_object) const;

  // For debugging purposes, capture the output during the next call to
  // AddLateLatch. Set to NULL to reset.
  void SetLateLatchDataCapture(LateLatchOutput* app_late_latch) {
    app_late_latch_output_ = app_late_latch;
  }

  // For debugging purposes, capture the output during the next call to
  // AddEdsLateLatch. Set to NULL to reset.
  void SetEdsLateLatchDataCapture(LateLatchOutput* eds_late_latch) {
    eds_late_latch_output_ = eds_late_latch;
  }

 private:
  LateLatch(const LateLatch&) = delete;
  LateLatch& operator=(const LateLatch&) = delete;

  void LoadLateLatchShader();

  // Late latch shader.
  ShaderProgram late_latch_program_;

  // Async pose ring buffer object.
  GLuint pose_buffer_object_;

  GLuint metadata_buffer_id_;

  // Pose matrix buffers
  GLuint input_buffer_id_;
  GLuint output_buffer_id_;

  bool is_app_late_latch_;
  // During development, these can be used to capture the pose output data.
  LateLatchOutput* app_late_latch_output_;
  LateLatchOutput* eds_late_latch_output_;

  DvrPose* pose_client_;

  pdx::LocalHandle surface_metadata_fd_;
  pdx::LocalHandle pose_buffer_fd_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_LATE_LATCH_H_
