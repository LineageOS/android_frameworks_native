#include "include/private/dvr/late_latch.h"

#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

#include <log/log.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/debug.h>
#include <private/dvr/graphics/gpu_profiler.h>
#include <private/dvr/pose_client_internal.h>
#include <private/dvr/sensor_constants.h>
#include <private/dvr/types.h>

#define PRINT_MATRIX 0

#if PRINT_MATRIX
#ifndef LOG_TAG
#define LOG_TAG "latelatch"
#endif

#define PE(str, ...)                                                  \
  fprintf(stderr, "[%s:%d] " str, __FILE__, __LINE__, ##__VA_ARGS__); \
  ALOGI("[%s:%d] " str, __FILE__, __LINE__, ##__VA_ARGS__)

#define PV4(v) PE(#v "=%f,%f,%f,%f\n", v[0], v[1], v[2], v[3]);
#define PM4(m)                                                               \
  PE(#m ":\n %f,%f,%f,%f\n %f,%f,%f,%f\n %f,%f,%f,%f\n %f,%f,%f,%f\n",       \
     m(0, 0), m(0, 1), m(0, 2), m(0, 3), m(1, 0), m(1, 1), m(1, 2), m(1, 3), \
     m(2, 0), m(2, 1), m(2, 2), m(2, 3), m(3, 0), m(3, 1), m(3, 2), m(3, 3))
#endif  // PRINT_MATRIX

#define STRINGIFY2(s) #s
#define STRINGIFY(s) STRINGIFY2(s)

// Compute shader bindings.
// GL_MAX_SHADER_STORAGE_BUFFER_BINDINGS must be at least 8 for GLES 3.1.
#define POSE_BINDING 0
#define RENDER_POSE_BINDING 1
#define INPUT_BINDING 2
#define OUTPUT_BINDING 3

using android::pdx::LocalHandle;

namespace {

static const std::string kShaderLateLatch = R"(  // NOLINT
  struct Pose {
    vec4 quat;
    vec3 pos;
  };

  // Must match DvrPoseAsync C struct.
  struct DvrPoseAsync {
    vec4 orientation;
    vec4 translation;
    vec4 right_orientation;
    vec4 right_translation;
    vec4 angular_velocity;
    vec4 velocity;
    vec4 reserved[2];
  };

  // Must match LateLatchInputData C struct.
  layout(binding = INPUT_BINDING, std140)
  buffer InputData {
    mat4 uEyeFromHeadMat[kSurfaceViewMaxCount];
    mat4 uProjMat[kSurfaceViewMaxCount];
    mat4 uPoseOffset[kSurfaceViewMaxCount];
    mat4 uEdsMat1[kSurfaceViewMaxCount];
    mat4 uEdsMat2[kSurfaceViewMaxCount];
    uint uPoseIndex;
    uint uRenderPoseIndex;
  } bIn;

  // std140 is to layout the structure in a consistent, standard way so we
  // can access it from C++.
  // This structure exactly matches the pose ring buffer in pose_client.h.
  layout(binding = POSE_BINDING, std140)
  buffer PoseBuffer {
    DvrPoseAsync data[kPoseAsyncBufferTotalCount];
  } bPose;

  // Must stay in sync with DisplaySurfaceMetadata C struct.
  // GPU thread 0 will exclusively read in a pose and capture it
  // into this array.
  layout(binding = RENDER_POSE_BINDING, std140)
  buffer DisplaySurfaceMetadata {
    vec4 orientation[kSurfaceBufferMaxCount];
    vec4 translation[kSurfaceBufferMaxCount];
  } bSurfaceData;

  // Must stay in sync with DisplaySurfaceMetadata C struct.
  // Each thread writes to a vertic
  layout(binding = OUTPUT_BINDING, std140)
  buffer Output {
    mat4 viewProjMatrix[kSurfaceViewMaxCount];
    mat4 viewMatrix[kSurfaceViewMaxCount];
    vec4 quaternion;
    vec4 translation;
  } bOut;

  // Thread 0 will also store the single quat/pos pair in shared variables
  // for the other threads to use (left and right eye in this array).
  shared Pose sharedPose[2];

  // Rotate v1 by the given quaternion. This is based on mathfu's
  // Quaternion::Rotate function. It is the typical implementation of this
  // operation. Eigen has a similar method (Quaternion::_transformVector) that
  // supposedly requires fewer operations, but I am skeptical of optimizing
  // shader code without proper profiling first.
  vec3 rotate(vec4 quat, vec3 v1) {
    float ss = 2.0 * quat.w;
    vec3 v = quat.xyz;
    return ss * cross(v, v1) + (ss * quat.w - 1.0) * v1 +
           2.0 * dot(v, v1) * v;
  }

  // See Eigen Quaternion::conjugate;
  // Note that this isn't a true multiplicative inverse unless you can guarantee
  // quat is also normalized, but that typically isn't an issue for our
  // purposes.
  vec4 quatInvert(vec4 quat) {
    return vec4(-quat.xyz, quat.w);
  }

  // This is based on mathfu's Quaternion::operator*(Quaternion)
  // Eigen's version is mathematically equivalent, just notationally different.
  vec4 quatMul(vec4 q1, vec4 q2) {
    return vec4(q1.w * q2.xyz + q2.w * q1.xyz + cross(q1.xyz, q2.xyz),
                q1.w * q2.w - dot(q1.xyz, q2.xyz));
  }

  // Equivalent to pose.h GetObjectFromReferenceMatrix.
  mat4 getInverseMatrix(Pose pose) {
    // Invert quaternion and store fields the way Eigen does so we can
    // keep in sync with Eigen methods easier.
    vec4 quatInv = quatInvert(pose.quat);
    vec3 v = quatInv.xyz;
    float s = quatInv.w;
    // Convert quaternion to matrix. See Eigen Quaternion::toRotationMatrix()
    float x2 = v.x * v.x, y2 = v.y * v.y, z2 = v.z * v.z;
    float sx = s * v.x, sy = s * v.y, sz = s * v.z;
    float xz = v.x * v.z, yz = v.y * v.z, xy = v.x * v.y;
    // Inverse translation.
    vec3 point = -pose.pos;

    return
      mat4(1.0 - 2.0 * (y2 + z2), 2.0 * (xy + sz), 2.0 * (xz - sy), 0.0,
           2.0 * (xy - sz), 1.0 - 2.0 * (x2 + z2), 2.0 * (sx + yz), 0.0,
           2.0 * (sy + xz), 2.0 * (yz - sx), 1.0 - 2.0 * (x2 + y2), 0.0,
           0.0, 0.0, 0.0, 1.0)*
      mat4(1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0,
           point.x, point.y, point.z, 1.0);
  }

  void appLateLatch() {
    uint poseIndex = (gl_LocalInvocationIndex & uint(1));
    mat4 head_from_center = getInverseMatrix(sharedPose[poseIndex]);
    bOut.viewMatrix[gl_LocalInvocationIndex] =
        bIn.uEyeFromHeadMat[gl_LocalInvocationIndex] *
        head_from_center * bIn.uPoseOffset[gl_LocalInvocationIndex];
    bOut.viewProjMatrix[gl_LocalInvocationIndex] =
        bIn.uProjMat[gl_LocalInvocationIndex] *
        bOut.viewMatrix[gl_LocalInvocationIndex];
  }

  // Extract the app frame's pose.
  Pose getPoseFromApp() {
    Pose p;
    p.quat = bSurfaceData.orientation[bIn.uRenderPoseIndex];
    p.pos =  bSurfaceData.translation[bIn.uRenderPoseIndex].xyz;
    return p;
  }

  // See Posef::GetPoseOffset.
  Pose getPoseOffset(Pose p1, Pose p2) {
    Pose p;
    p.quat = quatMul(quatInvert(p2.quat), p1.quat);
    // TODO(jbates) Consider enabling positional EDS when it is better
    //              tested.
    // p.pos = p2.pos - p1.pos;
    p.pos = vec3(0.0);
    return p;
  }

  void edsLateLatch() {
    Pose pose1 = getPoseFromApp();
    Pose correction;
    // Ignore the texture pose if the quat is not unit-length.
    float tex_quat_length = length(pose1.quat);
    uint poseIndex = (gl_LocalInvocationIndex & uint(1));
    if (abs(tex_quat_length - 1.0) < 0.001)
      correction = getPoseOffset(pose1, sharedPose[poseIndex]);
    else
      correction = Pose(vec4(0, 0, 0, 1), vec3(0, 0, 0));
    mat4 eye_old_from_eye_new_matrix = getInverseMatrix(correction);
    bOut.viewProjMatrix[gl_LocalInvocationIndex] =
        bIn.uEdsMat1[gl_LocalInvocationIndex] *
        eye_old_from_eye_new_matrix * bIn.uEdsMat2[gl_LocalInvocationIndex];
    // Currently unused, except for debugging:
    bOut.viewMatrix[gl_LocalInvocationIndex] = eye_old_from_eye_new_matrix;
  }

  // One thread per surface view.
  layout (local_size_x = kSurfaceViewMaxCount, local_size_y = 1,
          local_size_z = 1) in;

  void main() {
    // First, thread 0 late latches pose and stores it into various places.
    if (gl_LocalInvocationIndex == uint(0)) {
      sharedPose[0].quat = bPose.data[bIn.uPoseIndex].orientation;
      sharedPose[0].pos =  bPose.data[bIn.uPoseIndex].translation.xyz;
      sharedPose[1].quat = bPose.data[bIn.uPoseIndex].right_orientation;
      sharedPose[1].pos =  bPose.data[bIn.uPoseIndex].right_translation.xyz;
      if (IS_APP_LATE_LATCH) {
        bSurfaceData.orientation[bIn.uRenderPoseIndex] = sharedPose[0].quat;
        bSurfaceData.translation[bIn.uRenderPoseIndex] = vec4(sharedPose[0].pos, 0.0);
        // TODO(jbates) implement app late-latch support for separate eye poses.
        // App late latch currently uses the same pose for both eye views.
        sharedPose[1] = sharedPose[0];
      }
      bOut.quaternion = sharedPose[0].quat;
      bOut.translation = vec4(sharedPose[0].pos, 0.0);
    }

    // Memory barrier to make sure all threads can see prior writes.
    memoryBarrierShared();

    // Execution barrier to block all threads here until all threads have
    // reached this point -- ensures the late latching is done.
    barrier();

    if (IS_APP_LATE_LATCH)
      appLateLatch();
    else
      edsLateLatch();
  }
)";

}  // anonymous namespace

namespace android {
namespace dvr {

LateLatch::LateLatch(bool is_app_late_latch)
    : LateLatch(is_app_late_latch, LocalHandle()) {}

LateLatch::LateLatch(bool is_app_late_latch,
                     LocalHandle&& surface_metadata_fd)
    : is_app_late_latch_(is_app_late_latch),
      app_late_latch_output_(NULL),
      eds_late_latch_output_(NULL),
      surface_metadata_fd_(std::move(surface_metadata_fd)) {
  CHECK_GL();
  glGenBuffers(1, &input_buffer_id_);
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, input_buffer_id_);
  glBufferData(GL_SHADER_STORAGE_BUFFER, sizeof(LateLatchInput), nullptr,
               GL_DYNAMIC_DRAW);
  glGenBuffers(1, &output_buffer_id_);
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, output_buffer_id_);
  glBufferData(GL_SHADER_STORAGE_BUFFER, sizeof(LateLatchOutput), nullptr,
               GL_DYNAMIC_COPY);
  CHECK_GL();

  pose_client_ = dvrPoseCreate();
  if (!pose_client_) {
    ALOGE("LateLatch Error: failed to create pose client");
  } else {
    int ret = privateDvrPoseGetRingBufferFd(pose_client_, &pose_buffer_fd_);
    if (ret < 0) {
      ALOGE("LateLatch Error: failed to get pose ring buffer");
    }
  }

  glGenBuffers(1, &pose_buffer_object_);
  glGenBuffers(1, &metadata_buffer_id_);
  if (!glBindSharedBufferQCOM) {
    ALOGE("Error: Missing gralloc buffer extension, no pose data");
  } else {
    if (pose_buffer_fd_) {
      glBindBuffer(GL_SHADER_STORAGE_BUFFER, pose_buffer_object_);
      glBindSharedBufferQCOM(GL_SHADER_STORAGE_BUFFER,
                             kPoseAsyncBufferTotalCount * sizeof(DvrPoseAsync),
                             pose_buffer_fd_.Get());
    }
    CHECK_GL();
  }

  glBindBuffer(GL_SHADER_STORAGE_BUFFER, metadata_buffer_id_);
  if (surface_metadata_fd_ && glBindSharedBufferQCOM) {
    glBindSharedBufferQCOM(GL_SHADER_STORAGE_BUFFER,
                           sizeof(DisplaySurfaceMetadata),
                           surface_metadata_fd_.Get());
  } else {
    // Fall back on internal metadata buffer when none provided, for example
    // when distortion is done in the application process.
    glBufferData(GL_SHADER_STORAGE_BUFFER, sizeof(DisplaySurfaceMetadata),
                 nullptr, GL_DYNAMIC_COPY);
  }
  CHECK_GL();
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, 0);

  CHECK_GL();
  LoadLateLatchShader();
}

LateLatch::~LateLatch() {
  glDeleteBuffers(1, &metadata_buffer_id_);
  glDeleteBuffers(1, &input_buffer_id_);
  glDeleteBuffers(1, &output_buffer_id_);
  glDeleteBuffers(1, &pose_buffer_object_);
  dvrPoseDestroy(pose_client_);
}

void LateLatch::LoadLateLatchShader() {
  std::string str;
  str += "\n#define POSE_BINDING " STRINGIFY(POSE_BINDING);
  str += "\n#define RENDER_POSE_BINDING " STRINGIFY(RENDER_POSE_BINDING);
  str += "\n#define INPUT_BINDING " STRINGIFY(INPUT_BINDING);
  str += "\n#define OUTPUT_BINDING " STRINGIFY(OUTPUT_BINDING);
  str += "\n#define kPoseAsyncBufferTotalCount " STRINGIFY(
      kPoseAsyncBufferTotalCount);
  str += "\n#define kSurfaceBufferMaxCount " STRINGIFY(kSurfaceBufferMaxCount);
  str += "\n#define kSurfaceBufferMaxCount " STRINGIFY(kSurfaceBufferMaxCount);
  str += "\n#define kSurfaceViewMaxCount " STRINGIFY(kSurfaceViewMaxCount);
  str += "\n#define IS_APP_LATE_LATCH ";
  str += is_app_late_latch_ ? "true" : "false";
  str += "\n";
  str += kShaderLateLatch;
  late_latch_program_.Link(str);
  CHECK_GL();
}

void LateLatch::CaptureOutputData(LateLatchOutput* data) const {
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, output_buffer_id_);
  LateLatchOutput* out_data = static_cast<LateLatchOutput*>(glMapBufferRange(
      GL_SHADER_STORAGE_BUFFER, 0, sizeof(LateLatchOutput), GL_MAP_READ_BIT));
  *data = *out_data;
  glUnmapBuffer(GL_SHADER_STORAGE_BUFFER);
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, 0);
  CHECK_GL();
}

void LateLatch::AddLateLatch(const LateLatchInput& data) const {
  LOG_ALWAYS_FATAL_IF(!is_app_late_latch_);
  CHECK_GL();
  late_latch_program_.Use();

  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, RENDER_POSE_BINDING,
                   metadata_buffer_id_);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, POSE_BINDING, pose_buffer_object_);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, OUTPUT_BINDING, output_buffer_id_);
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, input_buffer_id_);
  LateLatchInput* adata = (LateLatchInput*)glMapBufferRange(
      GL_SHADER_STORAGE_BUFFER, 0, sizeof(LateLatchInput),
      GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT);
  if (adata)
    *adata = data;
  else
    ALOGE("Error: LateLatchInput gl mapping is null");
  glUnmapBuffer(GL_SHADER_STORAGE_BUFFER);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, INPUT_BINDING, input_buffer_id_);
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, 0);
  CHECK_GL();

  // The output buffer is going to be written but it may be read by
  // earlier shaders, so we need a shader storage memory barrier.
  glMemoryBarrier(GL_SHADER_STORAGE_BUFFER);

  glDispatchCompute(1, 1, 1);
  CHECK_GL();

  // The transform feedback buffer is going to be read as a uniform by the app,
  // so we need a uniform memory barrier.
  glMemoryBarrier(GL_UNIFORM_BARRIER_BIT);

  if (app_late_latch_output_) {
    // Capture the output data:
    CaptureOutputData(app_late_latch_output_);
  }
#if PRINT_MATRIX
  // Print the composed matrix to stderr:
  LateLatchOutput out_data;
  CaptureOutputData(&out_data);
  CHECK_GL();
  PE("LL APP slot:%d\n", data.render_pose_index);
  PM4(data.proj_mat[0]);
  PM4(out_data.view_proj_matrix[0]);
  PM4(out_data.view_proj_matrix[1]);
  PM4(out_data.view_proj_matrix[2]);
  PM4(out_data.view_proj_matrix[3]);
  PM4(out_data.view_matrix[0]);
  PM4(out_data.view_matrix[1]);
  PM4(out_data.view_matrix[2]);
  PM4(out_data.view_matrix[3]);
  PV4(out_data.pose_quaternion);
  PV4(out_data.pose_translation);
#endif

  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, RENDER_POSE_BINDING, 0);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, POSE_BINDING, 0);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, OUTPUT_BINDING, 0);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, INPUT_BINDING, 0);
  glUseProgram(0);
}

void LateLatch::AddEdsLateLatch(const LateLatchInput& data,
                                GLuint render_pose_buffer_object) const {
  LOG_ALWAYS_FATAL_IF(is_app_late_latch_);
  late_latch_program_.Use();

  // Fall back on internal buffer when none is provided.
  if (!render_pose_buffer_object)
    render_pose_buffer_object = metadata_buffer_id_;

  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, RENDER_POSE_BINDING,
                   render_pose_buffer_object);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, POSE_BINDING, pose_buffer_object_);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, OUTPUT_BINDING, output_buffer_id_);
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, input_buffer_id_);
  LateLatchInput* adata = (LateLatchInput*)glMapBufferRange(
      GL_SHADER_STORAGE_BUFFER, 0, sizeof(LateLatchInput),
      GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT);
  *adata = data;
  glUnmapBuffer(GL_SHADER_STORAGE_BUFFER);
  glBindBuffer(GL_SHADER_STORAGE_BUFFER, 0);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, INPUT_BINDING, input_buffer_id_);
  CHECK_GL();

  glDispatchCompute(1, 1, 1);
  CHECK_GL();

  if (eds_late_latch_output_) {
    // Capture the output data:
    CaptureOutputData(eds_late_latch_output_);
  }
#if PRINT_MATRIX
  // Print the composed matrix to stderr:
  LateLatchOutput out_data;
  CaptureOutputData(&out_data);
  CHECK_GL();
  PE("LL EDS\n");
  PM4(out_data.view_proj_matrix[0]);
  PM4(out_data.view_matrix[0]);
  PV4(out_data.pose_quaternion);
  PV4(out_data.pose_translation);
#endif

  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, RENDER_POSE_BINDING, 0);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, POSE_BINDING, 0);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, OUTPUT_BINDING, 0);
  glBindBufferBase(GL_SHADER_STORAGE_BUFFER, INPUT_BINDING, 0);
  glUseProgram(0);
}

}  // namespace dvr
}  // namespace android
