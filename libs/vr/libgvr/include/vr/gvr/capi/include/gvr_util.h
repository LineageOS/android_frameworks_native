#ifndef VR_GVR_CAPI_INCLUDE_GVR_UTIL_H_
#define VR_GVR_CAPI_INCLUDE_GVR_UTIL_H_

#include <private/dvr/eigen.h>
#include <private/dvr/numeric.h>
#include <private/dvr/types.h>
#include <vr/gvr/capi/include/gvr_types.h>

namespace android {
namespace dvr {

inline gvr_rectf FovRadiansToDegrees(const gvr_rectf& fov) {
  return gvr_rectf{ToDeg(fov.left), ToDeg(fov.right), ToDeg(fov.bottom),
                   ToDeg(fov.top)};
}

inline gvr_rectf FovDegreesToRadians(const gvr_rectf& fov) {
  return gvr_rectf{ToRad(fov.left), ToRad(fov.right), ToRad(fov.bottom),
                   ToRad(fov.top)};
}

inline FieldOfView GvrToDvrFov(const gvr_rectf& fov) {
  gvr_rectf fov_rad = FovDegreesToRadians(fov);
  return FieldOfView(fov_rad.left, fov_rad.right, fov_rad.bottom, fov_rad.top);
}

inline gvr_rectf DvrToGvrFov(const FieldOfView& fov) {
  return FovRadiansToDegrees(
      gvr_rectf{fov.GetLeft(), fov.GetRight(), fov.GetBottom(), fov.GetTop()});
}

inline gvr_mat4f GvrIdentityMatrix() {
  gvr_mat4f identity;
  memset(&identity.m, 0, sizeof(identity.m));
  for (int i = 0; i < 4; i++)
    identity.m[i][i] = 1;
  return identity;
}

inline gvr_mat4f GvrTranslationMatrix(float x, float y, float z) {
  gvr_mat4f trans = GvrIdentityMatrix();
  trans.m[0][3] = x;
  trans.m[1][3] = y;
  trans.m[2][3] = z;
  return trans;
}

inline gvr_mat4f EigenToGvrMatrix(const mat4& m) {
  gvr_mat4f ret;
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j)
      ret.m[i][j] = m(i, j);
  return ret;
}

inline mat4 GvrToEigenMatrix(const gvr::Mat4f& m) {
  mat4 ret;
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j)
      ret(i, j) = m.m[i][j];
  return ret;
}

inline quat GvrToEigenRotation(const gvr_mat4f& m) {
  mat3 ret;
  for (int r = 0; r < 3; ++r)
    for (int c = 0; c < 3; ++c)
      ret(r, c) = m.m[r][c];
  return quat(ret.matrix());
}

inline vec3 GvrToEigenTranslation(const gvr_mat4f& m) {
  return vec3(m.m[0][3], m.m[1][3], m.m[2][3]);
}

// Converts a DVR pose to 6DOF head transform as a GVR matrix.
inline gvr_mat4f PosefToGvrMatrix(const Posef& pose) {
  return EigenToGvrMatrix(pose.GetObjectFromReferenceMatrix());
}

// Converts a DVR pose to 3DOF head transform as a GVR matrix by stripping out
// position translation.
inline gvr_mat4f PosefTo3DofGvrMatrix(const Posef& pose) {
  gvr_mat4f ret = PosefToGvrMatrix(pose);
  ret.m[0][3] = 0;
  ret.m[1][3] = 0;
  ret.m[2][3] = 0;
  return ret;
}

// Converts a GVR matrix to a DVR pose.
inline Posef GvrMatrixToPosef(const gvr_mat4f& m) {
  return Posef(GvrToEigenRotation(m), GvrToEigenTranslation(m)).Inverse();
}

// Calculates an transform with only the yaw and position components of |pose|.
// The inverse of this matrix cancels yaw and position without affecting roll or
// pitch.
inline mat4 CalculateRecenterTransform(const mat4& pose) {
  const vec4 z_axis = pose * vec4::UnitZ();
  const float yaw = std::atan2(z_axis[0], z_axis[2]);
  const vec3 position = pose.translation();
  return mat4(Eigen::AngleAxis<float>(yaw, vec3::UnitY())).translate(position);
}

// Calculates a transform that negates the position component of |pose| and
// offsets the pose by |position|. The inverse of this matrix cancels the
// position component of pose and translates by |position| without affecting
// orientation.
inline mat4 CalculateOffsetTransform(const mat4& pose, const vec3& position) {
  // Transform the origin by the pose matrix to produce the offset that cancels
  // only the position of the pose.
  //          -1          T
  // [ R | t ]  [ 0 ] = -R * t
  // [ 0   1 ]  [ 1 ]
  const vec3 position_offset = (pose.inverse() * vec4(0, 0, 0, 1)).head<3>();
  return mat4(mat4::Identity()).translate(position - position_offset);
}

}  // namespace dvr
}  // namespace android

#endif  // VR_GVR_CAPI_INCLUDE_GVR_UTIL_H_
