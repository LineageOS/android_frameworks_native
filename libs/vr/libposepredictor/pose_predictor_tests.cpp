#include <gtest/gtest.h>

#include <private/dvr/pose_predictor.h>

namespace android {
namespace dvr {

namespace {

// For comparing expected and actual.
constexpr double kAbsErrorTolerance = 1e-4;

// Test the angular velocity computation from two orientations.
TEST(PosePredictor, AngularVelocity) {
  // Some random rotation axis we will rotate around.
  const vec3d kRotationAxis = vec3d(1, 2, 3).normalized();

  // Some random angle we will be rotating by.
  const double kRotationAngle = M_PI / 30;

  // Random start orientation we are currently at.
  const quatd kStartOrientation = quatd(5, 3, 4, 1).normalized();

  // The orientation we will end up at.
  const quatd kEndOrientation =
      kStartOrientation *
      quatd(Eigen::AngleAxis<double>(kRotationAngle, kRotationAxis));

  // The delta time for going from start orientation to end.
  const float kDeltaTime = 1.0;

  // Compute the angular velocity from start orientation to end.
  const auto angularVelocity = PosePredictor::AngularVelocity(
      kStartOrientation, kEndOrientation, kDeltaTime);

  // Extract the axis and the angular speed.
  const auto angularSpeed = angularVelocity.norm();
  const auto rotationAxis = angularVelocity.normalized();

  // The speed must match.
  EXPECT_NEAR(angularSpeed, kRotationAngle / kDeltaTime, kAbsErrorTolerance);

  // The rotation axis must match.
  EXPECT_NEAR(rotationAxis[0], kRotationAxis[0], kAbsErrorTolerance);
  EXPECT_NEAR(rotationAxis[1], kRotationAxis[1], kAbsErrorTolerance);
  EXPECT_NEAR(rotationAxis[2], kRotationAxis[2], kAbsErrorTolerance);
}

}  // namespace

}  // namespace dvr
}  // namespace android
