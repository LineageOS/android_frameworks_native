#include <gtest/gtest.h>

#include <predictor.h>

namespace posepredictor {

namespace {

// For comparing expected and actual.
constexpr real kAbsErrorTolerance = 1e-4;

// Test the angular velocity computation from two orientations.
TEST(PosePredictor, AngularVelocity) {
  // Some random rotation axis we will rotate around.
  const vec3 kRotationAxis = vec3(1, 2, 3).normalized();

  // Some random angle we will be rotating by.
  const real kRotationAngle = M_PI / 30;

  // Random start orientation we are currently at.
  const quat kStartOrientation = quat(5, 3, 4, 1).normalized();

  // The orientation we will end up at.
  const quat kEndOrientation =
      kStartOrientation *
      quat(Eigen::AngleAxis<real>(kRotationAngle, kRotationAxis));

  // The delta time for going from start orientation to end.
  const real kDeltaTime = 1.0;

  // Compute the angular velocity from start orientation to end.
  const auto angularVelocity = Predictor::AngularVelocity(
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

}  // namespace posepredictor
