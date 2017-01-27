#include <iostream>

#include <gtest/gtest.h>

#include <private/dvr/linear_pose_predictor.h>

namespace android {
namespace dvr {

namespace {

// For comparing expected and actual.
constexpr double kAbsErrorTolerance = 1e-5;

// The default rotation axis we will be using.
const vec3d kRotationAxis = vec3d(1, 4, 3).normalized();

// Linearly interpolate between a and b.
vec3d lerp(const vec3d& a, const vec3d& b, double t) { return (b - a) * t + a; }

// Linearly interpolate between two angles and return the resulting rotation as
// a quaternion (around the kRotationAxis).
quatd qlerp(double angle1, double angle2, double t) {
  return quatd(
      Eigen::AngleAxis<double>((angle2 - angle1) * t + angle1, kRotationAxis));
}

// Compare two positions.
void TestPosition(const vec3d& expected, const float32x4_t& actual) {
  for (int i = 0; i < 3; ++i) {
    EXPECT_NEAR(expected[i], static_cast<double>(actual[i]),
                kAbsErrorTolerance);
  }
}

// Compare two orientations.
void TestOrientation(const quatd& expected, const float32x4_t& actual) {
  // abs(expected.dot(actual)) > 1-eps
  EXPECT_GE(std::abs(vec4d(actual[0], actual[1], actual[2], actual[3])
                         .dot(expected.coeffs())),
            0.99);
}
}

// Test the extrapolation from two samples.
TEST(LinearPosePredictorTest, Extrapolation) {
  LinearPosePredictor predictor;

  // We wil extrapolate linearly from [position|orientation] 1 -> 2.
  const vec3d position1(0, 0, 0);
  const vec3d position2(1, 2, 3);
  const double angle1 = M_PI * 0.3;
  const double angle2 = M_PI * 0.5;
  const quatd orientation1(Eigen::AngleAxis<double>(angle1, kRotationAxis));
  const quatd orientation2(Eigen::AngleAxis<double>(angle2, kRotationAxis));
  const int64_t t1_ns = 0;           //< First sample time stamp
  const int64_t t2_ns = 10;          //< The second sample time stamp
  const int64_t eval_left_ns = 23;   //< The eval time for left
  const int64_t eval_right_ns = 31;  //< The eval time for right
  DvrPoseAsync start_pose, end_pose, extrapolated_pose;

  predictor.Add(
      PosePredictor::Sample{
          .position = position1, .orientation = orientation1, .time_ns = t1_ns},
      &start_pose);

  // The start pose is passthough.
  TestPosition(position1, start_pose.translation);
  TestPosition(position1, start_pose.right_translation);
  TestOrientation(orientation1, start_pose.orientation);
  TestOrientation(orientation1, start_pose.right_orientation);
  EXPECT_EQ(t1_ns, start_pose.timestamp_ns);

  predictor.Add(
      PosePredictor::Sample{
          .position = position2, .orientation = orientation2, .time_ns = t2_ns},
      &end_pose);

  TestPosition(position2, end_pose.translation);
  TestPosition(position2, end_pose.right_translation);
  TestOrientation(orientation2, end_pose.orientation);
  TestOrientation(orientation2, end_pose.right_orientation);
  EXPECT_EQ(t2_ns, end_pose.timestamp_ns);

  // Extrapolate from t1 - t2 to eval_[left/right].
  predictor.Predict(eval_left_ns, eval_right_ns, &extrapolated_pose);

  // The interpolation factors for left and right.
  const auto left_t =
      (eval_left_ns - t1_ns) / static_cast<double>(t2_ns - t1_ns);
  EXPECT_EQ(2.3, left_t);

  const auto right_t =
      (eval_right_ns - t1_ns) / static_cast<double>(t2_ns - t1_ns);
  EXPECT_EQ(3.1, right_t);

  TestPosition(lerp(position1, position2, left_t),
               extrapolated_pose.translation);
  TestPosition(lerp(position1, position2, right_t),
               extrapolated_pose.right_translation);
  TestOrientation(qlerp(angle1, angle2, left_t), extrapolated_pose.orientation);
  TestOrientation(qlerp(angle1, angle2, right_t),
                  extrapolated_pose.right_orientation);
}

// Test three samples, where the last two samples have the same timestamp.
TEST(LinearPosePredictorTest, DuplicateSamples) {
  LinearPosePredictor predictor;

  const vec3d position1(0, 0, 0);
  const vec3d position2(1, 2, 3);
  const vec3d position3(2, 2, 3);
  const double angle1 = M_PI * 0.3;
  const double angle2 = M_PI * 0.5;
  const double angle3 = M_PI * 0.65;
  const quatd orientation1(Eigen::AngleAxis<double>(angle1, kRotationAxis));
  const quatd orientation2(Eigen::AngleAxis<double>(angle2, kRotationAxis));
  const quatd orientation3(Eigen::AngleAxis<double>(angle3, kRotationAxis));
  const int64_t t1_ns = 0;
  const int64_t t2_ns = 10;
  const int64_t eval_left_ns = 27;
  const int64_t eval_right_ns = 31;
  DvrPoseAsync start_pose, end_pose, extrapolated_pose;

  predictor.Add(
      PosePredictor::Sample{
          .position = position1, .orientation = orientation1, .time_ns = t1_ns},
      &start_pose);

  predictor.Add(
      PosePredictor::Sample{
          .position = position2, .orientation = orientation2, .time_ns = t2_ns},
      &end_pose);

  {
    // Extrapolate from t1 - t2 to eval_[left/right].
    predictor.Predict(eval_left_ns, eval_right_ns, &extrapolated_pose);

    // The interpolation factors for left and right.
    const auto left_t =
        (eval_left_ns - t1_ns) / static_cast<double>(t2_ns - t1_ns);
    const auto right_t =
        (eval_right_ns - t1_ns) / static_cast<double>(t2_ns - t1_ns);

    // Test the result.
    TestPosition(lerp(position1, position2, left_t),
                 extrapolated_pose.translation);
    TestPosition(lerp(position1, position2, right_t),
                 extrapolated_pose.right_translation);
    TestOrientation(qlerp(angle1, angle2, left_t),
                    extrapolated_pose.orientation);
    TestOrientation(qlerp(angle1, angle2, right_t),
                    extrapolated_pose.right_orientation);
  }

  // Sending a duplicate sample here.
  predictor.Add(
      PosePredictor::Sample{
          .position = position3, .orientation = orientation3, .time_ns = t2_ns},
      &end_pose);

  {
    // Extrapolate from t1 - t2 to eval_[left/right].
    predictor.Predict(eval_left_ns, eval_right_ns, &extrapolated_pose);

    // The interpolation factors for left and right.
    const auto left_t =
        (eval_left_ns - t1_ns) / static_cast<double>(t2_ns - t1_ns);
    const auto right_t =
        (eval_right_ns - t1_ns) / static_cast<double>(t2_ns - t1_ns);

    // Test the result.
    TestPosition(lerp(position1, position3, left_t),
                 extrapolated_pose.translation);
    TestPosition(lerp(position1, position3, right_t),
                 extrapolated_pose.right_translation);
    TestOrientation(qlerp(angle1, angle3, left_t),
                    extrapolated_pose.orientation);
    TestOrientation(qlerp(angle1, angle3, right_t),
                    extrapolated_pose.right_orientation);
  }
}

}  // namespace dvr
}  // namespace android
