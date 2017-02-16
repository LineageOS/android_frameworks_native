#include <gtest/gtest.h>

#include <linear_predictor.h>

namespace posepredictor {

namespace {

// For comparing expected and actual.
constexpr real kAbsErrorTolerance = 1e-5;

// The default rotation axis we will be using.
const vec3 kRotationAxis = vec3(1, 4, 3).normalized();

// Linearly interpolate between a and b.
vec3 lerp(const vec3& a, const vec3& b, real t) { return (b - a) * t + a; }

// Linearly interpolate between two angles and return the resulting rotation as
// a quaternion (around the kRotationAxis).
quat qlerp(real angle1, real angle2, real t) {
  return quat(
      Eigen::AngleAxis<real>((angle2 - angle1) * t + angle1, kRotationAxis));
}

// Compare two positions.
void TestPosition(const vec3& expected, const vec3& actual) {
  for (int i = 0; i < 3; ++i) {
    EXPECT_NEAR(expected[i], actual[i], kAbsErrorTolerance);
  }
}

// Compare two orientations.
void TestOrientation(const quat& expected, const quat& actual) {
  // abs(expected.dot(actual)) > 1-eps
  EXPECT_GE(std::abs(actual.coeffs().dot(expected.coeffs())), 0.99);
}
}

// Test the extrapolation from two samples.
TEST(LinearPosePredictorTest, Extrapolation) {
  LinearPosePredictor predictor;

  // We wil extrapolate linearly from [position|orientation] 1 -> 2.
  const vec3 position1(0, 0, 0);
  const vec3 position2(1, 2, 3);
  const real angle1 = M_PI * 0.3;
  const real angle2 = M_PI * 0.5;
  const quat orientation1(Eigen::AngleAxis<real>(angle1, kRotationAxis));
  const quat orientation2(Eigen::AngleAxis<real>(angle2, kRotationAxis));
  const int64_t t1_ns = 0;           //< First sample time stamp
  const int64_t t2_ns = 10;          //< The second sample time stamp
  const int64_t eval_left_ns = 23;   //< The eval time for left
  const int64_t eval_right_ns = 31;  //< The eval time for right
  Pose start_pose, end_pose, extrapolated_pose;

  predictor.Add(Pose{
      .position = position1, .orientation = orientation1, .time_ns = t1_ns});

  predictor.Add(Pose{
      .position = position2, .orientation = orientation2, .time_ns = t2_ns});

  // Extrapolate from t1 - t2 to eval_[left/right].
  extrapolated_pose = predictor.Predict(eval_left_ns);

  // The interpolation factors for left and right.
  const auto left_t = (eval_left_ns - t1_ns) / static_cast<real>(t2_ns - t1_ns);
  EXPECT_EQ(2.3, left_t);

  TestPosition(lerp(position1, position2, left_t), extrapolated_pose.position);

  TestOrientation(qlerp(angle1, angle2, left_t), extrapolated_pose.orientation);

  extrapolated_pose = predictor.Predict(eval_right_ns);

  const auto right_t =
      (eval_right_ns - t1_ns) / static_cast<real>(t2_ns - t1_ns);
  EXPECT_EQ(3.1, right_t);

  TestPosition(lerp(position1, position2, right_t), extrapolated_pose.position);

  TestOrientation(qlerp(angle1, angle2, right_t),
                  extrapolated_pose.orientation);
}

// Test three samples, where the last two samples have the same timestamp.
TEST(LinearPosePredictorTest, DuplicateSamples) {
  LinearPosePredictor predictor;

  const vec3 position1(0, 0, 0);
  const vec3 position2(1, 2, 3);
  const vec3 position3(2, 2, 3);
  const real angle1 = M_PI * 0.3;
  const real angle2 = M_PI * 0.5;
  const real angle3 = M_PI * 0.65;
  const quat orientation1(Eigen::AngleAxis<real>(angle1, kRotationAxis));
  const quat orientation2(Eigen::AngleAxis<real>(angle2, kRotationAxis));
  const quat orientation3(Eigen::AngleAxis<real>(angle3, kRotationAxis));
  const int64_t t1_ns = 0;
  const int64_t t2_ns = 10;
  const int64_t eval_left_ns = 27;
  const int64_t eval_right_ns = 31;
  Pose extrapolated_pose;

  predictor.Add(Pose{
      .position = position1, .orientation = orientation1, .time_ns = t1_ns});

  predictor.Add(Pose{
      .position = position2, .orientation = orientation2, .time_ns = t2_ns});

  {
    // Extrapolate from t1 - t2 to eval_[left/right].
    extrapolated_pose = predictor.Predict(eval_left_ns);

    // The interpolation factors for left and right.
    const auto left_t =
        (eval_left_ns - t1_ns) / static_cast<real>(t2_ns - t1_ns);

    // Test the result.
    TestPosition(lerp(position1, position2, left_t),
                 extrapolated_pose.position);

    TestOrientation(qlerp(angle1, angle2, left_t),
                    extrapolated_pose.orientation);

    extrapolated_pose = predictor.Predict(eval_right_ns);

    const auto right_t =
        (eval_right_ns - t1_ns) / static_cast<real>(t2_ns - t1_ns);

    TestPosition(lerp(position1, position2, right_t),
                 extrapolated_pose.position);

    TestOrientation(qlerp(angle1, angle2, right_t),
                    extrapolated_pose.orientation);
  }

  // Sending a duplicate sample here.
  predictor.Add(Pose{
      .position = position3, .orientation = orientation3, .time_ns = t2_ns});

  {
    // Extrapolate from t1 - t2 to eval_[left/right].
    extrapolated_pose = predictor.Predict(eval_left_ns);

    // The interpolation factors for left and right.
    const auto left_t =
        (eval_left_ns - t1_ns) / static_cast<real>(t2_ns - t1_ns);

    TestPosition(lerp(position1, position3, left_t),
                 extrapolated_pose.position);

    TestOrientation(qlerp(angle1, angle3, left_t),
                    extrapolated_pose.orientation);

    extrapolated_pose = predictor.Predict(eval_right_ns);

    const auto right_t =
        (eval_right_ns - t1_ns) / static_cast<real>(t2_ns - t1_ns);

    // Test the result.

    TestPosition(lerp(position1, position3, right_t),
                 extrapolated_pose.position);

    TestOrientation(qlerp(angle1, angle3, right_t),
                    extrapolated_pose.orientation);
  }
}

}  // namespace posepredictor
