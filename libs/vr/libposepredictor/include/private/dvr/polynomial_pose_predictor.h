#ifndef ANDROID_DVR_POLYNOMIAL_POSE_PREDICTOR_H_
#define ANDROID_DVR_POLYNOMIAL_POSE_PREDICTOR_H_

#include <vector>

#include <Eigen/Dense>

#include "buffered_predictor.h"

namespace android {
namespace dvr {

// Make a polynomial prediction of the form
// y = coefficients_[0] + coefficients_[1] * t + coefficients_[2] * t^2 + ...
// where t is time and y is the position and orientation.
// We recompute the coefficients whenever we add a new sample using
// training_window previous samples.
template <size_t PolynomialDegree, size_t TrainingWindow>
class PolynomialPosePredictor : public BufferedPredictor {
 public:
  PolynomialPosePredictor(double regularization = 1e-9)
      : BufferedPredictor(TrainingWindow), regularization_(regularization) {
    static_assert(PolynomialDegree + 1 >= TrainingWindow,
                  "Underconstrained polynomial regressor");
  }

  ~PolynomialPosePredictor() = default;

  // We convert pose samples into a vector for matrix arithmetic using this
  // mapping.
  enum Components {
    kPositionX = 0,
    kPositionY,
    kPositionZ,
    kOrientationX,
    kOrientationY,
    kOrientationZ,
    kOrientationW,
    kNumComponents
  };

  // Add a new sample.
  void Add(const Sample& sample, DvrPoseAsync* out_pose) override {
    // Add the sample to the ring buffer.
    BufferedPredictor::BufferSample(sample);

    Eigen::Matrix<double, TrainingWindow, kNumComponents> values;

    // Get the pose samples into matrices for fitting.
    double t_vector[TrainingWindow];
    for (size_t i = 0; i < TrainingWindow; ++i) {
      const auto& prev_sample = PrevSample(i);

      t_vector[i] = NsToT(prev_sample.time_ns);

      // Save the values we will be fitting to at each sample time.
      values(i, kPositionX) = prev_sample.position.x();
      values(i, kPositionY) = prev_sample.position.y();
      values(i, kPositionZ) = prev_sample.position.z();
      values(i, kOrientationX) = prev_sample.orientation.x();
      values(i, kOrientationY) = prev_sample.orientation.y();
      values(i, kOrientationZ) = prev_sample.orientation.z();
      values(i, kOrientationW) = prev_sample.orientation.w();
    }

    // Some transient matrices for solving for coefficient matrix.
    Eigen::Matrix<double, PolynomialDegree + 1, PolynomialDegree + 1> M;
    Eigen::Vector<double, PolynomialDegree + 1> d;
    Eigen::Vector<double, PolynomialDegree + 1> p;

    // Create a polynomial fit for each component.
    for (size_t component = 0; component < kNumComponents; ++component) {
      // A = [ 1 t t^2 ... ]'
      // x = [ coefficients[0] coefficients[1] .... ]'
      // b = [ position.x ]'
      // We would like to solve A' x + regularization * I = b'
      // given the samples we have in our training window.
      //
      // The loop below will compute:
      // M = A' * A
      // d = A' * b
      // so we can solve M * coefficients + regularization * I = b

      M.setIdentity();
      d.setZero();
      p[0] = 1;

      // M = regularization * I
      M = M * regularization_;

      // Accumulate the poses in the training window.
      for (size_t i = 0; i < TrainingWindow; ++i) {
        // Compute the polynomial at this sample.
        for (size_t j = 1; j <= PolynomialDegree; ++j) {
          p[j] = p[j - 1] * t_vector[i];
        }

        // Accumulate the left and right hand sides.
        M = M + p * p.transpose();
        d = d + p * values(i, component);
      }

      // M is symmetric, positive semi-definite.
      // Note: This is not the most accurate solver out there but is fast.
      coefficients_.row(component) = Eigen::LLT<Eigen::MatrixXd>(M).solve(d);
    }

    // Fill out the out_pose at this sample.
    Predict(sample.time_ns, sample.time_ns, out_pose);
  }

  // Predict using the polynomial coefficients.
  void Predict(int64_t left_time_ns, int64_t right_time_ns,
               DvrPoseAsync* out_pose) const override {
    // Predict the left side.
    const auto left = SamplePolynomial(left_time_ns);
    out_pose->translation = {static_cast<float>(left[kPositionX]),
                             static_cast<float>(left[kPositionY]),
                             static_cast<float>(left[kPositionZ])};
    out_pose->orientation = normalize(left[kOrientationX], left[kOrientationY],
                                      left[kOrientationZ], left[kOrientationW]);

    // Predict the right side.
    const auto right = SamplePolynomial(right_time_ns);
    out_pose->right_translation = {static_cast<float>(right[kPositionX]),
                                   static_cast<float>(right[kPositionY]),
                                   static_cast<float>(right[kPositionZ])};
    out_pose->right_orientation =
        normalize(right[kOrientationX], right[kOrientationY],
                  right[kOrientationZ], right[kOrientationW]);

    // Finite differencing to estimate the velocities.
    const auto a = SamplePolynomial(
        (left_time_ns + right_time_ns - kFiniteDifferenceNs) / 2);
    const auto b = SamplePolynomial(
        (left_time_ns + right_time_ns + kFiniteDifferenceNs) / 2);

    out_pose->velocity = {static_cast<float>((b[kPositionX] - a[kPositionX]) /
                                             NsToSeconds(kFiniteDifferenceNs)),
                          static_cast<float>((b[kPositionY] - a[kPositionY]) /
                                             NsToSeconds(kFiniteDifferenceNs)),
                          static_cast<float>((b[kPositionZ] - a[kPositionZ]) /
                                             NsToSeconds(kFiniteDifferenceNs)),
                          0.0f};

    // Get the predicted orientations into quaternions, which are probably not
    // quite unit.
    const quatd a_orientation(a[kOrientationW], a[kOrientationX],
                              a[kOrientationY], a[kOrientationZ]);
    const quatd b_orientation(b[kOrientationW], b[kOrientationX],
                              b[kOrientationY], b[kOrientationZ]);
    const auto angular_velocity =
        AngularVelocity(a_orientation.normalized(), b_orientation.normalized(),
                        NsToSeconds(kFiniteDifferenceNs));

    out_pose->angular_velocity = {static_cast<float>(angular_velocity[0]),
                                  static_cast<float>(angular_velocity[1]),
                                  static_cast<float>(angular_velocity[2]),
                                  0.0f};
    out_pose->timestamp_ns = left_time_ns;
    out_pose->flags = DVR_POSE_FLAG_HEAD | DVR_POSE_FLAG_VALID;
    memset(out_pose->pad, 0, sizeof(out_pose->pad));
  }

 private:
  // Take a quaternion and return a normalized version in a float32x4_t.
  static float32x4_t normalize(double x, double y, double z, double w) {
    const auto l = std::sqrt(x * x + y * y + z * z + w * w);
    return {static_cast<float>(x / l), static_cast<float>(y / l),
            static_cast<float>(z / l), static_cast<float>(w / l)};
  }

  // Evaluate the polynomial at a particular time.
  Eigen::Vector<double, kNumComponents> SamplePolynomial(
      int64_t time_ns) const {
    const auto t = NsToT(time_ns);
    Eigen::Vector<double, PolynomialDegree + 1> polynomial;
    double current_polynomial = t;

    // Compute polynomial = [ 1 t t^2 ... ]
    polynomial[0] = 1;
    for (size_t degree = 1; degree <= PolynomialDegree;
         ++degree, current_polynomial *= t) {
      polynomial[degree] = polynomial[degree - 1] * t;
    }

    // The coefficients_ = [ numComponents x (polynomial degree + 1) ].
    return coefficients_ * polynomial;
  }

  // Convert a time in nanoseconds to t.
  // We could use the seconds as t but this would create make it more difficult
  // to tweak the regularization amount. So we subtract the last sample time so
  // the scale of the regularization constant doesn't change as a function of
  // time.
  double NsToT(int64_t time_ns) const {
    return NsToSeconds(time_ns - buffer_[current_pose_index_].time_ns);
  }

  // The ridge regularization constant.
  double regularization_;

  // This is where we store the polynomial coefficients.
  Eigen::Matrix<double, kNumComponents, PolynomialDegree + 1> coefficients_;
};

// Some common polynomial types.
extern template class PolynomialPosePredictor<1, 2>;
extern template class PolynomialPosePredictor<2, 3>;
extern template class PolynomialPosePredictor<3, 4>;
extern template class PolynomialPosePredictor<4, 5>;

using QuadricPosePredictor = PolynomialPosePredictor<2, 3>;
using CubicPosePredictor = PolynomialPosePredictor<3, 4>;
using QuarticPosePredictor = PolynomialPosePredictor<4, 5>;
}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_POSE_PREDICTOR_H_
