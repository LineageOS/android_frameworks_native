#ifndef POSEPREDICTOR_POLYNOMIAL_POSE_PREDICTOR_H_
#define POSEPREDICTOR_POLYNOMIAL_POSE_PREDICTOR_H_

#include <vector>

#include <Eigen/Dense>

#include "buffered_predictor.h"

namespace posepredictor {

// Make a polynomial prediction of the form
// y = coefficients_[0] + coefficients_[1] * t + coefficients_[2] * t^2 + ...
// where t is time and y is the position and orientation.
// We recompute the coefficients whenever we add a new sample using
// training_window previous samples.
template <size_t PolynomialDegree, size_t TrainingWindow>
class PolynomialPosePredictor : public BufferedPredictor {
 public:
  PolynomialPosePredictor(real regularization = 1e-9)
      : BufferedPredictor(TrainingWindow), regularization_(regularization) {
    static_assert(TrainingWindow >= PolynomialDegree + 1,
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
  void Add(const Pose& sample) override {
    // Add the sample to the ring buffer.
    BufferedPredictor::BufferSample(sample);

    Eigen::Matrix<real, TrainingWindow, kNumComponents> values;

    // Get the pose samples into matrices for fitting.
    real t_vector[TrainingWindow];
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
    Eigen::Matrix<real, PolynomialDegree + 1, PolynomialDegree + 1> M;
    Eigen::Matrix<real, PolynomialDegree + 1, 1> d;
    Eigen::Matrix<real, PolynomialDegree + 1, 1> p;

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
  }

  // Predict using the polynomial coefficients.
  Pose Predict(int64_t time_ns) const override {
    // Predict the left side.
    const auto components = SamplePolynomial(time_ns);

    return {time_ns,
            vec3(components[kPositionX], components[kPositionY],
                 components[kPositionZ]),
            quat(components[kOrientationW], components[kOrientationX],
                 components[kOrientationY], components[kOrientationZ])
                .normalized()};
  }

 private:
  // Evaluate the polynomial at a particular time.
  Eigen::Matrix<real, kNumComponents, 1> SamplePolynomial(
      int64_t time_ns) const {
    const auto t = NsToT(time_ns);
    Eigen::Matrix<real, PolynomialDegree + 1, 1> polynomial;
    real current_polynomial = t;

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
  real NsToT(int64_t time_ns) const {
    return NsToSeconds(time_ns - buffer_[current_pose_index_].time_ns);
  }

  // The ridge regularization constant.
  real regularization_;

  // This is where we store the polynomial coefficients.
  Eigen::Matrix<real, kNumComponents, PolynomialDegree + 1> coefficients_;
};

// Some common polynomial types.
extern template class PolynomialPosePredictor<1, 2>;
extern template class PolynomialPosePredictor<2, 3>;
extern template class PolynomialPosePredictor<3, 4>;
extern template class PolynomialPosePredictor<4, 5>;

using QuadricPosePredictor = PolynomialPosePredictor<2, 3>;
using CubicPosePredictor = PolynomialPosePredictor<3, 4>;
using QuarticPosePredictor = PolynomialPosePredictor<4, 5>;

}  // namespace posepredictor

#endif  // POSEPREDICTOR_POLYNOMIAL_POSE_PREDICTOR_H_
