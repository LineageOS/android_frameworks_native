#include <polynomial_predictor.h>

namespace posepredictor {

// Instantiate the common polynomial types.
template class PolynomialPosePredictor<1, 2>;
template class PolynomialPosePredictor<2, 3>;
template class PolynomialPosePredictor<3, 4>;
template class PolynomialPosePredictor<4, 5>;

}  // namespace posepredictor
