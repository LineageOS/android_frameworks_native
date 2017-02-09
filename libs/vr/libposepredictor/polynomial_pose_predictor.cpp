#include <private/dvr/polynomial_pose_predictor.h>

namespace android {
namespace dvr {

// Instantiate the common polynomial types.
template class PolynomialPosePredictor<1, 2>;
template class PolynomialPosePredictor<2, 3>;
template class PolynomialPosePredictor<3, 4>;
template class PolynomialPosePredictor<4, 5>;

}  // namespace dvr
}  // namespace android
