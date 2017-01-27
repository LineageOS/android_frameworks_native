#ifndef ANDROID_DVR_POLYNOMIAL_RADIAL_DISTORTION_H_
#define ANDROID_DVR_POLYNOMIAL_RADIAL_DISTORTION_H_

#include <vector>

#include <private/dvr/color_channel_distortion.h>

namespace android {
namespace dvr {

// PolynomialRadialDistortion implements a radial distortion based using
// a set of coefficients describing a polynomial function.
// See http://en.wikipedia.org/wiki/Distortion_(optics).
//
// Unless otherwise stated, the units used in this class are tan-angle units
// which can be computed as distance on the screen divided by distance from the
// virtual eye to the screen.
class PolynomialRadialDistortion : public ColorChannelDistortion {
 public:
  // Construct a PolynomialRadialDistortion with coefficients for
  // the radial distortion equation:
  //
  //   p' = p (1 + K1 r^2 + K2 r^4 + ... + Kn r^(2n))
  //
  // where r is the distance in tan-angle units from the optical center,
  // p the input point and p' the output point.
  // The provided vector contains the coefficients for the even monomials
  // in the distortion equation: coefficients[0] is K1, coefficients[1] is K2,
  // etc.  Thus the polynomial used for distortion has degree
  // (2 * coefficients.size()).
  explicit PolynomialRadialDistortion(const std::vector<float>& coefficients);

  // Given a radius (measuring distance from the optical axis of the lens),
  // returns the distortion factor for that radius.
  float DistortionFactor(float r_squared) const;

  // Given a radius (measuring distance from the optical axis of the lens),
  // returns the corresponding distorted radius.
  float DistortRadius(float r) const;

  // Given a 2d point p, returns the corresponding distorted point.
  // distance from the virtual eye to the screen.  The optical axis
  // of the lens defines the origin for both input and output points.
  vec2 Distort(vec2 p) const override;

  // Given a 2d point p, returns the point that would need to be passed to
  // Distort to get point p (approximately).
  vec2 DistortInverse(vec2 p) const override;

  // Returns the distortion coefficients.
  const std::vector<float>& GetCoefficients() const;

 private:
  std::vector<float> coefficients_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_POLYNOMIAL_RADIAL_DISTORTION_H_
