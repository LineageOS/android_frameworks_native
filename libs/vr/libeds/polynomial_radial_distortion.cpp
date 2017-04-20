#include "include/private/dvr/polynomial_radial_distortion.h"

namespace android {
namespace dvr {

PolynomialRadialDistortion::PolynomialRadialDistortion(
    const std::vector<float>& coefficients)
    : coefficients_(coefficients) {}

float PolynomialRadialDistortion::DistortionFactor(float r_squared) const {
  float r_factor = 1.0f;
  float distortion_factor = 1.0f;

  for (float ki : coefficients_) {
    r_factor *= r_squared;
    distortion_factor += ki * r_factor;
  }

  return distortion_factor;
}

float PolynomialRadialDistortion::DistortRadius(float r) const {
  return r * DistortionFactor(r * r);
}

vec2 PolynomialRadialDistortion::Distort(vec2 p) const {
  return p * DistortionFactor(p.squaredNorm());
}

vec2 PolynomialRadialDistortion::DistortInverse(vec2 p) const {
  // Secant method.
  const float radius = p.norm();
  float r0 = radius / 0.9f;
  float r1 = radius * 0.9f;
  float r2;
  float dr0 = radius - DistortRadius(r0);
  float dr1;
  while (fabsf(r1 - r0) > 0.0001f /** 0.1mm */) {
    dr1 = radius - DistortRadius(r1);
    r2 = r1 - dr1 * ((r1 - r0) / (dr1 - dr0));
    r0 = r1;
    r1 = r2;
    dr0 = dr1;
  }
  return (r1 / radius) * p;
}

const std::vector<float>& PolynomialRadialDistortion::GetCoefficients() const {
  return coefficients_;
}

}  // namespace dvr
}  // namespace android
