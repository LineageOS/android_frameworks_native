#include "include/private/dvr/lookup_radial_distortion.h"

namespace android {
namespace dvr {

LookupRadialDistortion::LookupRadialDistortion(const vec2* lookup, size_t count)
    : lookup_(lookup, lookup + count) {}

float LookupRadialDistortion::DistortionFactor(float r) const {
  for (size_t i = 1; i < lookup_.size(); ++i) {
    if (lookup_[i].x() > r) {
      float t =
          (r - lookup_[i - 1].x()) / (lookup_[i].x() - lookup_[i - 1].x());
      return lookup_[i - 1].y() + t * (lookup_[i].y() - lookup_[i - 1].y());
    }
  }
  return lookup_.back().y();
}

float LookupRadialDistortion::DistortRadius(float r) const {
  return r * DistortionFactor(r);
}

vec2 LookupRadialDistortion::Distort(vec2 p) const {
  return p * DistortionFactor(p.norm());
}

vec2 LookupRadialDistortion::DistortInverse(vec2 p) const {
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

}  // namespace dvr
}  // namespace android
