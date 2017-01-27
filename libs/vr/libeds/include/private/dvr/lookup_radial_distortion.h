#ifndef ANDROID_DVR_LOOKUP_RADIAL_DISTORTION_H_
#define ANDROID_DVR_LOOKUP_RADIAL_DISTORTION_H_

#include <vector>

#include <private/dvr/color_channel_distortion.h>

namespace android {
namespace dvr {

// LookupRadialDistortion implements a radial distortion based using using a
// vector of tan(angle) -> multipliers.  This can use measured data directly.
class LookupRadialDistortion : public ColorChannelDistortion {
 public:
  // lookup.x = tan(angle), lookup.y = distance from center multiplier.
  explicit LookupRadialDistortion(const vec2* lookup, size_t count);

  vec2 Distort(vec2 p) const override;
  vec2 DistortInverse(vec2 p) const override;

 private:
  float DistortionFactor(float r) const;
  float DistortRadius(float r) const;

  std::vector<vec2> lookup_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_LOOKUP_RADIAL_DISTORTION_H_
