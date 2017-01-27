#ifndef ANDROID_DVR_IDENTITY_DISTORTION_H_
#define ANDROID_DVR_IDENTITY_DISTORTION_H_

#include <private/dvr/color_channel_distortion.h>

namespace android {
namespace dvr {

// Provides an identity distortion operation if running the device without any
// lenses.
class IdentityDistortion : public ColorChannelDistortion {
 public:
  IdentityDistortion() {}

  vec2 Distort(vec2 p) const override { return p; }

  vec2 DistortInverse(vec2 p) const override { return p; }
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_IDENTITY_DISTORTION_H_
