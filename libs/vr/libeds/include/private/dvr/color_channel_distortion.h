#ifndef ANDROID_DVR_COLOR_CHANNEL_DISTORTION_H_
#define ANDROID_DVR_COLOR_CHANNEL_DISTORTION_H_

#include <private/dvr/types.h>

namespace android {
namespace dvr {

// ColorChannelDistortion encapsulates the way one color channel (wavelength)
// is distorted optically when an image is viewed through a lens.
class ColorChannelDistortion {
 public:
  virtual ~ColorChannelDistortion() {}

  // Given a 2d point p, returns the corresponding distorted point.
  // The units of both the input and output points are tan-angle units,
  // which can be computed as the distance on the screen divided by
  // distance from the virtual eye to the screen.  For both the input
  // and output points, the intersection of the optical axis of the lens
  // with the screen defines the origin, the x axis points right, and
  // the y axis points up.
  virtual vec2 Distort(vec2 p) const = 0;

  virtual vec2 DistortInverse(vec2 p) const = 0;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_COLOR_CHANNEL_DISTORTION_H_
