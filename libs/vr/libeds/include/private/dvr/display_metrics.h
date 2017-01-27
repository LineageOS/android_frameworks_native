#ifndef ANDROID_DVR_DISPLAY_METRICS_H_
#define ANDROID_DVR_DISPLAY_METRICS_H_

#include <private/dvr/types.h>

namespace android {
namespace dvr {

enum class DisplayOrientation { kPortrait, kLandscape };

// DisplayMetrics encapsulates metrics describing a display to be used
// with a head mount to create a head mounted display.
class DisplayMetrics {
 public:
  DisplayMetrics();
  // Constructs a DisplayMetrics given a display size in pixels,
  // meters per pixel, border size in meters, and frame duration in
  // seconds.
  //
  // size_pixels The size of the display in pixels.
  // meters_per_pixel The meters per pixel in each dimension.
  // border_size_meters The size of the border around the display
  //     in meters.  When the device sits on a surface in the proper
  //     orientation this is the distance from the surface to the edge
  //     of the display.
  // frame_duration_seconds The duration in seconds of each frame
  //     (i.e., 1 / framerate).
  DisplayMetrics(vec2i size_pixels, vec2 meters_per_pixel,
                 float border_size_meters, float frame_duration_seconds,
                 DisplayOrientation orientation);

  // Gets the size of the display in physical pixels (not logical pixels).
  vec2i GetSizePixels() const { return size_pixels_; }

  DisplayOrientation GetOrientation() const { return orientation_; }
  bool IsPortrait() const {
    return orientation_ == DisplayOrientation::kPortrait;
  }

  // Gets the size of the display in meters.
  vec2 GetSizeMeters() const {
    return vec2(static_cast<float>(size_pixels_[0]),
                static_cast<float>(size_pixels_[1]))
               .array() *
           meters_per_pixel_.array();
  }

  // Gets the meters per pixel.
  vec2 GetMetersPerPixel() const { return meters_per_pixel_; }

  // Gets the size of the border around the display.
  // For a phone in landscape position this would be the distance from
  // the bottom the edge of the phone to the bottom of the screen.
  float GetBorderSizeMeters() const { return border_size_meters_; }

  // Gets the frame duration in seconds for the display.
  float GetFrameDurationSeconds() const { return frame_duration_seconds_; }

  // Toggles the orientation and swaps all of the settings such that the
  // display is being held in the other orientation.
  void ToggleOrientation();

  // Override the meters per pixel.
  void SetMetersPerPixel(const vec2& meters_per_pixel) {
    meters_per_pixel_ = meters_per_pixel;
  }

 private:
  vec2i size_pixels_;
  vec2 meters_per_pixel_;
  float border_size_meters_;
  float frame_duration_seconds_;
  DisplayOrientation orientation_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DISPLAY_METRICS_H_
