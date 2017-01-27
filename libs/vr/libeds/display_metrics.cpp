#include "include/private/dvr/display_metrics.h"

namespace android {
namespace dvr {

DisplayMetrics::DisplayMetrics(vec2i size_pixels, vec2 meters_per_pixel,
                               float border_size_meters,
                               float frame_duration_seconds,
                               DisplayOrientation orientation)
    : size_pixels_(size_pixels),
      meters_per_pixel_(meters_per_pixel),
      border_size_meters_(border_size_meters),
      frame_duration_seconds_(frame_duration_seconds),
      orientation_(orientation) {}

void DisplayMetrics::ToggleOrientation() {
  std::swap(size_pixels_[0], size_pixels_[1]);
  std::swap(meters_per_pixel_[0], meters_per_pixel_[1]);
  if (orientation_ == DisplayOrientation::kPortrait)
    orientation_ = DisplayOrientation::kLandscape;
  else
    orientation_ = DisplayOrientation::kPortrait;
}

DisplayMetrics::DisplayMetrics()
    : DisplayMetrics(vec2i(0, 0), vec2(0.0f, 0.0f), 0.0f, 0.0f,
                     DisplayOrientation::kLandscape) {}

}  // namespace dvr
}  // namespace android
