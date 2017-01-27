#ifndef ANDROID_DVR_HEAD_MOUNT_METRICS_H_
#define ANDROID_DVR_HEAD_MOUNT_METRICS_H_

#include <array>

#include <private/dvr/color_channel_distortion.h>
#include <private/dvr/types.h>

namespace android {
namespace dvr {

// HeadMountMetrics encapsulates metrics describing a head mount to be used
// with a display to create a head mounted display.
class HeadMountMetrics {
 public:
  // The vertical point of the HMD where the lens distance is measured from.
  enum VerticalAlignment { kBottom = 0, kCenter = 1, kTop = 2 };

  enum EyeOrientation {
    kCCW0Degrees = 0,
    kCCW90Degrees = 1,
    kCCW180Degrees = 2,
    kCCW270Degrees = 3,
    kCCW0DegreesMirrored = 4,
    kCCW90DegreesMirrored = 5,
    kCCW180DegreesMirrored = 6,
    kCCW270DegreesMirrored = 7,

    // Rotations that consist of an odd number of 90 degree rotations will swap
    // the height and width of any bounding boxes/viewports. This bit informs
    // any viewport manipulating code to perform the appropriate transformation.
    kRightAngleBit = 0x01,
    // Viewports are represented as four floating point values (four half
    // angles). Rotating this structure can be done through a shift operation.
    // This mask extracts the rotation portion of the orientation.
    kRotationMask = 0x03,
    // This mask specifies whether the output is mirrored.
    kMirroredBit = 0x04
  };

  HeadMountMetrics(
      float inter_lens_distance, float tray_to_lens_distance,
      float virtual_eye_to_screen_distance,
      VerticalAlignment vertical_alignment, const FieldOfView& left_eye_max_fov,
      const FieldOfView& right_eye_max_fov,
      const std::shared_ptr<ColorChannelDistortion>& red_distortion,
      const std::shared_ptr<ColorChannelDistortion>& green_distortion,
      const std::shared_ptr<ColorChannelDistortion>& blue_distortion,
      EyeOrientation left_eye_orientation, EyeOrientation right_eye_orientation,
      float screen_center_to_lens_distance)
      : inter_lens_distance_(inter_lens_distance),
        tray_to_lens_distance_(tray_to_lens_distance),
        virtual_eye_to_screen_distance_(virtual_eye_to_screen_distance),
        screen_center_to_lens_distance_(screen_center_to_lens_distance),
        vertical_alignment_(vertical_alignment),
        eye_max_fov_({{left_eye_max_fov, right_eye_max_fov}}),
        color_channel_distortion_(
            {{red_distortion, green_distortion, blue_distortion}}),
        supports_chromatic_aberration_correction_(true),
        eye_orientation_({{left_eye_orientation, right_eye_orientation}}) {
    // If we're missing the green or blur distortions, assume that we don't
    // correct for chromatic aberration.
    if (!green_distortion || !blue_distortion) {
      color_channel_distortion_[1] = red_distortion;
      color_channel_distortion_[2] = red_distortion;
      supports_chromatic_aberration_correction_ = false;
    }
  }

  // Returns the distance in meters between the optical centers of the two
  // lenses.
  float GetInterLensDistance() const { return inter_lens_distance_; }

  // Returns the distance in meters from the "tray" upon which the display
  // rests to the optical center of a lens.
  float GetTrayToLensDistance() const { return tray_to_lens_distance_; }

  // Returns the distance in meters from the virtual eye to the screen.
  // See http://go/vr-distortion-correction for an explanation of what
  // this distance is.
  float GetVirtualEyeToScreenDistance() const {
    return virtual_eye_to_screen_distance_;
  }

  // Returns the horizontal distance from the center of the screen to the center
  // of the lens, in meters.
  float GetScreenCenterToLensDistance() const {
    return screen_center_to_lens_distance_;
  }

  // Returns the vertical alignment of the HMD.  The tray-to-lens distance
  // is relative to this position.  Exception: if the alignment is kCenter,
  // then the offset has no meaning.
  VerticalAlignment GetVerticalAlignment() const { return vertical_alignment_; }

  // Returns the given eye's maximum field of view visible through the lens.
  // The actual rendered field of view will be limited by this and also by
  // the size of the screen.
  const FieldOfView& GetEyeMaxFov(EyeType eye) const {
    return eye_max_fov_[eye];
  }

  // Returns the ColorChannelDistortion object representing the distortion
  // caused by the lenses for the given color channel.
  const ColorChannelDistortion& GetColorChannelDistortion(
      RgbColorChannel channel) const {
    return *color_channel_distortion_[channel];
  }

  bool supports_chromatic_aberration_correction() const {
    return supports_chromatic_aberration_correction_;
  }

  EyeOrientation GetEyeOrientation(EyeType eye) const {
    return eye_orientation_[eye];
  }

 private:
  float inter_lens_distance_;
  float tray_to_lens_distance_;
  float virtual_eye_to_screen_distance_;
  float screen_center_to_lens_distance_;
  VerticalAlignment vertical_alignment_;
  std::array<FieldOfView, 2> eye_max_fov_;
  std::array<std::shared_ptr<ColorChannelDistortion>, 3>
      color_channel_distortion_;
  bool supports_chromatic_aberration_correction_;
  std::array<EyeOrientation, 2> eye_orientation_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_HEAD_MOUNT_METRICS_H_
