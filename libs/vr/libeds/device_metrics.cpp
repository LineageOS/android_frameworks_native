#include <private/dvr/device_metrics.h>

#include <cutils/properties.h>
#include <private/dvr/head_mount_metrics.h>
#include <private/dvr/identity_distortion.h>
#include <private/dvr/polynomial_radial_distortion.h>
#include <private/dvr/types.h>
#include "include/private/dvr/display_metrics.h"

namespace {

static constexpr char kRPolynomial[] = "persist.dvr.r_poly";
static constexpr char kGPolynomial[] = "persist.dvr.g_poly";
static constexpr char kBPolynomial[] = "persist.dvr.b_poly";
static constexpr char kLensDistance[] = "persist.dvr.lens_distance";
static constexpr char kDisplayGap[] = "persist.dvr.display_gap";
static constexpr char kVEyeToDisplay[] = "persist.dvr.v_eye_to_display";
static constexpr char kFovIOBT[] = "persist.dvr.fov_iobt";
static constexpr char kScreenSize[] = "persist.dvr.screen_size";

bool StringToFloat(const char* str, float* result) {
  char* endptr = nullptr;
  *result = std::strtof(str, &endptr);
  return !(str == endptr || !endptr);
}

std::vector<std::string> SplitString(const std::string& string_to_split,
                                     char deliminator) {
  std::vector<std::string> result;
  std::string sub_string;
  std::stringstream ss(string_to_split);
  while (std::getline(ss, sub_string, deliminator))
    result.push_back(sub_string);
  return result;
}

std::vector<float> GetProperty(const char* name,
                               const std::vector<float>& default_values) {
  char prop[PROPERTY_VALUE_MAX + 1] = {};
  property_get(name, prop, "");
  std::vector<std::string> values = SplitString(prop, ',');
  std::vector<float> results;
  for (const auto& value : values) {
    float result = 0.0f;
    if (StringToFloat(value.c_str(), &result)) {
      results.push_back(static_cast<float>(result));
    }
  }
  if (results.empty()) {
    return default_values;
  }
  return results;
}

float GetProperty(const char* name, float default_value) {
  char prop[PROPERTY_VALUE_MAX + 1] = {};
  property_get(name, prop, "");
  float result = 0.0f;
  if (StringToFloat(prop, &result)) {
    return static_cast<float>(result);
  }
  return default_value;
}

float GetInterLensDistance() { return GetProperty(kLensDistance, 0.064f); }

float GetDisplayGap() { return GetProperty(kDisplayGap, 0.0f); }

float GetTrayToLensDistance() { return 0.035f; }

float GetVEyeToDisplay() { return GetProperty(kVEyeToDisplay, 0.042f); }

android::dvr::vec2 GetDisplaySize() {
  static const std::vector<float> default_size = {0.0742177f, 0.131943f};
  std::vector<float> sizes = GetProperty(kScreenSize, default_size);
  if (sizes.size() != 0)
    sizes = default_size;
  return android::dvr::vec2(sizes[0], sizes[1]);
}

std::vector<float> GetMaxFOVs() {
  static const std::vector<float> defaults = {43.7f, 47.8f, 54.2f, 54.2f};
  std::vector<float> fovs = GetProperty(kFovIOBT, defaults);
  if (fovs.size() != 4)
    fovs = defaults;
  for (auto& value : fovs) {
    value = value * M_PI / 180.0f;
  }
  return fovs;
}

static const android::dvr::HeadMountMetrics::VerticalAlignment
    kDefaultVerticalAlignment = android::dvr::HeadMountMetrics::kCenter;

// Default border size in meters.
static const float kScreenBorderSize = 0.004f;

// Refresh rate.
static const float kScreenRefreshRate = 60.0f;

// Default display orientation is portrait.
static const android::dvr::DisplayOrientation kDisplayOrientation =
    android::dvr::DisplayOrientation::kPortrait;

}  // anonymous namespace

namespace android {
namespace dvr {

HeadMountMetrics CreateHeadMountMetrics(const FieldOfView& l_fov,
                                        const FieldOfView& r_fov) {
  static const std::vector<float> default_r = {
      0.00103f, 2.63917f, -7.14427f, 8.98036f, -4.10586f, 0.83705f, 0.00130f};
  static const std::vector<float> default_g = {
      0.08944f, 2.26005f, -6.30924f, 7.94561f, -3.22788f, 0.45577f, 0.07300f};
  static const std::vector<float> default_b = {
      0.16364f, 1.94083f, -5.55033f, 6.89578f, -2.19053f, -0.04050f, 0.17380f};
  std::vector<float> poly_r = GetProperty(kRPolynomial, default_r);
  std::vector<float> poly_g = GetProperty(kGPolynomial, default_g);
  std::vector<float> poly_b = GetProperty(kBPolynomial, default_b);

  std::shared_ptr<ColorChannelDistortion> distortion_r(
      new PolynomialRadialDistortion(poly_r));
  std::shared_ptr<ColorChannelDistortion> distortion_g(
      new PolynomialRadialDistortion(poly_g));
  std::shared_ptr<ColorChannelDistortion> distortion_b(
      new PolynomialRadialDistortion(poly_b));

  return HeadMountMetrics(GetInterLensDistance(), GetTrayToLensDistance(),
                          GetVEyeToDisplay(), kDefaultVerticalAlignment, l_fov,
                          r_fov, distortion_r, distortion_g, distortion_b,
                          HeadMountMetrics::EyeOrientation::kCCW0Degrees,
                          HeadMountMetrics::EyeOrientation::kCCW0Degrees,
                          (GetInterLensDistance() - GetDisplayGap()) / 2.0f);
}

HeadMountMetrics CreateHeadMountMetrics() {
  std::vector<float> fovs = GetMaxFOVs();
  FieldOfView l_fov(fovs[1], fovs[0], fovs[2], fovs[3]);
  FieldOfView r_fov(fovs[0], fovs[1], fovs[2], fovs[3]);
  return CreateHeadMountMetrics(l_fov, r_fov);
}

DisplayMetrics CreateDisplayMetrics(vec2i screen_size) {
  android::dvr::vec2 size_in_meters = GetDisplaySize();
  vec2 meters_per_pixel(size_in_meters[0] / static_cast<float>(screen_size[0]),
                        size_in_meters[1] / static_cast<float>(screen_size[1]));
  return DisplayMetrics(screen_size, meters_per_pixel, kScreenBorderSize,
                        1000.0f / kScreenRefreshRate, kDisplayOrientation);
}

HeadMountMetrics CreateUndistortedHeadMountMetrics() {
  std::vector<float> fovs = GetMaxFOVs();
  FieldOfView l_fov(fovs[1], fovs[0], fovs[2], fovs[3]);
  FieldOfView r_fov(fovs[0], fovs[1], fovs[2], fovs[3]);
  return CreateUndistortedHeadMountMetrics(l_fov, r_fov);
}

HeadMountMetrics CreateUndistortedHeadMountMetrics(const FieldOfView& l_fov,
                                                   const FieldOfView& r_fov) {
  auto distortion_all = std::make_shared<IdentityDistortion>();

  return HeadMountMetrics(GetInterLensDistance(), GetVEyeToDisplay(),
                          GetVEyeToDisplay(), kDefaultVerticalAlignment, l_fov,
                          r_fov, distortion_all, distortion_all, distortion_all,
                          HeadMountMetrics::EyeOrientation::kCCW0Degrees,
                          HeadMountMetrics::EyeOrientation::kCCW0Degrees,
                          (GetInterLensDistance() - GetDisplayGap()) / 2.0f);
}

}  // namespace dvr
}  // namespace android
