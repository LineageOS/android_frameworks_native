/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cmath>
#include <vector>
#include <jpegrecoverymap/recoverymapmath.h>

namespace android::jpegrecoverymap {

static const std::vector<float> kPqOETF = [] {
    std::vector<float> result;
    for (int idx = 0; idx < kPqOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kPqOETFNumEntries - 1);
      result.push_back(pqOetf(value));
    }
    return result;
}();

static const std::vector<float> kPqInvOETF = [] {
    std::vector<float> result;
    for (int idx = 0; idx < kPqInvOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kPqInvOETFNumEntries - 1);
      result.push_back(pqInvOetf(value));
    }
    return result;
}();

static const std::vector<float> kHlgOETF = [] {
    std::vector<float> result;
    for (int idx = 0; idx < kHlgOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kHlgOETFNumEntries - 1);
      result.push_back(hlgOetf(value));
    }
    return result;
}();

static const std::vector<float> kHlgInvOETF = [] {
    std::vector<float> result;
    for (int idx = 0; idx < kHlgInvOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kHlgInvOETFNumEntries - 1);
      result.push_back(hlgInvOetf(value));
    }
    return result;
}();

static const std::vector<float> kSrgbInvOETF = [] {
    std::vector<float> result;
    for (int idx = 0; idx < kSrgbInvOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kSrgbInvOETFNumEntries - 1);
      result.push_back(srgbInvOetf(value));
    }
    return result;
}();

// Use Shepard's method for inverse distance weighting. For more information:
// en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method

float ShepardsIDW::euclideanDistance(float x1, float x2, float y1, float y2) {
  return sqrt(((y2 - y1) * (y2 - y1)) + (x2 - x1) * (x2 - x1));
}

void ShepardsIDW::fillShepardsIDW(float *weights, int incR, int incB) {
  for (int y = 0; y < mMapScaleFactor; y++) {
    for (int x = 0; x < mMapScaleFactor; x++) {
      float pos_x = ((float)x) / mMapScaleFactor;
      float pos_y = ((float)y) / mMapScaleFactor;
      int curr_x = floor(pos_x);
      int curr_y = floor(pos_y);
      int next_x = curr_x + incR;
      int next_y = curr_y + incB;
      float e1_distance = euclideanDistance(pos_x, curr_x, pos_y, curr_y);
      int index = y * mMapScaleFactor * 4 + x * 4;
      if (e1_distance == 0) {
        weights[index++] = 1.f;
        weights[index++] = 0.f;
        weights[index++] = 0.f;
        weights[index++] = 0.f;
      } else {
        float e1_weight = 1.f / e1_distance;

        float e2_distance = euclideanDistance(pos_x, curr_x, pos_y, next_y);
        float e2_weight = 1.f / e2_distance;

        float e3_distance = euclideanDistance(pos_x, next_x, pos_y, curr_y);
        float e3_weight = 1.f / e3_distance;

        float e4_distance = euclideanDistance(pos_x, next_x, pos_y, next_y);
        float e4_weight = 1.f / e4_distance;

        float total_weight = e1_weight + e2_weight + e3_weight + e4_weight;

        weights[index++] = e1_weight / total_weight;
        weights[index++] = e2_weight / total_weight;
        weights[index++] = e3_weight / total_weight;
        weights[index++] = e4_weight / total_weight;
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// sRGB transformations

static const float kMaxPixelFloat = 1.0f;
static float clampPixelFloat(float value) {
    return (value < 0.0f) ? 0.0f : (value > kMaxPixelFloat) ? kMaxPixelFloat : value;
}

// See IEC 61966-2-1, Equation F.7.
static const float kSrgbR = 0.2126f, kSrgbG = 0.7152f, kSrgbB = 0.0722f;

float srgbLuminance(Color e) {
  return kSrgbR * e.r + kSrgbG * e.g + kSrgbB * e.b;
}

// See ECMA TR/98, Section 7.
static const float kSrgbRCr = 1.402f, kSrgbGCb = 0.34414f, kSrgbGCr = 0.71414f, kSrgbBCb = 1.772f;

Color srgbYuvToRgb(Color e_gamma) {
  return {{{ clampPixelFloat(e_gamma.y + kSrgbRCr * e_gamma.v),
             clampPixelFloat(e_gamma.y - kSrgbGCb * e_gamma.u - kSrgbGCr * e_gamma.v),
             clampPixelFloat(e_gamma.y + kSrgbBCb * e_gamma.u) }}};
}

// See ECMA TR/98, Section 7.
static const float kSrgbYR = 0.299f, kSrgbYG = 0.587f, kSrgbYB = 0.114f;
static const float kSrgbUR = -0.1687f, kSrgbUG = -0.3313f, kSrgbUB = 0.5f;
static const float kSrgbVR = 0.5f, kSrgbVG = -0.4187f, kSrgbVB = -0.0813f;

Color srgbRgbToYuv(Color e_gamma) {
  return {{{ kSrgbYR * e_gamma.r + kSrgbYG * e_gamma.g + kSrgbYB * e_gamma.b,
             kSrgbUR * e_gamma.r + kSrgbUG * e_gamma.g + kSrgbUB * e_gamma.b,
             kSrgbVR * e_gamma.r + kSrgbVG * e_gamma.g + kSrgbVB * e_gamma.b }}};
}

// See IEC 61966-2-1, Equations F.5 and F.6.
float srgbInvOetf(float e_gamma) {
  if (e_gamma <= 0.04045f) {
    return e_gamma / 12.92f;
  } else {
    return pow((e_gamma + 0.055f) / 1.055f, 2.4);
  }
}

Color srgbInvOetf(Color e_gamma) {
  return {{{ srgbInvOetf(e_gamma.r),
             srgbInvOetf(e_gamma.g),
             srgbInvOetf(e_gamma.b) }}};
}

// See IEC 61966-2-1, Equations F.5 and F.6.
float srgbInvOetfLUT(float e_gamma) {
  uint32_t value = static_cast<uint32_t>(e_gamma * kSrgbInvOETFNumEntries);
  //TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kSrgbInvOETFNumEntries - 1);
  return kSrgbInvOETF[value];
}

Color srgbInvOetfLUT(Color e_gamma) {
  return {{{ srgbInvOetfLUT(e_gamma.r),
             srgbInvOetfLUT(e_gamma.g),
             srgbInvOetfLUT(e_gamma.b) }}};
}

////////////////////////////////////////////////////////////////////////////////
// Display-P3 transformations

// See SMPTE EG 432-1, Table 7-2.
static const float kP3R = 0.20949f, kP3G = 0.72160f, kP3B = 0.06891f;

float p3Luminance(Color e) {
  return kP3R * e.r + kP3G * e.g + kP3B * e.b;
}


////////////////////////////////////////////////////////////////////////////////
// BT.2100 transformations - according to ITU-R BT.2100-2

// See ITU-R BT.2100-2, Table 5, HLG Reference OOTF
static const float kBt2100R = 0.2627f, kBt2100G = 0.6780f, kBt2100B = 0.0593f;

float bt2100Luminance(Color e) {
  return kBt2100R * e.r + kBt2100G * e.g + kBt2100B * e.b;
}

// See ITU-R BT.2100-2, Table 6, Derivation of colour difference signals.
static const float kBt2100Cb = 1.8814f, kBt2100Cr = 1.4746f;

Color bt2100RgbToYuv(Color e_gamma) {
  float y_gamma = bt2100Luminance(e_gamma);
  return {{{ y_gamma,
             (e_gamma.b - y_gamma) / kBt2100Cb,
             (e_gamma.r - y_gamma) / kBt2100Cr }}};
}

// Derived by inversing bt2100RgbToYuv. The derivation for R and B are  pretty
// straight forward; we just invert the formulas for U and V above. But deriving
// the formula for G is a bit more complicated:
//
// Start with equation for luminance:
//   Y = kBt2100R * R + kBt2100G * G + kBt2100B * B
// Solve for G:
//   G = (Y - kBt2100R * R - kBt2100B * B) / kBt2100B
// Substitute equations for R and B in terms YUV:
//   G = (Y - kBt2100R * (Y + kBt2100Cr * V) - kBt2100B * (Y + kBt2100Cb * U)) / kBt2100B
// Simplify:
//   G = Y * ((1 - kBt2100R - kBt2100B) / kBt2100G)
//     + U * (kBt2100B * kBt2100Cb / kBt2100G)
//     + V * (kBt2100R * kBt2100Cr / kBt2100G)
//
// We then get the following coeficients for calculating G from YUV:
//
// Coef for Y = (1 - kBt2100R - kBt2100B) / kBt2100G = 1
// Coef for U = kBt2100B * kBt2100Cb / kBt2100G = kBt2100GCb = ~0.1645
// Coef for V = kBt2100R * kBt2100Cr / kBt2100G = kBt2100GCr = ~0.5713

static const float kBt2100GCb = kBt2100B * kBt2100Cb / kBt2100G;
static const float kBt2100GCr = kBt2100R * kBt2100Cr / kBt2100G;

Color bt2100YuvToRgb(Color e_gamma) {
  return {{{ clampPixelFloat(e_gamma.y + kBt2100Cr * e_gamma.v),
             clampPixelFloat(e_gamma.y - kBt2100GCb * e_gamma.u - kBt2100GCr * e_gamma.v),
             clampPixelFloat(e_gamma.y + kBt2100Cb * e_gamma.u) }}};
}

// See ITU-R BT.2100-2, Table 5, HLG Reference OETF.
static const float kHlgA = 0.17883277f, kHlgB = 0.28466892f, kHlgC = 0.55991073;

float hlgOetf(float e) {
  if (e <= 1.0f/12.0f) {
    return sqrt(3.0f * e);
  } else {
    return kHlgA * log(12.0f * e - kHlgB) + kHlgC;
  }
}

Color hlgOetf(Color e) {
  return {{{ hlgOetf(e.r), hlgOetf(e.g), hlgOetf(e.b) }}};
}

float hlgOetfLUT(float e) {
  uint32_t value = static_cast<uint32_t>(e * kHlgOETFNumEntries);
  //TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kHlgOETFNumEntries - 1);

  return kHlgOETF[value];
}

Color hlgOetfLUT(Color e) {
  return {{{ hlgOetfLUT(e.r), hlgOetfLUT(e.g), hlgOetfLUT(e.b) }}};
}

// See ITU-R BT.2100-2, Table 5, HLG Reference EOTF.
float hlgInvOetf(float e_gamma) {
  if (e_gamma <= 0.5f) {
    return pow(e_gamma, 2.0f) / 3.0f;
  } else {
    return (exp((e_gamma - kHlgC) / kHlgA) + kHlgB) / 12.0f;
  }
}

Color hlgInvOetf(Color e_gamma) {
  return {{{ hlgInvOetf(e_gamma.r),
             hlgInvOetf(e_gamma.g),
             hlgInvOetf(e_gamma.b) }}};
}

float hlgInvOetfLUT(float e_gamma) {
  uint32_t value = static_cast<uint32_t>(e_gamma * kHlgInvOETFNumEntries);
  //TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kHlgInvOETFNumEntries - 1);

  return kHlgInvOETF[value];
}

Color hlgInvOetfLUT(Color e_gamma) {
  return {{{ hlgInvOetfLUT(e_gamma.r),
             hlgInvOetfLUT(e_gamma.g),
             hlgInvOetfLUT(e_gamma.b) }}};
}

// See ITU-R BT.2100-2, Table 4, Reference PQ OETF.
static const float kPqM1 = 2610.0f / 16384.0f, kPqM2 = 2523.0f / 4096.0f * 128.0f;
static const float kPqC1 = 3424.0f / 4096.0f, kPqC2 = 2413.0f / 4096.0f * 32.0f,
                   kPqC3 = 2392.0f / 4096.0f * 32.0f;

float pqOetf(float e) {
  if (e <= 0.0f) return 0.0f;
  return pow((kPqC1 + kPqC2 * pow(e, kPqM1)) / (1 + kPqC3 * pow(e, kPqM1)),
             kPqM2);
}

Color pqOetf(Color e) {
  return {{{ pqOetf(e.r), pqOetf(e.g), pqOetf(e.b) }}};
}

float pqOetfLUT(float e) {
  uint32_t value = static_cast<uint32_t>(e * kPqOETFNumEntries);
  //TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kPqOETFNumEntries - 1);

  return kPqOETF[value];
}

Color pqOetfLUT(Color e) {
  return {{{ pqOetfLUT(e.r), pqOetfLUT(e.g), pqOetfLUT(e.b) }}};
}

// Derived from the inverse of the Reference PQ OETF.
static const float kPqInvA = 128.0f, kPqInvB = 107.0f, kPqInvC = 2413.0f, kPqInvD = 2392.0f,
                   kPqInvE = 6.2773946361f, kPqInvF = 0.0126833f;

float pqInvOetf(float e_gamma) {
  // This equation blows up if e_gamma is 0.0, and checking on <= 0.0 doesn't
  // always catch 0.0. So, check on 0.0001, since anything this small will
  // effectively be crushed to zero anyways.
  if (e_gamma <= 0.0001f) return 0.0f;
  return pow((kPqInvA * pow(e_gamma, kPqInvF) - kPqInvB)
           / (kPqInvC - kPqInvD * pow(e_gamma, kPqInvF)),
             kPqInvE);
}

Color pqInvOetf(Color e_gamma) {
  return {{{ pqInvOetf(e_gamma.r),
             pqInvOetf(e_gamma.g),
             pqInvOetf(e_gamma.b) }}};
}

float pqInvOetfLUT(float e_gamma) {
  uint32_t value = static_cast<uint32_t>(e_gamma * kPqInvOETFNumEntries);
  //TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kPqInvOETFNumEntries - 1);

  return kPqInvOETF[value];
}

Color pqInvOetfLUT(Color e_gamma) {
  return {{{ pqInvOetfLUT(e_gamma.r),
             pqInvOetfLUT(e_gamma.g),
             pqInvOetfLUT(e_gamma.b) }}};
}


////////////////////////////////////////////////////////////////////////////////
// Color conversions

Color bt709ToP3(Color e) {
 return {{{ 0.82254f * e.r + 0.17755f * e.g + 0.00006f * e.b,
            0.03312f * e.r + 0.96684f * e.g + -0.00001f * e.b,
            0.01706f * e.r + 0.07240f * e.g + 0.91049f * e.b }}};
}

Color bt709ToBt2100(Color e) {
 return {{{ 0.62740f * e.r + 0.32930f * e.g + 0.04332f * e.b,
            0.06904f * e.r + 0.91958f * e.g + 0.01138f * e.b,
            0.01636f * e.r + 0.08799f * e.g + 0.89555f * e.b }}};
}

Color p3ToBt709(Color e) {
 return {{{ 1.22482f * e.r + -0.22490f * e.g + -0.00007f * e.b,
            -0.04196f * e.r + 1.04199f * e.g + 0.00001f * e.b,
            -0.01961f * e.r + -0.07865f * e.g + 1.09831f * e.b }}};
}

Color p3ToBt2100(Color e) {
 return {{{ 0.75378f * e.r + 0.19862f * e.g + 0.04754f * e.b,
            0.04576f * e.r + 0.94177f * e.g + 0.01250f * e.b,
            -0.00121f * e.r + 0.01757f * e.g + 0.98359f * e.b }}};
}

Color bt2100ToBt709(Color e) {
 return {{{ 1.66045f * e.r + -0.58764f * e.g + -0.07286f * e.b,
            -0.12445f * e.r + 1.13282f * e.g + -0.00837f * e.b,
            -0.01811f * e.r + -0.10057f * e.g + 1.11878f * e.b }}};
}

Color bt2100ToP3(Color e) {
 return {{{ 1.34369f * e.r + -0.28223f * e.g + -0.06135f * e.b,
            -0.06533f * e.r + 1.07580f * e.g + -0.01051f * e.b,
            0.00283f * e.r + -0.01957f * e.g + 1.01679f * e.b
 }}};
}

// TODO: confirm we always want to convert like this before calculating
// luminance.
ColorTransformFn getHdrConversionFn(jpegr_color_gamut sdr_gamut, jpegr_color_gamut hdr_gamut) {
  switch (sdr_gamut) {
    case JPEGR_COLORGAMUT_BT709:
      switch (hdr_gamut) {
        case JPEGR_COLORGAMUT_BT709:
          return identityConversion;
        case JPEGR_COLORGAMUT_P3:
          return p3ToBt709;
        case JPEGR_COLORGAMUT_BT2100:
          return bt2100ToBt709;
        case JPEGR_COLORGAMUT_UNSPECIFIED:
          return nullptr;
      }
      break;
    case JPEGR_COLORGAMUT_P3:
      switch (hdr_gamut) {
        case JPEGR_COLORGAMUT_BT709:
          return bt709ToP3;
        case JPEGR_COLORGAMUT_P3:
          return identityConversion;
        case JPEGR_COLORGAMUT_BT2100:
          return bt2100ToP3;
        case JPEGR_COLORGAMUT_UNSPECIFIED:
          return nullptr;
      }
      break;
    case JPEGR_COLORGAMUT_BT2100:
      switch (hdr_gamut) {
        case JPEGR_COLORGAMUT_BT709:
          return bt709ToBt2100;
        case JPEGR_COLORGAMUT_P3:
          return p3ToBt2100;
        case JPEGR_COLORGAMUT_BT2100:
          return identityConversion;
        case JPEGR_COLORGAMUT_UNSPECIFIED:
          return nullptr;
      }
      break;
    case JPEGR_COLORGAMUT_UNSPECIFIED:
      return nullptr;
  }
}


////////////////////////////////////////////////////////////////////////////////
// Recovery map calculations
uint8_t encodeRecovery(float y_sdr, float y_hdr, jr_metadata_ptr metadata) {
  return encodeRecovery(y_sdr, y_hdr, metadata,
                        log2(metadata->minContentBoost), log2(metadata->maxContentBoost));
}

uint8_t encodeRecovery(float y_sdr, float y_hdr, jr_metadata_ptr metadata,
                       float log2MinContentBoost, float log2MaxContentBoost) {
  float gain = 1.0f;
  if (y_sdr > 0.0f) {
    gain = y_hdr / y_sdr;
  }

  if (gain < metadata->minContentBoost) gain = metadata->minContentBoost;
  if (gain > metadata->maxContentBoost) gain = metadata->maxContentBoost;

  return static_cast<uint8_t>((log2(gain) - log2MinContentBoost)
                            / (log2MaxContentBoost - log2MinContentBoost)
                            * 255.0f);
}

Color applyRecovery(Color e, float recovery, jr_metadata_ptr metadata) {
  float logBoost = log2(metadata->minContentBoost) * (1.0f - recovery)
                 + log2(metadata->maxContentBoost) * recovery;
  float recoveryFactor = exp2(logBoost);
  return e * recoveryFactor;
}

Color applyRecovery(Color e, float recovery, jr_metadata_ptr metadata, float displayBoost) {
  float logBoost = log2(metadata->minContentBoost) * (1.0f - recovery)
                 + log2(metadata->maxContentBoost) * recovery;
  float recoveryFactor = exp2(logBoost * displayBoost / metadata->maxContentBoost);
  return e * recoveryFactor;
}

Color applyRecoveryLUT(Color e, float recovery, RecoveryLUT& recoveryLUT) {
  float recoveryFactor = recoveryLUT.getRecoveryFactor(recovery);
  return e * recoveryFactor;
}

Color getYuv420Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
  size_t pixel_count = image->width * image->height;

  size_t pixel_y_idx = x + y * image->width;
  size_t pixel_uv_idx = x / 2 + (y / 2) * (image->width / 2);

  uint8_t y_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y_idx];
  uint8_t u_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_count + pixel_uv_idx];
  uint8_t v_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_count * 5 / 4 + pixel_uv_idx];

  // 128 bias for UV given we are using jpeglib; see:
  // https://github.com/kornelski/libjpeg/blob/master/structure.doc
  return {{{ static_cast<float>(y_uint) / 255.0f,
             (static_cast<float>(u_uint) - 128.0f) / 255.0f,
             (static_cast<float>(v_uint) - 128.0f) / 255.0f }}};
}

Color getP010Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
  size_t luma_stride = image->luma_stride;
  size_t chroma_stride = image->chroma_stride;
  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->data);
  uint16_t* chroma_data = reinterpret_cast<uint16_t*>(image->chroma_data);

  if (luma_stride == 0) {
    luma_stride = image->width;
  }
  if (chroma_stride == 0) {
    chroma_stride = luma_stride;
  }
  if (chroma_data == nullptr) {
    chroma_data = &reinterpret_cast<uint16_t*>(image->data)[image->luma_stride * image->height];
  }

  size_t pixel_y_idx = y * luma_stride + x;
  size_t pixel_u_idx = (y >> 1) * chroma_stride + (x & ~0x1);
  size_t pixel_v_idx = pixel_u_idx + 1;

  uint16_t y_uint = luma_data[pixel_y_idx] >> 6;
  uint16_t u_uint = chroma_data[pixel_u_idx] >> 6;
  uint16_t v_uint = chroma_data[pixel_v_idx] >> 6;

  // Conversions include taking narrow-range into account.
  return {{{ (static_cast<float>(y_uint) - 64.0f) / 876.0f,
             (static_cast<float>(u_uint) - 64.0f) / 896.0f - 0.5f,
             (static_cast<float>(v_uint) - 64.0f) / 896.0f - 0.5f }}};
}

typedef Color (*getPixelFn)(jr_uncompressed_ptr, size_t, size_t);

static Color samplePixels(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y,
                          getPixelFn get_pixel_fn) {
  Color e = {{{ 0.0f, 0.0f, 0.0f }}};
  for (size_t dy = 0; dy < map_scale_factor; ++dy) {
    for (size_t dx = 0; dx < map_scale_factor; ++dx) {
      e += get_pixel_fn(image, x * map_scale_factor + dx, y * map_scale_factor + dy);
    }
  }

  return e / static_cast<float>(map_scale_factor * map_scale_factor);
}

Color sampleYuv420(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
  return samplePixels(image, map_scale_factor, x, y, getYuv420Pixel);
}

Color sampleP010(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
  return samplePixels(image, map_scale_factor, x, y, getP010Pixel);
}

// TODO: do we need something more clever for filtering either the map or images
// to generate the map?

static size_t clamp(const size_t& val, const size_t& low, const size_t& high) {
  return val < low ? low : (high < val ? high : val);
}

static float mapUintToFloat(uint8_t map_uint) {
  return static_cast<float>(map_uint) / 255.0f;
}

static float pythDistance(float x_diff, float y_diff) {
  return sqrt(pow(x_diff, 2.0f) + pow(y_diff, 2.0f));
}

// TODO: If map_scale_factor is guaranteed to be an integer, then remove the following.
float sampleMap(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y) {
  float x_map = static_cast<float>(x) / map_scale_factor;
  float y_map = static_cast<float>(y) / map_scale_factor;

  size_t x_lower = static_cast<size_t>(floor(x_map));
  size_t x_upper = x_lower + 1;
  size_t y_lower = static_cast<size_t>(floor(y_map));
  size_t y_upper = y_lower + 1;

  x_lower = clamp(x_lower, 0, map->width - 1);
  x_upper = clamp(x_upper, 0, map->width - 1);
  y_lower = clamp(y_lower, 0, map->height - 1);
  y_upper = clamp(y_upper, 0, map->height - 1);

  // Use Shepard's method for inverse distance weighting. For more information:
  // en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method

  float e1 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_lower * map->width]);
  float e1_dist = pythDistance(x_map - static_cast<float>(x_lower),
                               y_map - static_cast<float>(y_lower));
  if (e1_dist == 0.0f) return e1;

  float e2 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_upper * map->width]);
  float e2_dist = pythDistance(x_map - static_cast<float>(x_lower),
                               y_map - static_cast<float>(y_upper));
  if (e2_dist == 0.0f) return e2;

  float e3 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_lower * map->width]);
  float e3_dist = pythDistance(x_map - static_cast<float>(x_upper),
                               y_map - static_cast<float>(y_lower));
  if (e3_dist == 0.0f) return e3;

  float e4 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_upper * map->width]);
  float e4_dist = pythDistance(x_map - static_cast<float>(x_upper),
                               y_map - static_cast<float>(y_upper));
  if (e4_dist == 0.0f) return e2;

  float e1_weight = 1.0f / e1_dist;
  float e2_weight = 1.0f / e2_dist;
  float e3_weight = 1.0f / e3_dist;
  float e4_weight = 1.0f / e4_dist;
  float total_weight = e1_weight + e2_weight + e3_weight + e4_weight;

  return e1 * (e1_weight / total_weight)
       + e2 * (e2_weight / total_weight)
       + e3 * (e3_weight / total_weight)
       + e4 * (e4_weight / total_weight);
}

float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
                ShepardsIDW& weightTables) {
  // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
  // following by computing log2(map_scale_factor) once and then using >> log2(map_scale_factor)
  int x_lower = x / map_scale_factor;
  int x_upper = x_lower + 1;
  int y_lower = y / map_scale_factor;
  int y_upper = y_lower + 1;

  x_lower = std::min(x_lower, map->width - 1);
  x_upper = std::min(x_upper, map->width - 1);
  y_lower = std::min(y_lower, map->height - 1);
  y_upper = std::min(y_upper, map->height - 1);

  float e1 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_lower * map->width]);
  float e2 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_upper * map->width]);
  float e3 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_lower * map->width]);
  float e4 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_upper * map->width]);

  // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
  // following by using & (map_scale_factor - 1)
  int offset_x = x % map_scale_factor;
  int offset_y = y % map_scale_factor;

  float* weights = weightTables.mWeights;
  if (x_lower == x_upper && y_lower == y_upper) weights = weightTables.mWeightsC;
  else if (x_lower == x_upper) weights = weightTables.mWeightsNR;
  else if (y_lower == y_upper) weights = weightTables.mWeightsNB;
  weights += offset_y * map_scale_factor * 4 + offset_x * 4;

  return e1 * weights[0] + e2 * weights[1] + e3 * weights[2] + e4 * weights[3];
}

uint32_t colorToRgba1010102(Color e_gamma) {
  return (0x3ff & static_cast<uint32_t>(e_gamma.r * 1023.0f))
       | ((0x3ff & static_cast<uint32_t>(e_gamma.g * 1023.0f)) << 10)
       | ((0x3ff & static_cast<uint32_t>(e_gamma.b * 1023.0f)) << 20)
       | (0x3 << 30);  // Set alpha to 1.0
}

uint64_t colorToRgbaF16(Color e_gamma) {
  return (uint64_t) floatToHalf(e_gamma.r)
       | (((uint64_t) floatToHalf(e_gamma.g)) << 16)
       | (((uint64_t) floatToHalf(e_gamma.b)) << 32)
       | (((uint64_t) floatToHalf(1.0f)) << 48);
}

} // namespace android::jpegrecoverymap
