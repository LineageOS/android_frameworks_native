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

#include <jpegrecoverymap/recoverymapmath.h>

namespace android::recoverymap {

static const float kBt2100R = 0.2627f, kBt2100G = 0.6780f, kBt2100B = 0.0593f;
static const float kBt2100Cb = 1.8814f, kBt2100Cr = 1.4746f;

Color bt2100RgbToYuv(Color e) {
  float yp = kBt2100R * e.r + kBt2100G * e.g + kBt2100B * e.b;
  return {{{yp, (e.b - yp) / kBt2100Cb, (e.r - yp) / kBt2100Cr }}};
}

static const float kSrgbRCr = 1.402f, kSrgbGCb = 0.34414f, kSrgbGCr = 0.71414f, kSrgbBCb = 1.772f;

Color srgbYuvToRgb(Color e) {
  return {{{ e.y + kSrgbRCr * e.v, e.y - kSrgbGCb * e.u - kSrgbGCr * e.v, e.y + kSrgbBCb * e.u }}};
}

float srgbInvOetf(float e) {
  if (e <= 0.04045f) {
    return e / 12.92f;
  } else {
    return pow((e + 0.055f) / 1.055f, 2.4);
  }
}

Color srgbInvOetf(Color e) {
  return {{{ srgbInvOetf(e.r), srgbInvOetf(e.g), srgbInvOetf(e.b) }}};
}

static const float kHlgA = 0.17883277f, kHlgB = 0.28466892f, kHlgC = 0.55991073;

float hlgInvOetf(float e) {
  if (e <= 0.5f) {
    return pow(e, 2.0f) / 3.0f;
  } else {
    return (exp((e - kHlgC) / kHlgA) + kHlgB) / 12.0f;
  }
}

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

uint8_t EncodeRecovery(float y_sdr, float y_hdr, float hdr_ratio) {
  float gain = 1.0f;
  if (y_sdr > 0.0f) {
    gain = y_hdr / y_sdr;
  }

  if (gain < -hdr_ratio) gain = -hdr_ratio;
  if (gain > hdr_ratio) gain = hdr_ratio;

  return static_cast<uint8_t>(log2(gain) / log2(hdr_ratio) * 127.5f  + 127.5f);
}

float applyRecovery(float y_sdr, float recovery, float hdr_ratio) {
  return exp2(log2(y_sdr) + recovery * log2(hdr_ratio));
}

// TODO: do we need something more clever for filtering either the map or images
// to generate the map?

static float mapUintToFloat(uint8_t map_uint) {
  return (static_cast<float>(map_uint) - 127.5f) / 127.5f;
}

float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y) {
  float x_map = static_cast<float>(x) / static_cast<float>(map_scale_factor);
  float y_map = static_cast<float>(y) / static_cast<float>(map_scale_factor);

  size_t x_lower = static_cast<size_t>(floor(x_map));
  size_t x_upper = x_lower + 1;
  size_t y_lower = static_cast<size_t>(floor(y_map));
  size_t y_upper = y_lower + 1;

  float x_influence = x_map - static_cast<float>(x_lower);
  float y_influence = y_map - static_cast<float>(y_lower);

  float e1 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_lower * map->width]);
  float e2 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_upper * map->width]);
  float e3 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_lower * map->width]);
  float e4 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_upper * map->width]);

  return e1 * (x_influence + y_influence) / 2.0f
      + e2 * (x_influence + 1.0f - y_influence) / 2.0f
      + e3 * (1.0f - x_influence + y_influence) / 2.0f
      + e4 * (1.0f - x_influence + 1.0f - y_influence) / 2.0f;
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

typedef float (*sampleComponentFn)(jr_uncompressed_ptr, size_t, size_t);

static float sampleComponent(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y,
                             sampleComponentFn sample_fn) {
  float e = 0.0f;
  for (size_t dy = 0; dy < map_scale_factor; ++dy) {
    for (size_t dx = 0; dx < map_scale_factor; ++dx) {
      e += sample_fn(image, x * map_scale_factor + dx, y * map_scale_factor + dy);
    }
  }

  return e / static_cast<float>(map_scale_factor * map_scale_factor);
}

static float getYuv420Y(jr_uncompressed_ptr image, size_t x, size_t y) {
  size_t pixel_idx = x + y * image->width;
  uint8_t y_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_idx];
  return static_cast<float>(y_uint) / 255.0f;
}


float sampleYuv420Y(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
  return sampleComponent(image, map_scale_factor, x, y, getYuv420Y);
}

static float getP010Y(jr_uncompressed_ptr image, size_t x, size_t y) {
  size_t pixel_idx = x + y * image->width;
  uint8_t y_uint = reinterpret_cast<uint16_t*>(image->data)[pixel_idx];
  // Expecting narrow range input
  return (static_cast<float>(y_uint) - 64.0f) / 960.0f;
}

float sampleP010Y(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
  return sampleComponent(image, map_scale_factor, x, y, getP010Y);
}
} // namespace android::recoverymap
