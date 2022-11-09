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

#ifndef ANDROID_JPEGRECOVERYMAP_RECOVERYMAPMATH_H
#define ANDROID_JPEGRECOVERYMAP_RECOVERYMAPMATH_H

#include <stdint.h>

#include <jpegrecoverymap/recoverymap.h>

namespace android::recoverymap {

const float kSdrWhiteNits = 100.0f;

struct Color {
  union {
    struct {
      float r;
      float g;
      float b;
    };
    struct {
      float y;
      float u;
      float v;
    };
  };
};

/*
 * Convert from OETF'd bt.2100 RGB to YUV, according to BT.2100
 */
Color bt2100RgbToYuv(Color e);

/*
 * Convert srgb YUV to RGB, according to ECMA TR/98.
 */
Color srgbYuvToRgb(Color e);

/*
 * TODO: better source for srgb transfer function
 * Convert from srgb to linear, according to https://en.wikipedia.org/wiki/SRGB.
 * [0.0, 1.0] range in and out.
 */
float srgbInvOetf(float e);
Color srgbInvOetf(Color e);

/*
 * Convert from HLG to scene luminance in nits, according to BT.2100.
 */
float hlgInvOetf(float e);

/*
 * Convert from scene luminance in nits to HLG,  according to BT.2100.
 */
float hlgOetf(float e);
Color hlgOetf(Color e);

/*
 * Calculate the 8-bit unsigned integer recovery value for the given SDR and HDR
 * luminances in linear space, and the hdr ratio to encode against.
 */
uint8_t encodeRecovery(float y_sdr, float y_hdr, float hdr_ratio);

/*
 * Calculates the linear luminance in nits after applying the given recovery
 * value, with the given hdr ratio, to the given sdr input in the range [0, 1].
 */
Color applyRecovery(Color e, float recovery, float hdr_ratio);

/*
 * Helper for sampling from images.
 */
Color getYuv420Pixel(jr_uncompressed_ptr image, size_t x, size_t y);

/*
 * Sample the recovery value for the map from a given x,y coordinate on a scale
 * that is map scale factor larger than the map size.
 */
float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y);

/*
 * Sample the image Y value at the provided location, with a weighting based on nearby pixels
 * and the map scale factor.
 *
 * Expect narrow-range image data for P010.
 */
float sampleYuv420Y(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y);
float sampleP010Y(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y);

} // namespace android::recoverymap

#endif // ANDROID_JPEGRECOVERYMAP_RECOVERYMAPMATH_H
