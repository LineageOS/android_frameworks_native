/*
 * Copyright 2023 The Android Open Source Project
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

#ifndef ANDROID_ULTRAHDR_ULTRAHDR_H
#define ANDROID_ULTRAHDR_ULTRAHDR_H

namespace android::ultrahdr {
// Color gamuts for image data
typedef enum {
  ULTRAHDR_COLORGAMUT_UNSPECIFIED,
  ULTRAHDR_COLORGAMUT_BT709,
  ULTRAHDR_COLORGAMUT_P3,
  ULTRAHDR_COLORGAMUT_BT2100,
  ULTRAHDR_COLORGAMUT_MAX = ULTRAHDR_COLORGAMUT_BT2100,
} ultrahdr_color_gamut;

// Transfer functions for image data
typedef enum {
  ULTRAHDR_TF_UNSPECIFIED = -1,
  ULTRAHDR_TF_LINEAR = 0,
  ULTRAHDR_TF_HLG = 1,
  ULTRAHDR_TF_PQ = 2,
  ULTRAHDR_TF_SRGB = 3,
  ULTRAHDR_TF_MAX = ULTRAHDR_TF_SRGB,
} ultrahdr_transfer_function;

// Target output formats for decoder
typedef enum {
  ULTRAHDR_OUTPUT_SDR,          // SDR in RGBA_8888 color format
  ULTRAHDR_OUTPUT_HDR_LINEAR,   // HDR in F16 color format (linear)
  ULTRAHDR_OUTPUT_HDR_PQ,       // HDR in RGBA_1010102 color format (PQ transfer function)
  ULTRAHDR_OUTPUT_HDR_HLG,      // HDR in RGBA_1010102 color format (HLG transfer function)
} ultrahdr_output_format;

/*
 * Holds information for gain map related metadata.
 */
struct ultrahdr_metadata_struct {
  // Ultra HDR library version
  const char* version;
  // Max Content Boost for the map
  float maxContentBoost;
  // Min Content Boost for the map
  float minContentBoost;
};
typedef struct ultrahdr_metadata_struct* ultrahdr_metadata_ptr;

}  // namespace android::ultrahdr

#endif //ANDROID_ULTRAHDR_ULTRAHDR_H
