/*
 * Copyright 2024 The Android Open Source Project
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
#pragma once
#include <SkImage.h>
#include <SkRuntimeEffect.h>
#include <SkShader.h>
#include "../compat/SkiaGpuContext.h"
namespace android {
namespace renderengine {
namespace skia {
/**
 * MouriMap is a fast, albeit not realtime, tonemapping algorithm optimized for near-exact
 * preservation of SDR (or, equivalently, LDR) regions, while trying to do an acceptable job of
 * preserving HDR detail.
 *
 * MouriMap is a local tonemapping algorithm, meaning that nearby pixels are taken into
 * consideration when choosing a tonemapping curve.
 *
 * The algorithm conceptually is as follows:
 * 1. Partition the image into 128x128 chunks, computing the log2(maximum luminance) in each chunk
 *.    a. Maximum luminance is computed as max(R, G, B), where the R, G, B values are in linear
 *.       luminance on a scale defined by the destination color gamut. Max(R, G, B) has been found
 *.       to minimize difference in hue while restricting to typical LDR color volumes. See: Burke,
 *.       Adam & Smith, Michael & Zink, Michael. 2020. Color Volume and Hue-preservation in HDR
 *.       Tone Mapping. SMPTE Motion Imaging Journal.
 *.    b. Each computed luminance is lower-bounded by 1.0 in Skia's color
 *.       management, or 203 nits.
 * 2. Blur the resulting chunks using a 5x5 gaussian kernel, to smooth out the local luminance map.
 * 3. Now, for each pixel in the original image:
 *     a. Upsample from the blurred chunks of luminance computed in (2). Call this luminance value
 *.       L: an estimate of the maximum luminance of surrounding pixels.
 *.    b. If the luminance is less than 1.0 (203 nits), then do not modify the pixel value of the
 *.       original image.
 *.    c. Otherwise,
 *.       parameterize a tone-mapping curve using a method described by Chrome:
 *.       https://docs.google.com/document/d/17T2ek1i2R7tXdfHCnM-i5n6__RoYe0JyMfKmTEjoGR8/.
 *.        i. Compute a gain G = (1 + max(linear R, linear G, linear B) / (L * L))
 *.           / (1 + max(linear R, linear G, linear B)). Note the similarity with the 1D curve
 *.           described by Erik Reinhard, Michael Stark, Peter Shirley, and James Ferwerda. 2002.
 *.           Photographic tone reproduction for digital images. ACM Trans. Graph.
 *.       ii. Multiply G by the linear source colors to compute the final colors.
 *
 * Because it is a multi-renderpass algorithm requiring multiple off-screen textures, MouriMap is
 * typically not suitable to be ran "frequently", at high refresh rates (e.g., 120hz). However,
 * MouriMap is sufficiently fast enough for infrequent composition where preserving SDR detail is
 * most important, such as for screenshots.
 */
class MouriMap {
public:
    MouriMap();
    // Apply the MouriMap tonemmaping operator to the input.
    // The HDR/SDR ratio describes the luminace range of the input. 1.0 means SDR. Anything larger
    // then 1.0 means that there is headroom above the SDR region.
    sk_sp<SkShader> mouriMap(SkiaGpuContext* context, sk_sp<SkShader> input, float hdrSdrRatio);

private:
    sk_sp<SkImage> downchunk(SkiaGpuContext* context, sk_sp<SkShader> input,
                             float hdrSdrRatio) const;
    sk_sp<SkImage> blur(SkiaGpuContext* context, SkImage* input) const;
    sk_sp<SkShader> tonemap(sk_sp<SkShader> input, SkImage* localLux, float hdrSdrRatio) const;
    const sk_sp<SkRuntimeEffect> mCrosstalkAndChunk16x16;
    const sk_sp<SkRuntimeEffect> mChunk8x8;
    const sk_sp<SkRuntimeEffect> mBlur;
    const sk_sp<SkRuntimeEffect> mTonemap;
};
} // namespace skia
} // namespace renderengine
} // namespace android