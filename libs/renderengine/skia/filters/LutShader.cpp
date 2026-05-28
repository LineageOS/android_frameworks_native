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
#include "LutShader.h"

#include <SkM44.h>
#include <SkTileMode.h>
#include <common/trace.h>
#include <cutils/ashmem.h>
#include <include/core/SkColorSpace.h>
#include <log/log.h>
#include <math/half.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ui/ColorSpace.h>

#include <renderengine/ColorSpaces.h>
#include "RuntimeEffectManager.h"

using aidl::android::hardware::graphics::composer3::LutProperties;

namespace android {
namespace renderengine {
namespace skia {

const SkString kEffectSource_LutEffect(R"(
    uniform shader image;
    uniform shader lut;
    uniform int size;
    uniform int key;
    uniform int dimension;
    uniform vec3 luminanceCoefficients; // for CIE_Y
    // for hlg/pq transfer function, we need normalize it to [0.0, 1.0]
    // we use `normalizeScalar` to do so
    uniform float normalizeScalar;

    vec4 main(vec2 xy) {
        float4 rgba = image.eval(xy);
        float3 linear = rgba.rgb * normalizeScalar;
        if (dimension == 1) {
            // RGB
            if (key == 0) {
                float indexR = linear.r * float(size - 1);
                float indexG = linear.g * float(size - 1);
                float indexB = linear.b * float(size - 1);
                float gainR = lut.eval(vec2(indexR, 0.0) + 0.5).r;
                float gainG = lut.eval(vec2(indexG, 0.0) + 0.5).r;
                float gainB = lut.eval(vec2(indexB, 0.0) + 0.5).r;
                linear = float3(linear.r * gainR, linear.g * gainG, linear.b * gainB);
            // MAX_RGB
            } else if (key == 1) {
                float maxRGB = max(linear.r, max(linear.g, linear.b));
                float index = maxRGB * float(size - 1);
                float gain = lut.eval(vec2(index, 0.0) + 0.5).r;
                linear = linear * gain;
            // CIE_Y
            } else if (key == 2) {
                float y = dot(linear, luminanceCoefficients);
                float index = y * float(size - 1);
                float gain = lut.eval(vec2(index, 0.0) + 0.5).r;
                linear = linear * gain;
            }
        } else if (dimension == 3) {
            if (key == 0) {
                // index
                float x = linear.r * float(size - 1);
                float y = linear.g * float(size - 1);
                float z = linear.b * float(size - 1);

                // lower bound
                float x0 = floor(x);
                float y0 = floor(y);
                float z0 = floor(z);

                // upper bound
                float x1 = min(x0 + 1.0, float(size - 1));
                float y1 = min(y0 + 1.0, float(size - 1));
                float z1 = min(z0 + 1.0, float(size - 1));

                // weight
                // if the value reaches to upper bound, x1 == x0, then weight is 0
                // if no, x1 - x0 should always be 1.0
                float tx = x1 == x0 ? 0 : x - x0;
                float ty = y1 == y0 ? 0 : y - y0;
                float tz = z1 == z0 ? 0 : z - z0;

                // get indices
                // this follows 3d flatten policy described in API/AIDL interface
                // i.e., `FLAT[z + DEPTH * (y + HEIGHT * x)] = ORIGINAL[x][y][z]`
                float i000 = z0 + (y0 * float(size)) + (x0 * float(size) * float(size));
                float i001 = z1 + (y0 * float(size)) + (x0 * float(size) * float(size));
                float i010 = z0 + (y1 * float(size)) + (x0 * float(size) * float(size));
                float i011 = z1 + (y1 * float(size)) + (x0 * float(size) * float(size));
                float i100 = z0 + (y0 * float(size)) + (x1 * float(size) * float(size));
                float i101 = z1 + (y0 * float(size)) + (x1 * float(size) * float(size));
                float i110 = z0 + (y1 * float(size)) + (x1 * float(size) * float(size));
                float i111 = z1 + (y1 * float(size)) + (x1 * float(size) * float(size));

                // TODO(b/377984618): support Tetrahedral interpolation
                // perform trilinear interpolation
                // see https://en.wikipedia.org/wiki/Trilinear_interpolation
                float3 c000 = lut.eval(vec2(i000, 0.0) + 0.5).rgb;
                float3 c001 = lut.eval(vec2(i001, 0.0) + 0.5).rgb;
                float3 c010 = lut.eval(vec2(i010, 0.0) + 0.5).rgb;
                float3 c011 = lut.eval(vec2(i011, 0.0) + 0.5).rgb;
                float3 c100 = lut.eval(vec2(i100, 0.0) + 0.5).rgb;
                float3 c101 = lut.eval(vec2(i101, 0.0) + 0.5).rgb;
                float3 c110 = lut.eval(vec2(i110, 0.0) + 0.5).rgb;
                float3 c111 = lut.eval(vec2(i111, 0.0) + 0.5).rgb;

                // mix(x, y, a) = x * (1 - a) + y * a
                // interpolate along the z-axis
                float3 c00 = mix(c000, c001, tz);
                float3 c01 = mix(c010, c011, tz);
                float3 c10 = mix(c100, c101, tz);
                float3 c11 = mix(c110, c111, tz);

                // interpolate along the y-axis
                float3 c0 = mix(c00, c01, ty);
                float3 c1 = mix(c10, c11, ty);

                // interpolate along the x-axis
                linear = mix(c0, c1, tx);
            }
        }
        return float4(linear, rgba.a);
    })");

// same as shader::toColorSpace function
// TODO: put this function in a general place
static ColorSpace toColorSpace(ui::Dataspace dataspace) {
    switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
        case HAL_DATASPACE_STANDARD_BT709:
            return ColorSpace::sRGB();
        case HAL_DATASPACE_STANDARD_DCI_P3:
            return ColorSpace::DisplayP3();
        case HAL_DATASPACE_STANDARD_BT2020:
        case HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE:
            return ColorSpace::BT2020();
        case HAL_DATASPACE_STANDARD_ADOBE_RGB:
            return ColorSpace::AdobeRGB();
        case HAL_DATASPACE_STANDARD_BT601_625:
        case HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED:
        case HAL_DATASPACE_STANDARD_BT601_525:
        case HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED:
        case HAL_DATASPACE_STANDARD_BT470M:
        case HAL_DATASPACE_STANDARD_FILM:
        case HAL_DATASPACE_STANDARD_UNSPECIFIED:
        default:
            return ColorSpace::sRGB();
    }
}

static float computeHlgScale() {
    static constexpr auto input = 0.7498773651;
    static constexpr auto a = 0.17883277;
    static constexpr auto b = 1 - 4 * a;
    const static auto c = 0.5 - a * std::log(4 * a);
    // Returns about 265 nits -- After the typical HLG OOTF this would map to 203 nits under ideal
    // conditions.
    return (exp((input - c) / a) + b) / 12;
}

static float computePqScale() {
    static constexpr auto input = 0.58068888104;
    static constexpr auto m1 = 0.1593017578125;
    static constexpr auto m2 = 78.84375;
    static constexpr auto c1 = 0.8359375;
    static constexpr auto c2 = 18.8515625;
    static constexpr auto c3 = 18.6875;
    // This should essetially return 203 nits
    return pow((pow(input, 1 / m2) - c1) / (c2 - c3 * pow(input, 1 / m2)), 1 / m1);
}

LutShader::LutShader(RuntimeEffectManager& effectManager) {
    mEffect = effectManager.mKnownEffects[kLutEffect];
}

sk_sp<SkShader> LutShader::generateLutShader(sk_sp<SkShader> input,
                                             const std::vector<float>& buffers,
                                             const int32_t offset, const int32_t length,
                                             const int32_t dimension, const int32_t size,
                                             const int32_t samplingKey,
                                             ui::Dataspace srcDataspace) {
    SFTRACE_NAME("lut shader");
    std::vector<half> buffer(length * 4); // 4 is for RGBA
    auto d = static_cast<LutProperties::Dimension>(dimension);
    if (d == LutProperties::Dimension::ONE_D) {
        auto it = buffers.begin() + offset;
        std::generate(buffer.begin(), buffer.end(), [it, i = 0]() mutable {
            float val = (i++ % 4 == 0) ? *it++ : 0.0f;
            return half(val);
        });
    } else {
        for (int i = 0; i < length; i++) {
            buffer[i * 4] = half(buffers[offset + i]);
            buffer[i * 4 + 1] = half(buffers[offset + length + i]);
            buffer[i * 4 + 2] = half(buffers[offset + length * 2 + i]);
            buffer[i * 4 + 3] = half(0);
        }
    }
    /**
     * 1D Lut RGB/MAX_RGB
     * (R0, 0, 0, 0)
     * (R1, 0, 0, 0)
     * ...
     * (R_length-1, 0, 0, 0)
     *
     * 1D Lut CIE_Y
     * (Y0, 0, 0, 0)
     * (Y1, 0, 0, 0)
     * ...
     * (Y_length-1, 0, 0, 0)
     *
     * 3D Lut MAX_RGB
     * (R0, G0, B0, 0)
     * (R1, G1, B1, 0)
     * ...
     * (R_length-1, G_length-1, B_length-1, 0)
     */
    SkImageInfo info = SkImageInfo::Make(length /* the number of rgba */, 1, kRGBA_F16_SkColorType,
                                         kPremul_SkAlphaType);
    SkBitmap bitmap;
    bitmap.allocPixels(info);
    if (!bitmap.installPixels(info, buffer.data(), info.minRowBytes())) {
        ALOGW("bitmap.installPixels failed, skip this Lut!");
        return input;
    }

    sk_sp<SkImage> lutImage = SkImages::RasterFromBitmap(bitmap);
    if (!lutImage) {
        ALOGW("Got a nullptr from SkImages::RasterFromBitmap, skip this Lut!");
        return input;
    }

    mBuilder->child("image") = input;
    mBuilder->child("lut") =
            lutImage->makeRawShader(SkTileMode::kClamp, SkTileMode::kClamp,
                                    d == LutProperties::Dimension::ONE_D
                                            ? SkSamplingOptions(SkFilterMode::kLinear)
                                            : SkSamplingOptions());

    float normalizeScalar = 1.0;
    switch (srcDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_HLG:
            normalizeScalar = computeHlgScale();
            break;
        case HAL_DATASPACE_TRANSFER_ST2084:
            normalizeScalar = computePqScale();
            break;
        default:
            normalizeScalar = 1.0;
    }
    const int uSize = static_cast<int>(size); // the size per dimension
    const int uKey = static_cast<int>(samplingKey);
    const int uDimension = static_cast<int>(dimension);
    const float uNormalizeScalar = static_cast<float>(normalizeScalar);

    if (static_cast<LutProperties::SamplingKey>(samplingKey) == LutProperties::SamplingKey::CIE_Y) {
        // Use predefined colorspaces of input dataspace so that we can get D65 illuminant
        mat3 toXYZMatrix(toColorSpace(srcDataspace).getRGBtoXYZ());
        mBuilder->uniform("luminanceCoefficients") =
                SkV3{toXYZMatrix[0][1], toXYZMatrix[1][1], toXYZMatrix[2][1]};
    } else {
        mBuilder->uniform("luminanceCoefficients") = SkV3{1.f / 3.f, 1.f / 3.f, 1.f / 3.f};
    }
    mBuilder->uniform("size") = uSize;
    mBuilder->uniform("key") = uKey;
    mBuilder->uniform("dimension") = uDimension;
    mBuilder->uniform("normalizeScalar") = uNormalizeScalar;

    // de-gamma the image without changing the primaries
    return mBuilder->makeShader()->makeWithWorkingColorSpace(
            renderengine::toSkColorSpace(srcDataspace, renderengine::ColorSpaceOptions::None)
                    ->makeLinearGamma());
}

sk_sp<SkShader> LutShader::lutShader(sk_sp<SkShader>& input,
                                     std::shared_ptr<gui::DisplayLuts> displayLuts,
                                     ui::Dataspace srcDataspace) {
    if (mBuilder == nullptr) {
        mBuilder = std::make_unique<SkRuntimeShaderBuilder>(mEffect);
    }

    if (!displayLuts || !displayLuts->isValid()) {
        ALOGW("displayLuts is nullptr or invalid, skip LutShader!");
        return input;
    }

    size_t maxEndOffset = displayLuts->getMaxEndOffset();
    auto& fd = displayLuts->getLutFileDescriptor();
    auto& offsets = displayLuts->offsets;
    auto& lutProperties = displayLuts->lutProperties;

    size_t bufferSize = static_cast<size_t>(ashmem_get_size_region(fd.get()));

    std::vector<float> buffers;
    // decode the shared memory of luts
    float* ptr = (float*)mmap(NULL, bufferSize, PROT_READ, MAP_SHARED, fd.get(), 0);
    if (ptr == MAP_FAILED) {
        ALOGW("mmap failed when decoding displayLuts");
        return input;
    }
    buffers = std::vector<float>(ptr, ptr + maxEndOffset);
    munmap(ptr, bufferSize);

    for (size_t i = 0; i < offsets.size(); i++) {
        size_t elementsNeededPerChannel = lutProperties[i].getElementsNeededPerChannel();
        if (elementsNeededPerChannel == 0) {
            ALOGW("Invalid elementsNeededPerChannel at index %zu", i);
            return input;
        }

        input = generateLutShader(input, buffers, offsets[i], elementsNeededPerChannel,
                                  lutProperties[i].dimension, lutProperties[i].size,
                                  lutProperties[i].samplingKey, srcDataspace);
    }
    return input;
}

} // namespace skia
} // namespace renderengine
} // namespace android
