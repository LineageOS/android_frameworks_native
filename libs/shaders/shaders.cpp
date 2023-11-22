/*
 * Copyright 2021 The Android Open Source Project
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

#include <shaders/shaders.h>

#include <tonemap/tonemap.h>

#include <cmath>
#include <optional>

#include <math/mat4.h>
#include <system/graphics-base-v1.0.h>
#include <ui/ColorSpace.h>

namespace android::shaders {

namespace {

aidl::android::hardware::graphics::common::Dataspace toAidlDataspace(ui::Dataspace dataspace) {
    return static_cast<aidl::android::hardware::graphics::common::Dataspace>(dataspace);
}

void generateXYZTransforms(std::string& shader) {
    shader.append(R"(
        uniform float3x3 in_rgbToXyz;
        uniform float3x3 in_xyzToSrcRgb;
        uniform float4x4 in_colorTransform;
        float3 ToXYZ(float3 rgb) {
            return in_rgbToXyz * rgb;
        }

        float3 ToSrcRGB(float3 xyz) {
            return in_xyzToSrcRgb * xyz;
        }

        float3 ApplyColorTransform(float3 rgb) {
            return (in_colorTransform * float4(rgb, 1.0)).rgb;
        }
    )");
}

// Conversion from relative light to absolute light
// Note that 1.0 == 203 nits.
void generateLuminanceScalesForOOTF(ui::Dataspace inputDataspace, std::string& shader) {
    switch (inputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_HLG:
            // BT. 2408 says that a signal level of 0.75 == 203 nits for HLG, but that's after
            // applying OOTF. But we haven't applied OOTF yet, so we need to scale by a different
            // constant instead.
            shader.append(R"(
                float3 ScaleLuminance(float3 xyz) {
                    return xyz * 264.96;
                }
            )");
            break;
        default:
            shader.append(R"(
                float3 ScaleLuminance(float3 xyz) {
                    return xyz * 203.0;
                }
            )");
            break;
    }
}

// Normalizes from absolute light back to relative light (maps from [0, maxNits] back to [0, 1])
static void generateLuminanceNormalizationForOOTF(ui::Dataspace inputDataspace,
                                                  ui::Dataspace outputDataspace,
                                                  std::string& shader) {
    switch (outputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(
                float3 NormalizeLuminance(float3 xyz) {
                    return xyz / 203.0;
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            switch (inputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
                case HAL_DATASPACE_TRANSFER_HLG:
                    shader.append(R"(
                            float3 NormalizeLuminance(float3 xyz) {
                                return xyz / 264.96;
                            }
                        )");
                    break;
                default:
                    // Transcoding to HLG requires applying the inverse OOTF
                    // with the expectation that the OOTF is then applied during
                    // tonemapping downstream.
                    // BT. 2100-2 operates on normalized luminances, so renormalize to the input to
                    // correctly adjust gamma.
                    // Note that following BT. 2408 for HLG OETF actually maps 0.75 == ~264.96 nits,
                    // rather than 203 nits, because 203 nits == OOTF(invOETF(0.75)), so even though
                    // we originally scaled by 203 nits we need to re-normalize to 264.96 nits when
                    // converting to the correct brightness range.
                    shader.append(R"(
                            float3 NormalizeLuminance(float3 xyz) {
                                float ootfGain = pow(xyz.y / 1000.0, -0.2 / 1.2);
                                return xyz * ootfGain / 264.96;
                            }
                        )");
                    break;
            }
            break;
        default:
            switch (inputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
                case HAL_DATASPACE_TRANSFER_HLG:
                case HAL_DATASPACE_TRANSFER_ST2084:
                    // libtonemap outputs a range [0, in_libtonemap_displayMaxLuminance], so
                    // normalize back to [0, 1] when the output is SDR.
                    shader.append(R"(
                        float3 NormalizeLuminance(float3 xyz) {
                            return xyz / in_libtonemap_displayMaxLuminance;
                        }
                    )");
                    break;
                default:
                    // Otherwise normalize back down to the range [0, 1]
                    // TODO: get this working for extended range outputs
                    shader.append(R"(
                        float3 NormalizeLuminance(float3 xyz) {
                            return xyz / 203.0;
                        }
                    )");
                    break;
            }
    }
}

void generateOOTF(ui::Dataspace inputDataspace, ui::Dataspace outputDataspace,
                  std::string& shader) {
    shader.append(tonemap::getToneMapper()
                          ->generateTonemapGainShaderSkSL(toAidlDataspace(inputDataspace),
                                                          toAidlDataspace(outputDataspace))
                          .c_str());

    generateLuminanceScalesForOOTF(inputDataspace, shader);
    generateLuminanceNormalizationForOOTF(inputDataspace, outputDataspace, shader);

    // Some tonemappers operate on CIE luminance, other tonemappers operate on linear rgb
    // luminance in the source gamut.
    shader.append(R"(
            float3 OOTF(float3 linearRGB) {
                float3 scaledLinearRGB = ScaleLuminance(linearRGB);
                float3 scaledXYZ = ToXYZ(scaledLinearRGB);

                float gain = libtonemap_LookupTonemapGain(ToSrcRGB(scaledXYZ), scaledXYZ);

                return NormalizeLuminance(scaledXYZ * gain);
            }
        )");
}

void generateOETF(std::string& shader) {
    // Only support gamma 2.2 for now
    shader.append(R"(
        float3 OETF(float3 linear) {
            return sign(linear) * pow(abs(linear), float3(1.0 / 2.2));
        }
    )");
}

void generateEffectiveOOTF(bool undoPremultipliedAlpha, LinearEffect::SkSLType type,
                           bool needsCustomOETF, std::string& shader) {
    switch (type) {
        case LinearEffect::SkSLType::ColorFilter:
            shader.append(R"(
                half4 main(half4 inputColor) {
                    float4 c = float4(inputColor);
            )");
            break;
        case LinearEffect::SkSLType::Shader:
            shader.append(R"(
                uniform shader child;
                half4 main(float2 xy) {
                    float4 c = float4(child.eval(xy));
            )");
            break;
    }
    if (undoPremultipliedAlpha) {
        shader.append(R"(
            c.rgb = c.rgb / (c.a + 0.0019);
        )");
    }
    // We are using linear sRGB as a working space, with 1.0 == 203 nits
    shader.append(R"(
        c.rgb = ApplyColorTransform(OOTF(toLinearSrgb(c.rgb)));
    )");
    if (needsCustomOETF) {
        shader.append(R"(
            c.rgb = OETF(c.rgb);
        )");
    } else {
        shader.append(R"(
            c.rgb = fromLinearSrgb(c.rgb);
        )");
    }
    if (undoPremultipliedAlpha) {
        shader.append(R"(
            c.rgb = c.rgb * (c.a + 0.0019);
        )");
    }
    shader.append(R"(
            return c;
        }
    )");
}

template <typename T, std::enable_if_t<std::is_trivially_copyable<T>::value, bool> = true>
std::vector<uint8_t> buildUniformValue(T value) {
    std::vector<uint8_t> result;
    result.resize(sizeof(value));
    std::memcpy(result.data(), &value, sizeof(value));
    return result;
}

} // namespace

std::string buildLinearEffectSkSL(const LinearEffect& linearEffect) {
    std::string shaderString;
    generateXYZTransforms(shaderString);
    generateOOTF(linearEffect.inputDataspace, linearEffect.outputDataspace, shaderString);

    const bool needsCustomOETF = (linearEffect.fakeOutputDataspace & HAL_DATASPACE_TRANSFER_MASK) ==
            HAL_DATASPACE_TRANSFER_GAMMA2_2;
    if (needsCustomOETF) {
        generateOETF(shaderString);
    }
    generateEffectiveOOTF(linearEffect.undoPremultipliedAlpha, linearEffect.type, needsCustomOETF,
                          shaderString);
    return shaderString;
}

ColorSpace toColorSpace(ui::Dataspace dataspace) {
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
            // TODO(b/208290320): BT601 format and variants return different primaries
        case HAL_DATASPACE_STANDARD_BT601_625:
        case HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED:
        case HAL_DATASPACE_STANDARD_BT601_525:
        case HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED:
            // TODO(b/208290329): BT407M format returns different primaries
        case HAL_DATASPACE_STANDARD_BT470M:
            // TODO(b/208290904): FILM format returns different primaries
        case HAL_DATASPACE_STANDARD_FILM:
        case HAL_DATASPACE_STANDARD_UNSPECIFIED:
        default:
            return ColorSpace::sRGB();
    }
}

// Generates a list of uniforms to set on the LinearEffect shader above.
std::vector<tonemap::ShaderUniform> buildLinearEffectUniforms(
        const LinearEffect& linearEffect, const mat4& colorTransform, float maxDisplayLuminance,
        float currentDisplayLuminanceNits, float maxLuminance, AHardwareBuffer* buffer,
        aidl::android::hardware::graphics::composer3::RenderIntent renderIntent) {
    std::vector<tonemap::ShaderUniform> uniforms;

    auto inputColorSpace = toColorSpace(linearEffect.inputDataspace);
    auto outputColorSpace = toColorSpace(linearEffect.outputDataspace);

    uniforms.push_back(
            {.name = "in_rgbToXyz",
             .value = buildUniformValue<mat3>(ColorSpace::linearExtendedSRGB().getRGBtoXYZ())});
    uniforms.push_back({.name = "in_xyzToSrcRgb",
                        .value = buildUniformValue<mat3>(inputColorSpace.getXYZtoRGB())});
    // Transforms xyz colors to linear source colors, then applies the color transform, then
    // transforms to linear extended RGB for skia to color manage.
    uniforms.push_back({.name = "in_colorTransform",
                        .value = buildUniformValue<mat4>(
                                mat4(ColorSpace::linearExtendedSRGB().getXYZtoRGB()) *
                                // TODO: the color transform ideally should be applied
                                // in the source colorspace, but doing that breaks
                                // renderengine tests
                                mat4(outputColorSpace.getRGBtoXYZ()) * colorTransform *
                                mat4(outputColorSpace.getXYZtoRGB()))});

    tonemap::Metadata metadata{.displayMaxLuminance = maxDisplayLuminance,
                               // If the input luminance is unknown, use display luminance (aka,
                               // no-op any luminance changes).
                               // This is expected to only be meaningful for PQ content
                               .contentMaxLuminance =
                                       maxLuminance > 0 ? maxLuminance : maxDisplayLuminance,
                               .currentDisplayLuminance = currentDisplayLuminanceNits > 0
                                       ? currentDisplayLuminanceNits
                                       : maxDisplayLuminance,
                               .buffer = buffer,
                               .renderIntent = renderIntent};

    for (const auto uniform : tonemap::getToneMapper()->generateShaderSkSLUniforms(metadata)) {
        uniforms.push_back(uniform);
    }

    return uniforms;
}

} // namespace android::shaders
