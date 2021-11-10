/*
 * Copyright 2020 The Android Open Source Project
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

#include "LinearEffect.h"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <SkString.h>
#include <tonemap/tonemap.h>
#include <utils/Trace.h>

#include <optional>

#include "log/log.h"
#include "math/mat4.h"
#include "system/graphics-base-v1.0.h"
#include "ui/ColorSpace.h"

namespace android {
namespace renderengine {
namespace skia {

static aidl::android::hardware::graphics::common::Dataspace toAidlDataspace(
        ui::Dataspace dataspace) {
    return static_cast<aidl::android::hardware::graphics::common::Dataspace>(dataspace);
}

static void generateEOTF(ui::Dataspace dataspace, SkString& shader) {
    switch (dataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(

                float3 EOTF(float3 color) {
                    float m1 = (2610.0 / 4096.0) / 4.0;
                    float m2 = (2523.0 / 4096.0) * 128.0;
                    float c1 = (3424.0 / 4096.0);
                    float c2 = (2413.0 / 4096.0) * 32.0;
                    float c3 = (2392.0 / 4096.0) * 32.0;

                    float3 tmp = pow(clamp(color, 0.0, 1.0), 1.0 / float3(m2));
                    tmp = max(tmp - c1, 0.0) / (c2 - c3 * tmp);
                    return pow(tmp, 1.0 / float3(m1));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                float EOTF_channel(float channel) {
                    const float a = 0.17883277;
                    const float b = 0.28466892;
                    const float c = 0.55991073;
                    return channel <= 0.5 ? channel * channel / 3.0 :
                            (exp((channel - c) / a) + b) / 12.0;
                }

                float3 EOTF(float3 color) {
                    return float3(EOTF_channel(color.r), EOTF_channel(color.g),
                            EOTF_channel(color.b));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_LINEAR:
            shader.append(R"(
                float3 EOTF(float3 color) {
                    return color;
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_SRGB:
        default:
            shader.append(R"(

                float EOTF_sRGB(float srgb) {
                    return srgb <= 0.04045 ? srgb / 12.92 : pow((srgb + 0.055) / 1.055, 2.4);
                }

                float3 EOTF_sRGB(float3 srgb) {
                    return float3(EOTF_sRGB(srgb.r), EOTF_sRGB(srgb.g), EOTF_sRGB(srgb.b));
                }

                float3 EOTF(float3 srgb) {
                    return sign(srgb.rgb) * EOTF_sRGB(abs(srgb.rgb));
                }
            )");
            break;
    }
}

static void generateXYZTransforms(SkString& shader) {
    shader.append(R"(
        uniform float4x4 in_rgbToXyz;
        uniform float4x4 in_xyzToRgb;
        float3 ToXYZ(float3 rgb) {
            return clamp((in_rgbToXyz * float4(rgb, 1.0)).rgb, 0.0, 1.0);
        }

        float3 ToRGB(float3 xyz) {
            return clamp((in_xyzToRgb * float4(xyz, 1.0)).rgb, 0.0, 1.0);
        }
    )");
}

// Conversion from relative light to absolute light (maps from [0, 1] to [0, maxNits])
static void generateLuminanceScalesForOOTF(ui::Dataspace inputDataspace, SkString& shader) {
    switch (inputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(
                    float3 ScaleLuminance(float3 xyz) {
                        return xyz * 10000.0;
                    }
                )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                    float3 ScaleLuminance(float3 xyz) {
                        return xyz * 1000.0 * pow(xyz.y, 0.2);
                    }
                )");
            break;
        default:
            shader.append(R"(
                    float3 ScaleLuminance(float3 xyz) {
                        return xyz * in_libtonemap_inputMaxLuminance;
                    }
                )");
            break;
    }
}

// Normalizes from absolute light back to relative light (maps from [0, maxNits] back to [0, 1])
static void generateLuminanceNormalizationForOOTF(ui::Dataspace outputDataspace, SkString& shader) {
    switch (outputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(
                    float3 NormalizeLuminance(float3 xyz) {
                        return xyz / 10000.0;
                    }
                )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                    float3 NormalizeLuminance(float3 xyz) {
                        return xyz / 1000.0 * pow(xyz.y / 1000.0, -0.2 / 1.2);
                    }
                )");
            break;
        default:
            shader.append(R"(
                    float3 NormalizeLuminance(float3 xyz) {
                        return xyz / in_libtonemap_displayMaxLuminance;
                    }
                )");
            break;
    }
}

static void generateOOTF(ui::Dataspace inputDataspace, ui::Dataspace outputDataspace,
                         SkString& shader) {
    shader.append(tonemap::getToneMapper()
                          ->generateTonemapGainShaderSkSL(toAidlDataspace(inputDataspace),
                                                          toAidlDataspace(outputDataspace))
                          .c_str());

    generateLuminanceScalesForOOTF(inputDataspace, shader);
    generateLuminanceNormalizationForOOTF(outputDataspace, shader);

    shader.append(R"(
            float3 OOTF(float3 linearRGB, float3 xyz) {
                float3 scaledLinearRGB = ScaleLuminance(linearRGB);
                float3 scaledXYZ = ScaleLuminance(xyz);

                float gain = libtonemap_LookupTonemapGain(scaledLinearRGB, scaledXYZ);

                return NormalizeLuminance(scaledXYZ * gain);
            }
        )");
}

static void generateOETF(ui::Dataspace dataspace, SkString& shader) {
    switch (dataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(

                float3 OETF(float3 xyz) {
                    float m1 = (2610.0 / 4096.0) / 4.0;
                    float m2 = (2523.0 / 4096.0) * 128.0;
                    float c1 = (3424.0 / 4096.0);
                    float c2 = (2413.0 / 4096.0) * 32.0;
                    float c3 = (2392.0 / 4096.0) * 32.0;

                    float3 tmp = pow(xyz, float3(m1));
                    tmp = (c1 + c2 * tmp) / (1.0 + c3 * tmp);
                    return pow(tmp, float3(m2));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                float OETF_channel(float channel) {
                    const float a = 0.17883277;
                    const float b = 0.28466892;
                    const float c = 0.55991073;
                    return channel <= 1.0 / 12.0 ? sqrt(3.0 * channel) :
                            a * log(12.0 * channel - b) + c;
                }

                float3 OETF(float3 linear) {
                    return float3(OETF_channel(linear.r), OETF_channel(linear.g),
                            OETF_channel(linear.b));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_LINEAR:
            shader.append(R"(
                float3 OETF(float3 linear) {
                    return linear;
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_SRGB:
        default:
            shader.append(R"(
                float OETF_sRGB(float linear) {
                    return linear <= 0.0031308 ?
                            linear * 12.92 : (pow(linear, 1.0 / 2.4) * 1.055) - 0.055;
                }

                float3 OETF_sRGB(float3 linear) {
                    return float3(OETF_sRGB(linear.r), OETF_sRGB(linear.g), OETF_sRGB(linear.b));
                }

                float3 OETF(float3 linear) {
                    return sign(linear.rgb) * OETF_sRGB(abs(linear.rgb));
                }
            )");
            break;
    }
}

static void generateEffectiveOOTF(bool undoPremultipliedAlpha, SkString& shader) {
    shader.append(R"(
        uniform shader child;
        half4 main(float2 xy) {
            float4 c = float4(child.eval(xy));
    )");
    if (undoPremultipliedAlpha) {
        shader.append(R"(
            c.rgb = c.rgb / (c.a + 0.0019);
        )");
    }
    shader.append(R"(
        float3 linearRGB = EOTF(c.rgb);
        float3 xyz = ToXYZ(linearRGB);
        c.rgb = OETF(ToRGB(OOTF(linearRGB, xyz)));
    )");
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
static ColorSpace toColorSpace(ui::Dataspace dataspace) {
    switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
        case HAL_DATASPACE_STANDARD_BT709:
            return ColorSpace::sRGB();
            break;
        case HAL_DATASPACE_STANDARD_DCI_P3:
            return ColorSpace::DisplayP3();
            break;
        case HAL_DATASPACE_STANDARD_BT2020:
            return ColorSpace::BT2020();
            break;
        default:
            return ColorSpace::sRGB();
            break;
    }
}

sk_sp<SkRuntimeEffect> buildRuntimeEffect(const LinearEffect& linearEffect) {
    ATRACE_CALL();
    SkString shaderString;
    generateEOTF(linearEffect.inputDataspace, shaderString);
    generateXYZTransforms(shaderString);
    generateOOTF(linearEffect.inputDataspace, linearEffect.outputDataspace, shaderString);
    generateOETF(linearEffect.outputDataspace, shaderString);
    generateEffectiveOOTF(linearEffect.undoPremultipliedAlpha, shaderString);

    auto [shader, error] = SkRuntimeEffect::MakeForShader(shaderString);
    if (!shader) {
        LOG_ALWAYS_FATAL("LinearColorFilter construction error: %s", error.c_str());
    }
    return shader;
}

sk_sp<SkShader> createLinearEffectShader(sk_sp<SkShader> shader, const LinearEffect& linearEffect,
                                         sk_sp<SkRuntimeEffect> runtimeEffect,
                                         const mat4& colorTransform, float maxDisplayLuminance,
                                         float maxLuminance) {
    ATRACE_CALL();
    SkRuntimeShaderBuilder effectBuilder(runtimeEffect);

    effectBuilder.child("child") = shader;

    if (linearEffect.inputDataspace == linearEffect.outputDataspace) {
        effectBuilder.uniform("in_rgbToXyz") = mat4();
        effectBuilder.uniform("in_xyzToRgb") = colorTransform;
    } else {
        ColorSpace inputColorSpace = toColorSpace(linearEffect.inputDataspace);
        ColorSpace outputColorSpace = toColorSpace(linearEffect.outputDataspace);

        effectBuilder.uniform("in_rgbToXyz") = mat4(inputColorSpace.getRGBtoXYZ());
        effectBuilder.uniform("in_xyzToRgb") =
                colorTransform * mat4(outputColorSpace.getXYZtoRGB());
    }

    tonemap::Metadata metadata{.displayMaxLuminance = maxDisplayLuminance,
                               // If the input luminance is unknown, use display luminance (aka,
                               // no-op any luminance changes)
                               // This will be the case for eg screenshots in addition to
                               // uncalibrated displays
                               .contentMaxLuminance =
                                       maxLuminance > 0 ? maxLuminance : maxDisplayLuminance};

    const auto uniforms = tonemap::getToneMapper()->generateShaderSkSLUniforms(metadata);

    for (const auto& uniform : uniforms) {
        effectBuilder.uniform(uniform.name.c_str()).set(uniform.value.data(), uniform.value.size());
    }

    return effectBuilder.makeShader(nullptr, false);
}

} // namespace skia
} // namespace renderengine
} // namespace android