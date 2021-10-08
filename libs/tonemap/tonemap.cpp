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

#include <tonemap/tonemap.h>

#include <cstdint>
#include <mutex>
#include <type_traits>

namespace android::tonemap {

namespace {

// Flag containing the variant of tone map algorithm to use.
enum class ToneMapAlgorithm {
    AndroidO, // Default algorithm in place since Android O,
};

static const constexpr auto kToneMapAlgorithm = ToneMapAlgorithm::AndroidO;

static const constexpr auto kTransferMask =
        static_cast<int32_t>(aidl::android::hardware::graphics::common::Dataspace::TRANSFER_MASK);
static const constexpr auto kTransferST2084 =
        static_cast<int32_t>(aidl::android::hardware::graphics::common::Dataspace::TRANSFER_ST2084);
static const constexpr auto kTransferHLG =
        static_cast<int32_t>(aidl::android::hardware::graphics::common::Dataspace::TRANSFER_HLG);

template <typename T, std::enable_if_t<std::is_trivially_copyable<T>::value, bool> = true>
std::vector<uint8_t> buildUniformValue(T value) {
    std::vector<uint8_t> result;
    result.resize(sizeof(value));
    std::memcpy(result.data(), &value, sizeof(value));
    return result;
}

class ToneMapperO : public ToneMapper {
public:
    std::string generateTonemapGainShaderSkSL(
            aidl::android::hardware::graphics::common::Dataspace sourceDataspace,
            aidl::android::hardware::graphics::common::Dataspace destinationDataspace) override {
        const int32_t sourceDataspaceInt = static_cast<int32_t>(sourceDataspace);
        const int32_t destinationDataspaceInt = static_cast<int32_t>(destinationDataspace);

        std::string program;
        // Define required uniforms
        program.append(R"(
                uniform float in_libtonemap_displayMaxLuminance;
                uniform float in_libtonemap_inputMaxLuminance;
            )");
        switch (sourceDataspaceInt & kTransferMask) {
            case kTransferST2084:
            case kTransferHLG:
                switch (destinationDataspaceInt & kTransferMask) {
                    case kTransferST2084:
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        return xyz.y;
                                    }
                                )");
                        break;
                    case kTransferHLG:
                        // PQ has a wider luminance range (10,000 nits vs. 1,000 nits) than HLG, so
                        // we'll clamp the luminance range in case we're mapping from PQ input to
                        // HLG output.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        return clamp(xyz.y, 0.0, 1000.0);
                                    }
                                )");
                        break;
                    default:
                        // Here we're mapping from HDR to SDR content, so interpolate using a
                        // Hermitian polynomial onto the smaller luminance range.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        float maxInLumi = in_libtonemap_inputMaxLuminance;
                                        float maxOutLumi = in_libtonemap_displayMaxLuminance;

                                        float nits = xyz.y;

                                        // if the max input luminance is less than what we can
                                        // output then no tone mapping is needed as all color
                                        // values will be in range.
                                        if (maxInLumi <= maxOutLumi) {
                                            return xyz.y;
                                        } else {

                                            // three control points
                                            const float x0 = 10.0;
                                            const float y0 = 17.0;
                                            float x1 = maxOutLumi * 0.75;
                                            float y1 = x1;
                                            float x2 = x1 + (maxInLumi - x1) / 2.0;
                                            float y2 = y1 + (maxOutLumi - y1) * 0.75;

                                            // horizontal distances between the last three
                                            // control points
                                            float h12 = x2 - x1;
                                            float h23 = maxInLumi - x2;
                                            // tangents at the last three control points
                                            float m1 = (y2 - y1) / h12;
                                            float m3 = (maxOutLumi - y2) / h23;
                                            float m2 = (m1 + m3) / 2.0;

                                            if (nits < x0) {
                                                // scale [0.0, x0] to [0.0, y0] linearly
                                                float slope = y0 / x0;
                                                return nits * slope;
                                            } else if (nits < x1) {
                                                // scale [x0, x1] to [y0, y1] linearly
                                                float slope = (y1 - y0) / (x1 - x0);
                                                nits = y0 + (nits - x0) * slope;
                                            } else if (nits < x2) {
                                                // scale [x1, x2] to [y1, y2] using Hermite interp
                                                float t = (nits - x1) / h12;
                                                nits = (y1 * (1.0 + 2.0 * t) + h12 * m1 * t) *
                                                        (1.0 - t) * (1.0 - t) +
                                                        (y2 * (3.0 - 2.0 * t) +
                                                        h12 * m2 * (t - 1.0)) * t * t;
                                            } else {
                                                // scale [x2, maxInLumi] to [y2, maxOutLumi] using
                                                // Hermite interp
                                                float t = (nits - x2) / h23;
                                                nits = (y2 * (1.0 + 2.0 * t) + h23 * m2 * t) *
                                                        (1.0 - t) * (1.0 - t) + (maxOutLumi *
                                                        (3.0 - 2.0 * t) + h23 * m3 *
                                                        (t - 1.0)) * t * t;
                                            }
                                        }

                                        return nits;
                                    }
                                )");
                        break;
                }
                break;
            default:
                switch (destinationDataspaceInt & kTransferMask) {
                    case kTransferST2084:
                    case kTransferHLG:
                        // Map from SDR onto an HDR output buffer
                        // Here we use a polynomial curve to map from [0, displayMaxLuminance] onto
                        // [0, maxOutLumi] which is hard-coded to be 3000 nits.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        const float maxOutLumi = 3000.0;

                                        const float x0 = 5.0;
                                        const float y0 = 2.5;
                                        float x1 = in_libtonemap_displayMaxLuminance * 0.7;
                                        float y1 = maxOutLumi * 0.15;
                                        float x2 = in_libtonemap_displayMaxLuminance * 0.9;
                                        float y2 = maxOutLumi * 0.45;
                                        float x3 = in_libtonemap_displayMaxLuminance;
                                        float y3 = maxOutLumi;

                                        float c1 = y1 / 3.0;
                                        float c2 = y2 / 2.0;
                                        float c3 = y3 / 1.5;

                                        float nits = xyz.y;

                                        if (nits <= x0) {
                                            // scale [0.0, x0] to [0.0, y0] linearly
                                            float slope = y0 / x0;
                                            return nits * slope;
                                        } else if (nits <= x1) {
                                            // scale [x0, x1] to [y0, y1] using a curve
                                            float t = (nits - x0) / (x1 - x0);
                                            nits = (1.0 - t) * (1.0 - t) * y0 +
                                                    2.0 * (1.0 - t) * t * c1 + t * t * y1;
                                        } else if (nits <= x2) {
                                            // scale [x1, x2] to [y1, y2] using a curve
                                            float t = (nits - x1) / (x2 - x1);
                                            nits = (1.0 - t) * (1.0 - t) * y1 +
                                                    2.0 * (1.0 - t) * t * c2 + t * t * y2;
                                        } else {
                                            // scale [x2, x3] to [y2, y3] using a curve
                                            float t = (nits - x2) / (x3 - x2);
                                            nits = (1.0 - t) * (1.0 - t) * y2 +
                                                    2.0 * (1.0 - t) * t * c3 + t * t * y3;
                                        }

                                        return nits;
                                    }
                                )");
                        break;
                    default:
                        // For completeness, this is tone-mapping from SDR to SDR, where this is
                        // just a no-op.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        return xyz.y;
                                    }
                                )");
                        break;
                }
                break;
        }

        program.append(R"(
            float libtonemap_LookupTonemapGain(vec3 linearRGB, vec3 xyz) {
                if (xyz.y <= 0.0) {
                    return 1.0;
                }
                return libtonemap_ToneMapTargetNits(xyz) / xyz.y;
            }
        )");
        return program;
    }

    std::vector<ShaderUniform> generateShaderSkSLUniforms(const Metadata& metadata) override {
        std::vector<ShaderUniform> uniforms;

        uniforms.reserve(2);

        uniforms.push_back({.name = "in_libtonemap_displayMaxLuminance",
                            .value = buildUniformValue<float>(metadata.displayMaxLuminance)});
        uniforms.push_back({.name = "in_libtonemap_inputMaxLuminance",
                            .value = buildUniformValue<float>(metadata.contentMaxLuminance)});

        return uniforms;
    }
};

} // namespace

ToneMapper* getToneMapper() {
    static std::once_flag sOnce;
    static std::unique_ptr<ToneMapper> sToneMapper;

    std::call_once(sOnce, [&] {
        switch (kToneMapAlgorithm) {
            case ToneMapAlgorithm::AndroidO:
                sToneMapper = std::unique_ptr<ToneMapper>(new ToneMapperO());
                break;
        }
    });

    return sToneMapper.get();
}

} // namespace android::tonemap