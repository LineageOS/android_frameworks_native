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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <tonemap/tonemap.h>
#include <cmath>

namespace android {

using testing::HasSubstr;

struct TonemapTest : public ::testing::Test {};

TEST_F(TonemapTest, generateShaderSkSLUniforms_containsDefaultUniforms) {
    static const constexpr float kDisplayMaxLuminance = 1.f;
    static const constexpr float kContentMaxLuminance = 2.f;
    tonemap::Metadata metadata{.displayMaxLuminance = kDisplayMaxLuminance,
                               .contentMaxLuminance = kContentMaxLuminance};
    const auto uniforms = tonemap::getToneMapper()->generateShaderSkSLUniforms(metadata);

    ASSERT_EQ(1, std::count_if(uniforms.cbegin(), uniforms.cend(), [](const auto& data) {
                  return data.name == "in_libtonemap_displayMaxLuminance";
              }));
    ASSERT_EQ(1, std::count_if(uniforms.cbegin(), uniforms.cend(), [](const auto& data) {
                  return data.name == "in_libtonemap_inputMaxLuminance";
              }));

    // Smoke check that metadata values are "real", specifically that they're non-zero and actually
    // numbers. This is to help avoid shaders using these uniforms from dividing by zero or other
    // catastrophic errors.
    const auto& displayLum = std::find_if(uniforms.cbegin(), uniforms.cend(), [](const auto& data) {
                                 return data.name == "in_libtonemap_displayMaxLuminance";
                             })->value;

    float displayLumFloat = 0.f;
    std::memcpy(&displayLumFloat, displayLum.data(), displayLum.size());
    EXPECT_FALSE(std::isnan(displayLumFloat));
    EXPECT_GT(displayLumFloat, 0);

    const auto& contentLum = std::find_if(uniforms.cbegin(), uniforms.cend(), [](const auto& data) {
                                 return data.name == "in_libtonemap_inputMaxLuminance";
                             })->value;

    float contentLumFloat = 0.f;
    std::memcpy(&contentLumFloat, contentLum.data(), contentLum.size());
    EXPECT_FALSE(std::isnan(contentLumFloat));
    EXPECT_GT(contentLumFloat, 0);
}

TEST_F(TonemapTest, generateTonemapGainShaderSkSL_containsEntryPointForPQ) {
    const auto shader =
            tonemap::getToneMapper()
                    ->generateTonemapGainShaderSkSL(aidl::android::hardware::graphics::common::
                                                            Dataspace::BT2020_ITU_PQ,
                                                    aidl::android::hardware::graphics::common::
                                                            Dataspace::DISPLAY_P3);

    // Other tests such as librenderengine_test will plug in the shader to check compilation.
    EXPECT_THAT(shader, HasSubstr("float libtonemap_LookupTonemapGain(vec3 linearRGB, vec3 xyz)"));
}

TEST_F(TonemapTest, generateTonemapGainShaderSkSL_containsEntryPointForHLG) {
    const auto shader =
            tonemap::getToneMapper()
                    ->generateTonemapGainShaderSkSL(aidl::android::hardware::graphics::common::
                                                            Dataspace::BT2020_ITU_HLG,
                                                    aidl::android::hardware::graphics::common::
                                                            Dataspace::DISPLAY_P3);

    // Other tests such as librenderengine_test will plug in the shader to check compilation.
    EXPECT_THAT(shader, HasSubstr("float libtonemap_LookupTonemapGain(vec3 linearRGB, vec3 xyz)"));
}

} // namespace android
