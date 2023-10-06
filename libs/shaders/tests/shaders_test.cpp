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

#include "shaders/shaders.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <math/mat4.h>
#include <tonemap/tonemap.h>
#include <ui/ColorSpace.h>
#include <cmath>

namespace android {

using testing::Contains;
using testing::HasSubstr;

struct ShadersTest : public ::testing::Test {};

namespace {

MATCHER_P2(UniformEq, name, value, "") {
    return arg.name == name && arg.value == value;
}

MATCHER_P(UniformNameEq, name, "") {
    return arg.name == name;
}

template <typename T, std::enable_if_t<std::is_trivially_copyable<T>::value, bool> = true>
std::vector<uint8_t> buildUniformValue(T value) {
    std::vector<uint8_t> result;
    result.resize(sizeof(value));
    std::memcpy(result.data(), &value, sizeof(value));
    return result;
}

} // namespace

TEST_F(ShadersTest, buildLinearEffectUniforms_selectsNoOpGamutMatrices) {
    shaders::LinearEffect effect =
            shaders::LinearEffect{.inputDataspace = ui::Dataspace::V0_SRGB_LINEAR,
                                  .outputDataspace = ui::Dataspace::V0_SRGB_LINEAR,
                                  .fakeOutputDataspace = ui::Dataspace::UNKNOWN};

    mat4 colorTransform = mat4::scale(vec4(.9, .9, .9, 1.));
    auto uniforms =
            shaders::buildLinearEffectUniforms(effect, colorTransform, 1.f, 1.f, 1.f, nullptr,
                                               aidl::android::hardware::graphics::composer3::
                                                       RenderIntent::COLORIMETRIC);
    EXPECT_THAT(uniforms,
                Contains(UniformEq("in_rgbToXyz",
                                   buildUniformValue<mat3>(
                                           ColorSpace::linearExtendedSRGB().getRGBtoXYZ()))));
    EXPECT_THAT(uniforms,
                Contains(UniformEq("in_xyzToSrcRgb",
                                   buildUniformValue<mat3>(
                                           ColorSpace::linearSRGB().getXYZtoRGB()))));
    // color transforms are already tested in renderengine's tests
    EXPECT_THAT(uniforms, Contains(UniformNameEq("in_colorTransform")));
}

TEST_F(ShadersTest, buildLinearEffectUniforms_selectsGamutTransformMatrices) {
    shaders::LinearEffect effect =
            shaders::LinearEffect{.inputDataspace = ui::Dataspace::V0_SRGB,
                                  .outputDataspace = ui::Dataspace::DISPLAY_P3,
                                  .fakeOutputDataspace = ui::Dataspace::UNKNOWN};

    ColorSpace inputColorSpace = ColorSpace::sRGB();
    auto uniforms =
            shaders::buildLinearEffectUniforms(effect, mat4(), 1.f, 1.f, 1.f, nullptr,
                                               aidl::android::hardware::graphics::composer3::
                                                       RenderIntent::COLORIMETRIC);
    EXPECT_THAT(uniforms,
                Contains(UniformEq("in_rgbToXyz",
                                   buildUniformValue<mat3>(
                                           ColorSpace::linearExtendedSRGB().getRGBtoXYZ()))));
    EXPECT_THAT(uniforms,
                Contains(UniformEq("in_xyzToSrcRgb",
                                   buildUniformValue<mat3>(inputColorSpace.getXYZtoRGB()))));
    EXPECT_THAT(uniforms, Contains(UniformNameEq("in_colorTransform")));
}

} // namespace android
