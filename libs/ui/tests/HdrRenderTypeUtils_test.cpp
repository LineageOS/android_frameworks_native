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

#undef LOG_TAG
#define LOG_TAG "HdrRenderTypeUtilsTest"

#include <gtest/gtest.h>
#include <ui/HdrRenderTypeUtils.h>

namespace android {

class HdrRenderTypeUtilsTest : public testing::Test {};

TEST_F(HdrRenderTypeUtilsTest, getHdrRenderType) {
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::BT2020_ITU_HLG, std::nullopt),
              HdrRenderType::GENERIC_HDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::BT2020_ITU_PQ, std::nullopt),
              HdrRenderType::GENERIC_HDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::BT2020_PQ, std::nullopt), HdrRenderType::GENERIC_HDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::BT2020_HLG, std::nullopt),
              HdrRenderType::GENERIC_HDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_SCRGB,
                               std::optional<ui::PixelFormat>(ui::PixelFormat::RGBA_FP16)),
              HdrRenderType::GENERIC_HDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_SCRGB,
                               std::optional<ui::PixelFormat>(ui::PixelFormat::RGBA_8888), 2.f),
              HdrRenderType::DISPLAY_HDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_SCRGB_LINEAR,
                               std::optional<ui::PixelFormat>(ui::PixelFormat::RGBA_8888), 2.f),
              HdrRenderType::DISPLAY_HDR);

    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_SRGB_LINEAR, std::nullopt), HdrRenderType::SDR);
    // scRGB defines a very wide gamut but not an expanded luminance range
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_SCRGB_LINEAR, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_SCRGB, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_SRGB, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_JFIF, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_BT601_625, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_BT601_525, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::V0_BT709, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::DCI_P3_LINEAR, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::DCI_P3, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::DISPLAY_P3_LINEAR, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::DISPLAY_P3, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::ADOBE_RGB, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::BT2020_LINEAR, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::BT2020, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::BT2020_ITU, std::nullopt), HdrRenderType::SDR);
    EXPECT_EQ(getHdrRenderType(ui::Dataspace::DISPLAY_BT2020, std::nullopt), HdrRenderType::SDR);
}

} // namespace android
