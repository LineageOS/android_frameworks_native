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
#define LOG_TAG "DataspaceUtilsTest"

#include <gtest/gtest.h>
#include <ui/DataspaceUtils.h>

namespace android {

class DataspaceUtilsTest : public testing::Test {};

TEST_F(DataspaceUtilsTest, isHdrDataspace) {
    EXPECT_TRUE(isHdrDataspace(ui::Dataspace::BT2020_ITU_HLG));
    EXPECT_TRUE(isHdrDataspace(ui::Dataspace::BT2020_ITU_PQ));
    EXPECT_TRUE(isHdrDataspace(ui::Dataspace::BT2020_PQ));
    EXPECT_TRUE(isHdrDataspace(ui::Dataspace::BT2020_HLG));

    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_SRGB_LINEAR));
    // scRGB defines a very wide gamut but not an expanded luminance range
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_SCRGB_LINEAR));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_SRGB));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_SCRGB));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_JFIF));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_BT601_625));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_BT601_525));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::V0_BT709));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::DCI_P3_LINEAR));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::DCI_P3));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::DISPLAY_P3_LINEAR));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::DISPLAY_P3));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::ADOBE_RGB));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::BT2020_LINEAR));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::BT2020));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::BT2020_ITU));
    EXPECT_FALSE(isHdrDataspace(ui::Dataspace::DISPLAY_BT2020));
}

} // namespace android
