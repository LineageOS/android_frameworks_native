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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace {

using hal::RenderIntent;

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

class GetBestColorModeTest : public DisplayTransactionTest {
public:
    void setHasWideColorGamut(bool hasWideColorGamut) { mHasWideColorGamut = hasWideColorGamut; }

    void addHwcColorModesMapping(ui::ColorMode colorMode,
                                 std::vector<ui::RenderIntent> renderIntents) {
        mHwcColorModes[colorMode] = renderIntents;
    }

    void setInputDataspace(ui::Dataspace dataspace) { mInputDataspace = dataspace; }

    void setInputRenderIntent(ui::RenderIntent renderIntent) { mInputRenderIntent = renderIntent; }

    void getBestColorMode() {
        auto displayDevice =
                injectDefaultInternalDisplay([this](FakeDisplayDeviceInjector& injector) {
                    injector.setHwcColorModes(mHwcColorModes);
                    injector.setHasWideColorGamut(mHasWideColorGamut);
                    injector.setNativeWindow(mNativeWindow);
                });

        displayDevice->getCompositionDisplay()
                ->getDisplayColorProfile()
                ->getBestColorMode(mInputDataspace, mInputRenderIntent, &mOutDataspace,
                                   &mOutColorMode, &mOutRenderIntent);
    }

    ui::Dataspace mOutDataspace;
    ui::ColorMode mOutColorMode;
    ui::RenderIntent mOutRenderIntent;

private:
    ui::Dataspace mInputDataspace;
    ui::RenderIntent mInputRenderIntent;
    bool mHasWideColorGamut = false;
    std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>> mHwcColorModes;
};

TEST_F(GetBestColorModeTest, DataspaceDisplayP3_ColorModeSRGB) {
    addHwcColorModesMapping(ui::ColorMode::SRGB,
                            std::vector<ui::RenderIntent>(1, RenderIntent::COLORIMETRIC));
    setInputDataspace(ui::Dataspace::DISPLAY_P3);
    setInputRenderIntent(ui::RenderIntent::COLORIMETRIC);
    setHasWideColorGamut(true);

    getBestColorMode();

    ASSERT_EQ(ui::Dataspace::V0_SRGB, mOutDataspace);
    ASSERT_EQ(ui::ColorMode::SRGB, mOutColorMode);
    ASSERT_EQ(ui::RenderIntent::COLORIMETRIC, mOutRenderIntent);
}

TEST_F(GetBestColorModeTest, DataspaceDisplayP3_ColorModeDisplayP3) {
    addHwcColorModesMapping(ui::ColorMode::DISPLAY_P3,
                            std::vector<ui::RenderIntent>(1, RenderIntent::COLORIMETRIC));
    addHwcColorModesMapping(ui::ColorMode::SRGB,
                            std::vector<ui::RenderIntent>(1, RenderIntent::COLORIMETRIC));
    addHwcColorModesMapping(ui::ColorMode::DISPLAY_BT2020,
                            std::vector<ui::RenderIntent>(1, RenderIntent::COLORIMETRIC));
    setInputDataspace(ui::Dataspace::DISPLAY_P3);
    setInputRenderIntent(ui::RenderIntent::COLORIMETRIC);
    setHasWideColorGamut(true);

    getBestColorMode();

    ASSERT_EQ(ui::Dataspace::DISPLAY_P3, mOutDataspace);
    ASSERT_EQ(ui::ColorMode::DISPLAY_P3, mOutColorMode);
    ASSERT_EQ(ui::RenderIntent::COLORIMETRIC, mOutRenderIntent);
}

TEST_F(GetBestColorModeTest, DataspaceDisplayP3_ColorModeDISPLAY_BT2020) {
    addHwcColorModesMapping(ui::ColorMode::DISPLAY_BT2020,
                            std::vector<ui::RenderIntent>(1, RenderIntent::COLORIMETRIC));
    setInputDataspace(ui::Dataspace::DISPLAY_P3);
    setInputRenderIntent(ui::RenderIntent::COLORIMETRIC);
    setHasWideColorGamut(true);

    getBestColorMode();

    ASSERT_EQ(ui::Dataspace::DISPLAY_BT2020, mOutDataspace);
    ASSERT_EQ(ui::ColorMode::DISPLAY_BT2020, mOutColorMode);
    ASSERT_EQ(ui::RenderIntent::COLORIMETRIC, mOutRenderIntent);
}

} // namespace
} // namespace android
