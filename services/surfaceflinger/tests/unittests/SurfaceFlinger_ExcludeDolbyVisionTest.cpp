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

namespace android {
namespace {

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

class ExcludeDolbyVisionTest : public DisplayTransactionTest {
public:
    void injectDisplayModes(std::vector<DisplayModePtr> displayModePtrs) {
        DisplayModes modes;
        for (DisplayModePtr displayMode : displayModePtrs) {
            modes.try_emplace(displayMode->getId(), displayMode);
        }

        mDisplay = PrimaryDisplayVariant::makeFakeExistingDisplayInjector(this)
                           .setDisplayModes(std::move(modes), displayModePtrs[0]->getId())
                           .inject();
        mDisplay->overrideHdrTypes(types);
    }

protected:
    sp<DisplayDevice> mDisplay;

    static constexpr DisplayModeId modeId1080p60{0};
    static constexpr DisplayModeId modeId4k30{1};
    static constexpr DisplayModeId modeId4k60{2};

    static inline const DisplayModePtr mode1080p60 =
            createDisplayMode(modeId1080p60, 60_Hz, 0, ui::Size(1920, 1080));
    static inline const DisplayModePtr mode4k30 =
            createDisplayMode(modeId4k30, 30_Hz, 1, ui::Size(3840, 2160));
    static inline const DisplayModePtr mode4k30NonStandard =
            createDisplayMode(modeId4k30, 30.1_Hz, 1, ui::Size(3840, 2160));
    static inline const DisplayModePtr mode4k60 =
            createDisplayMode(modeId4k60, 60_Hz, 2, ui::Size(3840, 2160));

    const std::vector<ui::Hdr> types = {ui::Hdr::DOLBY_VISION, ui::Hdr::DOLBY_VISION_4K30,
                                        ui::Hdr::HDR10_PLUS};
};

TEST_F(ExcludeDolbyVisionTest, excludesDolbyVisionOnModesHigherThan4k30) {
    injectDisplayModes({mode4k60});
    ui::DynamicDisplayInfo info;
    mFlinger.getDynamicDisplayInfoFromToken(mDisplay->getDisplayToken().promote(), &info);

    std::vector<ui::DisplayMode> displayModes = info.supportedDisplayModes;

    ASSERT_EQ(1, displayModes.size());
    ASSERT_TRUE(std::any_of(displayModes[0].supportedHdrTypes.begin(),
                            displayModes[0].supportedHdrTypes.end(),
                            [](ui::Hdr type) { return type == ui::Hdr::HDR10_PLUS; }));
    ASSERT_TRUE(displayModes[0].supportedHdrTypes.size() == 1);
}

TEST_F(ExcludeDolbyVisionTest, includesDolbyVisionOnModesLowerThanOrEqualTo4k30) {
    injectDisplayModes({mode1080p60, mode4k30, mode4k30NonStandard});
    ui::DynamicDisplayInfo info;
    mFlinger.getDynamicDisplayInfoFromToken(mDisplay->getDisplayToken().promote(), &info);

    std::vector<ui::DisplayMode> displayModes = info.supportedDisplayModes;

    ASSERT_EQ(2, displayModes.size());
    for (size_t i = 0; i < displayModes.size(); i++) {
        ASSERT_TRUE(std::any_of(displayModes[i].supportedHdrTypes.begin(),
                                displayModes[i].supportedHdrTypes.end(),
                                [](ui::Hdr type) { return type == ui::Hdr::HDR10_PLUS; }));
        ASSERT_TRUE(std::any_of(displayModes[i].supportedHdrTypes.begin(),
                                displayModes[i].supportedHdrTypes.end(),
                                [](ui::Hdr type) { return type == ui::Hdr::DOLBY_VISION; }));
        ASSERT_TRUE(displayModes[i].supportedHdrTypes.size() == 2);
    }
}

TEST_F(ExcludeDolbyVisionTest, 4k30IsNotReportedAsAValidHdrType) {
    injectDisplayModes({mode4k60});
    ui::DynamicDisplayInfo info;
    mFlinger.getDynamicDisplayInfoFromToken(mDisplay->getDisplayToken().promote(), &info);

    std::vector<ui::Hdr> displayHdrTypes = info.hdrCapabilities.getSupportedHdrTypes();

    ASSERT_EQ(2, displayHdrTypes.size());
    ASSERT_TRUE(std::any_of(displayHdrTypes.begin(), displayHdrTypes.end(),
                            [](ui::Hdr type) { return type == ui::Hdr::HDR10_PLUS; }));
    ASSERT_TRUE(std::any_of(displayHdrTypes.begin(), displayHdrTypes.end(),
                            [](ui::Hdr type) { return type == ui::Hdr::DOLBY_VISION; }));
}

} // namespace
} // namespace android
