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

using hal::RenderIntent;

// For this variant, SurfaceFlinger should configure itself with wide display
// support, and the display should respond with an non-empty list of supported
// color modes. Wide-color support should be configured.
template <typename Display>
struct WideColorP3ColorimetricSupportedVariant {
    static constexpr bool WIDE_COLOR_SUPPORTED = true;

    static void injectConfigChange(DisplayTransactionTest* test) {
        test->mFlinger.mutableUseColorManagement() = true;
        test->mFlinger.mutableHasWideColorDisplay() = true;
        test->mFlinger.mutableDisplayColorSetting() = DisplayColorSetting::kUnmanaged;
    }

    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mNativeWindow, perform(NATIVE_WINDOW_SET_BUFFERS_DATASPACE)).Times(1);

        EXPECT_CALL(*test->mComposer, getColorModes(Display::HWC_DISPLAY_ID, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<ColorMode>({ColorMode::DISPLAY_P3})),
                                Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    getRenderIntents(Display::HWC_DISPLAY_ID, ColorMode::DISPLAY_P3, _))
                .WillOnce(DoAll(SetArgPointee<2>(
                                        std::vector<RenderIntent>({RenderIntent::COLORIMETRIC})),
                                Return(Error::NONE)));
        EXPECT_CALL(*test->mComposer,
                    setColorMode(Display::HWC_DISPLAY_ID, ColorMode::SRGB,
                                 RenderIntent::COLORIMETRIC))
                .WillOnce(Return(Error::NONE));
    }
};

template <typename Display>
struct Hdr10PlusSupportedVariant {
    static constexpr bool HDR10_PLUS_SUPPORTED = true;
    static constexpr bool HDR10_SUPPORTED = true;
    static constexpr bool HDR_HLG_SUPPORTED = false;
    static constexpr bool HDR_DOLBY_VISION_SUPPORTED = false;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getHdrCapabilities(_, _, _, _, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hdr>({
                                        Hdr::HDR10_PLUS,
                                        Hdr::HDR10,
                                })),
                                Return(Error::NONE)));
    }
};

// For this variant, the composer should respond with a non-empty list of HDR
// modes containing HDR10, so HDR10 support should be configured.
template <typename Display>
struct Hdr10SupportedVariant {
    static constexpr bool HDR10_PLUS_SUPPORTED = false;
    static constexpr bool HDR10_SUPPORTED = true;
    static constexpr bool HDR_HLG_SUPPORTED = false;
    static constexpr bool HDR_DOLBY_VISION_SUPPORTED = false;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getHdrCapabilities(Display::HWC_DISPLAY_ID, _, _, _, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hdr>({Hdr::HDR10})),
                                Return(Error::NONE)));
    }
};

// For this variant, the composer should respond with a non-empty list of HDR
// modes containing HLG, so HLG support should be configured.
template <typename Display>
struct HdrHlgSupportedVariant {
    static constexpr bool HDR10_PLUS_SUPPORTED = false;
    static constexpr bool HDR10_SUPPORTED = false;
    static constexpr bool HDR_HLG_SUPPORTED = true;
    static constexpr bool HDR_DOLBY_VISION_SUPPORTED = false;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getHdrCapabilities(Display::HWC_DISPLAY_ID, _, _, _, _))
                .WillOnce(
                        DoAll(SetArgPointee<1>(std::vector<Hdr>({Hdr::HLG})), Return(Error::NONE)));
    }
};

// For this variant, the composer should respond with a non-empty list of HDR
// modes containing DOLBY_VISION, so DOLBY_VISION support should be configured.
template <typename Display>
struct HdrDolbyVisionSupportedVariant {
    static constexpr bool HDR10_PLUS_SUPPORTED = false;
    static constexpr bool HDR10_SUPPORTED = false;
    static constexpr bool HDR_HLG_SUPPORTED = false;
    static constexpr bool HDR_DOLBY_VISION_SUPPORTED = true;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getHdrCapabilities(Display::HWC_DISPLAY_ID, _, _, _, _))
                .WillOnce(DoAll(SetArgPointee<1>(std::vector<Hdr>({Hdr::DOLBY_VISION})),
                                Return(Error::NONE)));
    }
};

template <typename Display>
struct Smpte2086PerFrameMetadataSupportVariant {
    static constexpr int PER_FRAME_METADATA_KEYS = HdrMetadata::Type::SMPTE2086;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getPerFrameMetadataKeys(Display::HWC_DISPLAY_ID))
                .WillOnce(Return(std::vector<PerFrameMetadataKey>({
                        PerFrameMetadataKey::DISPLAY_RED_PRIMARY_X,
                        PerFrameMetadataKey::DISPLAY_RED_PRIMARY_Y,
                        PerFrameMetadataKey::DISPLAY_GREEN_PRIMARY_X,
                        PerFrameMetadataKey::DISPLAY_GREEN_PRIMARY_Y,
                        PerFrameMetadataKey::DISPLAY_BLUE_PRIMARY_X,
                        PerFrameMetadataKey::DISPLAY_BLUE_PRIMARY_Y,
                        PerFrameMetadataKey::WHITE_POINT_X,
                        PerFrameMetadataKey::WHITE_POINT_Y,
                        PerFrameMetadataKey::MAX_LUMINANCE,
                        PerFrameMetadataKey::MIN_LUMINANCE,
                })));
    }
};

template <typename Display>
struct Cta861_3_PerFrameMetadataSupportVariant {
    static constexpr int PER_FRAME_METADATA_KEYS = HdrMetadata::Type::CTA861_3;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getPerFrameMetadataKeys(Display::HWC_DISPLAY_ID))
                .WillOnce(Return(std::vector<PerFrameMetadataKey>({
                        PerFrameMetadataKey::MAX_CONTENT_LIGHT_LEVEL,
                        PerFrameMetadataKey::MAX_FRAME_AVERAGE_LIGHT_LEVEL,
                })));
    }
};

template <typename Display>
struct Hdr10_Plus_PerFrameMetadataSupportVariant {
    static constexpr int PER_FRAME_METADATA_KEYS = HdrMetadata::Type::HDR10PLUS;
    static void setupComposerCallExpectations(DisplayTransactionTest* test) {
        EXPECT_CALL(*test->mComposer, getPerFrameMetadataKeys(Display::HWC_DISPLAY_ID))
                .WillOnce(Return(std::vector<PerFrameMetadataKey>({
                        PerFrameMetadataKey::HDR10_PLUS_SEI,
                })));
    }
};

using WideColorP3ColorimetricDisplayCase =
        Case<PrimaryDisplayVariant, WideColorP3ColorimetricSupportedVariant<PrimaryDisplayVariant>,
             HdrNotSupportedVariant<PrimaryDisplayVariant>,
             NoPerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;
using Hdr10PlusDisplayCase =
        Case<PrimaryDisplayVariant, WideColorNotSupportedVariant<PrimaryDisplayVariant>,
             Hdr10SupportedVariant<PrimaryDisplayVariant>,
             Hdr10_Plus_PerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;
using Hdr10DisplayCase =
        Case<PrimaryDisplayVariant, WideColorNotSupportedVariant<PrimaryDisplayVariant>,
             Hdr10SupportedVariant<PrimaryDisplayVariant>,
             NoPerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;
using HdrHlgDisplayCase =
        Case<PrimaryDisplayVariant, WideColorNotSupportedVariant<PrimaryDisplayVariant>,
             HdrHlgSupportedVariant<PrimaryDisplayVariant>,
             NoPerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;
using HdrDolbyVisionDisplayCase =
        Case<PrimaryDisplayVariant, WideColorNotSupportedVariant<PrimaryDisplayVariant>,
             HdrDolbyVisionSupportedVariant<PrimaryDisplayVariant>,
             NoPerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;
using HdrSmpte2086DisplayCase =
        Case<PrimaryDisplayVariant, WideColorNotSupportedVariant<PrimaryDisplayVariant>,
             HdrNotSupportedVariant<PrimaryDisplayVariant>,
             Smpte2086PerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;
using HdrCta861_3_DisplayCase =
        Case<PrimaryDisplayVariant, WideColorNotSupportedVariant<PrimaryDisplayVariant>,
             HdrNotSupportedVariant<PrimaryDisplayVariant>,
             Cta861_3_PerFrameMetadataSupportVariant<PrimaryDisplayVariant>>;

class SetupNewDisplayDeviceInternalTest : public DisplayTransactionTest {
public:
    template <typename T>
    void setupNewDisplayDeviceInternalTest();
};

template <typename Case>
void SetupNewDisplayDeviceInternalTest::setupNewDisplayDeviceInternalTest() {
    const sp<BBinder> displayToken = new BBinder();
    const sp<compositionengine::mock::DisplaySurface> displaySurface =
            new compositionengine::mock::DisplaySurface();
    const sp<mock::GraphicBufferProducer> producer = new mock::GraphicBufferProducer();

    // --------------------------------------------------------------------
    // Preconditions

    // Wide color displays support is configured appropriately
    Case::WideColorSupport::injectConfigChange(this);

    // The display is setup with the HWC.
    Case::Display::injectHwcDisplay(this);

    // SurfaceFlinger will use a test-controlled factory for native window
    // surfaces.
    injectFakeNativeWindowSurfaceFactory();

    // A compositionengine::Display has already been created
    auto compositionDisplay = Case::Display::injectCompositionDisplay(this);

    // --------------------------------------------------------------------
    // Call Expectations

    // Various native window calls will be made.
    Case::Display::setupNativeWindowSurfaceCreationCallExpectations(this);
    Case::Display::setupHwcGetActiveConfigCallExpectations(this);
    Case::Display::setupHwcGetConfigsCallExpectations(this);
    Case::WideColorSupport::setupComposerCallExpectations(this);
    Case::HdrSupport::setupComposerCallExpectations(this);
    Case::PerFrameMetadataSupport::setupComposerCallExpectations(this);

    // --------------------------------------------------------------------
    // Invocation

    DisplayDeviceState state;
    if (const auto connectionType = Case::Display::CONNECTION_TYPE::value) {
        const auto displayId = PhysicalDisplayId::tryCast(Case::Display::DISPLAY_ID::get());
        ASSERT_TRUE(displayId);
        const auto hwcDisplayId = Case::Display::HWC_DISPLAY_ID_OPT::value;
        ASSERT_TRUE(hwcDisplayId);
        mFlinger.getHwComposer().allocatePhysicalDisplay(*hwcDisplayId, *displayId);
        state.physical = {.id = *displayId, .type = *connectionType, .hwcDisplayId = *hwcDisplayId};
    }

    state.isSecure = static_cast<bool>(Case::Display::SECURE);

    auto device = mFlinger.setupNewDisplayDeviceInternal(displayToken, compositionDisplay, state,
                                                         displaySurface, producer);

    // --------------------------------------------------------------------
    // Postconditions

    ASSERT_TRUE(device != nullptr);
    EXPECT_EQ(Case::Display::DISPLAY_ID::get(), device->getId());
    EXPECT_EQ(Case::Display::CONNECTION_TYPE::value, device->getConnectionType());
    EXPECT_EQ(static_cast<bool>(Case::Display::VIRTUAL), device->isVirtual());
    EXPECT_EQ(static_cast<bool>(Case::Display::SECURE), device->isSecure());
    EXPECT_EQ(static_cast<bool>(Case::Display::PRIMARY), device->isPrimary());
    EXPECT_EQ(Case::Display::WIDTH, device->getWidth());
    EXPECT_EQ(Case::Display::HEIGHT, device->getHeight());
    EXPECT_EQ(Case::WideColorSupport::WIDE_COLOR_SUPPORTED, device->hasWideColorGamut());
    EXPECT_EQ(Case::HdrSupport::HDR10_PLUS_SUPPORTED, device->hasHDR10PlusSupport());
    EXPECT_EQ(Case::HdrSupport::HDR10_SUPPORTED, device->hasHDR10Support());
    EXPECT_EQ(Case::HdrSupport::HDR_HLG_SUPPORTED, device->hasHLGSupport());
    EXPECT_EQ(Case::HdrSupport::HDR_DOLBY_VISION_SUPPORTED, device->hasDolbyVisionSupport());
    // Note: This is not Case::Display::HWC_ACTIVE_CONFIG_ID as the ids are
    // remapped, and the test only ever sets up one config. If there were an error
    // looking up the remapped index, device->getActiveConfig() would be -1 instead.
    EXPECT_EQ(0, device->getActiveConfig().value());
    EXPECT_EQ(Case::PerFrameMetadataSupport::PER_FRAME_METADATA_KEYS,
              device->getSupportedPerFrameMetadata());
}

TEST_F(SetupNewDisplayDeviceInternalTest, createSimplePrimaryDisplay) {
    setupNewDisplayDeviceInternalTest<SimplePrimaryDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createSimpleExternalDisplay) {
    setupNewDisplayDeviceInternalTest<SimpleExternalDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createNonHwcVirtualDisplay) {
    setupNewDisplayDeviceInternalTest<NonHwcVirtualDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createHwcVirtualDisplay) {
    setupNewDisplayDeviceInternalTest<HwcVirtualDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createWideColorP3Display) {
    setupNewDisplayDeviceInternalTest<WideColorP3ColorimetricDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createHdr10PlusDisplay) {
    setupNewDisplayDeviceInternalTest<Hdr10PlusDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createHdr10Display) {
    setupNewDisplayDeviceInternalTest<Hdr10DisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createHdrHlgDisplay) {
    setupNewDisplayDeviceInternalTest<HdrHlgDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createHdrDolbyVisionDisplay) {
    setupNewDisplayDeviceInternalTest<HdrDolbyVisionDisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createHdrSmpte2086DisplayCase) {
    setupNewDisplayDeviceInternalTest<HdrSmpte2086DisplayCase>();
}

TEST_F(SetupNewDisplayDeviceInternalTest, createHdrCta816_3_DisplayCase) {
    setupNewDisplayDeviceInternalTest<HdrCta861_3_DisplayCase>();
}

} // namespace
} // namespace android
