/*
 * Copyright (C) 2020 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <gtest/gtest.h>
#include <gui/ISurfaceComposer.h>
#include <gui/LayerDebugInfo.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <private/android_filesystem_config.h>
#include <private/gui/ComposerService.h>
#include <ui/DisplayMode.h>
#include <utils/String8.h>
#include <functional>
#include "utils/ScreenshotUtils.h"

namespace android {

using Transaction = SurfaceComposerClient::Transaction;
using ui::ColorMode;

namespace {
const String8 DISPLAY_NAME("Credentials Display Test");
const String8 SURFACE_NAME("Test Surface Name");
} // namespace

/**
 * This class tests the CheckCredentials method in SurfaceFlinger.
 * Methods like EnableVsyncInjections and InjectVsync are not tested since they do not
 * return anything meaningful.
 */

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
class CredentialsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Start the tests as root.
        seteuid(AID_ROOT);

        ASSERT_NO_FATAL_FAILURE(initClient());
    }

    void TearDown() override {
        mComposerClient->dispose();
        mBGSurfaceControl.clear();
        mComposerClient.clear();
        // Finish the tests as root.
        seteuid(AID_ROOT);
    }

    sp<IBinder> mDisplay;
    sp<IBinder> mVirtualDisplay;
    sp<SurfaceComposerClient> mComposerClient;
    sp<SurfaceControl> mBGSurfaceControl;
    sp<SurfaceControl> mVirtualSurfaceControl;

    void initClient() {
        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());
    }

    void setupBackgroundSurface() {
        mDisplay = SurfaceComposerClient::getInternalDisplayToken();
        ASSERT_FALSE(mDisplay == nullptr);

        ui::DisplayMode mode;
        ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayMode(mDisplay, &mode));

        // Background surface
        mBGSurfaceControl = mComposerClient->createSurface(SURFACE_NAME, mode.resolution.getWidth(),
                                                           mode.resolution.getHeight(),
                                                           PIXEL_FORMAT_RGBA_8888, 0);
        ASSERT_TRUE(mBGSurfaceControl != nullptr);
        ASSERT_TRUE(mBGSurfaceControl->isValid());

        Transaction t;
        t.setDisplayLayerStack(mDisplay, 0);
        ASSERT_EQ(NO_ERROR,
                  t.setLayer(mBGSurfaceControl, INT_MAX - 3).show(mBGSurfaceControl).apply());
    }

    /**
     * Sets UID to imitate Graphic's process.
     */
    void setGraphicsUID() {
        seteuid(AID_ROOT);
        seteuid(AID_GRAPHICS);
    }

    /**
     * Sets UID to imitate System's process.
     */
    void setSystemUID() {
        seteuid(AID_ROOT);
        seteuid(AID_SYSTEM);
    }

    /**
     * Sets UID to imitate a process that doesn't have any special privileges in
     * our code.
     */
    void setBinUID() {
        seteuid(AID_ROOT);
        seteuid(AID_BIN);
    }

    /**
     * Template function the check a condition for different types of users: root
     * graphics, system, and non-supported user. Root, graphics, and system should
     * always equal privilegedValue, and non-supported user should equal unprivilegedValue.
     */
    template <typename T>
    void checkWithPrivileges(std::function<T()> condition, T privilegedValue, T unprivilegedValue) {
        // Check with root.
        seteuid(AID_ROOT);
        ASSERT_EQ(privilegedValue, condition());

        // Check as a Graphics user.
        setGraphicsUID();
        ASSERT_EQ(privilegedValue, condition());

        // Check as a system user.
        setSystemUID();
        ASSERT_EQ(privilegedValue, condition());

        // Check as a non-supported user.
        setBinUID();
        ASSERT_EQ(unprivilegedValue, condition());

        // Check as shell since shell has some additional permissions
        seteuid(AID_SHELL);
        ASSERT_EQ(unprivilegedValue, condition());
    }
};

TEST_F(CredentialsTest, ClientInitTest) {
    // Root can init can init the client.
    ASSERT_NO_FATAL_FAILURE(initClient());

    // Graphics can init the client.
    setGraphicsUID();
    ASSERT_NO_FATAL_FAILURE(initClient());

    // System can init the client.
    setSystemUID();
    ASSERT_NO_FATAL_FAILURE(initClient());

    // Anyone else can init the client.
    setBinUID();
    mComposerClient = new SurfaceComposerClient;
    ASSERT_NO_FATAL_FAILURE(initClient());
}

TEST_F(CredentialsTest, GetBuiltInDisplayAccessTest) {
    std::function<bool()> condition = [] {
        return SurfaceComposerClient::getInternalDisplayToken() != nullptr;
    };
    // Anyone can access display information.
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges(condition, true, true));
}

TEST_F(CredentialsTest, AllowedGetterMethodsTest) {
    // The following methods are tested with a UID that is not root, graphics,
    // or system, to show that anyone can access them.
    setBinUID();
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    ASSERT_TRUE(display != nullptr);

    ui::DisplayMode mode;
    ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayMode(display, &mode));

    Vector<ui::DisplayMode> modes;
    ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayModes(display, &modes));

    ASSERT_TRUE(SurfaceComposerClient::getActiveDisplayModeId(display) >= 0);

    ASSERT_NE(static_cast<ui::ColorMode>(BAD_VALUE),
              SurfaceComposerClient::getActiveColorMode(display));
}

TEST_F(CredentialsTest, GetDisplayColorModesTest) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    std::function<status_t()> condition = [=]() {
        Vector<ui::ColorMode> outColorModes;
        return SurfaceComposerClient::getDisplayColorModes(display, &outColorModes);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, NO_ERROR));
}

TEST_F(CredentialsTest, GetDisplayNativePrimariesTest) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    std::function<status_t()> condition = [=]() {
        ui::DisplayPrimaries primaries;
        return SurfaceComposerClient::getDisplayNativePrimaries(display, primaries);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, NO_ERROR));
}

TEST_F(CredentialsTest, SetDesiredDisplayConfigsTest) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    size_t defaultMode;
    bool allowGroupSwitching;
    float primaryFpsMin;
    float primaryFpsMax;
    float appRequestFpsMin;
    float appRequestFpsMax;
    status_t res =
            SurfaceComposerClient::getDesiredDisplayModeSpecs(display, &defaultMode,
                                                              &allowGroupSwitching, &primaryFpsMin,
                                                              &primaryFpsMax, &appRequestFpsMin,
                                                              &appRequestFpsMax);
    ASSERT_EQ(res, NO_ERROR);
    std::function<status_t()> condition = [=]() {
        return SurfaceComposerClient::setDesiredDisplayModeSpecs(display, defaultMode,
                                                                 allowGroupSwitching, primaryFpsMin,
                                                                 primaryFpsMax, appRequestFpsMin,
                                                                 appRequestFpsMax);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, PERMISSION_DENIED));
}

TEST_F(CredentialsTest, SetActiveColorModeTest) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    std::function<status_t()> condition = [=]() {
        return SurfaceComposerClient::setActiveColorMode(display, ui::ColorMode::NATIVE);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, PERMISSION_DENIED));
}

TEST_F(CredentialsTest, CreateDisplayTest) {
    // Only graphics and system processes can create a secure display.
    std::function<bool()> condition = [=]() {
        sp<IBinder> testDisplay = SurfaceComposerClient::createDisplay(DISPLAY_NAME, true);
        return testDisplay.get() != nullptr;
    };

    // Check with root.
    seteuid(AID_ROOT);
    ASSERT_FALSE(condition());

    // Check as a Graphics user.
    setGraphicsUID();
    ASSERT_TRUE(condition());

    // Check as a system user.
    setSystemUID();
    ASSERT_TRUE(condition());

    // Check as a non-supported user.
    setBinUID();
    ASSERT_FALSE(condition());

    // Check as shell since shell has some additional permissions
    seteuid(AID_SHELL);
    ASSERT_FALSE(condition());

    condition = [=]() {
        sp<IBinder> testDisplay = SurfaceComposerClient::createDisplay(DISPLAY_NAME, false);
        return testDisplay.get() != nullptr;
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges(condition, true, false));
}

TEST_F(CredentialsTest, CaptureTest) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    std::function<status_t()> condition = [=]() {
        sp<GraphicBuffer> outBuffer;
        DisplayCaptureArgs captureArgs;
        captureArgs.displayToken = display;
        ScreenCaptureResults captureResults;
        return ScreenCapture::captureDisplay(captureArgs, captureResults);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, PERMISSION_DENIED));
}

TEST_F(CredentialsTest, CaptureLayersTest) {
    setupBackgroundSurface();
    sp<GraphicBuffer> outBuffer;
    std::function<status_t()> condition = [=]() {
        LayerCaptureArgs captureArgs;
        captureArgs.layerHandle = mBGSurfaceControl->getHandle();
        captureArgs.sourceCrop = {0, 0, 1, 1};

        ScreenCaptureResults captureResults;
        return ScreenCapture::captureLayers(captureArgs, captureResults);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, PERMISSION_DENIED));
}

/**
 * The following tests are for methods accessible directly through SurfaceFlinger.
 */

/**
 * An app can pass a buffer queue to the media server and ask the media server to decode a DRM video
 * to that buffer queue. The media server is the buffer producer in this case. Because the app may create
 * its own buffer queue and act as the buffer consumer, the media server wants to be careful to avoid
 * sending decoded video frames to the app. This is where authenticateSurfaceTexture call comes in, to check
 * the consumer of a buffer queue is SurfaceFlinger.
 */
TEST_F(CredentialsTest, AuthenticateSurfaceTextureTest) {
    setupBackgroundSurface();
    sp<IGraphicBufferProducer> producer =
            mBGSurfaceControl->getSurface()->getIGraphicBufferProducer();
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());

    std::function<bool()> condition = [=]() { return sf->authenticateSurfaceTexture(producer); };
    // Anyone should be able to check if the consumer of the buffer queue is SF.
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges(condition, true, true));
}

TEST_F(CredentialsTest, GetLayerDebugInfo) {
    setupBackgroundSurface();
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());

    // Historically, only root and shell can access the getLayerDebugInfo which
    // is called when we call dumpsys. I don't see a reason why we should change this.
    std::vector<LayerDebugInfo> outLayers;
    // Check with root.
    seteuid(AID_ROOT);
    ASSERT_EQ(NO_ERROR, sf->getLayerDebugInfo(&outLayers));

    // Check as a shell.
    seteuid(AID_SHELL);
    ASSERT_EQ(NO_ERROR, sf->getLayerDebugInfo(&outLayers));

    // Check as anyone else.
    seteuid(AID_ROOT);
    seteuid(AID_BIN);
    ASSERT_EQ(PERMISSION_DENIED, sf->getLayerDebugInfo(&outLayers));
}

TEST_F(CredentialsTest, IsWideColorDisplayBasicCorrectness) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    ASSERT_FALSE(display == nullptr);
    bool result = false;
    status_t error = SurfaceComposerClient::isWideColorDisplay(display, &result);
    ASSERT_EQ(NO_ERROR, error);
    bool hasWideColorMode = false;
    Vector<ColorMode> colorModes;
    SurfaceComposerClient::getDisplayColorModes(display, &colorModes);
    for (ColorMode colorMode : colorModes) {
        switch (colorMode) {
            case ColorMode::DISPLAY_P3:
            case ColorMode::ADOBE_RGB:
            case ColorMode::DCI_P3:
                hasWideColorMode = true;
                break;
            default:
                break;
        }
    }
    ASSERT_EQ(hasWideColorMode, result);
}

TEST_F(CredentialsTest, IsWideColorDisplayWithPrivileges) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    ASSERT_FALSE(display == nullptr);
    std::function<status_t()> condition = [=]() {
        bool result = false;
        return SurfaceComposerClient::isWideColorDisplay(display, &result);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, NO_ERROR));
}

TEST_F(CredentialsTest, GetActiveColorModeBasicCorrectness) {
    const auto display = SurfaceComposerClient::getInternalDisplayToken();
    ASSERT_FALSE(display == nullptr);
    ColorMode colorMode = SurfaceComposerClient::getActiveColorMode(display);
    ASSERT_NE(static_cast<ColorMode>(BAD_VALUE), colorMode);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
