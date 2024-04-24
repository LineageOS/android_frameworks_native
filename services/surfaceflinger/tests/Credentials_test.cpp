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

#include <android/gui/ISurfaceComposer.h>
#include <gtest/gtest.h>
#include <gui/AidlStatusUtil.h>
#include <gui/LayerDebugInfo.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <private/android_filesystem_config.h>
#include <private/gui/ComposerServiceAIDL.h>
#include <ui/DisplayMode.h>
#include <ui/DynamicDisplayInfo.h>
#include <utils/String8.h>
#include <functional>
#include "utils/ScreenshotUtils.h"
#include "utils/WindowInfosListenerUtils.h"

namespace android {

using Transaction = SurfaceComposerClient::Transaction;
using gui::LayerDebugInfo;
using gui::aidl_utils::statusTFromBinderStatus;
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
    void SetUp() override { ASSERT_NO_FATAL_FAILURE(initClient()); }

    void TearDown() override {
        mComposerClient->dispose();
        mBGSurfaceControl.clear();
        mComposerClient.clear();
    }

    sp<IBinder> mDisplay;
    sp<IBinder> mVirtualDisplay;
    sp<SurfaceComposerClient> mComposerClient;
    sp<SurfaceControl> mBGSurfaceControl;
    sp<SurfaceControl> mVirtualSurfaceControl;

    void initClient() {
        mComposerClient = sp<SurfaceComposerClient>::make();
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());
    }

    static sp<IBinder> getFirstDisplayToken() {
        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        if (ids.empty()) {
            return nullptr;
        }

        return SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
    }

    static std::optional<uint64_t> getFirstDisplayId() {
        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        if (ids.empty()) {
            return std::nullopt;
        }

        return ids.front().value;
    }

    void setupBackgroundSurface() {
        mDisplay = getFirstDisplayToken();
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
        t.setDisplayLayerStack(mDisplay, ui::DEFAULT_LAYER_STACK);
        ASSERT_EQ(NO_ERROR,
                  t.setLayer(mBGSurfaceControl, INT_MAX - 3).show(mBGSurfaceControl).apply());
    }

    /**
     * Template function the check a condition for different types of users: root
     * graphics, system, and non-supported user. Root, graphics, and system should
     * always equal privilegedValue, and non-supported user should equal unprivilegedValue.
     */
    template <typename T>
    void checkWithPrivileges(std::function<T()> condition, T privilegedValue, T unprivilegedValue) {
        // Check with root.
        {
            UIDFaker f(AID_SYSTEM);
            ASSERT_EQ(privilegedValue, condition());
        }

        // Check as a Graphics user.
        {
            UIDFaker f(AID_GRAPHICS);
            ASSERT_EQ(privilegedValue, condition());
        }

        // Check as a system user.
        {
            UIDFaker f(AID_SYSTEM);
            ASSERT_EQ(privilegedValue, condition());
        }

        // Check as a non-supported user.
        {
            UIDFaker f(AID_BIN);
            ASSERT_EQ(unprivilegedValue, condition());
        }

        // Check as shell since shell has some additional permissions
        {
            UIDFaker f(AID_SHELL);
            ASSERT_EQ(privilegedValue, condition());
        }
    }
};

TEST_F(CredentialsTest, ClientInitTest) {
    // Root can init can init the client.
    ASSERT_NO_FATAL_FAILURE(initClient());

    // Graphics can init the client.
    {
        UIDFaker f(AID_GRAPHICS);
        ASSERT_NO_FATAL_FAILURE(initClient());
    }

    // System can init the client.
    {
        UIDFaker f(AID_SYSTEM);
        ASSERT_NO_FATAL_FAILURE(initClient());
    }

    // Anyone else can init the client.
    {
        UIDFaker f(AID_BIN);
        mComposerClient = sp<SurfaceComposerClient>::make();
        ASSERT_NO_FATAL_FAILURE(initClient());
    }
}

TEST_F(CredentialsTest, GetBuiltInDisplayAccessTest) {
    std::function<bool()> condition = [] { return getFirstDisplayToken() != nullptr; };
    // Anyone can access display information.
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges(condition, true, false));
}

TEST_F(CredentialsTest, AllowedGetterMethodsTest) {
    // The following methods are tested with a UID that is not root, graphics,
    // or system, to show that anyone can access them.
    UIDFaker f(AID_BIN);
    const auto id = getFirstDisplayId();
    ASSERT_TRUE(id);
    ui::DynamicDisplayInfo info;
    ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getDynamicDisplayInfoFromId(*id, &info));
}

TEST_F(CredentialsTest, GetDynamicDisplayInfoTest) {
    const auto id = getFirstDisplayId();
    ASSERT_TRUE(id);
    std::function<status_t()> condition = [=]() {
        ui::DynamicDisplayInfo info;
        return SurfaceComposerClient::getDynamicDisplayInfoFromId(*id, &info);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, NO_ERROR));
}

TEST_F(CredentialsTest, GetDisplayNativePrimariesTest) {
    const auto display = getFirstDisplayToken();
    std::function<status_t()> condition = [=]() {
        ui::DisplayPrimaries primaries;
        return SurfaceComposerClient::getDisplayNativePrimaries(display, primaries);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, NO_ERROR));
}

TEST_F(CredentialsTest, SetDesiredDisplayConfigsTest) {
    const auto display = getFirstDisplayToken();
    gui::DisplayModeSpecs specs;
    status_t res = SurfaceComposerClient::getDesiredDisplayModeSpecs(display, &specs);
    ASSERT_EQ(res, NO_ERROR);
    gui::DisplayModeSpecs setSpecs;
    std::function<status_t()> condition = [=]() {
        return SurfaceComposerClient::setDesiredDisplayModeSpecs(display, specs);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, PERMISSION_DENIED));
}

TEST_F(CredentialsTest, SetActiveColorModeTest) {
    const auto display = getFirstDisplayToken();
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
    {
        UIDFaker f(AID_ROOT);
        ASSERT_FALSE(condition());
    }

    // Check as a Graphics user.
    {
        UIDFaker f(AID_GRAPHICS);
        ASSERT_TRUE(condition());
    }

    // Check as a system user.
    {
        UIDFaker f(AID_SYSTEM);
        ASSERT_TRUE(condition());
    }

    // Check as a non-supported user.
    {
        UIDFaker f(AID_BIN);
        ASSERT_FALSE(condition());
    }

    // Check as shell since shell has some additional permissions
    {
        UIDFaker f(AID_SHELL);
        ASSERT_FALSE(condition());
    }

    condition = [=]() {
        sp<IBinder> testDisplay = SurfaceComposerClient::createDisplay(DISPLAY_NAME, false);
        return testDisplay.get() != nullptr;
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges(condition, true, false));
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
TEST_F(CredentialsTest, GetLayerDebugInfo) {
    setupBackgroundSurface();
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());

    // Historically, only root and shell can access the getLayerDebugInfo which
    // is called when we call dumpsys. I don't see a reason why we should change this.
    std::vector<LayerDebugInfo> outLayers;
    binder::Status status = binder::Status::ok();
    // Check with root.
    {
        UIDFaker f(AID_ROOT);
        status = sf->getLayerDebugInfo(&outLayers);
        ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    }

    // Check as a shell.
    {
        UIDFaker f(AID_SHELL);
        status = sf->getLayerDebugInfo(&outLayers);
        ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    }

    // Check as anyone else.
    {
        UIDFaker f(AID_BIN);
        status = sf->getLayerDebugInfo(&outLayers);
        ASSERT_EQ(PERMISSION_DENIED, statusTFromBinderStatus(status));
    }
}

TEST_F(CredentialsTest, IsWideColorDisplayBasicCorrectness) {
    const auto display = getFirstDisplayToken();
    ASSERT_FALSE(display == nullptr);
    bool result = false;
    status_t error = SurfaceComposerClient::isWideColorDisplay(display, &result);
    ASSERT_EQ(NO_ERROR, error);
    bool hasWideColorMode = false;
    const auto id = getFirstDisplayId();
    ASSERT_TRUE(id);
    ui::DynamicDisplayInfo info;
    SurfaceComposerClient::getDynamicDisplayInfoFromId(*id, &info);
    const auto& colorModes = info.supportedColorModes;
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
    const auto display = getFirstDisplayToken();
    ASSERT_FALSE(display == nullptr);
    std::function<status_t()> condition = [=]() {
        bool result = false;
        return SurfaceComposerClient::isWideColorDisplay(display, &result);
    };
    ASSERT_NO_FATAL_FAILURE(checkWithPrivileges<status_t>(condition, NO_ERROR, NO_ERROR));
}

TEST_F(CredentialsTest, GetActiveColorModeBasicCorrectness) {
    const auto id = getFirstDisplayId();
    ASSERT_TRUE(id);
    ui::DynamicDisplayInfo info;
    SurfaceComposerClient::getDynamicDisplayInfoFromId(*id, &info);
    ColorMode colorMode = info.activeColorMode;
    ASSERT_NE(static_cast<ColorMode>(BAD_VALUE), colorMode);
}

TEST_F(CredentialsTest, TransactionPermissionTest) {
    WindowInfosListenerUtils windowInfosListenerUtils;
    std::string name = "Test Layer";
    sp<IBinder> token = sp<BBinder>::make();
    WindowInfo windowInfo;
    windowInfo.name = name;
    windowInfo.token = token;
    sp<SurfaceControl> surfaceControl =
            mComposerClient->createSurface(String8(name.c_str()), 100, 100, PIXEL_FORMAT_RGBA_8888,
                                           ISurfaceComposerClient::eFXSurfaceBufferState);
    const Rect crop(0, 0, 100, 100);
    {
        UIDFaker f(AID_SYSTEM);
        Transaction()
                .setLayerStack(surfaceControl, ui::DEFAULT_LAYER_STACK)
                .show(surfaceControl)
                .setLayer(surfaceControl, INT32_MAX - 1)
                .setCrop(surfaceControl, crop)
                .setInputWindowInfo(surfaceControl, windowInfo)
                .apply();
    }

    // Attempt to set a trusted overlay from a non-privileged process. This should fail silently.
    {
        UIDFaker f{AID_BIN};
        Transaction().setTrustedOverlay(surfaceControl, true).apply(/*synchronous=*/true);
    }

    // Verify that the layer was not made a trusted overlay.
    {
        UIDFaker f(AID_SYSTEM);
        auto windowIsPresentAndNotTrusted = [&](const std::vector<WindowInfo>& windowInfos) {
            auto foundWindowInfo =
                    WindowInfosListenerUtils::findMatchingWindowInfo(windowInfo, windowInfos);
            if (!foundWindowInfo) {
                return false;
            }
            return !foundWindowInfo->inputConfig.test(WindowInfo::InputConfig::TRUSTED_OVERLAY);
        };
        ASSERT_TRUE(
                windowInfosListenerUtils.waitForWindowInfosPredicate(windowIsPresentAndNotTrusted));
    }

    // Verify that privileged processes are able to set trusted overlays.
    {
        UIDFaker f(AID_SYSTEM);
        Transaction().setTrustedOverlay(surfaceControl, true).apply(/*synchronous=*/true);
        auto windowIsPresentAndTrusted = [&](const std::vector<WindowInfo>& windowInfos) {
            auto foundWindowInfo =
                    WindowInfosListenerUtils::findMatchingWindowInfo(windowInfo, windowInfos);
            if (!foundWindowInfo) {
                return false;
            }
            return foundWindowInfo->inputConfig.test(WindowInfo::InputConfig::TRUSTED_OVERLAY);
        };
        ASSERT_TRUE(
                windowInfosListenerUtils.waitForWindowInfosPredicate(windowIsPresentAndTrusted));
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
