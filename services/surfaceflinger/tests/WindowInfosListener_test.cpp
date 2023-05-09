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

#include <gtest/gtest.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/WindowInfosUpdate.h>
#include <private/android_filesystem_config.h>
#include <cstdint>
#include <future>
#include "utils/WindowInfosListenerUtils.h"

namespace android {
using Transaction = SurfaceComposerClient::Transaction;
using gui::DisplayInfo;
using gui::WindowInfo;
constexpr auto findMatchingWindowInfo = WindowInfosListenerUtils::findMatchingWindowInfo;

using WindowInfosPredicate = std::function<bool(const std::vector<WindowInfo>&)>;

class WindowInfosListenerTest : public ::testing::Test {
protected:
    void SetUp() override {
        seteuid(AID_SYSTEM);
        mClient = sp<SurfaceComposerClient>::make();
    }

    void TearDown() override { seteuid(AID_ROOT); }

    sp<SurfaceComposerClient> mClient;
    WindowInfosListenerUtils mWindowInfosListenerUtils;

    bool waitForWindowInfosPredicate(const WindowInfosPredicate& predicate) {
        return mWindowInfosListenerUtils.waitForWindowInfosPredicate(std::move(predicate));
    }
};

TEST_F(WindowInfosListenerTest, WindowInfoAddedAndRemoved) {
    std::string name = "Test Layer";
    sp<IBinder> token = sp<BBinder>::make();
    WindowInfo windowInfo;
    windowInfo.name = name;
    windowInfo.token = token;
    sp<SurfaceControl> surfaceControl =
            mClient->createSurface(String8(name.c_str()), 100, 100, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceBufferState);

    Transaction()
            .setLayerStack(surfaceControl, ui::DEFAULT_LAYER_STACK)
            .show(surfaceControl)
            .setLayer(surfaceControl, INT32_MAX - 1)
            .setInputWindowInfo(surfaceControl, windowInfo)
            .apply();

    auto windowPresent = [&](const std::vector<WindowInfo>& windowInfos) {
        return findMatchingWindowInfo(windowInfo, windowInfos);
    };
    ASSERT_TRUE(waitForWindowInfosPredicate(windowPresent));

    Transaction().reparent(surfaceControl, nullptr).apply();

    auto windowNotPresent = [&](const std::vector<WindowInfo>& windowInfos) {
        return !findMatchingWindowInfo(windowInfo, windowInfos);
    };
    ASSERT_TRUE(waitForWindowInfosPredicate(windowNotPresent));
}

TEST_F(WindowInfosListenerTest, WindowInfoChanged) {
    std::string name = "Test Layer";
    sp<IBinder> token = sp<BBinder>::make();
    WindowInfo windowInfo;
    windowInfo.name = name;
    windowInfo.token = token;
    sp<SurfaceControl> surfaceControl =
            mClient->createSurface(String8(name.c_str()), 100, 100, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceBufferState);
    const Rect crop(0, 0, 100, 100);
    Transaction()
            .setLayerStack(surfaceControl, ui::DEFAULT_LAYER_STACK)
            .show(surfaceControl)
            .setLayer(surfaceControl, INT32_MAX - 1)
            .setCrop(surfaceControl, crop)
            .setInputWindowInfo(surfaceControl, windowInfo)
            .apply();

    auto windowIsPresentAndTouchableRegionEmpty = [&](const std::vector<WindowInfo>& windowInfos) {
        auto foundWindowInfo = findMatchingWindowInfo(windowInfo, windowInfos);
        if (!foundWindowInfo) {
            return false;
        }
        return foundWindowInfo->touchableRegion.isEmpty();
    };
    ASSERT_TRUE(waitForWindowInfosPredicate(windowIsPresentAndTouchableRegionEmpty));

    windowInfo.addTouchableRegion({0, 0, 50, 50});
    Transaction().setInputWindowInfo(surfaceControl, windowInfo).apply();

    auto windowIsPresentAndTouchableRegionMatches =
            [&](const std::vector<WindowInfo>& windowInfos) {
                auto foundWindowInfo = findMatchingWindowInfo(windowInfo, windowInfos);
                if (!foundWindowInfo) {
                    return false;
                }

                auto touchableRegion =
                        foundWindowInfo->transform.transform(foundWindowInfo->touchableRegion);
                return touchableRegion.hasSameRects(windowInfo.touchableRegion);
            };
    ASSERT_TRUE(waitForWindowInfosPredicate(windowIsPresentAndTouchableRegionMatches));
}

} // namespace android
