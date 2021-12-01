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
#include <private/android_filesystem_config.h>
#include <future>
#include "utils/TransactionUtils.h"

namespace android {
using Transaction = SurfaceComposerClient::Transaction;
using gui::DisplayInfo;
using gui::WindowInfo;

class WindowInfosListenerTest : public ::testing::Test {
protected:
    void SetUp() override {
        seteuid(AID_SYSTEM);
        mClient = new SurfaceComposerClient;
        mWindowInfosListener = new SyncWindowInfosListener();
        mClient->addWindowInfosListener(mWindowInfosListener);
    }

    void TearDown() override {
        mClient->removeWindowInfosListener(mWindowInfosListener);
        seteuid(AID_ROOT);
    }

    struct SyncWindowInfosListener : public gui::WindowInfosListener {
    public:
        void onWindowInfosChanged(const std::vector<WindowInfo>& windowInfos,
                                  const std::vector<DisplayInfo>&) override {
            windowInfosPromise.set_value(windowInfos);
        }

        std::vector<WindowInfo> waitForWindowInfos() {
            std::future<std::vector<WindowInfo>> windowInfosFuture =
                    windowInfosPromise.get_future();
            std::vector<WindowInfo> windowInfos = windowInfosFuture.get();
            windowInfosPromise = std::promise<std::vector<WindowInfo>>();
            return windowInfos;
        }

    private:
        std::promise<std::vector<WindowInfo>> windowInfosPromise;
    };

    sp<SurfaceComposerClient> mClient;
    sp<SyncWindowInfosListener> mWindowInfosListener;
};

std::optional<WindowInfo> findMatchingWindowInfo(WindowInfo targetWindowInfo,
                                                 std::vector<WindowInfo> windowInfos) {
    std::optional<WindowInfo> foundWindowInfo = std::nullopt;
    for (WindowInfo windowInfo : windowInfos) {
        if (windowInfo.token == targetWindowInfo.token) {
            foundWindowInfo = std::make_optional<>(windowInfo);
            break;
        }
    }

    return foundWindowInfo;
}

TEST_F(WindowInfosListenerTest, WindowInfoAddedAndRemoved) {
    std::string name = "Test Layer";
    sp<IBinder> token = new BBinder();
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

    std::vector<WindowInfo> windowInfos = mWindowInfosListener->waitForWindowInfos();
    std::optional<WindowInfo> foundWindowInfo = findMatchingWindowInfo(windowInfo, windowInfos);
    ASSERT_NE(std::nullopt, foundWindowInfo);

    Transaction().reparent(surfaceControl, nullptr).apply();

    windowInfos = mWindowInfosListener->waitForWindowInfos();
    foundWindowInfo = findMatchingWindowInfo(windowInfo, windowInfos);
    ASSERT_EQ(std::nullopt, foundWindowInfo);
}

TEST_F(WindowInfosListenerTest, WindowInfoChanged) {
    std::string name = "Test Layer";
    sp<IBinder> token = new BBinder();
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

    std::vector<WindowInfo> windowInfos = mWindowInfosListener->waitForWindowInfos();
    std::optional<WindowInfo> foundWindowInfo = findMatchingWindowInfo(windowInfo, windowInfos);
    ASSERT_NE(std::nullopt, foundWindowInfo);
    ASSERT_TRUE(foundWindowInfo->touchableRegion.isEmpty());

    Rect touchableRegions(0, 0, 50, 50);
    windowInfo.addTouchableRegion(Rect(0, 0, 50, 50));
    Transaction().setInputWindowInfo(surfaceControl, windowInfo).apply();

    windowInfos = mWindowInfosListener->waitForWindowInfos();
    foundWindowInfo = findMatchingWindowInfo(windowInfo, windowInfos);
    ASSERT_NE(std::nullopt, foundWindowInfo);
    ASSERT_TRUE(foundWindowInfo->touchableRegion.hasSameRects(windowInfo.touchableRegion));
}

} // namespace android
