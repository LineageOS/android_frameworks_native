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

#include <thread>

#include <gtest/gtest.h>

#include <gui/AidlStatusUtil.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <private/gui/ComposerServiceAIDL.h>
#include <chrono>

namespace android {

using gui::aidl_utils::statusTFromBinderStatus;

struct BootDisplayModeTest : public ::testing::Test {
protected:
    void SetUp() override {
        mSf = ComposerServiceAIDL::getComposerService();

        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        ASSERT_FALSE(ids.empty());
        mDisplayToken = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
        bool bootModeSupport = false;
        binder::Status status = mSf->getBootDisplayModeSupport(&bootModeSupport);
        ASSERT_NO_FATAL_FAILURE(statusTFromBinderStatus(status));

        if (!bootModeSupport) {
            GTEST_SKIP() << "Boot mode not supported";
        }

        gui::DynamicDisplayInfo info;
        status = mSf->getDynamicDisplayInfoFromToken(mDisplayToken, &info);
        ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
        mOldMode = info.preferredBootDisplayMode;
        const auto newMode = [&]() -> std::optional<ui::DisplayModeId> {
            for (const auto& mode : info.supportedDisplayModes) {
                if (mode.id != mOldMode) {
                    return std::optional(mode.id);
                }
            }
            return std::nullopt;
        }();

        if (!newMode) {
            GTEST_SKIP() << "Only a single mode is supported";
        }

        mNewMode = *newMode;
    }

    void TearDown() override {
        binder::Status status = mSf->setBootDisplayMode(mDisplayToken, mOldMode);
        EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));

        gui::DynamicDisplayInfo info;
        status = mSf->getDynamicDisplayInfoFromToken(mDisplayToken, &info);
        EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));
        EXPECT_EQ(mOldMode, info.preferredBootDisplayMode);
    }

    ui::DisplayModeId mOldMode;
    ui::DisplayModeId mNewMode;
    sp<gui::ISurfaceComposer> mSf;
    sp<IBinder> mDisplayToken;
};

TEST_F(BootDisplayModeTest, setBootDisplayMode) {
    // Set a new mode and check that it got applied
    binder::Status status = mSf->setBootDisplayMode(mDisplayToken, mNewMode);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));

    gui::DynamicDisplayInfo info;
    status = mSf->getDynamicDisplayInfoFromToken(mDisplayToken, &info);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    EXPECT_EQ(mNewMode, info.preferredBootDisplayMode);
}

TEST_F(BootDisplayModeTest, clearBootDisplayMode) {
    // Clear once to figure out what the system default is
    binder::Status status = mSf->clearBootDisplayMode(mDisplayToken);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));

    gui::DynamicDisplayInfo info;
    status = mSf->getDynamicDisplayInfoFromToken(mDisplayToken, &info);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));

    const ui::DisplayModeId systemMode = info.preferredBootDisplayMode;
    const ui::DisplayModeId newMode = systemMode == mOldMode ? mNewMode : mOldMode;

    // Now set a new mode and clear the boot mode again to figure out if the api worked.
    status = mSf->setBootDisplayMode(mDisplayToken, newMode);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));

    status = mSf->getDynamicDisplayInfoFromToken(mDisplayToken, &info);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    EXPECT_EQ(newMode, info.preferredBootDisplayMode);

    status = mSf->clearBootDisplayMode(mDisplayToken);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));

    status = mSf->getDynamicDisplayInfoFromToken(mDisplayToken, &info);
    EXPECT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    EXPECT_EQ(systemMode, info.preferredBootDisplayMode);
}

} // namespace android
