/*
 * Copyright (C) 2019 The Android Open Source Project
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
#pragma clang diagnostic ignored "-Wextra"

#include <gtest/gtest.h>
#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <ui/DisplayMode.h>
#include <ui/DynamicDisplayInfo.h>
#include <utils/Errors.h>
#include <utils/Vector.h>

#include "utils/TransactionUtils.h"

namespace android {

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

/**
 * Test class for setting display configs and passing around refresh rate ranges.
 */
class RefreshRateRangeTest : public ::testing::Test {
private:
    gui::DisplayModeSpecs mSpecs;

protected:
    void SetUp() override {
        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        ASSERT_FALSE(ids.empty());
        mDisplayId = ids.front().value;
        mDisplayToken = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
        status_t res = SurfaceComposerClient::getDesiredDisplayModeSpecs(mDisplayToken, &mSpecs);
        ASSERT_EQ(res, NO_ERROR);
    }

    void TearDown() override {
        status_t res = SurfaceComposerClient::setDesiredDisplayModeSpecs(mDisplayToken, mSpecs);
        ASSERT_EQ(res, NO_ERROR);
    }

    void testSetDesiredDisplayModeSpecs(bool allowGroupSwitching = false) {
        ui::DynamicDisplayInfo info;
        status_t res =
                SurfaceComposerClient::getDynamicDisplayInfoFromId(static_cast<int64_t>(mDisplayId),
                                                                   &info);
        const auto& modes = info.supportedDisplayModes;
        ASSERT_EQ(res, NO_ERROR);
        ASSERT_GT(modes.size(), 0);
        for (const auto& mode : modes) {
            gui::DisplayModeSpecs setSpecs;
            setSpecs.defaultMode = mode.id;
            setSpecs.allowGroupSwitching = allowGroupSwitching;
            setSpecs.primaryRanges.physical.min = mode.peakRefreshRate;
            setSpecs.primaryRanges.physical.max = mode.peakRefreshRate;
            setSpecs.primaryRanges.render = setSpecs.primaryRanges.physical;
            setSpecs.appRequestRanges = setSpecs.primaryRanges;

            res = SurfaceComposerClient::setDesiredDisplayModeSpecs(mDisplayToken, setSpecs);
            ASSERT_EQ(res, NO_ERROR);
            gui::DisplayModeSpecs getSpecs;
            res = SurfaceComposerClient::getDesiredDisplayModeSpecs(mDisplayToken, &getSpecs);
            ASSERT_EQ(res, NO_ERROR);
            ASSERT_EQ(setSpecs, getSpecs);
        }
    }

    sp<IBinder> mDisplayToken;
    uint64_t mDisplayId;
};

TEST_F(RefreshRateRangeTest, setAllConfigs) {
    testSetDesiredDisplayModeSpecs();
}

TEST_F(RefreshRateRangeTest, setAllowGroupSwitching) {
    testSetDesiredDisplayModeSpecs(/*allowGroupSwitching=*/true);
    testSetDesiredDisplayModeSpecs(/*allowGroupSwitching=*/false);
    testSetDesiredDisplayModeSpecs(/*allowGroupSwitching=*/true);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
