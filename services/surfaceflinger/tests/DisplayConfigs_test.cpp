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
    size_t initialDefaultMode;
    bool initialAllowGroupSwitching;
    float initialPrimaryMin;
    float initialPrimaryMax;
    float initialAppRequestMin;
    float initialAppRequestMax;

protected:
    void SetUp() override {
        mDisplayToken = SurfaceComposerClient::getInternalDisplayToken();
        status_t res =
                SurfaceComposerClient::getDesiredDisplayModeSpecs(mDisplayToken,
                                                                  &initialDefaultMode,
                                                                  &initialAllowGroupSwitching,
                                                                  &initialPrimaryMin,
                                                                  &initialPrimaryMax,
                                                                  &initialAppRequestMin,
                                                                  &initialAppRequestMax);
        ASSERT_EQ(res, NO_ERROR);
    }

    void TearDown() override {
        status_t res =
                SurfaceComposerClient::setDesiredDisplayModeSpecs(mDisplayToken, initialDefaultMode,
                                                                  initialAllowGroupSwitching,
                                                                  initialPrimaryMin,
                                                                  initialPrimaryMax,
                                                                  initialAppRequestMin,
                                                                  initialAppRequestMax);
        ASSERT_EQ(res, NO_ERROR);
    }

    void testSetAllowGroupSwitching(bool allowGroupSwitching);

    sp<IBinder> mDisplayToken;
};

TEST_F(RefreshRateRangeTest, setAllConfigs) {
    Vector<ui::DisplayMode> modes;
    status_t res = SurfaceComposerClient::getDisplayModes(mDisplayToken, &modes);
    ASSERT_EQ(res, NO_ERROR);
    ASSERT_GT(modes.size(), 0);

    for (size_t i = 0; i < modes.size(); i++) {
        res = SurfaceComposerClient::setDesiredDisplayModeSpecs(mDisplayToken, i, false,
                                                                modes[i].refreshRate,
                                                                modes[i].refreshRate,
                                                                modes[i].refreshRate,
                                                                modes[i].refreshRate);
        ASSERT_EQ(res, NO_ERROR);

        size_t defaultConfig;
        bool allowGroupSwitching;
        float primaryRefreshRateMin;
        float primaryRefreshRateMax;
        float appRequestRefreshRateMin;
        float appRequestRefreshRateMax;
        res = SurfaceComposerClient::getDesiredDisplayModeSpecs(mDisplayToken, &defaultConfig,
                                                                &allowGroupSwitching,
                                                                &primaryRefreshRateMin,
                                                                &primaryRefreshRateMax,
                                                                &appRequestRefreshRateMin,
                                                                &appRequestRefreshRateMax);
        ASSERT_EQ(res, NO_ERROR);
        ASSERT_EQ(defaultConfig, i);
        ASSERT_EQ(allowGroupSwitching, false);
        ASSERT_EQ(primaryRefreshRateMin, modes[i].refreshRate);
        ASSERT_EQ(primaryRefreshRateMax, modes[i].refreshRate);
        ASSERT_EQ(appRequestRefreshRateMin, modes[i].refreshRate);
        ASSERT_EQ(appRequestRefreshRateMax, modes[i].refreshRate);
    }
}

void RefreshRateRangeTest::testSetAllowGroupSwitching(bool allowGroupSwitching) {
    status_t res =
            SurfaceComposerClient::setDesiredDisplayModeSpecs(mDisplayToken, 0, allowGroupSwitching,
                                                              0.f, 90.f, 0.f, 90.f);
    ASSERT_EQ(res, NO_ERROR);
    size_t defaultConfig;
    bool newAllowGroupSwitching;
    float primaryRefreshRateMin;
    float primaryRefreshRateMax;
    float appRequestRefreshRateMin;
    float appRequestRefreshRateMax;

    res = SurfaceComposerClient::getDesiredDisplayModeSpecs(mDisplayToken, &defaultConfig,
                                                            &newAllowGroupSwitching,
                                                            &primaryRefreshRateMin,
                                                            &primaryRefreshRateMax,
                                                            &appRequestRefreshRateMin,
                                                            &appRequestRefreshRateMax);
    ASSERT_EQ(res, NO_ERROR);
    ASSERT_EQ(defaultConfig, 0);
    ASSERT_EQ(newAllowGroupSwitching, allowGroupSwitching);
    ASSERT_EQ(primaryRefreshRateMin, 0.f);
    ASSERT_EQ(primaryRefreshRateMax, 90.f);
    ASSERT_EQ(appRequestRefreshRateMin, 0.f);
    ASSERT_EQ(appRequestRefreshRateMax, 90.f);
}

TEST_F(RefreshRateRangeTest, setAllowGroupSwitching) {
    testSetAllowGroupSwitching(true);
    testSetAllowGroupSwitching(false);
    testSetAllowGroupSwitching(true);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"