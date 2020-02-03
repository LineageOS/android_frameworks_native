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
#pragma clang diagnostic ignored "-Wconversion"

#include <thread>
#include "LayerTransactionTest.h"
namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

/**
 * Test class for setting display configs and passing around refresh rate ranges.
 */
class RefreshRateRangeTest : public ::testing::Test {
protected:
    void SetUp() override { mDisplayToken = SurfaceComposerClient::getInternalDisplayToken(); }

    sp<IBinder> mDisplayToken;
};

TEST_F(RefreshRateRangeTest, setAllConfigs) {
    int32_t initialDefaultConfig;
    float initialMin;
    float initialMax;
    status_t res = SurfaceComposerClient::getDesiredDisplayConfigSpecs(mDisplayToken,
                                                                       &initialDefaultConfig,
                                                                       &initialMin, &initialMax);
    ASSERT_EQ(res, NO_ERROR);

    Vector<DisplayConfig> configs;
    res = SurfaceComposerClient::getDisplayConfigs(mDisplayToken, &configs);
    ASSERT_EQ(res, NO_ERROR);

    for (size_t i = 0; i < configs.size(); i++) {
        res = SurfaceComposerClient::setDesiredDisplayConfigSpecs(mDisplayToken, i,
                                                                  configs[i].refreshRate,
                                                                  configs[i].refreshRate);
        ASSERT_EQ(res, NO_ERROR);

        int defaultConfig;
        float minRefreshRate;
        float maxRefreshRate;
        res = SurfaceComposerClient::getDesiredDisplayConfigSpecs(mDisplayToken, &defaultConfig,
                                                                  &minRefreshRate, &maxRefreshRate);
        ASSERT_EQ(res, NO_ERROR);
        ASSERT_EQ(defaultConfig, i);
        ASSERT_EQ(minRefreshRate, configs[i].refreshRate);
        ASSERT_EQ(maxRefreshRate, configs[i].refreshRate);
    }

    res = SurfaceComposerClient::setDesiredDisplayConfigSpecs(mDisplayToken, initialDefaultConfig,
                                                              initialMin, initialMax);
    ASSERT_EQ(res, NO_ERROR);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"