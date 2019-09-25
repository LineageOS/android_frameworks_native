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

#include <thread>
#include "LayerTransactionTest.h"
namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

class DisplayActiveConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        mDisplayToken = SurfaceComposerClient::getInternalDisplayToken();
        SurfaceComposerClient::getDisplayConfigs(mDisplayToken, &mDisplayconfigs);
        EXPECT_GT(mDisplayconfigs.size(), 0);

        // set display power to on to make sure config can be changed
        SurfaceComposerClient::setDisplayPowerMode(mDisplayToken, HWC_POWER_MODE_NORMAL);
    }

    sp<IBinder> mDisplayToken;
    Vector<DisplayInfo> mDisplayconfigs;
};

TEST_F(DisplayActiveConfigTest, allConfigsAllowed) {
    std::vector<int32_t> allowedConfigs;

    // Add all configs to the allowed configs
    for (int i = 0; i < mDisplayconfigs.size(); i++) {
        allowedConfigs.push_back(i);
    }

    status_t res = SurfaceComposerClient::setAllowedDisplayConfigs(mDisplayToken, allowedConfigs);
    EXPECT_EQ(res, NO_ERROR);

    std::vector<int32_t> outConfigs;
    res = SurfaceComposerClient::getAllowedDisplayConfigs(mDisplayToken, &outConfigs);
    EXPECT_EQ(res, NO_ERROR);
    EXPECT_EQ(allowedConfigs, outConfigs);
}

TEST_F(DisplayActiveConfigTest, changeAllowedConfig) {
    // we need at least 2 configs available for this test
    if (mDisplayconfigs.size() <= 1) return;

    int activeConfig = SurfaceComposerClient::getActiveConfig(mDisplayToken);

    // We want to set the allowed config to everything but the active config
    std::vector<int32_t> allowedConfigs;
    for (int i = 0; i < mDisplayconfigs.size(); i++) {
        if (i != activeConfig) {
            allowedConfigs.push_back(i);
        }
    }

    status_t res = SurfaceComposerClient::setAllowedDisplayConfigs(mDisplayToken, allowedConfigs);
    EXPECT_EQ(res, NO_ERROR);

    // Allow some time for the config change
    std::this_thread::sleep_for(200ms);

    int newActiveConfig = SurfaceComposerClient::getActiveConfig(mDisplayToken);
    EXPECT_NE(activeConfig, newActiveConfig);

    // Make sure the new config is part of allowed config
    EXPECT_TRUE(std::find(allowedConfigs.begin(), allowedConfigs.end(), newActiveConfig) !=
                allowedConfigs.end());
}
} // namespace android
