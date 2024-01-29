/*
 * Copyright 2023 The Android Open Source Project
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
#define LOG_TAG "SmallAreaDetectionAllowMappingsTest"

#include <gtest/gtest.h>

#include "Scheduler/SmallAreaDetectionAllowMappings.h"

namespace android::scheduler {

class SmallAreaDetectionAllowMappingsTest : public testing::Test {
protected:
    SmallAreaDetectionAllowMappings mMappings;
    static constexpr int32_t kAppId1 = 10100;
    static constexpr int32_t kAppId2 = 10101;
    static constexpr float kThreshold1 = 0.05f;
    static constexpr float kThreshold2 = 0.07f;
};

namespace {
TEST_F(SmallAreaDetectionAllowMappingsTest, testUpdate) {
    std::vector<std::pair<int32_t, float>> mappings;
    mappings.reserve(2);
    mappings.push_back(std::make_pair(kAppId1, kThreshold1));
    mappings.push_back(std::make_pair(kAppId2, kThreshold2));

    mMappings.update(mappings);
    ASSERT_EQ(mMappings.getThresholdForAppId(kAppId1).value(), kThreshold1);
    ASSERT_EQ(mMappings.getThresholdForAppId(kAppId2).value(), kThreshold2);
}

TEST_F(SmallAreaDetectionAllowMappingsTest, testSetThresholdForAppId) {
    mMappings.setThresholdForAppId(kAppId1, kThreshold1);
    ASSERT_EQ(mMappings.getThresholdForAppId(kAppId1), kThreshold1);
}

TEST_F(SmallAreaDetectionAllowMappingsTest, testAppIdNotInTheMappings) {
    ASSERT_EQ(mMappings.getThresholdForAppId(kAppId1), std::nullopt);
}

} // namespace
} // namespace android::scheduler
