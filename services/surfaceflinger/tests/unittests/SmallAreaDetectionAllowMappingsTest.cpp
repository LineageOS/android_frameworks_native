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

class SmallAreaDetectionMappingsAllowTest : public testing::Test {
protected:
    SmallAreaDetectionAllowMappings mMappings;
};

namespace {
TEST_F(SmallAreaDetectionMappingsAllowTest, testUpdate) {
    const uid_t uid1 = 10100;
    const uid_t uid2 = 10101;
    const float threshold1 = 0.05f;
    const float threshold2 = 0.07f;
    std::vector<std::pair<uid_t, float>> mappings;
    mappings.reserve(2);
    mappings.push_back(std::make_pair(uid1, threshold1));
    mappings.push_back(std::make_pair(uid2, threshold2));

    mMappings.update(mappings);
    ASSERT_EQ(mMappings.getThresholdForUid(uid1).value(), threshold1);
    ASSERT_EQ(mMappings.getThresholdForUid(uid2).value(), threshold2);
}

TEST_F(SmallAreaDetectionMappingsAllowTest, testSetThesholdForUid) {
    const uid_t uid = 10111;
    const float threshold = 0.05f;

    mMappings.setThesholdForUid(uid, threshold);
    ASSERT_EQ(mMappings.getThresholdForUid(uid), threshold);
}

TEST_F(SmallAreaDetectionMappingsAllowTest, testUidNotInTheMappings) {
    const uid_t uid = 10222;
    ASSERT_EQ(mMappings.getThresholdForUid(uid), std::nullopt);
}

} // namespace
} // namespace android::scheduler
