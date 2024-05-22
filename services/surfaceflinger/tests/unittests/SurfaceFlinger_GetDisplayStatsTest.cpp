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
#define LOG_TAG "SurfaceFlingerGetDisplayStatsTest"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ui/DisplayStatInfo.h>

#include "CommitAndCompositeTest.h"

namespace android {
namespace {

struct SurfaceFlingerGetDisplayStatsTest : CommitAndCompositeTest {};

// TODO (b/277364366): Clients should be updated to pass in the display they want.
TEST_F(SurfaceFlingerGetDisplayStatsTest, nullptrSucceeds) {
    DisplayStatInfo info;
    status_t status = mFlinger.getDisplayStats(nullptr, &info);
    EXPECT_EQ(status, NO_ERROR);
}

TEST_F(SurfaceFlingerGetDisplayStatsTest, explicitToken) {
    DisplayStatInfo info;
    status_t status = mFlinger.getDisplayStats(mDisplay->getDisplayToken().promote(), &info);
    EXPECT_EQ(status, NO_ERROR);
}

TEST_F(SurfaceFlingerGetDisplayStatsTest, invalidToken) {
    static const std::string kDisplayName("fakeDisplay");
    sp<IBinder> displayToken = mFlinger.createVirtualDisplay(kDisplayName, false /*isSecure*/);
    DisplayStatInfo info;
    status_t status = mFlinger.getDisplayStats(displayToken, &info);
    EXPECT_EQ(status, NAME_NOT_FOUND);
}

} // namespace
} // namespace android
