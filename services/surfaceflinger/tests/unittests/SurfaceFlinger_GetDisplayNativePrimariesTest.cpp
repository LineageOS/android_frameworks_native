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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace {

class GetDisplayNativePrimaries : public DisplayTransactionTest {
public:
    GetDisplayNativePrimaries();
    void populateDummyDisplayNativePrimaries(ui::DisplayPrimaries& primaries);
    void checkDummyDisplayNativePrimaries(const ui::DisplayPrimaries& primaries);

private:
    static constexpr float mStartingTestValue = 1.0f;
};

GetDisplayNativePrimaries::GetDisplayNativePrimaries() {
    SimplePrimaryDisplayCase::Display::injectHwcDisplay(this);
    injectFakeNativeWindowSurfaceFactory();
}

void GetDisplayNativePrimaries::populateDummyDisplayNativePrimaries(
        ui::DisplayPrimaries& primaries) {
    float startingVal = mStartingTestValue;
    primaries.red.X = startingVal++;
    primaries.red.Y = startingVal++;
    primaries.red.Z = startingVal++;
    primaries.green.X = startingVal++;
    primaries.green.Y = startingVal++;
    primaries.green.Z = startingVal++;
    primaries.blue.X = startingVal++;
    primaries.blue.Y = startingVal++;
    primaries.blue.Z = startingVal++;
    primaries.white.X = startingVal++;
    primaries.white.Y = startingVal++;
    primaries.white.Z = startingVal++;
}

void GetDisplayNativePrimaries::checkDummyDisplayNativePrimaries(
        const ui::DisplayPrimaries& primaries) {
    float startingVal = mStartingTestValue;
    EXPECT_EQ(primaries.red.X, startingVal++);
    EXPECT_EQ(primaries.red.Y, startingVal++);
    EXPECT_EQ(primaries.red.Z, startingVal++);
    EXPECT_EQ(primaries.green.X, startingVal++);
    EXPECT_EQ(primaries.green.Y, startingVal++);
    EXPECT_EQ(primaries.green.Z, startingVal++);
    EXPECT_EQ(primaries.blue.X, startingVal++);
    EXPECT_EQ(primaries.blue.Y, startingVal++);
    EXPECT_EQ(primaries.blue.Z, startingVal++);
    EXPECT_EQ(primaries.white.X, startingVal++);
    EXPECT_EQ(primaries.white.Y, startingVal++);
    EXPECT_EQ(primaries.white.Z, startingVal++);
}

TEST_F(GetDisplayNativePrimaries, nullDisplayToken) {
    ui::DisplayPrimaries primaries;
    EXPECT_EQ(BAD_VALUE, mFlinger.getDisplayNativePrimaries(nullptr, primaries));
}

TEST_F(GetDisplayNativePrimaries, internalDisplayWithPrimariesData) {
    auto injector = SimplePrimaryDisplayCase::Display::makeFakeExistingDisplayInjector(this);
    injector.inject();
    auto internalDisplayToken = injector.token();

    ui::DisplayPrimaries expectedPrimaries;
    populateDummyDisplayNativePrimaries(expectedPrimaries);
    mFlinger.setInternalDisplayPrimaries(expectedPrimaries);

    ui::DisplayPrimaries primaries;
    EXPECT_EQ(NO_ERROR, mFlinger.getDisplayNativePrimaries(internalDisplayToken, primaries));

    checkDummyDisplayNativePrimaries(primaries);
}

TEST_F(GetDisplayNativePrimaries, notInternalDisplayToken) {
    sp<BBinder> notInternalDisplayToken = sp<BBinder>::make();

    ui::DisplayPrimaries primaries;
    populateDummyDisplayNativePrimaries(primaries);
    EXPECT_EQ(NAME_NOT_FOUND,
              mFlinger.getDisplayNativePrimaries(notInternalDisplayToken, primaries));

    // Check primaries argument wasn't modified in case of failure
    checkDummyDisplayNativePrimaries(primaries);
}

} // namespace
} // namespace android
