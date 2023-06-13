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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

#include <ftl/fake_guard.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace {

using hal::RenderIntent;

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;

class SetDisplayBrightnessTest : public DisplayTransactionTest {
public:
    sp<DisplayDevice> getDisplayDevice() { return injectDefaultInternalDisplay({}); }
};

TEST_F(SetDisplayBrightnessTest, persistDisplayBrightnessNoComposite) {
    ftl::FakeGuard guard(kMainThreadContext);
    sp<DisplayDevice> displayDevice = getDisplayDevice();

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());

    constexpr float kDisplayBrightness = 0.5f;
    displayDevice->stageBrightness(kDisplayBrightness);

    EXPECT_EQ(0.5f, displayDevice->getStagedBrightness());

    displayDevice->persistBrightness(false);

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());
    EXPECT_EQ(std::nullopt, displayDevice->getCompositionDisplay()->getState().displayBrightness);
}

TEST_F(SetDisplayBrightnessTest, persistDisplayBrightnessWithComposite) {
    ftl::FakeGuard guard(kMainThreadContext);
    sp<DisplayDevice> displayDevice = getDisplayDevice();

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());

    constexpr float kDisplayBrightness = 0.5f;
    displayDevice->stageBrightness(kDisplayBrightness);

    EXPECT_EQ(0.5f, displayDevice->getStagedBrightness());

    displayDevice->persistBrightness(true);

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());
    EXPECT_EQ(kDisplayBrightness,
              displayDevice->getCompositionDisplay()->getState().displayBrightness);
}

TEST_F(SetDisplayBrightnessTest, persistDisplayBrightnessWithCompositeShortCircuitsOnNoOp) {
    ftl::FakeGuard guard(kMainThreadContext);
    sp<DisplayDevice> displayDevice = getDisplayDevice();

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());

    constexpr float kDisplayBrightness = 0.5f;
    displayDevice->stageBrightness(kDisplayBrightness);

    EXPECT_EQ(0.5f, displayDevice->getStagedBrightness());

    displayDevice->persistBrightness(true);

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());
    EXPECT_EQ(kDisplayBrightness,
              displayDevice->getCompositionDisplay()->getState().displayBrightness);
    displayDevice->getCompositionDisplay()->editState().displayBrightness = std::nullopt;

    displayDevice->stageBrightness(kDisplayBrightness);
    EXPECT_EQ(0.5f, displayDevice->getStagedBrightness());
    displayDevice->persistBrightness(true);

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());
    EXPECT_EQ(std::nullopt, displayDevice->getCompositionDisplay()->getState().displayBrightness);
}

TEST_F(SetDisplayBrightnessTest, firstDisplayBrightnessWithComposite) {
    ftl::FakeGuard guard(kMainThreadContext);
    sp<DisplayDevice> displayDevice = getDisplayDevice();

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());

    constexpr float kDisplayBrightness = -1.0f;
    displayDevice->stageBrightness(kDisplayBrightness);

    EXPECT_EQ(-1.0f, displayDevice->getStagedBrightness());

    displayDevice->persistBrightness(true);

    EXPECT_EQ(std::nullopt, displayDevice->getStagedBrightness());
    EXPECT_EQ(kDisplayBrightness,
              displayDevice->getCompositionDisplay()->getState().displayBrightness);
}

} // namespace
} // namespace android
