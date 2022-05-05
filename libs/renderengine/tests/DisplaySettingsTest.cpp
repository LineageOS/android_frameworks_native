/*
 * Copyright 2022 The Android Open Source Project
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
#define LOG_TAG "DisplaySettingsTest"

#include <gtest/gtest.h>
#include <renderengine/DisplaySettings.h>

namespace android::renderengine {

TEST(DisplaySettingsTest, currentLuminanceNits) {
    DisplaySettings a, b;
    ASSERT_EQ(a, b);

    a.currentLuminanceNits = 45.f;

    ASSERT_FALSE(a == b);
}

TEST(DisplaySettingsTest, targetLuminanceNits) {
    DisplaySettings a, b;
    ASSERT_EQ(a, b);

    a.targetLuminanceNits = 45.f;

    ASSERT_FALSE(a == b);
}

TEST(DisplaySettingsTest, deviceHandlesColorTransform) {
    DisplaySettings a, b;
    ASSERT_EQ(a, b);

    a.deviceHandlesColorTransform = true;

    ASSERT_FALSE(a == b);
}

TEST(DisplaySettingsTest, dimmingStage) {
    DisplaySettings a, b;
    ASSERT_EQ(a, b);

    a.dimmingStage = aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF;

    ASSERT_FALSE(a == b);
}

TEST(DisplaySettingsTest, renderIntent) {
    DisplaySettings a, b;
    ASSERT_EQ(a, b);

    a.renderIntent = aidl::android::hardware::graphics::composer3::RenderIntent::TONE_MAP_ENHANCE;

    ASSERT_FALSE(a == b);
}
} // namespace android::renderengine
