/*
 * Copyright 2018 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <gui/FrameRateUtils.h>
#include <inttypes.h>
#include <system/window.h>

#include <com_android_graphics_libgui_flags.h>

namespace android {
using namespace com::android::graphics::libgui;

TEST(FrameRateUtilsTest, ValidateFrameRate) {
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS, ""));
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_GTE,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Privileged APIs.
    EXPECT_FALSE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    constexpr bool kPrivileged = true;
    EXPECT_TRUE(ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_EXACT,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, "",
                                  kPrivileged));
    EXPECT_TRUE(ValidateFrameRate(0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, "",
                                  kPrivileged));

    // Invalid frame rate.
    EXPECT_FALSE(ValidateFrameRate(-1, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(1.0f / 0.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(0.0f / 0.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT,
                                   ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Invalid compatibility.
    EXPECT_FALSE(
            ValidateFrameRate(60.0f, -1, ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));
    EXPECT_FALSE(ValidateFrameRate(60.0f, 2, ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS, ""));

    // Invalid change frame rate strategy.
    if (flags::bq_setframerate()) {
        EXPECT_FALSE(
                ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT, -1, ""));
        EXPECT_FALSE(
                ValidateFrameRate(60.0f, ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT, 2, ""));
    }
}

} // namespace android
