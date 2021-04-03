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

#include "DisplayHardware/FramebufferSurface.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {

class FramebufferSurfaceTest : public testing::Test {
public:
    ui::Size limitSize(const ui::Size& size, const ui::Size maxSize) {
        return FramebufferSurface::limitSizeInternal(size, maxSize);
    }
};

TEST_F(FramebufferSurfaceTest, limitSize) {
    const ui::Size kMaxSize(1920, 1080);
    EXPECT_EQ(ui::Size(1920, 1080), limitSize({3840, 2160}, kMaxSize));
    EXPECT_EQ(ui::Size(1920, 1080), limitSize({1920, 1080}, kMaxSize));
    EXPECT_EQ(ui::Size(1920, 1012), limitSize({4096, 2160}, kMaxSize));
    EXPECT_EQ(ui::Size(1080, 1080), limitSize({3840, 3840}, kMaxSize));
    EXPECT_EQ(ui::Size(1280, 720), limitSize({1280, 720}, kMaxSize));
}

} // namespace android
