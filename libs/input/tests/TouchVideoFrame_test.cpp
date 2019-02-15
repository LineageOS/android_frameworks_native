/*
 * Copyright 2019 The Android Open Source Project
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

#include <input/TouchVideoFrame.h>

namespace android {
namespace test {

static const struct timeval TIMESTAMP = {1, 2};

TEST(TouchVideoFrame, Constructor) {
    const std::vector<int16_t> data = {1, 2, 3, 4, 5, 6};
    constexpr uint32_t height = 3;
    constexpr uint32_t width = 2;

    TouchVideoFrame frame(height, width, data, TIMESTAMP);

    ASSERT_EQ(data, frame.getData());
    ASSERT_EQ(height, frame.getHeight());
    ASSERT_EQ(width, frame.getWidth());
    ASSERT_EQ(TIMESTAMP.tv_sec, frame.getTimestamp().tv_sec);
    ASSERT_EQ(TIMESTAMP.tv_usec, frame.getTimestamp().tv_usec);
}

TEST(TouchVideoFrame, Equality) {
    const std::vector<int16_t> data = {1, 2, 3, 4, 5, 6};
    constexpr uint32_t height = 3;
    constexpr uint32_t width = 2;
    TouchVideoFrame frame(height, width, data, TIMESTAMP);

    TouchVideoFrame identicalFrame(height, width, data, TIMESTAMP);
    ASSERT_EQ(frame, identicalFrame);

    // The two cases below create an invalid frame, but it is OK for comparison purposes.
    // There aren't any checks currently enforced on the frame dimensions and data
    // Change height
    TouchVideoFrame changedHeightFrame(height + 1, width, data, TIMESTAMP);
    ASSERT_FALSE(frame == changedHeightFrame);

    // Change width
    TouchVideoFrame changedWidthFrame(height, width + 1, data, TIMESTAMP);
    ASSERT_FALSE(frame == changedWidthFrame);

    // Change data
    const std::vector<int16_t> differentData = {1, 2, 3, 3, 5, 6};
    TouchVideoFrame changedDataFrame(height, width, differentData, TIMESTAMP);
    ASSERT_FALSE(frame == changedDataFrame);

    // Change timestamp
    const struct timeval differentTimestamp = {TIMESTAMP.tv_sec + 1, TIMESTAMP.tv_usec + 1};
    TouchVideoFrame changedTimestampFrame(height, width, data, differentTimestamp);
    ASSERT_FALSE(frame == changedTimestampFrame);
}

} // namespace test
} // namespace android
