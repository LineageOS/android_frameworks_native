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

#define LOG_TAG "GraphicBufferTest"

#include <ui/GraphicBuffer.h>

#include <gtest/gtest.h>

namespace android {

namespace {

constexpr uint32_t kTestWidth = 1024;
constexpr uint32_t kTestHeight = 1;
constexpr uint32_t kTestLayerCount = 1;
constexpr uint64_t kTestUsage = GraphicBuffer::USAGE_SW_WRITE_OFTEN;

} // namespace

class GraphicBufferTest : public testing::Test {};

TEST_F(GraphicBufferTest, AllocateNoError) {
    PixelFormat format = PIXEL_FORMAT_RGBA_8888;
    sp<GraphicBuffer> gb(new GraphicBuffer(kTestWidth, kTestHeight, format, kTestLayerCount,
                                           kTestUsage, std::string("test")));
    ASSERT_EQ(NO_ERROR, gb->initCheck());
}

TEST_F(GraphicBufferTest, AllocateBadDimensions) {
    PixelFormat format = PIXEL_FORMAT_RGBA_8888;
    if (std::numeric_limits<size_t>::max() / std::numeric_limits<uint32_t>::max() /
                bytesPerPixel(format) >=
        std::numeric_limits<uint32_t>::max()) {
        GTEST_SUCCEED() << "Cannot overflow with this format";
    }
    uint32_t width, height;
    width = height = std::numeric_limits<uint32_t>::max();
    sp<GraphicBuffer> gb(new GraphicBuffer(width, height, format, kTestLayerCount, kTestUsage,
                                           std::string("test")));
    ASSERT_EQ(BAD_VALUE, gb->initCheck());

    const size_t targetArea = std::numeric_limits<size_t>::max() / bytesPerPixel(format);
    const size_t widthCandidate = targetArea / std::numeric_limits<uint32_t>::max();
    if (widthCandidate == 0) {
        width = 1;
    } else {
        width = std::numeric_limits<uint32_t>::max();
    }
    height = (targetArea / width) + 1;
    sp<GraphicBuffer> gb2(new GraphicBuffer(width, height, format, kTestLayerCount, kTestUsage,
                                            std::string("test")));
    ASSERT_EQ(BAD_VALUE, gb2->initCheck());
}

} // namespace android
