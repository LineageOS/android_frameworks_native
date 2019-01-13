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

#include <ui/BufferHubBuffer.h>
#include <ui/GraphicBuffer.h>

#include <gtest/gtest.h>

namespace android {

namespace {

constexpr uint32_t kTestWidth = 1024;
constexpr uint32_t kTestHeight = 1;
constexpr uint32_t kTestFormat = HAL_PIXEL_FORMAT_BLOB;
constexpr uint32_t kTestLayerCount = 1;
constexpr uint64_t kTestUsage = GraphicBuffer::USAGE_SW_WRITE_OFTEN;

} // namespace

class GraphicBufferTest : public testing::Test {};

TEST_F(GraphicBufferTest, CreateFromBufferHubBuffer) {
    std::unique_ptr<BufferHubBuffer> b1 =
            BufferHubBuffer::Create(kTestWidth, kTestHeight, kTestLayerCount, kTestFormat,
                                    kTestUsage, /*userMetadataSize=*/0);
    ASSERT_NE(b1, nullptr);
    EXPECT_TRUE(b1->IsValid());

    sp<GraphicBuffer> gb(new GraphicBuffer(std::move(b1)));
    EXPECT_TRUE(gb->isBufferHubBuffer());

    EXPECT_EQ(gb->getWidth(), kTestWidth);
    EXPECT_EQ(gb->getHeight(), kTestHeight);
    EXPECT_EQ(static_cast<uint32_t>(gb->getPixelFormat()), kTestFormat);
    EXPECT_EQ(gb->getUsage(), kTestUsage);
    EXPECT_EQ(gb->getLayerCount(), kTestLayerCount);
}

TEST_F(GraphicBufferTest, InvalidBufferIdForNoneBufferHubBuffer) {
    sp<GraphicBuffer> gb(
            new GraphicBuffer(kTestWidth, kTestHeight, kTestFormat, kTestLayerCount, kTestUsage));
    EXPECT_FALSE(gb->isBufferHubBuffer());
    EXPECT_EQ(gb->getBufferId(), -1);
}

TEST_F(GraphicBufferTest, BufferIdMatchesBufferHubBufferId) {
    std::unique_ptr<BufferHubBuffer> b1 =
            BufferHubBuffer::Create(kTestWidth, kTestHeight, kTestLayerCount, kTestFormat,
                                    kTestUsage, /*userMetadataSize=*/0);
    EXPECT_NE(b1, nullptr);
    EXPECT_TRUE(b1->IsValid());

    int b1_id = b1->id();
    EXPECT_GE(b1_id, 0);

    sp<GraphicBuffer> gb(new GraphicBuffer(std::move(b1)));
    EXPECT_TRUE(gb->isBufferHubBuffer());
    EXPECT_EQ(gb->getBufferId(), b1_id);
}

} // namespace android
