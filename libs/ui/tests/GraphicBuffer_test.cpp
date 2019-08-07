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

TEST_F(GraphicBufferTest, CreateFromBufferHubBuffer) {
    std::unique_ptr<BufferHubBuffer> b1 =
            BufferHubBuffer::create(kTestWidth, kTestHeight, kTestLayerCount, kTestFormat,
                                    kTestUsage, /*userMetadataSize=*/0);
    ASSERT_NE(b1, nullptr);
    EXPECT_TRUE(b1->isValid());

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
            BufferHubBuffer::create(kTestWidth, kTestHeight, kTestLayerCount, kTestFormat,
                                    kTestUsage, /*userMetadataSize=*/0);
    EXPECT_NE(b1, nullptr);
    EXPECT_TRUE(b1->isValid());

    int b1_id = b1->id();
    EXPECT_GE(b1_id, 0);

    sp<GraphicBuffer> gb(new GraphicBuffer(std::move(b1)));
    EXPECT_TRUE(gb->isBufferHubBuffer());
    EXPECT_EQ(gb->getBufferId(), b1_id);
}

TEST_F(GraphicBufferTest, flattenAndUnflatten) {
    std::unique_ptr<BufferHubBuffer> b1 =
            BufferHubBuffer::create(kTestWidth, kTestHeight, kTestLayerCount, kTestFormat,
                                    kTestUsage, /*userMetadataSize=*/0);
    ASSERT_NE(b1, nullptr);
    sp<GraphicBuffer> gb1(new GraphicBuffer(std::move(b1)));
    gb1->setGenerationNumber(42);

    size_t flattenedSize = gb1->getFlattenedSize();
    EXPECT_EQ(flattenedSize, 48);
    size_t fdCount = gb1->getFdCount();
    EXPECT_EQ(fdCount, 0);

    int data[flattenedSize];
    int fds[0];

    // Make copies of needed items since flatten modifies them.
    size_t flattenedSizeCopy = flattenedSize;
    size_t fdCountCopy = fdCount;
    void* dataStart = data;
    int* fdsStart = fds;
    status_t err = gb1->flatten(dataStart, flattenedSizeCopy, fdsStart, fdCountCopy);
    ASSERT_EQ(err, NO_ERROR);
    EXPECT_EQ(flattenedSizeCopy, 0);
    EXPECT_EQ(fdCountCopy, 0);

    size_t unflattenSize = flattenedSize;
    size_t unflattenFdCount = fdCount;
    const void* unflattenData = static_cast<const void*>(dataStart);
    const int* unflattenFdData = static_cast<const int*>(fdsStart);

    GraphicBuffer* gb2 = new GraphicBuffer();
    err = gb2->unflatten(unflattenData, unflattenSize, unflattenFdData, unflattenFdCount);
    ASSERT_EQ(err, NO_ERROR);
    EXPECT_TRUE(gb2->isBufferHubBuffer());

    EXPECT_EQ(gb2->getWidth(), kTestWidth);
    EXPECT_EQ(gb2->getHeight(), kTestHeight);
    EXPECT_EQ(static_cast<uint32_t>(gb2->getPixelFormat()), kTestFormat);
    EXPECT_EQ(gb2->getUsage(), kTestUsage);
    EXPECT_EQ(gb2->getLayerCount(), kTestLayerCount);
    EXPECT_EQ(gb1->getBufferId(), gb2->getBufferId());
    EXPECT_EQ(gb2->getGenerationNumber(), 42);
}

} // namespace android
