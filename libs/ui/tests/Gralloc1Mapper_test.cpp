/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "Gralloc1Mapper_test"
//#define LOG_NDEBUG 0

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ui/GraphicBuffer.h>
#include <ui/GraphicBufferMapper.h>
#include <utils/Errors.h>

#include <gtest/gtest.h>

using namespace android;

class Gralloc1MapperTest : public ::testing::Test
{
public:
    ~Gralloc1MapperTest() override = default;

protected:
    void SetUp() override {
        buffer = new GraphicBuffer(4, 8, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                GRALLOC1_PRODUCER_USAGE_CPU_WRITE_OFTEN,
                GRALLOC1_CONSUMER_USAGE_CPU_READ_OFTEN, "Gralloc1MapperTest");
        ASSERT_NE(nullptr, buffer.get());

        handle = static_cast<buffer_handle_t>(buffer->handle);

        mapper = &GraphicBufferMapper::get();
    }

    sp<GraphicBuffer> buffer;
    buffer_handle_t handle;
    GraphicBufferMapper* mapper;
};

TEST_F(Gralloc1MapperTest, Gralloc1MapperTest_getDimensions) {
    uint32_t width = 0;
    uint32_t height = 0;
    status_t err = mapper->getDimensions(handle, &width, &height);
    ASSERT_EQ(GRALLOC1_ERROR_NONE, err);
    EXPECT_EQ(4U, width);
    EXPECT_EQ(8U, height);
}

TEST_F(Gralloc1MapperTest, Gralloc1MapperTest_getFormat) {
    int32_t value = 0;
    status_t err = mapper->getFormat(handle, &value);
    ASSERT_EQ(GRALLOC1_ERROR_NONE, err);
    EXPECT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, value);
}

TEST_F(Gralloc1MapperTest, Gralloc1MapperTest_getLayerCount) {
    uint32_t value = 0;
    status_t err = mapper->getLayerCount(handle, &value);
    if (err != GRALLOC1_ERROR_UNSUPPORTED) {
        EXPECT_EQ(1U, value);
    }
}

TEST_F(Gralloc1MapperTest, Gralloc1MapperTest_getProducerUsage) {
    uint64_t value = 0;
    status_t err = mapper->getProducerUsage(handle, &value);
    ASSERT_EQ(GRALLOC1_ERROR_NONE, err);
    EXPECT_EQ(GRALLOC1_PRODUCER_USAGE_CPU_WRITE_OFTEN, value);
}

TEST_F(Gralloc1MapperTest, Gralloc1MapperTest_getConsumerUsage) {
    uint64_t value = 0;
    status_t err = mapper->getConsumerUsage(handle, &value);
    ASSERT_EQ(GRALLOC1_ERROR_NONE, err);
    EXPECT_EQ(GRALLOC1_CONSUMER_USAGE_CPU_READ_OFTEN, value);
}

TEST_F(Gralloc1MapperTest, Gralloc1MapperTest_getBackingStore) {
    uint64_t value = 0;
    status_t err = mapper->getBackingStore(handle, &value);
    ASSERT_EQ(GRALLOC1_ERROR_NONE, err);
}

TEST_F(Gralloc1MapperTest, Gralloc1MapperTest_getStride) {
    uint32_t value = 0;
    status_t err = mapper->getStride(handle, &value);
    ASSERT_EQ(GRALLOC1_ERROR_NONE, err);
    // The stride should be at least the width of the buffer.
    EXPECT_LE(4U, value);
}
