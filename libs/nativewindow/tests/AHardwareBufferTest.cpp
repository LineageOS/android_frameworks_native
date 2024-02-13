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

#define LOG_TAG "AHardwareBuffer_test"
//#define LOG_NDEBUG 0

#include <android-base/properties.h>
#include <android/data_space.h>
#include <android/hardware/graphics/common/1.0/types.h>
#include <gtest/gtest.h>
#include <private/android/AHardwareBufferHelpers.h>
#include <ui/GraphicBuffer.h>
#include <vndk/hardware_buffer.h>

using namespace android;
using android::hardware::graphics::common::V1_0::BufferUsage;

static bool IsCuttlefish() {
    return ::android::base::GetProperty("ro.product.board", "") == "cutf";
}

static ::testing::AssertionResult BuildHexFailureMessage(uint64_t expected,
        uint64_t actual, const char* type) {
    std::ostringstream ss;
    ss << type << " 0x" << std::hex << actual
            << " does not match expected " << type << " 0x" << std::hex
            << expected;
    return ::testing::AssertionFailure() << ss.str();
}

static ::testing::AssertionResult TestUsageConversion(
        uint64_t grallocUsage, uint64_t hardwareBufferUsage) {
    uint64_t convertedGrallocUsage = AHardwareBuffer_convertToGrallocUsageBits(hardwareBufferUsage);
    if (convertedGrallocUsage != grallocUsage)
        return BuildHexFailureMessage(grallocUsage, convertedGrallocUsage, "converToGralloc");

    uint64_t convertedHArdwareBufferUsage = AHardwareBuffer_convertFromGrallocUsageBits(grallocUsage);
    if (convertedHArdwareBufferUsage != grallocUsage)
        return BuildHexFailureMessage(grallocUsage, convertedHArdwareBufferUsage, "convertFromGralloc");

    return testing::AssertionSuccess();
}

// This is a unit test rather than going through AHardwareBuffer because not
// all flags may be supported by the host device.
TEST(AHardwareBufferTest, ConvertToAndFromGrallocBits) {
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::CPU_READ_RARELY,
            AHARDWAREBUFFER_USAGE_CPU_READ_RARELY));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::CPU_READ_OFTEN,
            AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::CPU_WRITE_RARELY,
            AHARDWAREBUFFER_USAGE_CPU_WRITE_RARELY));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::CPU_WRITE_OFTEN,
            AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN));

    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::GPU_TEXTURE,
            AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::GPU_RENDER_TARGET,
            AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::GPU_DATA_BUFFER,
            AHARDWAREBUFFER_USAGE_GPU_DATA_BUFFER));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::PROTECTED,
            AHARDWAREBUFFER_USAGE_PROTECTED_CONTENT));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::SENSOR_DIRECT_DATA,
            AHARDWAREBUFFER_USAGE_SENSOR_DIRECT_DATA));
    EXPECT_TRUE(TestUsageConversion((uint64_t)BufferUsage::VIDEO_ENCODER,
            AHARDWAREBUFFER_USAGE_VIDEO_ENCODE));

    EXPECT_TRUE(TestUsageConversion(1ull<<28, AHARDWAREBUFFER_USAGE_VENDOR_0));
    EXPECT_TRUE(TestUsageConversion(1ull<<29, AHARDWAREBUFFER_USAGE_VENDOR_1));
    EXPECT_TRUE(TestUsageConversion(1ull<<30, AHARDWAREBUFFER_USAGE_VENDOR_2));
    EXPECT_TRUE(TestUsageConversion(1ull<<31, AHARDWAREBUFFER_USAGE_VENDOR_3));
    EXPECT_TRUE(TestUsageConversion(1ull<<48, AHARDWAREBUFFER_USAGE_VENDOR_4));
    EXPECT_TRUE(TestUsageConversion(1ull<<49, AHARDWAREBUFFER_USAGE_VENDOR_5));
    EXPECT_TRUE(TestUsageConversion(1ull<<50, AHARDWAREBUFFER_USAGE_VENDOR_6));
    EXPECT_TRUE(TestUsageConversion(1ull<<51, AHARDWAREBUFFER_USAGE_VENDOR_7));
    EXPECT_TRUE(TestUsageConversion(1ull<<52, AHARDWAREBUFFER_USAGE_VENDOR_8));
    EXPECT_TRUE(TestUsageConversion(1ull<<53, AHARDWAREBUFFER_USAGE_VENDOR_9));
    EXPECT_TRUE(TestUsageConversion(1ull<<54, AHARDWAREBUFFER_USAGE_VENDOR_10));
    EXPECT_TRUE(TestUsageConversion(1ull<<55, AHARDWAREBUFFER_USAGE_VENDOR_11));
    EXPECT_TRUE(TestUsageConversion(1ull<<56, AHARDWAREBUFFER_USAGE_VENDOR_12));
    EXPECT_TRUE(TestUsageConversion(1ull<<57, AHARDWAREBUFFER_USAGE_VENDOR_13));
    EXPECT_TRUE(TestUsageConversion(1ull<<58, AHARDWAREBUFFER_USAGE_VENDOR_14));
    EXPECT_TRUE(TestUsageConversion(1ull<<59, AHARDWAREBUFFER_USAGE_VENDOR_15));
    EXPECT_TRUE(TestUsageConversion(1ull<<60, AHARDWAREBUFFER_USAGE_VENDOR_16));
    EXPECT_TRUE(TestUsageConversion(1ull<<61, AHARDWAREBUFFER_USAGE_VENDOR_17));
    EXPECT_TRUE(TestUsageConversion(1ull<<62, AHARDWAREBUFFER_USAGE_VENDOR_18));
    EXPECT_TRUE(TestUsageConversion(1ull<<63, AHARDWAREBUFFER_USAGE_VENDOR_19));

    // Test some more complex flag combinations.
    EXPECT_TRUE(TestUsageConversion(
            (uint64_t)BufferUsage::CPU_READ_RARELY |
            (uint64_t)BufferUsage::CPU_WRITE_RARELY,
            AHARDWAREBUFFER_USAGE_CPU_READ_RARELY | AHARDWAREBUFFER_USAGE_CPU_WRITE_RARELY));

    EXPECT_TRUE(TestUsageConversion(
        (uint64_t)BufferUsage::GPU_RENDER_TARGET | (uint64_t)BufferUsage::GPU_TEXTURE |
        1ull << 29 | 1ull << 57,
        AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT | AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
        AHARDWAREBUFFER_USAGE_VENDOR_1 | AHARDWAREBUFFER_USAGE_VENDOR_13));
}

TEST(AHardwareBufferTest, GetCreateHandleTest) {
    AHardwareBuffer_Desc desc{
            .width = 64,
            .height = 1,
            .layers = 1,
            .format = AHARDWAREBUFFER_FORMAT_BLOB,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
            .stride = 64,
    };

    AHardwareBuffer* buffer = nullptr;
    EXPECT_EQ(0, AHardwareBuffer_allocate(&desc, &buffer));
    const native_handle_t* handle = AHardwareBuffer_getNativeHandle(buffer);
    EXPECT_NE(nullptr, handle);

    AHardwareBuffer* otherBuffer = nullptr;
    EXPECT_EQ(0, AHardwareBuffer_createFromHandle(
        &desc, handle, AHARDWAREBUFFER_CREATE_FROM_HANDLE_METHOD_CLONE, &otherBuffer));
    EXPECT_NE(nullptr, otherBuffer);

    AHardwareBuffer_release(buffer);
    AHardwareBuffer_release(otherBuffer);
}

TEST(AHardwareBufferTest, GetIdTest) {
    const uint32_t testWidth = 4;
    const uint32_t testHeight = 4;
    const uint32_t testLayers = 1;

    AHardwareBuffer* ahb1 = nullptr;
    uint64_t id1 = 0;
    const AHardwareBuffer_Desc desc = {
            .width = testWidth,
            .height = testHeight,
            .layers = testLayers,
            .format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_RARELY,
    };
    int res = AHardwareBuffer_allocate(&desc, &ahb1);
    EXPECT_EQ(NO_ERROR, res);
    EXPECT_NE(nullptr, ahb1);
    EXPECT_EQ(0, AHardwareBuffer_getId(ahb1, &id1));
    const GraphicBuffer* gb1 = AHardwareBuffer_to_GraphicBuffer(ahb1);
    EXPECT_NE(nullptr, gb1);
    EXPECT_EQ(id1, gb1->getId());
    EXPECT_NE(id1, 0);

    sp<GraphicBuffer> gb2(new GraphicBuffer(testWidth,
                                            testHeight,
                                            PIXEL_FORMAT_RGBA_8888,
                                            testLayers,
                                            GraphicBuffer::USAGE_SW_READ_RARELY,
                                            std::string("test")));
    EXPECT_NE(nullptr, gb2.get());
    const AHardwareBuffer* ahb2 = AHardwareBuffer_from_GraphicBuffer(gb2.get());
    EXPECT_NE(nullptr, ahb2);
    uint64_t id2 = 0;
    EXPECT_EQ(0, AHardwareBuffer_getId(ahb2, &id2));
    EXPECT_EQ(id2, gb2->getId());
    EXPECT_NE(id2, 0);

    EXPECT_NE(id1, id2);
}

TEST(AHardwareBufferTest, Allocate2NoExtras) {
    AHardwareBuffer_Desc desc{
            .width = 64,
            .height = 1,
            .layers = 1,
            .format = AHARDWAREBUFFER_FORMAT_BLOB,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
            .stride = 0,
    };

    AHardwareBuffer* buffer = nullptr;
    ASSERT_EQ(0, AHardwareBuffer_allocateWithOptions(&desc, nullptr, 0, &buffer));
    uint64_t id = 0;
    EXPECT_EQ(0, AHardwareBuffer_getId(buffer, &id));
    EXPECT_NE(0, id);
    AHardwareBuffer_Desc desc2{};
    AHardwareBuffer_describe(buffer, &desc2);
    EXPECT_EQ(desc.width, desc2.width);
    EXPECT_EQ(desc.height, desc2.height);
    EXPECT_GE(desc2.stride, desc2.width);

    AHardwareBuffer_release(buffer);
}

TEST(AHardwareBufferTest, Allocate2WithExtras) {
    if (!IsCuttlefish()) {
        GTEST_SKIP() << "Unknown gralloc HAL, cannot test extras";
    }

    AHardwareBuffer_Desc desc{
            .width = 64,
            .height = 48,
            .layers = 1,
            .format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
            .stride = 0,
    };

    AHardwareBuffer* buffer = nullptr;
    std::array<AHardwareBufferLongOptions, 1> extras = {{
            {.name = "android.hardware.graphics.common.Dataspace", ADATASPACE_DISPLAY_P3},
    }};
    ASSERT_EQ(0, AHardwareBuffer_allocateWithOptions(&desc, extras.data(), extras.size(), &buffer));
    uint64_t id = 0;
    EXPECT_EQ(0, AHardwareBuffer_getId(buffer, &id));
    EXPECT_NE(0, id);
    AHardwareBuffer_Desc desc2{};
    AHardwareBuffer_describe(buffer, &desc2);
    EXPECT_EQ(desc.width, desc2.width);
    EXPECT_EQ(desc.height, desc2.height);
    EXPECT_GE(desc2.stride, desc2.width);

    EXPECT_EQ(ADATASPACE_DISPLAY_P3, AHardwareBuffer_getDataSpace(buffer));

    AHardwareBuffer_release(buffer);
}

TEST(AHardwareBufferTest, GetSetDataspace) {
    AHardwareBuffer_Desc desc{
            .width = 64,
            .height = 48,
            .layers = 1,
            .format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
            .stride = 0,
    };

    AHardwareBuffer* buffer = nullptr;
    ASSERT_EQ(0, AHardwareBuffer_allocate(&desc, &buffer));

    EXPECT_EQ(ADATASPACE_UNKNOWN, AHardwareBuffer_getDataSpace(buffer));
    AHardwareBufferStatus status = AHardwareBuffer_setDataSpace(buffer, ADATASPACE_DISPLAY_P3);
    if (status != AHARDWAREBUFFER_STATUS_UNSUPPORTED) {
        EXPECT_EQ(0, status);
        EXPECT_EQ(ADATASPACE_DISPLAY_P3, AHardwareBuffer_getDataSpace(buffer));
    }

    AHardwareBuffer_release(buffer);
}