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

#include <android/hardware_buffer.h>
#include <private/android/AHardwareBufferHelpers.h>
#include <hardware/gralloc1.h>

#include <gtest/gtest.h>

using namespace android;

static ::testing::AssertionResult BuildHexFailureMessage(uint64_t expected,
        uint64_t actual, const char* type) {
    std::ostringstream ss;
    ss << type << " 0x" << std::hex << actual
            << " does not match expected " << type << " 0x" << std::hex
            << expected;
    return ::testing::AssertionFailure() << ss.str();
}

static ::testing::AssertionResult TestUsageConversion(
        uint64_t grallocProducerUsage, uint64_t grallocConsumerUsage,
        uint64_t hardwareBufferUsage0, uint64_t hardwareBufferUsage1) {
    uint64_t producerUsage = 0;
    uint64_t consumerUsage = 0;
    uint64_t usage0 = 0;
    uint64_t usage1 = 0;

    AHardwareBuffer_convertToGrallocUsageBits(
            &producerUsage, &consumerUsage, hardwareBufferUsage0, hardwareBufferUsage1);
    if (producerUsage != grallocProducerUsage)
        return BuildHexFailureMessage(grallocProducerUsage, producerUsage,
                "producer");
    if (consumerUsage != grallocConsumerUsage)
        return BuildHexFailureMessage(grallocConsumerUsage, consumerUsage,
                "consumer");

    AHardwareBuffer_convertFromGrallocUsageBits(
            &usage0, &usage1, grallocProducerUsage, grallocConsumerUsage);
    if (usage0 != hardwareBufferUsage0)
        return BuildHexFailureMessage(hardwareBufferUsage0, usage0, "usage0");
    if (usage1 != hardwareBufferUsage1)
        return BuildHexFailureMessage(hardwareBufferUsage1, usage1, "usage1");

    return testing::AssertionSuccess();
}

// This is a unit test rather than going through AHardwareBuffer because not
// all flags may be supported by the host device.
TEST(AHardwareBufferTest, ConvertToAndFromGrallocBits) {
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_CPU_READ,
            AHARDWAREBUFFER_USAGE0_CPU_READ, 0));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_CPU_READ_OFTEN,
            AHARDWAREBUFFER_USAGE0_CPU_READ_OFTEN, 0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_CPU_WRITE, 0,
            AHARDWAREBUFFER_USAGE0_CPU_WRITE, 0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_CPU_WRITE_OFTEN, 0,
            AHARDWAREBUFFER_USAGE0_CPU_WRITE_OFTEN, 0));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_GPU_TEXTURE,
            AHARDWAREBUFFER_USAGE0_GPU_SAMPLED_IMAGE, 0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_GPU_RENDER_TARGET,
            0, AHARDWAREBUFFER_USAGE0_GPU_COLOR_OUTPUT, 0));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_GPU_DATA_BUFFER,
            AHARDWAREBUFFER_USAGE0_GPU_DATA_BUFFER, 0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PROTECTED, 0,
            AHARDWAREBUFFER_USAGE0_PROTECTED_CONTENT, 0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_SENSOR_DIRECT_DATA,
            0, AHARDWAREBUFFER_USAGE0_SENSOR_DIRECT_DATA, 0));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_VIDEO_ENCODER,
            AHARDWAREBUFFER_USAGE0_VIDEO_ENCODE, 0));

    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_0, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_1, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_1));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_2, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_2));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_3, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_3));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_4, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_4));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_5, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_5));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_6, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_6));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_7, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_7));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_8, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_8));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_9, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_9));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_10, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_10));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_11, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_11));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_12, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_12));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_13, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_13));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_14, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_14));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_15, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_15));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_16, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_16));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_17, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_17));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_18, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_18));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_PRIVATE_19, 0,
            0, AHARDWAREBUFFER_USAGE1_PRODUCER_PRIVATE_19));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_0,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_0));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_1,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_1));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_2,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_2));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_3,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_3));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_4,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_4));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_5,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_5));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_6,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_6));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_7,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_7));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_8,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_8));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_9,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_9));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_10,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_10));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_11,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_11));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_12,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_12));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_13,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_13));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_14,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_14));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_15,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_15));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_16,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_16));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_17,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_17));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_18,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_18));
    EXPECT_TRUE(TestUsageConversion(0, GRALLOC1_CONSUMER_USAGE_PRIVATE_19,
            0, AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_19));

    // Test some more complex flag combinations.
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_CPU_WRITE,
            GRALLOC1_CONSUMER_USAGE_CPU_READ,
            AHARDWAREBUFFER_USAGE0_CPU_READ | AHARDWAREBUFFER_USAGE0_CPU_WRITE,
            0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_CPU_WRITE_OFTEN, 0,
            AHARDWAREBUFFER_USAGE0_CPU_WRITE_OFTEN, 0));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_GPU_RENDER_TARGET,
            GRALLOC1_CONSUMER_USAGE_GPU_TEXTURE |
                    GRALLOC1_CONSUMER_USAGE_PRIVATE_17,
            AHARDWAREBUFFER_USAGE0_GPU_COLOR_OUTPUT |
                    AHARDWAREBUFFER_USAGE0_GPU_SAMPLED_IMAGE,
            AHARDWAREBUFFER_USAGE1_CONSUMER_PRIVATE_17));
    EXPECT_TRUE(TestUsageConversion(GRALLOC1_PRODUCER_USAGE_SENSOR_DIRECT_DATA,
            GRALLOC1_CONSUMER_USAGE_GPU_DATA_BUFFER,
            AHARDWAREBUFFER_USAGE0_GPU_DATA_BUFFER |
                    AHARDWAREBUFFER_USAGE0_SENSOR_DIRECT_DATA, 0));
}
