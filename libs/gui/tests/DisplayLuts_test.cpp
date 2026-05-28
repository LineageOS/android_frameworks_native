/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <android-base/unique_fd.h>
#include <cutils/ashmem.h>
#include <gtest/gtest.h>
#include <gui/DisplayLuts.h>
#include <sys/mman.h>

namespace android {
namespace gui {

class DisplayLutsTest : public ::testing::Test {
protected:
    base::unique_fd createAshmem(size_t size) {
        int fd = ashmem_create_region("DisplayLutsTestAshmem", size);
        EXPECT_GE(fd, 0);
        return base::unique_fd(fd);
    }
};

TEST_F(DisplayLutsTest, EntryElementsNeeded) {
    // 1D LUT
    DisplayLuts::Entry entry1D(1, 16, 0);
    EXPECT_EQ(entry1D.getElementsNeededPerChannel(), 16u);

    // 3D LUT
    DisplayLuts::Entry entry3D(3, 4, 0);
    EXPECT_EQ(entry3D.getElementsNeededPerChannel(), 64u); // 4^3

    // Invalid dimension
    DisplayLuts::Entry entryInvalidDim(2, 16, 0);
    EXPECT_EQ(entryInvalidDim.getElementsNeededPerChannel(), 0u);

    // Invalid size
    DisplayLuts::Entry entryInvalidSize(1, 0, 0);
    EXPECT_EQ(entryInvalidSize.getElementsNeededPerChannel(), 0u);
    DisplayLuts::Entry entryNegativeSize(1, -5, 0);
    EXPECT_EQ(entryNegativeSize.getElementsNeededPerChannel(), 0u);

    // Overflow size 3D
    DisplayLuts::Entry entryOverflowSize(3, 3000000, 0);
    EXPECT_EQ(entryOverflowSize.getElementsNeededPerChannel(), 0u);
}

TEST_F(DisplayLutsTest, ValidDisplayLuts) {
    size_t ashmemSize = 100 * sizeof(float);
    base::unique_fd fd = createAshmem(ashmemSize);

    std::vector<int32_t> offsets = {0, 40};
    std::vector<int32_t> dimensions = {1, 3};
    std::vector<int32_t> sizes = {16, 2}; // 16 elements (1D), 2^3*3 = 24 elements (3D)
    std::vector<int32_t> samplingKeys = {0, 0};

    DisplayLuts luts(std::move(fd), offsets, dimensions, sizes, samplingKeys);
    EXPECT_TRUE(luts.isValid());
    // Max end offset:
    // LUT 0: offset 0, size 16 (1D) -> end 16
    // LUT 1: offset 40, size 2 (3D) -> 2^3 * 3 = 24 elements -> end 40 + 24 = 64
    // Max end offset should be 64.
    EXPECT_EQ(luts.getMaxEndOffset(), 64u);
}

TEST_F(DisplayLutsTest, InvalidAshmemSize) {
    // Size not multiple of float
    base::unique_fd fd = createAshmem(100 * sizeof(float) + 2);

    std::vector<int32_t> offsets = {0};
    std::vector<int32_t> dimensions = {1};
    std::vector<int32_t> sizes = {16};
    std::vector<int32_t> samplingKeys = {0};

    DisplayLuts luts(std::move(fd), offsets, dimensions, sizes, samplingKeys);
    EXPECT_FALSE(luts.isValid());
}

TEST_F(DisplayLutsTest, NegativeOffset) {
    base::unique_fd fd = createAshmem(100 * sizeof(float));

    std::vector<int32_t> offsets = {-10};
    std::vector<int32_t> dimensions = {1};
    std::vector<int32_t> sizes = {16};
    std::vector<int32_t> samplingKeys = {0};

    DisplayLuts luts(std::move(fd), offsets, dimensions, sizes, samplingKeys);
    EXPECT_FALSE(luts.isValid());
    EXPECT_EQ(luts.getMaxEndOffset(), 0u);
}

TEST_F(DisplayLutsTest, OffsetExceedsBounds) {
    base::unique_fd fd = createAshmem(30 * sizeof(float)); // Ashmem fits 30 floats

    std::vector<int32_t> offsets = {20}; // End offset will be 20 + 16 = 36 > 30
    std::vector<int32_t> dimensions = {1};
    std::vector<int32_t> sizes = {16};
    std::vector<int32_t> samplingKeys = {0};

    DisplayLuts luts(std::move(fd), offsets, dimensions, sizes, samplingKeys);
    EXPECT_FALSE(luts.isValid());
    EXPECT_EQ(luts.getMaxEndOffset(), 36u); // Still calculates max end offset
}

TEST_F(DisplayLutsTest, Parceling) {
    size_t ashmemSize = 100 * sizeof(float);
    base::unique_fd fd = createAshmem(ashmemSize);

    std::vector<int32_t> offsets = {0, 40};
    std::vector<int32_t> dimensions = {1, 3};
    std::vector<int32_t> sizes = {16, 2};
    std::vector<int32_t> samplingKeys = {1, 2};

    DisplayLuts luts(std::move(fd), offsets, dimensions, sizes, samplingKeys);
    ASSERT_TRUE(luts.isValid());

    Parcel parcel;
    ASSERT_EQ(luts.writeToParcel(&parcel), OK);

    parcel.setDataPosition(0);

    DisplayLuts deSerializedLuts;
    ASSERT_EQ(deSerializedLuts.readFromParcel(&parcel), OK);

    EXPECT_TRUE(deSerializedLuts.isValid());
    EXPECT_EQ(deSerializedLuts.offsets, luts.offsets);
    EXPECT_EQ(deSerializedLuts.lutProperties.size(), luts.lutProperties.size());
    for (size_t i = 0; i < luts.lutProperties.size(); ++i) {
        EXPECT_EQ(deSerializedLuts.lutProperties[i].dimension, luts.lutProperties[i].dimension);
        EXPECT_EQ(deSerializedLuts.lutProperties[i].size, luts.lutProperties[i].size);
        EXPECT_EQ(deSerializedLuts.lutProperties[i].samplingKey, luts.lutProperties[i].samplingKey);
    }
    EXPECT_EQ(deSerializedLuts.getMaxEndOffset(), luts.getMaxEndOffset());
}

} // namespace gui
} // namespace android
