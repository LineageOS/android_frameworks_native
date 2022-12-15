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

#include <compositionengine/impl/HwcBufferCache.h>
#include <gtest/gtest.h>
#include <gui/BufferQueue.h>
#include <ui/GraphicBuffer.h>

namespace android::compositionengine {
namespace {

using impl::HwcBufferCache;
using impl::HwcSlotAndBuffer;

class HwcBufferCacheTest : public testing::Test {
public:
    ~HwcBufferCacheTest() override = default;

    sp<GraphicBuffer> mBuffer1 =
            sp<GraphicBuffer>::make(1u, 1u, HAL_PIXEL_FORMAT_RGBA_8888, 1u, 0u);
    sp<GraphicBuffer> mBuffer2 =
            sp<GraphicBuffer>::make(1u, 1u, HAL_PIXEL_FORMAT_RGBA_8888, 1u, 0u);
};

TEST_F(HwcBufferCacheTest, getHwcSlotAndBuffer_returnsUniqueSlotNumberForEachBuffer) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    HwcSlotAndBuffer slotAndBufferFor1 = cache.getHwcSlotAndBuffer(mBuffer1);
    EXPECT_NE(slotAndBufferFor1.slot, UINT32_MAX);
    EXPECT_EQ(slotAndBufferFor1.buffer, mBuffer1);

    HwcSlotAndBuffer slotAndBufferFor2 = cache.getHwcSlotAndBuffer(mBuffer2);
    EXPECT_NE(slotAndBufferFor2.slot, slotAndBufferFor1.slot);
    EXPECT_NE(slotAndBufferFor2.slot, UINT32_MAX);
    EXPECT_EQ(slotAndBufferFor2.buffer, mBuffer2);
}

TEST_F(HwcBufferCacheTest, getHwcSlotAndBuffer_whenCached_returnsSameSlotNumberAndNullBuffer) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    HwcSlotAndBuffer originalSlotAndBuffer = cache.getHwcSlotAndBuffer(mBuffer1);
    EXPECT_NE(originalSlotAndBuffer.slot, UINT32_MAX);
    EXPECT_EQ(originalSlotAndBuffer.buffer, mBuffer1);

    HwcSlotAndBuffer finalSlotAndBuffer = cache.getHwcSlotAndBuffer(mBuffer1);
    EXPECT_EQ(finalSlotAndBuffer.slot, originalSlotAndBuffer.slot);
    EXPECT_EQ(finalSlotAndBuffer.buffer, nullptr);
}

TEST_F(HwcBufferCacheTest, getHwcSlotAndBuffer_whenSlotsFull_evictsOldestCachedBuffer) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    sp<GraphicBuffer> graphicBuffers[100];
    HwcSlotAndBuffer slotsAndBuffers[100];
    int finalCachedBufferIndex = 0;
    for (int i = 0; i < 100; ++i) {
        graphicBuffers[i] = sp<GraphicBuffer>::make(1u, 1u, HAL_PIXEL_FORMAT_RGBA_8888, 1u, 0u);
        slotsAndBuffers[i] = cache.getHwcSlotAndBuffer(graphicBuffers[i]);
        // we fill up the cache when the slot number for the first buffer is reused
        if (i > 0 && slotsAndBuffers[i].slot == slotsAndBuffers[0].slot) {
            finalCachedBufferIndex = i;
            break;
        }
    }
    ASSERT_GT(finalCachedBufferIndex, 1);
    // the final cached buffer has the same slot value as the oldest buffer
    EXPECT_EQ(slotsAndBuffers[finalCachedBufferIndex].slot, slotsAndBuffers[0].slot);
    // the oldest buffer is no longer in the cache because it was evicted
    EXPECT_EQ(cache.uncache(graphicBuffers[0]->getId()), UINT32_MAX);
}

TEST_F(HwcBufferCacheTest, uncache_whenCached_returnsSlotNumber) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    HwcSlotAndBuffer slotAndBufferFor1 = cache.getHwcSlotAndBuffer(mBuffer1);
    ASSERT_NE(slotAndBufferFor1.slot, UINT32_MAX);

    HwcSlotAndBuffer slotAndBufferFor2 = cache.getHwcSlotAndBuffer(mBuffer2);
    ASSERT_NE(slotAndBufferFor2.slot, UINT32_MAX);

    // the 1st buffer should be found in the cache with a slot number
    EXPECT_EQ(cache.uncache(mBuffer1->getId()), slotAndBufferFor1.slot);
    // since the 1st buffer has been previously uncached, we should no longer receive a slot number
    EXPECT_EQ(cache.uncache(mBuffer1->getId()), UINT32_MAX);
    // the 2nd buffer should be still found in the cache with a slot number
    EXPECT_EQ(cache.uncache(mBuffer2->getId()), slotAndBufferFor2.slot);
    // since the 2nd buffer has been previously uncached, we should no longer receive a slot number
    EXPECT_EQ(cache.uncache(mBuffer2->getId()), UINT32_MAX);
}

TEST_F(HwcBufferCacheTest, uncache_whenUncached_returnsInvalidSlotNumber) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    HwcSlotAndBuffer slotAndBufferFor1 = cache.getHwcSlotAndBuffer(mBuffer1);
    ASSERT_NE(slotAndBufferFor1.slot, UINT32_MAX);

    EXPECT_EQ(cache.uncache(mBuffer2->getId()), UINT32_MAX);
}

TEST_F(HwcBufferCacheTest, getOverrideHwcSlotAndBuffer_whenCached_returnsSameSlotAndNullBuffer) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    HwcSlotAndBuffer originalSlotAndBuffer = cache.getOverrideHwcSlotAndBuffer(mBuffer1);
    EXPECT_NE(originalSlotAndBuffer.slot, UINT32_MAX);
    EXPECT_EQ(originalSlotAndBuffer.buffer, mBuffer1);

    HwcSlotAndBuffer finalSlotAndBuffer = cache.getOverrideHwcSlotAndBuffer(mBuffer1);
    EXPECT_EQ(finalSlotAndBuffer.slot, originalSlotAndBuffer.slot);
    EXPECT_EQ(finalSlotAndBuffer.buffer, nullptr);
}

TEST_F(HwcBufferCacheTest, getOverrideHwcSlotAndBuffer_whenSlotsFull_returnsIndependentSlot) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    sp<GraphicBuffer> graphicBuffers[100];
    HwcSlotAndBuffer slotsAndBuffers[100];
    int finalCachedBufferIndex = -1;
    for (int i = 0; i < 100; ++i) {
        graphicBuffers[i] = sp<GraphicBuffer>::make(1u, 1u, HAL_PIXEL_FORMAT_RGBA_8888, 1u, 0u);
        slotsAndBuffers[i] = cache.getHwcSlotAndBuffer(graphicBuffers[i]);
        // we fill up the cache when the slot number for the first buffer is reused
        if (i > 0 && slotsAndBuffers[i].slot == slotsAndBuffers[0].slot) {
            finalCachedBufferIndex = i;
            break;
        }
    }
    // expect to have cached at least a few buffers before evicting
    ASSERT_GT(finalCachedBufferIndex, 1);

    sp<GraphicBuffer> overrideBuffer =
            sp<GraphicBuffer>::make(1u, 1u, HAL_PIXEL_FORMAT_RGBA_8888, 1u, 0u);
    HwcSlotAndBuffer overrideSlotAndBuffer = cache.getOverrideHwcSlotAndBuffer(overrideBuffer);
    // expect us to have a slot number
    EXPECT_NE(overrideSlotAndBuffer.slot, UINT32_MAX);
    // expect this to be the first time we cached the buffer
    EXPECT_NE(overrideSlotAndBuffer.buffer, nullptr);

    // expect the slot number to not equal any other slot number, even after the slots have been
    // exhausted, indicating that the override buffer slot is independent from the slots for
    // non-override buffers
    for (int i = 0; i < finalCachedBufferIndex; ++i) {
        EXPECT_NE(overrideSlotAndBuffer.slot, slotsAndBuffers[i].slot);
    }
    // the override buffer is independently uncached from the oldest cached buffer
    // expect to find the override buffer still in the override buffer slot
    EXPECT_EQ(cache.uncache(overrideBuffer->getId()), overrideSlotAndBuffer.slot);
    // expect that the first buffer was not evicted from the cache when the override buffer was
    // cached
    EXPECT_EQ(cache.uncache(graphicBuffers[1]->getId()), slotsAndBuffers[1].slot);
}

TEST_F(HwcBufferCacheTest, uncache_whenOverrideCached_returnsSlotNumber) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    HwcSlotAndBuffer hwcSlotAndBuffer = cache.getOverrideHwcSlotAndBuffer(mBuffer1);
    ASSERT_NE(hwcSlotAndBuffer.slot, UINT32_MAX);

    EXPECT_EQ(cache.uncache(mBuffer1->getId()), hwcSlotAndBuffer.slot);
    EXPECT_EQ(cache.uncache(mBuffer1->getId()), UINT32_MAX);
}

TEST_F(HwcBufferCacheTest, uncache_whenOverrideUncached_returnsInvalidSlotNumber) {
    HwcBufferCache cache;
    sp<GraphicBuffer> outBuffer;

    HwcSlotAndBuffer hwcSlotAndBuffer = cache.getOverrideHwcSlotAndBuffer(mBuffer1);
    ASSERT_NE(hwcSlotAndBuffer.slot, UINT32_MAX);

    EXPECT_EQ(cache.uncache(mBuffer2->getId()), UINT32_MAX);
}

} // namespace
} // namespace android::compositionengine
