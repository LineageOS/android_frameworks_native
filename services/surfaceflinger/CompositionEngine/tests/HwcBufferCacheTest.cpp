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

class TestableHwcBufferCache : public impl::HwcBufferCache {
public:
    void getHwcBuffer(const sp<GraphicBuffer>& buffer, uint32_t* outSlot,
                      sp<GraphicBuffer>* outBuffer) {
        HwcBufferCache::getHwcBuffer(buffer, outSlot, outBuffer);
    }
    bool getSlot(const sp<GraphicBuffer>& buffer, uint32_t* outSlot) {
        return HwcBufferCache::getSlot(buffer, outSlot);
    }
    uint32_t getLeastRecentlyUsedSlot() { return HwcBufferCache::getLeastRecentlyUsedSlot(); }
};

class HwcBufferCacheTest : public testing::Test {
public:
    ~HwcBufferCacheTest() override = default;

    TestableHwcBufferCache mCache;
    sp<GraphicBuffer> mBuffer1{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
    sp<GraphicBuffer> mBuffer2{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
};

TEST_F(HwcBufferCacheTest, testSlot) {
    uint32_t outSlot;
    sp<GraphicBuffer> outBuffer;

    // The first time, the output  is the same as the input
    mCache.getHwcBuffer(mBuffer1, &outSlot, &outBuffer);
    EXPECT_EQ(0, outSlot);
    EXPECT_EQ(mBuffer1, outBuffer);

    // The second time with the same buffer, the outBuffer is nullptr.
    mCache.getHwcBuffer(mBuffer1, &outSlot, &outBuffer);
    EXPECT_EQ(0, outSlot);
    EXPECT_EQ(nullptr, outBuffer.get());

    // With a new buffer, the outBuffer is the input.
    mCache.getHwcBuffer(mBuffer2, &outSlot, &outBuffer);
    EXPECT_EQ(1, outSlot);
    EXPECT_EQ(mBuffer2, outBuffer);

    // Again, the second request with the same buffer sets outBuffer to nullptr.
    mCache.getHwcBuffer(mBuffer2, &outSlot, &outBuffer);
    EXPECT_EQ(1, outSlot);
    EXPECT_EQ(nullptr, outBuffer.get());

    // Setting a slot to use nullptr lookslike works, but note that
    // the output values make it look like no new buffer is being set....
    mCache.getHwcBuffer(sp<GraphicBuffer>(), &outSlot, &outBuffer);
    EXPECT_EQ(2, outSlot);
    EXPECT_EQ(nullptr, outBuffer.get());
}

TEST_F(HwcBufferCacheTest, testGetLeastRecentlyUsedSlot) {
    int slot;
    uint32_t outSlot;
    sp<GraphicBuffer> outBuffer;

    // fill up cache
    for (int i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
        sp<GraphicBuffer> buf{new GraphicBuffer(1, 1, HAL_PIXEL_FORMAT_RGBA_8888, 1, 0)};
        mCache.getHwcBuffer(buf, &outSlot, &outBuffer);
        EXPECT_EQ(buf, outBuffer);
        EXPECT_EQ(i, outSlot);
    }

    slot = mCache.getLeastRecentlyUsedSlot();
    EXPECT_EQ(0, slot);

    mCache.getHwcBuffer(mBuffer1, &outSlot, &outBuffer);
    EXPECT_EQ(0, outSlot);
    EXPECT_EQ(mBuffer1, outBuffer);

    slot = mCache.getLeastRecentlyUsedSlot();
    EXPECT_EQ(1, slot);
}

} // namespace
} // namespace android::compositionengine
