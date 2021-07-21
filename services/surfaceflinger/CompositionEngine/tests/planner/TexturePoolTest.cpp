/*
 * Copyright 2021 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "TexturePoolTest"

#include <compositionengine/impl/planner/TexturePool.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <renderengine/mock/RenderEngine.h>

namespace android::compositionengine::impl::planner {
namespace {

const ui::Size kDisplaySize(1, 1);
const ui::Size kDisplaySizeTwo(2, 2);

class TestableTexturePool : public TexturePool {
public:
    TestableTexturePool(renderengine::RenderEngine& renderEngine) : TexturePool(renderEngine) {}

    size_t getMinPoolSize() const { return kMinPoolSize; }
    size_t getMaxPoolSize() const { return kMaxPoolSize; }
    size_t getPoolSize() const { return mPool.size(); }
};

struct TexturePoolTest : public testing::Test {
    TexturePoolTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        mTexturePool.setEnabled(true);
        mTexturePool.setDisplaySize(kDisplaySize);
    }

    ~TexturePoolTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    renderengine::mock::RenderEngine mRenderEngine;
    TestableTexturePool mTexturePool = TestableTexturePool(mRenderEngine);
};

TEST_F(TexturePoolTest, preallocatesMinPool) {
    EXPECT_EQ(mTexturePool.getMinPoolSize(), mTexturePool.getPoolSize());
}

TEST_F(TexturePoolTest, doesNotAllocateBeyondMinPool) {
    for (size_t i = 0; i < mTexturePool.getMinPoolSize() + 1; i++) {
        auto texture = mTexturePool.borrowTexture();
    }

    EXPECT_EQ(mTexturePool.getMinPoolSize(), mTexturePool.getPoolSize());
}

TEST_F(TexturePoolTest, cyclesUpToMaxPoolSize) {
    std::unordered_set<uint64_t> bufferIds;
    std::deque<std::shared_ptr<TexturePool::AutoTexture>> textures;
    for (size_t i = 0; i < mTexturePool.getMaxPoolSize(); i++) {
        textures.emplace_back(mTexturePool.borrowTexture());
        bufferIds.insert(textures.back()->get()->getBuffer()->getId());
    }

    EXPECT_EQ(mTexturePool.getMaxPoolSize(), bufferIds.size());

    for (size_t i = 0; i < 3; i++) {
        textures.pop_front();
        textures.emplace_back(mTexturePool.borrowTexture());
        bufferIds.insert(textures.back()->get()->getBuffer()->getId());
    }

    EXPECT_EQ(mTexturePool.getMaxPoolSize(), bufferIds.size());
}

TEST_F(TexturePoolTest, goesPastMaxSizeAndRebounds) {
    std::unordered_set<uint64_t> bufferIds;
    std::vector<std::shared_ptr<TexturePool::AutoTexture>> textures;
    for (size_t i = 0; i < mTexturePool.getMaxPoolSize() + 2; i++) {
        textures.emplace_back(mTexturePool.borrowTexture());
        bufferIds.insert(textures.back()->get()->getBuffer()->getId());
    }

    EXPECT_EQ(mTexturePool.getMaxPoolSize() + 2, bufferIds.size());

    // Return the textures to the pool.
    // Now when we cycle through the pool it's again bounded by max textures.
    textures.clear();

    std::unordered_set<uint64_t> newBufferIds;
    for (size_t i = 0; i < 2 * mTexturePool.getMaxPoolSize(); i++) {
        auto texture = mTexturePool.borrowTexture();
        newBufferIds.insert(texture->get()->getBuffer()->getId());
    }

    EXPECT_EQ(mTexturePool.getMaxPoolSize(), newBufferIds.size());
}

TEST_F(TexturePoolTest, reallocatesWhenDisplaySizeChanges) {
    auto texture = mTexturePool.borrowTexture();

    EXPECT_EQ(kDisplaySize.getWidth(),
              static_cast<int32_t>(texture->get()->getBuffer()->getWidth()));
    EXPECT_EQ(kDisplaySize.getHeight(),
              static_cast<int32_t>(texture->get()->getBuffer()->getHeight()));
    mTexturePool.setDisplaySize(kDisplaySizeTwo);

    EXPECT_EQ(mTexturePool.getMinPoolSize(), mTexturePool.getPoolSize());
    texture.reset();
    // When the texture is returned to the pool, the pool now destroys it.
    EXPECT_EQ(mTexturePool.getMinPoolSize(), mTexturePool.getPoolSize());

    texture = mTexturePool.borrowTexture();
    EXPECT_EQ(kDisplaySizeTwo.getWidth(),
              static_cast<int32_t>(texture->get()->getBuffer()->getWidth()));
    EXPECT_EQ(kDisplaySizeTwo.getHeight(),
              static_cast<int32_t>(texture->get()->getBuffer()->getHeight()));
}

TEST_F(TexturePoolTest, freesBuffersWhenDisabled) {
    EXPECT_EQ(mTexturePool.getPoolSize(), mTexturePool.getMinPoolSize());

    std::deque<std::shared_ptr<TexturePool::AutoTexture>> textures;
    for (size_t i = 0; i < mTexturePool.getMinPoolSize() - 1; i++) {
        textures.emplace_back(mTexturePool.borrowTexture());
    }

    EXPECT_EQ(mTexturePool.getPoolSize(), 1u);
    mTexturePool.setEnabled(false);
    EXPECT_EQ(mTexturePool.getPoolSize(), 0u);

    textures.clear();
    EXPECT_EQ(mTexturePool.getPoolSize(), 0u);
}

TEST_F(TexturePoolTest, doesNotHoldBuffersWhenDisabled) {
    EXPECT_EQ(mTexturePool.getPoolSize(), mTexturePool.getMinPoolSize());
    mTexturePool.setEnabled(false);
    EXPECT_EQ(mTexturePool.getPoolSize(), 0u);

    std::deque<std::shared_ptr<TexturePool::AutoTexture>> textures;
    for (size_t i = 0; i < mTexturePool.getMinPoolSize() - 1; i++) {
        textures.emplace_back(mTexturePool.borrowTexture());
    }

    EXPECT_EQ(mTexturePool.getPoolSize(), 0u);
    textures.clear();
    EXPECT_EQ(mTexturePool.getPoolSize(), 0u);
}

TEST_F(TexturePoolTest, reallocatesWhenReEnabled) {
    EXPECT_EQ(mTexturePool.getPoolSize(), mTexturePool.getMinPoolSize());
    mTexturePool.setEnabled(false);
    EXPECT_EQ(mTexturePool.getPoolSize(), 0u);
    mTexturePool.setEnabled(true);
    EXPECT_EQ(mTexturePool.getPoolSize(), mTexturePool.getMinPoolSize());
}

} // namespace
} // namespace android::compositionengine::impl::planner
