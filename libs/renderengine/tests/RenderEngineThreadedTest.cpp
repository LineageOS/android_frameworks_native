/*
 * Copyright 2020 The Android Open Source Project
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

#include <cutils/properties.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <renderengine/mock/RenderEngine.h>
#include "../threaded/RenderEngineThreaded.h"

namespace android {

using testing::_;
using testing::Eq;
using testing::Mock;
using testing::Return;

struct RenderEngineThreadedTest : public ::testing::Test {
    RenderEngineThreadedTest() {
        sThreadedRE->setRenderEngine(std::unique_ptr<renderengine::RenderEngine>(mRenderEngine));
    }

    ~RenderEngineThreadedTest() {}

    static void SetUpTestSuite() {
        sThreadedRE = renderengine::threaded::RenderEngineThreaded::create(
                renderengine::RenderEngineCreationArgs::Builder()
                        .setRenderEngineType(renderengine::RenderEngine::RenderEngineType::THREADED)
                        .build());
    }

    static void TearDownTestSuite() { sThreadedRE = nullptr; }

    // To avoid creating RE on every instantiation of the test, it is kept as a static variable.
    static std::unique_ptr<renderengine::threaded::RenderEngineThreaded> sThreadedRE;
    renderengine::mock::RenderEngine* mRenderEngine = new renderengine::mock::RenderEngine();
};

std::unique_ptr<renderengine::threaded::RenderEngineThreaded>
        RenderEngineThreadedTest::sThreadedRE = nullptr;

TEST_F(RenderEngineThreadedTest, dump) {
    std::string testString = "XYZ";
    EXPECT_CALL(*mRenderEngine, dump(_));
    sThreadedRE->dump(testString);
}

TEST_F(RenderEngineThreadedTest, primeCache) {
    EXPECT_CALL(*mRenderEngine, primeCache());
    sThreadedRE->primeCache();
}

TEST_F(RenderEngineThreadedTest, genTextures) {
    uint32_t texName;
    EXPECT_CALL(*mRenderEngine, genTextures(1, &texName));
    sThreadedRE->genTextures(1, &texName);
}

TEST_F(RenderEngineThreadedTest, deleteTextures) {
    uint32_t texName;
    EXPECT_CALL(*mRenderEngine, deleteTextures(1, &texName));
    sThreadedRE->deleteTextures(1, &texName);
}

TEST_F(RenderEngineThreadedTest, bindExternalBuffer_nullptrBuffer) {
    EXPECT_CALL(*mRenderEngine, bindExternalTextureBuffer(0, Eq(nullptr), Eq(nullptr)))
            .WillOnce(Return(BAD_VALUE));
    status_t result = sThreadedRE->bindExternalTextureBuffer(0, nullptr, nullptr);
    ASSERT_EQ(BAD_VALUE, result);
}

TEST_F(RenderEngineThreadedTest, bindExternalBuffer_withBuffer) {
    sp<GraphicBuffer> buf = new GraphicBuffer();
    EXPECT_CALL(*mRenderEngine, bindExternalTextureBuffer(0, buf, Eq(nullptr)))
            .WillOnce(Return(NO_ERROR));
    status_t result = sThreadedRE->bindExternalTextureBuffer(0, buf, nullptr);
    ASSERT_EQ(NO_ERROR, result);
}

TEST_F(RenderEngineThreadedTest, cacheExternalTextureBuffer_nullptr) {
    EXPECT_CALL(*mRenderEngine, cacheExternalTextureBuffer(Eq(nullptr)));
    sThreadedRE->cacheExternalTextureBuffer(nullptr);
}

TEST_F(RenderEngineThreadedTest, cacheExternalTextureBuffer_withBuffer) {
    sp<GraphicBuffer> buf = new GraphicBuffer();
    EXPECT_CALL(*mRenderEngine, cacheExternalTextureBuffer(buf));
    sThreadedRE->cacheExternalTextureBuffer(buf);
}

TEST_F(RenderEngineThreadedTest, unbindExternalTextureBuffer) {
    EXPECT_CALL(*mRenderEngine, unbindExternalTextureBuffer(0x0));
    sThreadedRE->unbindExternalTextureBuffer(0x0);
}

TEST_F(RenderEngineThreadedTest, bindFrameBuffer_returnsBadValue) {
    std::unique_ptr<renderengine::Framebuffer> framebuffer;
    EXPECT_CALL(*mRenderEngine, bindFrameBuffer(framebuffer.get())).WillOnce(Return(BAD_VALUE));
    status_t result = sThreadedRE->bindFrameBuffer(framebuffer.get());
    ASSERT_EQ(BAD_VALUE, result);
}

TEST_F(RenderEngineThreadedTest, bindFrameBuffer_returnsNoError) {
    std::unique_ptr<renderengine::Framebuffer> framebuffer;
    EXPECT_CALL(*mRenderEngine, bindFrameBuffer(framebuffer.get())).WillOnce(Return(NO_ERROR));
    status_t result = sThreadedRE->bindFrameBuffer(framebuffer.get());
    ASSERT_EQ(NO_ERROR, result);
}

TEST_F(RenderEngineThreadedTest, unbindFrameBuffer) {
    std::unique_ptr<renderengine::Framebuffer> framebuffer;
    EXPECT_CALL(*mRenderEngine, unbindFrameBuffer(framebuffer.get()));
    sThreadedRE->unbindFrameBuffer(framebuffer.get());
}

TEST_F(RenderEngineThreadedTest, getMaxTextureSize_returns20) {
    size_t size = 20;
    EXPECT_CALL(*mRenderEngine, getMaxTextureSize()).WillOnce(Return(size));
    size_t result = sThreadedRE->getMaxTextureSize();
    ASSERT_EQ(size, result);
}

TEST_F(RenderEngineThreadedTest, getMaxTextureSize_returns0) {
    size_t size = 0;
    EXPECT_CALL(*mRenderEngine, getMaxTextureSize()).WillOnce(Return(size));
    size_t result = sThreadedRE->getMaxTextureSize();
    ASSERT_EQ(size, result);
}

TEST_F(RenderEngineThreadedTest, getMaxViewportDims_returns20) {
    size_t dims = 20;
    EXPECT_CALL(*mRenderEngine, getMaxViewportDims()).WillOnce(Return(dims));
    size_t result = sThreadedRE->getMaxViewportDims();
    ASSERT_EQ(dims, result);
}

TEST_F(RenderEngineThreadedTest, getMaxViewportDims_returns0) {
    size_t dims = 0;
    EXPECT_CALL(*mRenderEngine, getMaxViewportDims()).WillOnce(Return(dims));
    size_t result = sThreadedRE->getMaxViewportDims();
    ASSERT_EQ(dims, result);
}

TEST_F(RenderEngineThreadedTest, isProtected_returnsFalse) {
    EXPECT_CALL(*mRenderEngine, isProtected()).WillOnce(Return(false));
    status_t result = sThreadedRE->isProtected();
    ASSERT_EQ(false, result);
}

TEST_F(RenderEngineThreadedTest, isProtected_returnsTrue) {
    EXPECT_CALL(*mRenderEngine, isProtected()).WillOnce(Return(true));
    size_t result = sThreadedRE->isProtected();
    ASSERT_EQ(true, result);
}

TEST_F(RenderEngineThreadedTest, supportsProtectedContent_returnsFalse) {
    EXPECT_CALL(*mRenderEngine, supportsProtectedContent()).WillOnce(Return(false));
    status_t result = sThreadedRE->supportsProtectedContent();
    ASSERT_EQ(false, result);
}

TEST_F(RenderEngineThreadedTest, supportsProtectedContent_returnsTrue) {
    EXPECT_CALL(*mRenderEngine, supportsProtectedContent()).WillOnce(Return(true));
    status_t result = sThreadedRE->supportsProtectedContent();
    ASSERT_EQ(true, result);
}

TEST_F(RenderEngineThreadedTest, useProtectedContext_returnsFalse) {
    EXPECT_CALL(*mRenderEngine, useProtectedContext(false)).WillOnce(Return(false));
    status_t result = sThreadedRE->useProtectedContext(false);
    ASSERT_EQ(false, result);
}

TEST_F(RenderEngineThreadedTest, useProtectedContext_returnsTrue) {
    EXPECT_CALL(*mRenderEngine, useProtectedContext(false)).WillOnce(Return(true));
    status_t result = sThreadedRE->useProtectedContext(false);
    ASSERT_EQ(true, result);
}

TEST_F(RenderEngineThreadedTest, cleanupPostRender_returnsFalse) {
    EXPECT_CALL(*mRenderEngine, cleanupPostRender()).WillOnce(Return(false));
    status_t result = sThreadedRE->cleanupPostRender();
    ASSERT_EQ(false, result);
}

TEST_F(RenderEngineThreadedTest, cleanupPostRender_returnsTrue) {
    EXPECT_CALL(*mRenderEngine, cleanupPostRender()).WillOnce(Return(true));
    status_t result = sThreadedRE->cleanupPostRender();
    ASSERT_EQ(true, result);
}

TEST_F(RenderEngineThreadedTest, drawLayers) {
    renderengine::DisplaySettings settings;
    std::vector<const renderengine::LayerSettings*> layers;
    sp<GraphicBuffer> buffer = new GraphicBuffer();
    base::unique_fd bufferFence;
    base::unique_fd drawFence;

    EXPECT_CALL(*mRenderEngine, drawLayers)
            .WillOnce([](const renderengine::DisplaySettings&,
                         const std::vector<const renderengine::LayerSettings*>&,
                         const sp<GraphicBuffer>&, const bool, base::unique_fd&&,
                         base::unique_fd*) -> status_t { return NO_ERROR; });

    status_t result = sThreadedRE->drawLayers(settings, layers, buffer, false,
                                              std::move(bufferFence), &drawFence);
    ASSERT_EQ(NO_ERROR, result);
}

} // namespace android
