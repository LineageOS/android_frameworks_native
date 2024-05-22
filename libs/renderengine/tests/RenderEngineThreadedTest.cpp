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
#include <hardware/gralloc.h>
#include <renderengine/impl/ExternalTexture.h>
#include <renderengine/mock/RenderEngine.h>
#include <ui/PixelFormat.h>
#include "../threaded/RenderEngineThreaded.h"

namespace android {

using renderengine::PrimeCacheConfig;
using testing::_;
using testing::Eq;
using testing::Mock;
using testing::Return;

struct RenderEngineThreadedTest : public ::testing::Test {
    ~RenderEngineThreadedTest() {}

    void SetUp() override {
        mThreadedRE = renderengine::threaded::RenderEngineThreaded::create(
                [this]() { return std::unique_ptr<renderengine::RenderEngine>(mRenderEngine); });
    }

    std::unique_ptr<renderengine::threaded::RenderEngineThreaded> mThreadedRE;
    renderengine::mock::RenderEngine* mRenderEngine = new renderengine::mock::RenderEngine();
};

TEST_F(RenderEngineThreadedTest, dump) {
    std::string testString = "XYZ";
    EXPECT_CALL(*mRenderEngine, dump(_));
    mThreadedRE->dump(testString);
}

MATCHER_P(EqConfig, other, "Equality for prime cache config") {
    return arg.cacheHolePunchLayer == other.cacheHolePunchLayer &&
            arg.cacheSolidLayers == other.cacheSolidLayers &&
            arg.cacheSolidDimmedLayers == other.cacheSolidDimmedLayers &&
            arg.cacheImageLayers == other.cacheImageLayers &&
            arg.cacheImageDimmedLayers == other.cacheImageDimmedLayers &&
            arg.cacheClippedLayers == other.cacheClippedLayers &&
            arg.cacheShadowLayers == other.cacheShadowLayers &&
            arg.cachePIPImageLayers == other.cachePIPImageLayers &&
            arg.cacheTransparentImageDimmedLayers == other.cacheTransparentImageDimmedLayers &&
            arg.cacheClippedDimmedImageLayers == other.cacheClippedDimmedImageLayers &&
            arg.cacheUltraHDR == other.cacheUltraHDR;
}

TEST_F(RenderEngineThreadedTest, primeCache) {
    PrimeCacheConfig config;
    config.cacheUltraHDR = false;
    EXPECT_CALL(*mRenderEngine, primeCache(EqConfig(config)));
    mThreadedRE->primeCache(config);
    // need to call ANY synchronous function after primeCache to ensure that primeCache has
    // completed asynchronously before the test completes execution.
    mThreadedRE->getContextPriority();
}

TEST_F(RenderEngineThreadedTest, getMaxTextureSize_returns20) {
    size_t size = 20;
    EXPECT_CALL(*mRenderEngine, getMaxTextureSize()).WillOnce(Return(size));
    size_t result = mThreadedRE->getMaxTextureSize();
    ASSERT_EQ(size, result);
}

TEST_F(RenderEngineThreadedTest, getMaxTextureSize_returns0) {
    size_t size = 0;
    EXPECT_CALL(*mRenderEngine, getMaxTextureSize()).WillOnce(Return(size));
    size_t result = mThreadedRE->getMaxTextureSize();
    ASSERT_EQ(size, result);
}

TEST_F(RenderEngineThreadedTest, getMaxViewportDims_returns20) {
    size_t dims = 20;
    EXPECT_CALL(*mRenderEngine, getMaxViewportDims()).WillOnce(Return(dims));
    size_t result = mThreadedRE->getMaxViewportDims();
    ASSERT_EQ(dims, result);
}

TEST_F(RenderEngineThreadedTest, getMaxViewportDims_returns0) {
    size_t dims = 0;
    EXPECT_CALL(*mRenderEngine, getMaxViewportDims()).WillOnce(Return(dims));
    size_t result = mThreadedRE->getMaxViewportDims();
    ASSERT_EQ(dims, result);
}

TEST_F(RenderEngineThreadedTest, supportsProtectedContent_returnsFalse) {
    EXPECT_CALL(*mRenderEngine, supportsProtectedContent()).WillOnce(Return(false));
    status_t result = mThreadedRE->supportsProtectedContent();
    ASSERT_EQ(false, result);
}

TEST_F(RenderEngineThreadedTest, supportsProtectedContent_returnsTrue) {
    EXPECT_CALL(*mRenderEngine, supportsProtectedContent()).WillOnce(Return(true));
    status_t result = mThreadedRE->supportsProtectedContent();
    ASSERT_EQ(true, result);
}

TEST_F(RenderEngineThreadedTest, PostRenderCleanup_skipped) {
    EXPECT_CALL(*mRenderEngine, cleanupPostRender()).Times(0);
    mThreadedRE->cleanupPostRender();

    // call ANY synchronous function to ensure that cleanupPostRender has completed.
    mThreadedRE->getContextPriority();
}

TEST_F(RenderEngineThreadedTest, PostRenderCleanup_notSkipped) {
    renderengine::DisplaySettings settings;
    std::vector<renderengine::LayerSettings> layers;
    std::shared_ptr<renderengine::ExternalTexture> buffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), *mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    base::unique_fd bufferFence;

    EXPECT_CALL(*mRenderEngine, useProtectedContext(false));
    EXPECT_CALL(*mRenderEngine, drawLayersInternal)
        .WillOnce([&](const std::shared_ptr<std::promise<FenceResult>>&& resultPromise,
                          const renderengine::DisplaySettings&,
                          const std::vector<renderengine::LayerSettings>&,
                          const std::shared_ptr<renderengine::ExternalTexture>&,
                          base::unique_fd&&) { resultPromise->set_value(Fence::NO_FENCE); });
    EXPECT_CALL(*mRenderEngine, cleanupPostRender()).WillOnce(Return());
    ftl::Future<FenceResult> future =
            mThreadedRE->drawLayers(settings, layers, buffer, std::move(bufferFence));
    mThreadedRE->cleanupPostRender();

    // call ANY synchronous function to ensure that cleanupPostRender has completed.
    mThreadedRE->getContextPriority();
}

TEST_F(RenderEngineThreadedTest, supportsBackgroundBlur_returnsFalse) {
    EXPECT_CALL(*mRenderEngine, supportsBackgroundBlur()).WillOnce(Return(false));
    status_t result = mThreadedRE->supportsBackgroundBlur();
    ASSERT_EQ(false, result);
}

TEST_F(RenderEngineThreadedTest, supportsBackgroundBlur_returnsTrue) {
    EXPECT_CALL(*mRenderEngine, supportsBackgroundBlur()).WillOnce(Return(true));
    status_t result = mThreadedRE->supportsBackgroundBlur();
    ASSERT_EQ(true, result);
}

TEST_F(RenderEngineThreadedTest, drawLayers) {
    renderengine::DisplaySettings settings;
    std::vector<renderengine::LayerSettings> layers;
    std::shared_ptr<renderengine::ExternalTexture> buffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), *mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);

    base::unique_fd bufferFence;

    EXPECT_CALL(*mRenderEngine, useProtectedContext(false));
    EXPECT_CALL(*mRenderEngine, drawLayersInternal)
            .WillOnce([&](const std::shared_ptr<std::promise<FenceResult>>&& resultPromise,
                          const renderengine::DisplaySettings&,
                          const std::vector<renderengine::LayerSettings>&,
                          const std::shared_ptr<renderengine::ExternalTexture>&,
                          base::unique_fd&&) { resultPromise->set_value(Fence::NO_FENCE); });

    ftl::Future<FenceResult> future =
            mThreadedRE->drawLayers(settings, layers, buffer, std::move(bufferFence));
    ASSERT_TRUE(future.valid());
    auto result = future.get();
    ASSERT_TRUE(result.ok());
}

TEST_F(RenderEngineThreadedTest, drawLayers_protectedLayer) {
    renderengine::DisplaySettings settings;
    auto layerBuffer = sp<GraphicBuffer>::make();
    layerBuffer->usage |= GRALLOC_USAGE_PROTECTED;
    renderengine::LayerSettings layer;
    layer.source.buffer.buffer = std::make_shared<
            renderengine::impl::ExternalTexture>(std::move(layerBuffer), *mRenderEngine,
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         READABLE);
    std::vector<renderengine::LayerSettings> layers = {std::move(layer)};
    std::shared_ptr<renderengine::ExternalTexture> buffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(), *mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);

    base::unique_fd bufferFence;

    EXPECT_CALL(*mRenderEngine, useProtectedContext(true));
    EXPECT_CALL(*mRenderEngine, drawLayersInternal)
            .WillOnce([&](const std::shared_ptr<std::promise<FenceResult>>&& resultPromise,
                          const renderengine::DisplaySettings&,
                          const std::vector<renderengine::LayerSettings>&,
                          const std::shared_ptr<renderengine::ExternalTexture>&,
                          base::unique_fd&&) { resultPromise->set_value(Fence::NO_FENCE); });

    ftl::Future<FenceResult> future =
            mThreadedRE->drawLayers(settings, layers, buffer, std::move(bufferFence));
    ASSERT_TRUE(future.valid());
    auto result = future.get();
    ASSERT_TRUE(result.ok());
}

TEST_F(RenderEngineThreadedTest, drawLayers_protectedOutputBuffer) {
    renderengine::DisplaySettings settings;
    std::vector<renderengine::LayerSettings> layers;
    auto graphicBuffer = sp<GraphicBuffer>::make();
    graphicBuffer->usage |= GRALLOC_USAGE_PROTECTED;
    std::shared_ptr<renderengine::ExternalTexture> buffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(std::move(graphicBuffer), *mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);

    base::unique_fd bufferFence;

    EXPECT_CALL(*mRenderEngine, useProtectedContext(true));
    EXPECT_CALL(*mRenderEngine, drawLayersInternal)
            .WillOnce([&](const std::shared_ptr<std::promise<FenceResult>>&& resultPromise,
                          const renderengine::DisplaySettings&,
                          const std::vector<renderengine::LayerSettings>&,
                          const std::shared_ptr<renderengine::ExternalTexture>&,
                          base::unique_fd&&) { resultPromise->set_value(Fence::NO_FENCE); });

    ftl::Future<FenceResult> future =
            mThreadedRE->drawLayers(settings, layers, buffer, std::move(bufferFence));
    ASSERT_TRUE(future.valid());
    auto result = future.get();
    ASSERT_TRUE(result.ok());
}

} // namespace android
