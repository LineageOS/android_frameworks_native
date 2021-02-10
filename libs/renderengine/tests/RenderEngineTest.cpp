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

#undef LOG_TAG
#define LOG_TAG "RenderEngineTest"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <cutils/properties.h>
#include <gtest/gtest.h>
#include <renderengine/RenderEngine.h>
#include <sync/sync.h>
#include <ui/PixelFormat.h>

#include <chrono>
#include <condition_variable>
#include <fstream>

#include "../gl/GLESRenderEngine.h"
#include "../skia/SkiaGLRenderEngine.h"
#include "../threaded/RenderEngineThreaded.h"

constexpr int DEFAULT_DISPLAY_WIDTH = 128;
constexpr int DEFAULT_DISPLAY_HEIGHT = 256;
constexpr int DEFAULT_DISPLAY_OFFSET = 64;
constexpr bool WRITE_BUFFER_TO_FILE_ON_FAILURE = false;

namespace android {

class RenderEngineFactory {
public:
    virtual ~RenderEngineFactory() = default;

    virtual std::string name() = 0;
    virtual renderengine::RenderEngine::RenderEngineType type() = 0;
    virtual std::unique_ptr<renderengine::RenderEngine> createRenderEngine() = 0;
    virtual std::unique_ptr<renderengine::gl::GLESRenderEngine> createGLESRenderEngine() {
        return nullptr;
    }
};

class GLESRenderEngineFactory : public RenderEngineFactory {
public:
    std::string name() override { return "GLESRenderEngineFactory"; }

    renderengine::RenderEngine::RenderEngineType type() {
        return renderengine::RenderEngine::RenderEngineType::GLES;
    }

    std::unique_ptr<renderengine::RenderEngine> createRenderEngine() override {
        return createGLESRenderEngine();
    }

    std::unique_ptr<renderengine::gl::GLESRenderEngine> createGLESRenderEngine() {
        renderengine::RenderEngineCreationArgs reCreationArgs =
                renderengine::RenderEngineCreationArgs::Builder()
                        .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                        .setImageCacheSize(1)
                        .setUseColorManagerment(false)
                        .setEnableProtectedContext(false)
                        .setPrecacheToneMapperShaderOnly(false)
                        .setSupportsBackgroundBlur(true)
                        .setContextPriority(renderengine::RenderEngine::ContextPriority::MEDIUM)
                        .setRenderEngineType(type())
                        .build();
        return renderengine::gl::GLESRenderEngine::create(reCreationArgs);
    }
};

class GLESCMRenderEngineFactory : public RenderEngineFactory {
public:
    std::string name() override { return "GLESCMRenderEngineFactory"; }

    renderengine::RenderEngine::RenderEngineType type() {
        return renderengine::RenderEngine::RenderEngineType::GLES;
    }

    std::unique_ptr<renderengine::RenderEngine> createRenderEngine() override {
        return createGLESRenderEngine();
    }

    std::unique_ptr<renderengine::gl::GLESRenderEngine> createGLESRenderEngine() override {
        renderengine::RenderEngineCreationArgs reCreationArgs =
                renderengine::RenderEngineCreationArgs::Builder()
                        .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                        .setImageCacheSize(1)
                        .setEnableProtectedContext(false)
                        .setPrecacheToneMapperShaderOnly(false)
                        .setSupportsBackgroundBlur(true)
                        .setContextPriority(renderengine::RenderEngine::ContextPriority::MEDIUM)
                        .setRenderEngineType(type())
                        .setUseColorManagerment(true)
                        .build();
        return renderengine::gl::GLESRenderEngine::create(reCreationArgs);
    }
};

class SkiaGLESRenderEngineFactory : public RenderEngineFactory {
public:
    std::string name() override { return "SkiaGLRenderEngineFactory"; }

    renderengine::RenderEngine::RenderEngineType type() {
        return renderengine::RenderEngine::RenderEngineType::SKIA_GL;
    }

    std::unique_ptr<renderengine::RenderEngine> createRenderEngine() override {
        renderengine::RenderEngineCreationArgs reCreationArgs =
                renderengine::RenderEngineCreationArgs::Builder()
                        .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                        .setImageCacheSize(1)
                        .setEnableProtectedContext(false)
                        .setPrecacheToneMapperShaderOnly(false)
                        .setSupportsBackgroundBlur(true)
                        .setContextPriority(renderengine::RenderEngine::ContextPriority::MEDIUM)
                        .setRenderEngineType(type())
                        .build();
        return renderengine::skia::SkiaGLRenderEngine::create(reCreationArgs);
    }
};

class SkiaGLESCMRenderEngineFactory : public RenderEngineFactory {
public:
    std::string name() override { return "SkiaGLCMRenderEngineFactory"; }

    renderengine::RenderEngine::RenderEngineType type() {
        return renderengine::RenderEngine::RenderEngineType::SKIA_GL;
    }

    std::unique_ptr<renderengine::RenderEngine> createRenderEngine() override {
        renderengine::RenderEngineCreationArgs reCreationArgs =
                renderengine::RenderEngineCreationArgs::Builder()
                        .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                        .setImageCacheSize(1)
                        .setEnableProtectedContext(false)
                        .setPrecacheToneMapperShaderOnly(false)
                        .setSupportsBackgroundBlur(true)
                        .setContextPriority(renderengine::RenderEngine::ContextPriority::MEDIUM)
                        .setRenderEngineType(type())
                        .setUseColorManagerment(true)
                        .build();
        return renderengine::skia::SkiaGLRenderEngine::create(reCreationArgs);
    }
};

class RenderEngineTest : public ::testing::TestWithParam<std::shared_ptr<RenderEngineFactory>> {
public:
    static sp<GraphicBuffer> allocateDefaultBuffer() {
        return new GraphicBuffer(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT,
                                 HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                 GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
                                         GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE,
                                 "output");
    }

    // Allocates a 1x1 buffer to fill with a solid color
    static sp<GraphicBuffer> allocateSourceBuffer(uint32_t width, uint32_t height) {
        return new GraphicBuffer(width, height, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                 GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
                                         GRALLOC_USAGE_HW_TEXTURE,
                                 "input");
    }

    RenderEngineTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        mBuffer = allocateDefaultBuffer();
    }

    ~RenderEngineTest() {
        if (WRITE_BUFFER_TO_FILE_ON_FAILURE && ::testing::Test::HasFailure()) {
            writeBufferToFile("/data/texture_out_");
        }
        for (uint32_t texName : mTexNames) {
            mRE->deleteTextures(1, &texName);
            if (mGLESRE != nullptr) {
                EXPECT_FALSE(mGLESRE->isTextureNameKnownForTesting(texName));
            }
        }
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void writeBufferToFile(const char* basename) {
        std::string filename(basename);
        filename.append(::testing::UnitTest::GetInstance()->current_test_info()->name());
        filename.append(".ppm");
        std::ofstream file(filename.c_str(), std::ios::binary);
        if (!file.is_open()) {
            ALOGE("Unable to open file: %s", filename.c_str());
            ALOGE("You may need to do: \"adb shell setenforce 0\" to enable "
                  "surfaceflinger to write debug images");
            return;
        }

        uint8_t* pixels;
        mBuffer->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                      reinterpret_cast<void**>(&pixels));

        file << "P6\n";
        file << mBuffer->getWidth() << "\n";
        file << mBuffer->getHeight() << "\n";
        file << 255 << "\n";

        std::vector<uint8_t> outBuffer(mBuffer->getWidth() * mBuffer->getHeight() * 3);
        auto outPtr = reinterpret_cast<uint8_t*>(outBuffer.data());

        for (int32_t j = 0; j < mBuffer->getHeight(); j++) {
            const uint8_t* src = pixels + (mBuffer->getStride() * j) * 4;
            for (int32_t i = 0; i < mBuffer->getWidth(); i++) {
                // Only copy R, G and B components
                outPtr[0] = src[0];
                outPtr[1] = src[1];
                outPtr[2] = src[2];
                outPtr += 3;

                src += 4;
            }
        }
        file.write(reinterpret_cast<char*>(outBuffer.data()), outBuffer.size());
        mBuffer->unlock();
    }

    void expectBufferColor(const Region& region, uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
        size_t c;
        Rect const* rect = region.getArray(&c);
        for (size_t i = 0; i < c; i++, rect++) {
            expectBufferColor(*rect, r, g, b, a);
        }
    }

    void expectBufferColor(const Rect& rect, uint8_t r, uint8_t g, uint8_t b, uint8_t a,
                           uint8_t tolerance = 0) {
        auto colorCompare = [tolerance](const uint8_t* colorA, const uint8_t* colorB) {
            auto colorBitCompare = [tolerance](uint8_t a, uint8_t b) {
                uint8_t tmp = a >= b ? a - b : b - a;
                return tmp <= tolerance;
            };
            return std::equal(colorA, colorA + 4, colorB, colorBitCompare);
        };

        expectBufferColor(rect, r, g, b, a, colorCompare);
    }

    void expectBufferColor(const Rect& region, uint8_t r, uint8_t g, uint8_t b, uint8_t a,
                           std::function<bool(const uint8_t* a, const uint8_t* b)> colorCompare) {
        uint8_t* pixels;
        mBuffer->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                      reinterpret_cast<void**>(&pixels));
        int32_t maxFails = 10;
        int32_t fails = 0;
        for (int32_t j = 0; j < region.getHeight(); j++) {
            const uint8_t* src =
                    pixels + (mBuffer->getStride() * (region.top + j) + region.left) * 4;
            for (int32_t i = 0; i < region.getWidth(); i++) {
                const uint8_t expected[4] = {r, g, b, a};
                bool equal = colorCompare(src, expected);
                EXPECT_TRUE(equal)
                        << "pixel @ (" << region.left + i << ", " << region.top + j << "): "
                        << "expected (" << static_cast<uint32_t>(r) << ", "
                        << static_cast<uint32_t>(g) << ", " << static_cast<uint32_t>(b) << ", "
                        << static_cast<uint32_t>(a) << "), "
                        << "got (" << static_cast<uint32_t>(src[0]) << ", "
                        << static_cast<uint32_t>(src[1]) << ", " << static_cast<uint32_t>(src[2])
                        << ", " << static_cast<uint32_t>(src[3]) << ")";
                src += 4;
                if (!equal && ++fails >= maxFails) {
                    break;
                }
            }
            if (fails >= maxFails) {
                break;
            }
        }
        mBuffer->unlock();
    }

    void expectAlpha(const Rect& rect, uint8_t a) {
        auto colorCompare = [](const uint8_t* colorA, const uint8_t* colorB) {
            return colorA[3] == colorB[3];
        };
        expectBufferColor(rect, 0.0f /* r */, 0.0f /*g */, 0.0f /* b */, a, colorCompare);
    }

    void expectShadowColor(const renderengine::LayerSettings& castingLayer,
                           const renderengine::ShadowSettings& shadow, const ubyte4& casterColor,
                           const ubyte4& backgroundColor) {
        const Rect casterRect(castingLayer.geometry.boundaries);
        Region casterRegion = Region(casterRect);
        const float casterCornerRadius = castingLayer.geometry.roundedCornersRadius;
        if (casterCornerRadius > 0.0f) {
            // ignore the corners if a corner radius is set
            Rect cornerRect(casterCornerRadius, casterCornerRadius);
            casterRegion.subtractSelf(cornerRect.offsetTo(casterRect.left, casterRect.top));
            casterRegion.subtractSelf(
                    cornerRect.offsetTo(casterRect.right - casterCornerRadius, casterRect.top));
            casterRegion.subtractSelf(
                    cornerRect.offsetTo(casterRect.left, casterRect.bottom - casterCornerRadius));
            casterRegion.subtractSelf(cornerRect.offsetTo(casterRect.right - casterCornerRadius,
                                                          casterRect.bottom - casterCornerRadius));
        }

        const float shadowInset = shadow.length * -1.0f;
        const Rect casterWithShadow =
                Rect(casterRect).inset(shadowInset, shadowInset, shadowInset, shadowInset);
        const Region shadowRegion = Region(casterWithShadow).subtractSelf(casterRect);
        const Region backgroundRegion = Region(fullscreenRect()).subtractSelf(casterWithShadow);

        // verify casting layer
        expectBufferColor(casterRegion, casterColor.r, casterColor.g, casterColor.b, casterColor.a);

        // verify shadows by testing just the alpha since its difficult to validate the shadow color
        size_t c;
        Rect const* r = shadowRegion.getArray(&c);
        for (size_t i = 0; i < c; i++, r++) {
            expectAlpha(*r, 255);
        }

        // verify background
        expectBufferColor(backgroundRegion, backgroundColor.r, backgroundColor.g, backgroundColor.b,
                          backgroundColor.a);
    }

    void expectShadowColorWithoutCaster(const FloatRect& casterBounds,
                                        const renderengine::ShadowSettings& shadow,
                                        const ubyte4& backgroundColor) {
        const float shadowInset = shadow.length * -1.0f;
        const Rect casterRect(casterBounds);
        const Rect shadowRect =
                Rect(casterRect).inset(shadowInset, shadowInset, shadowInset, shadowInset);

        const Region backgroundRegion =
                Region(fullscreenRect()).subtractSelf(casterRect).subtractSelf(shadowRect);

        expectAlpha(shadowRect, 255);
        // (0, 0, 0) fill on the bounds of the layer should be ignored.
        expectBufferColor(casterRect, 255, 255, 255, 255, 254);

        // verify background
        expectBufferColor(backgroundRegion, backgroundColor.r, backgroundColor.g, backgroundColor.b,
                          backgroundColor.a);
    }

    static renderengine::ShadowSettings getShadowSettings(const vec2& casterPos, float shadowLength,
                                                          bool casterIsTranslucent) {
        renderengine::ShadowSettings shadow;
        shadow.ambientColor = {0.0f, 0.0f, 0.0f, 0.039f};
        shadow.spotColor = {0.0f, 0.0f, 0.0f, 0.19f};
        shadow.lightPos = vec3(casterPos.x, casterPos.y, 0);
        shadow.lightRadius = 0.0f;
        shadow.length = shadowLength;
        shadow.casterIsTranslucent = casterIsTranslucent;
        return shadow;
    }

    static Rect fullscreenRect() { return Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT); }

    static Rect offsetRect() {
        return Rect(DEFAULT_DISPLAY_OFFSET, DEFAULT_DISPLAY_OFFSET, DEFAULT_DISPLAY_WIDTH,
                    DEFAULT_DISPLAY_HEIGHT);
    }

    static Rect offsetRectAtZero() {
        return Rect(DEFAULT_DISPLAY_WIDTH - DEFAULT_DISPLAY_OFFSET,
                    DEFAULT_DISPLAY_HEIGHT - DEFAULT_DISPLAY_OFFSET);
    }

    void invokeDraw(renderengine::DisplaySettings settings,
                    std::vector<const renderengine::LayerSettings*> layers) {
        base::unique_fd fence;
        status_t status =
                mRE->drawLayers(settings, layers, mBuffer, true, base::unique_fd(), &fence);
        mCurrentBuffer = mBuffer;

        int fd = fence.release();
        if (fd >= 0) {
            sync_wait(fd, -1);
            close(fd);
        }

        ASSERT_EQ(NO_ERROR, status);
        if (layers.size() > 0 && mGLESRE != nullptr) {
            ASSERT_TRUE(mGLESRE->isFramebufferImageCachedForTesting(mBuffer->getId()));
        }
    }

    void drawEmptyLayers() {
        renderengine::DisplaySettings settings;
        std::vector<const renderengine::LayerSettings*> layers;
        invokeDraw(settings, layers);
    }

    template <typename SourceVariant>
    void fillBuffer(half r, half g, half b, half a);

    template <typename SourceVariant>
    void fillRedBuffer();

    template <typename SourceVariant>
    void fillGreenBuffer();

    template <typename SourceVariant>
    void fillBlueBuffer();

    template <typename SourceVariant>
    void fillRedTransparentBuffer();

    template <typename SourceVariant>
    void fillRedOffsetBuffer();

    template <typename SourceVariant>
    void fillBufferPhysicalOffset();

    template <typename SourceVariant>
    void fillBufferCheckers(uint32_t rotation);

    template <typename SourceVariant>
    void fillBufferCheckersRotate0();

    template <typename SourceVariant>
    void fillBufferCheckersRotate90();

    template <typename SourceVariant>
    void fillBufferCheckersRotate180();

    template <typename SourceVariant>
    void fillBufferCheckersRotate270();

    template <typename SourceVariant>
    void fillBufferWithLayerTransform();

    template <typename SourceVariant>
    void fillBufferLayerTransform();

    template <typename SourceVariant>
    void fillBufferWithColorTransform();

    template <typename SourceVariant>
    void fillBufferColorTransform();

    template <typename SourceVariant>
    void fillBufferWithColorTransformZeroLayerAlpha();

    template <typename SourceVariant>
    void fillBufferColorTransformZeroLayerAlpha();

    template <typename SourceVariant>
    void fillRedBufferWithRoundedCorners();

    template <typename SourceVariant>
    void fillBufferWithRoundedCorners();

    template <typename SourceVariant>
    void fillBufferAndBlurBackground();

    template <typename SourceVariant>
    void overlayCorners();

    void fillRedBufferTextureTransform();

    void fillBufferTextureTransform();

    void fillRedBufferWithPremultiplyAlpha();

    void fillBufferWithPremultiplyAlpha();

    void fillRedBufferWithoutPremultiplyAlpha();

    void fillBufferWithoutPremultiplyAlpha();

    void fillGreenColorBufferThenClearRegion();

    void clearLeftRegion();

    void clearRegion();

    template <typename SourceVariant>
    void drawShadow(const renderengine::LayerSettings& castingLayer,
                    const renderengine::ShadowSettings& shadow, const ubyte4& casterColor,
                    const ubyte4& backgroundColor);

    void drawShadowWithoutCaster(const FloatRect& castingBounds,
                                 const renderengine::ShadowSettings& shadow,
                                 const ubyte4& backgroundColor);

    void initializeRenderEngine();

    std::unique_ptr<renderengine::RenderEngine> mRE;
    // GLESRenderEngine for testing GLES-specific behavior.
    // Owened by mRE, but this is downcasted.
    renderengine::gl::GLESRenderEngine* mGLESRE = nullptr;

    // Dumb hack to avoid NPE in the EGL driver: the GraphicBuffer needs to
    // be freed *after* RenderEngine is destroyed, so that the EGL image is
    // destroyed first.
    sp<GraphicBuffer> mCurrentBuffer;

    sp<GraphicBuffer> mBuffer;

    std::vector<uint32_t> mTexNames;
};

void RenderEngineTest::initializeRenderEngine() {
    const auto& renderEngineFactory = GetParam();
    if (renderEngineFactory->type() == renderengine::RenderEngine::RenderEngineType::GLES) {
        // Only GLESRenderEngine exposes test-only methods. Provide a pointer to the
        // GLESRenderEngine if we're using it so that we don't need to dynamic_cast
        // every time.
        std::unique_ptr<renderengine::gl::GLESRenderEngine> renderEngine =
                renderEngineFactory->createGLESRenderEngine();
        mGLESRE = renderEngine.get();
        mRE = std::move(renderEngine);
    } else {
        mRE = renderEngineFactory->createRenderEngine();
    }
}

struct ColorSourceVariant {
    static void fillColor(renderengine::LayerSettings& layer, half r, half g, half b,
                          RenderEngineTest* /*fixture*/) {
        layer.source.solidColor = half3(r, g, b);
        layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    }
};

struct RelaxOpaqueBufferVariant {
    static void setOpaqueBit(renderengine::LayerSettings& layer) {
        layer.source.buffer.isOpaque = false;
        layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    }

    static uint8_t getAlphaChannel() { return 255; }
};

struct ForceOpaqueBufferVariant {
    static void setOpaqueBit(renderengine::LayerSettings& layer) {
        layer.source.buffer.isOpaque = true;
        layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    }

    static uint8_t getAlphaChannel() {
        // The isOpaque bit will override the alpha channel, so this should be
        // arbitrary.
        return 50;
    }
};

template <typename OpaquenessVariant>
struct BufferSourceVariant {
    static void fillColor(renderengine::LayerSettings& layer, half r, half g, half b,
                          RenderEngineTest* fixture) {
        sp<GraphicBuffer> buf = RenderEngineTest::allocateSourceBuffer(1, 1);
        uint32_t texName;
        fixture->mRE->genTextures(1, &texName);
        fixture->mTexNames.push_back(texName);

        uint8_t* pixels;
        buf->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                  reinterpret_cast<void**>(&pixels));

        for (int32_t j = 0; j < buf->getHeight(); j++) {
            uint8_t* iter = pixels + (buf->getStride() * j) * 4;
            for (int32_t i = 0; i < buf->getWidth(); i++) {
                iter[0] = uint8_t(r * 255);
                iter[1] = uint8_t(g * 255);
                iter[2] = uint8_t(b * 255);
                iter[3] = OpaquenessVariant::getAlphaChannel();
                iter += 4;
            }
        }

        buf->unlock();

        layer.source.buffer.buffer = buf;
        layer.source.buffer.textureName = texName;
        layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
        OpaquenessVariant::setOpaqueBit(layer);
    }
};

template <typename SourceVariant>
void RenderEngineTest::fillBuffer(half r, half g, half b, half a) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(layer, r, g, b, this);
    layer.alpha = a;

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillRedBuffer() {
    fillBuffer<SourceVariant>(1.0f, 0.0f, 0.0f, 1.0f);
    expectBufferColor(fullscreenRect(), 255, 0, 0, 255);
}

template <typename SourceVariant>
void RenderEngineTest::fillGreenBuffer() {
    fillBuffer<SourceVariant>(0.0f, 1.0f, 0.0f, 1.0f);
    expectBufferColor(fullscreenRect(), 0, 255, 0, 255);
}

template <typename SourceVariant>
void RenderEngineTest::fillBlueBuffer() {
    fillBuffer<SourceVariant>(0.0f, 0.0f, 1.0f, 1.0f);
    expectBufferColor(fullscreenRect(), 0, 0, 255, 255);
}

template <typename SourceVariant>
void RenderEngineTest::fillRedTransparentBuffer() {
    fillBuffer<SourceVariant>(1.0f, 0.0f, 0.0f, .2f);
    expectBufferColor(fullscreenRect(), 51, 0, 0, 51);
}

template <typename SourceVariant>
void RenderEngineTest::fillRedOffsetBuffer() {
    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = offsetRect();
    settings.clip = offsetRectAtZero();

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = offsetRectAtZero().toFloatRect();
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0f;

    layers.push_back(&layer);
    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferPhysicalOffset() {
    fillRedOffsetBuffer<SourceVariant>();

    expectBufferColor(Rect(DEFAULT_DISPLAY_OFFSET, DEFAULT_DISPLAY_OFFSET, DEFAULT_DISPLAY_WIDTH,
                           DEFAULT_DISPLAY_HEIGHT),
                      255, 0, 0, 255);
    Rect offsetRegionLeft(DEFAULT_DISPLAY_OFFSET, DEFAULT_DISPLAY_HEIGHT);
    Rect offsetRegionTop(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_OFFSET);

    expectBufferColor(offsetRegionLeft, 0, 0, 0, 0);
    expectBufferColor(offsetRegionTop, 0, 0, 0, 0);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferCheckers(uint32_t orientationFlag) {
    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    // Here logical space is 2x2
    settings.clip = Rect(2, 2);
    settings.orientation = orientationFlag;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layerOne;
    layerOne.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    Rect rectOne(0, 0, 1, 1);
    layerOne.geometry.boundaries = rectOne.toFloatRect();
    SourceVariant::fillColor(layerOne, 1.0f, 0.0f, 0.0f, this);
    layerOne.alpha = 1.0f;

    renderengine::LayerSettings layerTwo;
    layerTwo.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    Rect rectTwo(0, 1, 1, 2);
    layerTwo.geometry.boundaries = rectTwo.toFloatRect();
    SourceVariant::fillColor(layerTwo, 0.0f, 1.0f, 0.0f, this);
    layerTwo.alpha = 1.0f;

    renderengine::LayerSettings layerThree;
    layerThree.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    Rect rectThree(1, 0, 2, 1);
    layerThree.geometry.boundaries = rectThree.toFloatRect();
    SourceVariant::fillColor(layerThree, 0.0f, 0.0f, 1.0f, this);
    layerThree.alpha = 1.0f;

    layers.push_back(&layerOne);
    layers.push_back(&layerTwo);
    layers.push_back(&layerThree);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferCheckersRotate0() {
    fillBufferCheckers<SourceVariant>(ui::Transform::ROT_0);
    expectBufferColor(Rect(0, 0, DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2), 255, 0, 0,
                      255);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, 0, DEFAULT_DISPLAY_WIDTH,
                           DEFAULT_DISPLAY_HEIGHT / 2),
                      0, 0, 255, 255);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 0, 0);
    expectBufferColor(Rect(0, DEFAULT_DISPLAY_HEIGHT / 2, DEFAULT_DISPLAY_WIDTH / 2,
                           DEFAULT_DISPLAY_HEIGHT),
                      0, 255, 0, 255);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferCheckersRotate90() {
    fillBufferCheckers<SourceVariant>(ui::Transform::ROT_90);
    expectBufferColor(Rect(0, 0, DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2), 0, 255, 0,
                      255);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, 0, DEFAULT_DISPLAY_WIDTH,
                           DEFAULT_DISPLAY_HEIGHT / 2),
                      255, 0, 0, 255);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 255, 255);
    expectBufferColor(Rect(0, DEFAULT_DISPLAY_HEIGHT / 2, DEFAULT_DISPLAY_WIDTH / 2,
                           DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 0, 0);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferCheckersRotate180() {
    fillBufferCheckers<SourceVariant>(ui::Transform::ROT_180);
    expectBufferColor(Rect(0, 0, DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2), 0, 0, 0,
                      0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, 0, DEFAULT_DISPLAY_WIDTH,
                           DEFAULT_DISPLAY_HEIGHT / 2),
                      0, 255, 0, 255);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      255, 0, 0, 255);
    expectBufferColor(Rect(0, DEFAULT_DISPLAY_HEIGHT / 2, DEFAULT_DISPLAY_WIDTH / 2,
                           DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 255, 255);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferCheckersRotate270() {
    fillBufferCheckers<SourceVariant>(ui::Transform::ROT_270);
    expectBufferColor(Rect(0, 0, DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2), 0, 0, 255,
                      255);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, 0, DEFAULT_DISPLAY_WIDTH,
                           DEFAULT_DISPLAY_HEIGHT / 2),
                      0, 0, 0, 0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 255, 0, 255);
    expectBufferColor(Rect(0, DEFAULT_DISPLAY_HEIGHT / 2, DEFAULT_DISPLAY_WIDTH / 2,
                           DEFAULT_DISPLAY_HEIGHT),
                      255, 0, 0, 255);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferWithLayerTransform() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    // Here logical space is 2x2
    settings.clip = Rect(2, 2);
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    // Translate one pixel diagonally
    layer.geometry.positionTransform = mat4(1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1);
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    layer.alpha = 1.0f;

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferLayerTransform() {
    fillBufferWithLayerTransform<SourceVariant>();
    expectBufferColor(Rect(0, 0, DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT / 2), 0, 0, 0, 0);
    expectBufferColor(Rect(0, 0, DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT), 0, 0, 0, 0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      255, 0, 0, 255);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferWithColorTransform() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    SourceVariant::fillColor(layer, 0.5f, 0.25f, 0.125f, this);
    layer.alpha = 1.0f;

    // construct a fake color matrix
    // annihilate green and blue channels
    settings.colorTransform = mat4::scale(vec4(0.9f, 0, 0, 1));
    // set red channel to red + green
    layer.colorTransform = mat4(1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1);

    layer.alpha = 1.0f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferColorTransform() {
    fillBufferWithColorTransform<SourceVariant>();
    expectBufferColor(fullscreenRect(), 172, 0, 0, 255, 1);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferWithColorTransformZeroLayerAlpha() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    SourceVariant::fillColor(layer, 0.5f, 0.25f, 0.125f, this);
    layer.alpha = 0;

    // construct a fake color matrix
    // simple inverse color
    settings.colorTransform = mat4(-1, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 1, 1, 1, 1);

    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferColorTransformZeroLayerAlpha() {
    fillBufferWithColorTransformZeroLayerAlpha<SourceVariant>();
    expectBufferColor(fullscreenRect(), 0, 0, 0, 0);
}

template <typename SourceVariant>
void RenderEngineTest::fillRedBufferWithRoundedCorners() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    layer.geometry.roundedCornersRadius = 5.0f;
    layer.geometry.roundedCornersCrop = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0f;

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferWithRoundedCorners() {
    fillRedBufferWithRoundedCorners<SourceVariant>();
    // Corners should be ignored...
    expectBufferColor(Rect(0, 0, 1, 1), 0, 0, 0, 0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH - 1, 0, DEFAULT_DISPLAY_WIDTH, 1), 0, 0, 0, 0);
    expectBufferColor(Rect(0, DEFAULT_DISPLAY_HEIGHT - 1, 1, DEFAULT_DISPLAY_HEIGHT), 0, 0, 0, 0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH - 1, DEFAULT_DISPLAY_HEIGHT - 1,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 0, 0);
    // ...And the non-rounded portion should be red.
    // Other pixels may be anti-aliased, so let's not check those.
    expectBufferColor(Rect(5, 5, DEFAULT_DISPLAY_WIDTH - 5, DEFAULT_DISPLAY_HEIGHT - 5), 255, 0, 0,
                      255);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferAndBlurBackground() {
        char value[PROPERTY_VALUE_MAX];
    property_get("ro.surface_flinger.supports_background_blur", value, "0");
    if (!atoi(value)) {
        // This device doesn't support blurs, no-op.
        return;
    }

    auto blurRadius = 50;
    auto center = DEFAULT_DISPLAY_WIDTH / 2;

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings backgroundLayer;
    backgroundLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    backgroundLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(backgroundLayer, 0.0f, 1.0f, 0.0f, this);
    backgroundLayer.alpha = 1.0f;
    layers.push_back(&backgroundLayer);

    renderengine::LayerSettings leftLayer;
    leftLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    leftLayer.geometry.boundaries =
            Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT).toFloatRect();
    SourceVariant::fillColor(leftLayer, 1.0f, 0.0f, 0.0f, this);
    leftLayer.alpha = 1.0f;
    layers.push_back(&leftLayer);

    renderengine::LayerSettings blurLayer;
    blurLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    blurLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    blurLayer.backgroundBlurRadius = blurRadius;
    SourceVariant::fillColor(blurLayer, 0.0f, 0.0f, 1.0f, this);
    blurLayer.alpha = 0;
    layers.push_back(&blurLayer);

    invokeDraw(settings, layers);

    // solid color
    expectBufferColor(Rect(0, 0, 1, 1), 255, 0, 0, 255, 0 /* tolerance */);

    // blurred color (downsampling should result in the center color being close to 128)
    expectBufferColor(Rect(center - 1, center - 5, center + 1, center + 5), 128, 128, 0, 255,
                      10 /* tolerance */);
}

template <typename SourceVariant>
void RenderEngineTest::overlayCorners() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layersFirst;

    renderengine::LayerSettings layerOne;
    layerOne.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layerOne.geometry.boundaries =
            FloatRect(0, 0, DEFAULT_DISPLAY_WIDTH / 3.0, DEFAULT_DISPLAY_HEIGHT / 3.0);
    SourceVariant::fillColor(layerOne, 1.0f, 0.0f, 0.0f, this);
    layerOne.alpha = 0.2;

    layersFirst.push_back(&layerOne);
    invokeDraw(settings, layersFirst);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3, DEFAULT_DISPLAY_HEIGHT / 3), 51, 0, 0, 51);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3 + 1, DEFAULT_DISPLAY_HEIGHT / 3 + 1,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 0, 0);

    std::vector<const renderengine::LayerSettings*> layersSecond;
    renderengine::LayerSettings layerTwo;
    layerTwo.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layerTwo.geometry.boundaries =
            FloatRect(DEFAULT_DISPLAY_WIDTH / 3.0, DEFAULT_DISPLAY_HEIGHT / 3.0,
                      DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT);
    SourceVariant::fillColor(layerTwo, 0.0f, 1.0f, 0.0f, this);
    layerTwo.alpha = 1.0f;

    layersSecond.push_back(&layerTwo);
    invokeDraw(settings, layersSecond);

    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3, DEFAULT_DISPLAY_HEIGHT / 3), 0, 0, 0, 0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3 + 1, DEFAULT_DISPLAY_HEIGHT / 3 + 1,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 255, 0, 255);
}

void RenderEngineTest::fillRedBufferTextureTransform() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    // Here will allocate a checker board texture, but transform texture
    // coordinates so that only the upper left is applied.
    sp<GraphicBuffer> buf = allocateSourceBuffer(2, 2);
    uint32_t texName;
    RenderEngineTest::mRE->genTextures(1, &texName);
    this->mTexNames.push_back(texName);

    uint8_t* pixels;
    buf->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
              reinterpret_cast<void**>(&pixels));
    // Red top left, Green top right, Blue bottom left, Black bottom right
    pixels[0] = 255;
    pixels[1] = 0;
    pixels[2] = 0;
    pixels[3] = 255;
    pixels[4] = 0;
    pixels[5] = 255;
    pixels[6] = 0;
    pixels[7] = 255;
    pixels[8] = 0;
    pixels[9] = 0;
    pixels[10] = 255;
    pixels[11] = 255;
    buf->unlock();

    layer.source.buffer.buffer = buf;
    layer.source.buffer.textureName = texName;
    // Transform coordinates to only be inside the red quadrant.
    layer.source.buffer.textureTransform = mat4::scale(vec4(0.2, 0.2, 1, 1));
    layer.alpha = 1.0f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

void RenderEngineTest::fillBufferTextureTransform() {
    fillRedBufferTextureTransform();
    expectBufferColor(fullscreenRect(), 255, 0, 0, 255);
}

void RenderEngineTest::fillRedBufferWithPremultiplyAlpha() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    // Here logical space is 1x1
    settings.clip = Rect(1, 1);

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    sp<GraphicBuffer> buf = allocateSourceBuffer(1, 1);
    uint32_t texName;
    RenderEngineTest::mRE->genTextures(1, &texName);
    this->mTexNames.push_back(texName);

    uint8_t* pixels;
    buf->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
              reinterpret_cast<void**>(&pixels));
    pixels[0] = 255;
    pixels[1] = 0;
    pixels[2] = 0;
    pixels[3] = 255;
    buf->unlock();

    layer.source.buffer.buffer = buf;
    layer.source.buffer.textureName = texName;
    layer.source.buffer.usePremultipliedAlpha = true;
    layer.alpha = 0.5f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

void RenderEngineTest::fillBufferWithPremultiplyAlpha() {
    fillRedBufferWithPremultiplyAlpha();
    expectBufferColor(fullscreenRect(), 128, 0, 0, 128);
}

void RenderEngineTest::fillRedBufferWithoutPremultiplyAlpha() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    // Here logical space is 1x1
    settings.clip = Rect(1, 1);

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    sp<GraphicBuffer> buf = allocateSourceBuffer(1, 1);
    uint32_t texName;
    RenderEngineTest::mRE->genTextures(1, &texName);
    this->mTexNames.push_back(texName);

    uint8_t* pixels;
    buf->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
              reinterpret_cast<void**>(&pixels));
    pixels[0] = 255;
    pixels[1] = 0;
    pixels[2] = 0;
    pixels[3] = 255;
    buf->unlock();

    layer.source.buffer.buffer = buf;
    layer.source.buffer.textureName = texName;
    layer.source.buffer.usePremultipliedAlpha = false;
    layer.alpha = 0.5f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

void RenderEngineTest::fillBufferWithoutPremultiplyAlpha() {
    fillRedBufferWithoutPremultiplyAlpha();
    expectBufferColor(fullscreenRect(), 128, 0, 0, 128, 1);
}

void RenderEngineTest::clearLeftRegion() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    // Here logical space is 4x4
    settings.clip = Rect(4, 4);
    settings.clearRegion = Region(Rect(2, 4));
    std::vector<const renderengine::LayerSettings*> layers;
    // fake layer, without bounds should not render anything
    renderengine::LayerSettings layer;
    layers.push_back(&layer);
    invokeDraw(settings, layers);
}

void RenderEngineTest::clearRegion() {
    // Reuse mBuffer
    clearLeftRegion();
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT), 0, 0, 0, 255);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 2, 0, DEFAULT_DISPLAY_WIDTH,
                           DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 0, 0);
}

template <typename SourceVariant>
void RenderEngineTest::drawShadow(const renderengine::LayerSettings& castingLayer,
                                  const renderengine::ShadowSettings& shadow,
                                  const ubyte4& casterColor, const ubyte4& backgroundColor) {
    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    // add background layer
    renderengine::LayerSettings bgLayer;
    bgLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    bgLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    ColorSourceVariant::fillColor(bgLayer, backgroundColor.r / 255.0f, backgroundColor.g / 255.0f,
                                  backgroundColor.b / 255.0f, this);
    bgLayer.alpha = backgroundColor.a / 255.0f;
    layers.push_back(&bgLayer);

    // add shadow layer
    renderengine::LayerSettings shadowLayer;
    shadowLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    shadowLayer.geometry.boundaries = castingLayer.geometry.boundaries;
    shadowLayer.alpha = castingLayer.alpha;
    shadowLayer.shadow = shadow;
    layers.push_back(&shadowLayer);

    // add layer casting the shadow
    renderengine::LayerSettings layer = castingLayer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    SourceVariant::fillColor(layer, casterColor.r / 255.0f, casterColor.g / 255.0f,
                             casterColor.b / 255.0f, this);
    layers.push_back(&layer);

    invokeDraw(settings, layers);
}

void RenderEngineTest::drawShadowWithoutCaster(const FloatRect& castingBounds,
                                               const renderengine::ShadowSettings& shadow,
                                               const ubyte4& backgroundColor) {
    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    // add background layer
    renderengine::LayerSettings bgLayer;
    bgLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    bgLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    ColorSourceVariant::fillColor(bgLayer, backgroundColor.r / 255.0f, backgroundColor.g / 255.0f,
                                  backgroundColor.b / 255.0f, this);
    bgLayer.alpha = backgroundColor.a / 255.0f;
    layers.push_back(&bgLayer);

    // add shadow layer
    renderengine::LayerSettings shadowLayer;
    shadowLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    shadowLayer.geometry.boundaries = castingBounds;
    shadowLayer.alpha = 1.0f;
    ColorSourceVariant::fillColor(shadowLayer, 0, 0, 0, this);
    shadowLayer.shadow = shadow;
    layers.push_back(&shadowLayer);

    invokeDraw(settings, layers);
}

INSTANTIATE_TEST_SUITE_P(PerRenderEngineType, RenderEngineTest,
                         testing::Values(std::make_shared<GLESRenderEngineFactory>(),
                                         std::make_shared<GLESCMRenderEngineFactory>(),
                                         std::make_shared<SkiaGLESRenderEngineFactory>(),
                                         std::make_shared<SkiaGLESCMRenderEngineFactory>()));

TEST_P(RenderEngineTest, drawLayers_noLayersToDraw) {
    initializeRenderEngine();
    drawEmptyLayers();
}

TEST_P(RenderEngineTest, drawLayers_withoutBuffers_withColorTransform) {
    const auto& renderEngineFactory = GetParam();
    mRE = renderEngineFactory->createRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    // 255, 255, 255, 255 is full opaque white.
    const ubyte4 backgroundColor(255.f, 255.f, 255.f, 255.f);
    // Create layer with given color.
    renderengine::LayerSettings bgLayer;
    bgLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    bgLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    bgLayer.source.solidColor = half3(backgroundColor.r / 255.0f, backgroundColor.g / 255.0f,
                                      backgroundColor.b / 255.0f);
    bgLayer.alpha = backgroundColor.a / 255.0f;
    // Transform the red color.
    bgLayer.colorTransform = mat4(-1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1);

    std::vector<const renderengine::LayerSettings*> layers;
    layers.push_back(&bgLayer);

    invokeDraw(settings, layers);

    // Expect to see full opaque pixel (with inverted red from the transform).
    expectBufferColor(Rect(0, 0, 10, 10), 0.f, backgroundColor.g, backgroundColor.b,
                      backgroundColor.a);
}

TEST_P(RenderEngineTest, drawLayers_nullOutputBuffer) {
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layers.push_back(&layer);
    base::unique_fd fence;
    status_t status = mRE->drawLayers(settings, layers, nullptr, true, base::unique_fd(), &fence);

    ASSERT_EQ(BAD_VALUE, status);
}

TEST_P(RenderEngineTest, drawLayers_nullOutputFence) {
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    status_t status = mRE->drawLayers(settings, layers, mBuffer, true, base::unique_fd(), nullptr);
    mCurrentBuffer = mBuffer;
    ASSERT_EQ(NO_ERROR, status);
    expectBufferColor(fullscreenRect(), 255, 0, 0, 255);
}

TEST_P(RenderEngineTest, drawLayers_doesNotCacheFramebuffer) {
    const auto& renderEngineFactory = GetParam();

    if (renderEngineFactory->type() != renderengine::RenderEngine::RenderEngineType::GLES) {
        // GLES-specific test
        return;
    }

    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    status_t status = mRE->drawLayers(settings, layers, mBuffer, false, base::unique_fd(), nullptr);
    mCurrentBuffer = mBuffer;
    ASSERT_EQ(NO_ERROR, status);
    ASSERT_FALSE(mGLESRE->isFramebufferImageCachedForTesting(mBuffer->getId()));
    expectBufferColor(fullscreenRect(), 255, 0, 0, 255);
}

TEST_P(RenderEngineTest, drawLayers_fillRedBuffer_colorSource) {
    initializeRenderEngine();
    fillRedBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillGreenBuffer_colorSource) {
    initializeRenderEngine();
    fillGreenBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBlueBuffer_colorSource) {
    initializeRenderEngine();
    fillBlueBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedTransparentBuffer_colorSource) {
    initializeRenderEngine();
    fillRedTransparentBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_colorSource) {
    initializeRenderEngine();
    fillBufferPhysicalOffset<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_colorSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate0<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_colorSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate90<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_colorSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate180<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_colorSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate270<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferLayerTransform_colorSource) {
    initializeRenderEngine();
    fillBufferLayerTransform<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_colorSource) {
    initializeRenderEngine();
    fillBufferColorTransform<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferRoundedCorners_colorSource) {
    initializeRenderEngine();
    fillBufferWithRoundedCorners<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_colorSource) {
    initializeRenderEngine();
    fillBufferColorTransformZeroLayerAlpha<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_colorSource) {
    initializeRenderEngine();
    fillBufferAndBlurBackground<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_overlayCorners_colorSource) {
    initializeRenderEngine();
    overlayCorners<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedBuffer_opaqueBufferSource) {
    initializeRenderEngine();
    fillRedBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillGreenBuffer_opaqueBufferSource) {
    initializeRenderEngine();
    fillGreenBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBlueBuffer_opaqueBufferSource) {
    initializeRenderEngine();
    fillBlueBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedTransparentBuffer_opaqueBufferSource) {
    initializeRenderEngine();
    fillRedTransparentBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferPhysicalOffset<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate0<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate90<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate180<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate270<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferLayerTransform_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferLayerTransform<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferColorTransform<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferRoundedCorners_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferWithRoundedCorners<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferColorTransformZeroLayerAlpha<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_opaqueBufferSource) {
    initializeRenderEngine();
    fillBufferAndBlurBackground<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_overlayCorners_opaqueBufferSource) {
    initializeRenderEngine();
    overlayCorners<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedBuffer_bufferSource) {
    initializeRenderEngine();
    fillRedBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillGreenBuffer_bufferSource) {
    initializeRenderEngine();
    fillGreenBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBlueBuffer_bufferSource) {
    initializeRenderEngine();
    fillBlueBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedTransparentBuffer_bufferSource) {
    initializeRenderEngine();
    fillRedTransparentBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_bufferSource) {
    initializeRenderEngine();
    fillBufferPhysicalOffset<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_bufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate0<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_bufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate90<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_bufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate180<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_bufferSource) {
    initializeRenderEngine();
    fillBufferCheckersRotate270<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferLayerTransform_bufferSource) {
    initializeRenderEngine();
    fillBufferLayerTransform<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_bufferSource) {
    initializeRenderEngine();
    fillBufferColorTransform<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferRoundedCorners_bufferSource) {
    initializeRenderEngine();
    fillBufferWithRoundedCorners<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_bufferSource) {
    initializeRenderEngine();
    fillBufferColorTransformZeroLayerAlpha<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_bufferSource) {
    initializeRenderEngine();
    fillBufferAndBlurBackground<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_overlayCorners_bufferSource) {
    initializeRenderEngine();
    overlayCorners<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferTextureTransform) {
    initializeRenderEngine();
    fillBufferTextureTransform();
}

TEST_P(RenderEngineTest, drawLayers_fillBuffer_premultipliesAlpha) {
    initializeRenderEngine();
    fillBufferWithPremultiplyAlpha();
}

TEST_P(RenderEngineTest, drawLayers_fillBuffer_withoutPremultiplyingAlpha) {
    initializeRenderEngine();
    fillBufferWithoutPremultiplyAlpha();
}

TEST_P(RenderEngineTest, drawLayers_clearRegion) {
    initializeRenderEngine();
    clearRegion();
}

TEST_P(RenderEngineTest, drawLayers_fillsBufferAndCachesImages) {
    const auto& renderEngineFactory = GetParam();

    if (renderEngineFactory->type() != renderengine::RenderEngine::RenderEngineType::GLES) {
        // GLES-specific test
        return;
    }

    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);

    layers.push_back(&layer);
    invokeDraw(settings, layers);
    uint64_t bufferId = layer.source.buffer.buffer->getId();
    EXPECT_TRUE(mGLESRE->isImageCachedForTesting(bufferId));
    std::shared_ptr<renderengine::gl::ImageManager::Barrier> barrier =
            mGLESRE->unbindExternalTextureBufferForTesting(bufferId);
    std::lock_guard<std::mutex> lock(barrier->mutex);
    ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                            [&]() REQUIRES(barrier->mutex) {
                                                return barrier->isOpen;
                                            }));
    EXPECT_FALSE(mGLESRE->isImageCachedForTesting(bufferId));
    EXPECT_EQ(NO_ERROR, barrier->result);
}

TEST_P(RenderEngineTest, cacheExternalBuffer_withNullBuffer) {
    const auto& renderEngineFactory = GetParam();

    if (renderEngineFactory->type() != renderengine::RenderEngine::RenderEngineType::GLES) {
        // GLES-specific test
        return;
    }

    initializeRenderEngine();

    std::shared_ptr<renderengine::gl::ImageManager::Barrier> barrier =
            mGLESRE->cacheExternalTextureBufferForTesting(nullptr);
    std::lock_guard<std::mutex> lock(barrier->mutex);
    ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                            [&]() REQUIRES(barrier->mutex) {
                                                return barrier->isOpen;
                                            }));
    EXPECT_TRUE(barrier->isOpen);
    EXPECT_EQ(BAD_VALUE, barrier->result);
}

TEST_P(RenderEngineTest, cacheExternalBuffer_cachesImages) {
    const auto& renderEngineFactory = GetParam();

    if (renderEngineFactory->type() != renderengine::RenderEngine::RenderEngineType::GLES) {
        // GLES-specific test
        return;
    }

    initializeRenderEngine();

    sp<GraphicBuffer> buf = allocateSourceBuffer(1, 1);
    uint64_t bufferId = buf->getId();
    std::shared_ptr<renderengine::gl::ImageManager::Barrier> barrier =
            mGLESRE->cacheExternalTextureBufferForTesting(buf);
    {
        std::lock_guard<std::mutex> lock(barrier->mutex);
        ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                                [&]() REQUIRES(barrier->mutex) {
                                                    return barrier->isOpen;
                                                }));
        EXPECT_EQ(NO_ERROR, barrier->result);
    }
    EXPECT_TRUE(mGLESRE->isImageCachedForTesting(bufferId));
    barrier = mGLESRE->unbindExternalTextureBufferForTesting(bufferId);
    {
        std::lock_guard<std::mutex> lock(barrier->mutex);
        ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                                [&]() REQUIRES(barrier->mutex) {
                                                    return barrier->isOpen;
                                                }));
        EXPECT_EQ(NO_ERROR, barrier->result);
    }
    EXPECT_FALSE(mGLESRE->isImageCachedForTesting(bufferId));
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_castsWithoutCasterLayer) {
    initializeRenderEngine();

    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::ShadowSettings settings =
            getShadowSettings(vec2(casterBounds.left, casterBounds.top), shadowLength,
                              false /* casterIsTranslucent */);

    drawShadowWithoutCaster(casterBounds.toFloatRect(), settings, backgroundColor);
    expectShadowColorWithoutCaster(casterBounds.toFloatRect(), settings, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterLayerMinSize) {
    initializeRenderEngine();

    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(1, 1);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    renderengine::ShadowSettings settings =
            getShadowSettings(vec2(casterBounds.left, casterBounds.top), shadowLength,
                              false /* casterIsTranslucent */);

    drawShadow<ColorSourceVariant>(castingLayer, settings, casterColor, backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterColorLayer) {
    initializeRenderEngine();

    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    renderengine::ShadowSettings settings =
            getShadowSettings(vec2(casterBounds.left, casterBounds.top), shadowLength,
                              false /* casterIsTranslucent */);

    drawShadow<ColorSourceVariant>(castingLayer, settings, casterColor, backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterOpaqueBufferLayer) {
    initializeRenderEngine();

    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    renderengine::ShadowSettings settings =
            getShadowSettings(vec2(casterBounds.left, casterBounds.top), shadowLength,
                              false /* casterIsTranslucent */);

    drawShadow<BufferSourceVariant<ForceOpaqueBufferVariant>>(castingLayer, settings, casterColor,
                                                              backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterWithRoundedCorner) {
    initializeRenderEngine();

    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.geometry.roundedCornersRadius = 3.0f;
    castingLayer.geometry.roundedCornersCrop = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    renderengine::ShadowSettings settings =
            getShadowSettings(vec2(casterBounds.left, casterBounds.top), shadowLength,
                              false /* casterIsTranslucent */);

    drawShadow<BufferSourceVariant<ForceOpaqueBufferVariant>>(castingLayer, settings, casterColor,
                                                              backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_translucentCasterWithAlpha) {
    initializeRenderEngine();

    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 0.5f;
    renderengine::ShadowSettings settings =
            getShadowSettings(vec2(casterBounds.left, casterBounds.top), shadowLength,
                              true /* casterIsTranslucent */);

    drawShadow<BufferSourceVariant<RelaxOpaqueBufferVariant>>(castingLayer, settings, casterColor,
                                                              backgroundColor);

    // verify only the background since the shadow will draw behind the caster
    const float shadowInset = settings.length * -1.0f;
    const Rect casterWithShadow =
            Rect(casterBounds).inset(shadowInset, shadowInset, shadowInset, shadowInset);
    const Region backgroundRegion = Region(fullscreenRect()).subtractSelf(casterWithShadow);
    expectBufferColor(backgroundRegion, backgroundColor.r, backgroundColor.g, backgroundColor.b,
                      backgroundColor.a);
}

TEST_P(RenderEngineTest, cleanupPostRender_cleansUpOnce) {
    const auto& renderEngineFactory = GetParam();

    if (renderEngineFactory->type() != renderengine::RenderEngine::RenderEngineType::GLES) {
        // GLES-specific test
        return;
    }

    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    base::unique_fd fenceOne;
    mRE->drawLayers(settings, layers, mBuffer, true, base::unique_fd(), &fenceOne);
    base::unique_fd fenceTwo;
    mRE->drawLayers(settings, layers, mBuffer, true, std::move(fenceOne), &fenceTwo);

    const int fd = fenceTwo.get();
    if (fd >= 0) {
        sync_wait(fd, -1);
    }
    // Only cleanup the first time.
    EXPECT_TRUE(mRE->cleanupPostRender(
            renderengine::RenderEngine::CleanupMode::CLEAN_OUTPUT_RESOURCES));
    EXPECT_FALSE(mRE->cleanupPostRender(
            renderengine::RenderEngine::CleanupMode::CLEAN_OUTPUT_RESOURCES));
}

TEST_P(RenderEngineTest, cleanupPostRender_whenCleaningAll_replacesTextureMemory) {
    const auto& renderEngineFactory = GetParam();

    if (renderEngineFactory->type() != renderengine::RenderEngine::RenderEngineType::GLES) {
        // GLES-specific test
        return;
    }

    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    base::unique_fd fence;
    mRE->drawLayers(settings, layers, mBuffer, true, base::unique_fd(), &fence);

    const int fd = fence.get();
    if (fd >= 0) {
        sync_wait(fd, -1);
    }

    uint64_t bufferId = layer.source.buffer.buffer->getId();
    uint32_t texName = layer.source.buffer.textureName;
    EXPECT_TRUE(mGLESRE->isImageCachedForTesting(bufferId));
    EXPECT_EQ(bufferId, mGLESRE->getBufferIdForTextureNameForTesting(texName));

    EXPECT_TRUE(mRE->cleanupPostRender(renderengine::RenderEngine::CleanupMode::CLEAN_ALL));

    // Now check that our view of memory is good.
    EXPECT_FALSE(mGLESRE->isImageCachedForTesting(bufferId));
    EXPECT_EQ(std::nullopt, mGLESRE->getBufferIdForTextureNameForTesting(bufferId));
    EXPECT_TRUE(mGLESRE->isTextureNameKnownForTesting(texName));
}

TEST_P(RenderEngineTest, testRoundedCornersCrop) {
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings redLayer;
    redLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    redLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    redLayer.geometry.roundedCornersRadius = 5.0f;
    redLayer.geometry.roundedCornersCrop = fullscreenRect().toFloatRect();
    // Red background.
    redLayer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    redLayer.alpha = 1.0f;

    layers.push_back(&redLayer);

    // Green layer with 1/3 size.
    renderengine::LayerSettings greenLayer;
    greenLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    greenLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    greenLayer.geometry.roundedCornersRadius = 5.0f;
    // Bottom right corner is not going to be rounded.
    greenLayer.geometry.roundedCornersCrop =
            Rect(DEFAULT_DISPLAY_WIDTH / 3, DEFAULT_DISPLAY_HEIGHT / 3, DEFAULT_DISPLAY_HEIGHT,
                 DEFAULT_DISPLAY_HEIGHT)
                    .toFloatRect();
    greenLayer.source.solidColor = half3(0.0f, 1.0f, 0.0f);
    greenLayer.alpha = 1.0f;

    layers.push_back(&greenLayer);

    invokeDraw(settings, layers);

    // Corners should be ignored...
    // Screen size: width is 128, height is 256.
    expectBufferColor(Rect(0, 0, 1, 1), 0, 0, 0, 0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH - 1, 0, DEFAULT_DISPLAY_WIDTH, 1), 0, 0, 0, 0);
    expectBufferColor(Rect(0, DEFAULT_DISPLAY_HEIGHT - 1, 1, DEFAULT_DISPLAY_HEIGHT), 0, 0, 0, 0);
    // Bottom right corner is kept out of the clipping, and it's green.
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH - 1, DEFAULT_DISPLAY_HEIGHT - 1,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 255, 0, 255);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
