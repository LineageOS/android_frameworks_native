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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <chrono>
#include <condition_variable>
#include <fstream>

#include <gtest/gtest.h>
#include <cutils/properties.h>
#include <renderengine/RenderEngine.h>
#include <sync/sync.h>
#include <ui/PixelFormat.h>
#include "../gl/GLESRenderEngine.h"

constexpr int DEFAULT_DISPLAY_WIDTH = 128;
constexpr int DEFAULT_DISPLAY_HEIGHT = 256;
constexpr int DEFAULT_DISPLAY_OFFSET = 64;
constexpr bool WRITE_BUFFER_TO_FILE_ON_FAILURE = false;

namespace android {

struct RenderEngineTest : public ::testing::Test {
    static void SetUpTestSuite() {
        renderengine::RenderEngineCreationArgs reCreationArgs =
            renderengine::RenderEngineCreationArgs::Builder()
                .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                .setImageCacheSize(1)
                .setUseColorManagerment(false)
                .setEnableProtectedContext(false)
                .setPrecacheToneMapperShaderOnly(false)
                .setSupportsBackgroundBlur(true)
                .setContextPriority(renderengine::RenderEngine::ContextPriority::MEDIUM)
                .build();
        sRE = renderengine::gl::GLESRenderEngine::create(reCreationArgs);

        reCreationArgs.useColorManagement = true;
        sRECM = renderengine::gl::GLESRenderEngine::create(reCreationArgs);
    }

    static void TearDownTestSuite() {
        // The ordering here is important - sCurrentBuffer must live longer
        // than RenderEngine to avoid a null reference on tear-down.
        sRE = nullptr;
        sRECM = nullptr;
        sCurrentBuffer = nullptr;
    }

    static sp<GraphicBuffer> allocateDefaultBuffer() {
        return new GraphicBuffer(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT,
                                 HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                 GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
                                         GRALLOC_USAGE_HW_RENDER,
                                 "output");
    }

    // Allocates a 1x1 buffer to fill with a solid color
    static sp<GraphicBuffer> allocateSourceBuffer(uint32_t width, uint32_t height) {
        return new GraphicBuffer(width, height, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                 GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
                                         GRALLOC_USAGE_HW_TEXTURE,
                                 "input");
    }

    RenderEngineTest() { mBuffer = allocateDefaultBuffer(); }

    ~RenderEngineTest() {
        if (WRITE_BUFFER_TO_FILE_ON_FAILURE && ::testing::Test::HasFailure()) {
            writeBufferToFile("/data/texture_out_");
        }
        for (uint32_t texName : mTexNames) {
            sRE->deleteTextures(1, &texName);
            EXPECT_FALSE(sRE->isTextureNameKnownForTesting(texName));
        }
        for (uint32_t texName : mTexNamesCM) {
            sRECM->deleteTextures(1, &texName);
        }
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
                    std::vector<const renderengine::LayerSettings*> layers,
                    sp<GraphicBuffer> buffer,
                    bool useColorManagement = false) {
        base::unique_fd fence;
        status_t status = useColorManagement ?
                          sRECM ->drawLayers(settings, layers, buffer->getNativeBuffer(), true,
                                             base::unique_fd(), &fence) :
                          sRE->drawLayers(settings, layers, buffer->getNativeBuffer(), true,
                                          base::unique_fd(), &fence);
        sCurrentBuffer = buffer;

        int fd = fence.release();
        if (fd >= 0) {
            sync_wait(fd, -1);
            close(fd);
        }

        ASSERT_EQ(NO_ERROR, status);
        if (layers.size() > 0) {
            if (useColorManagement) {
                ASSERT_TRUE(sRECM->isFramebufferImageCachedForTesting(buffer->getId()));
            } else {
                ASSERT_TRUE(sRE->isFramebufferImageCachedForTesting(buffer->getId()));
            }
        }
    }

    void drawEmptyLayers() {
        renderengine::DisplaySettings settings;
        std::vector<const renderengine::LayerSettings*> layers;
        // Meaningless buffer since we don't do any drawing
        sp<GraphicBuffer> buffer = new GraphicBuffer();
        invokeDraw(settings, layers, buffer);
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
    void fillBufferWithColorTransform(bool useColorManagement = false);

    template <typename SourceVariant>
    void fillBufferColorTransform();

    template <typename SourceVariant>
    void fillBufferColorTransformCM();

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

    // Keep around the same renderengine object to save on initialization time.
    // For now, exercise the GL backend directly so that some caching specifics
    // can be tested without changing the interface.
    static std::unique_ptr<renderengine::gl::GLESRenderEngine> sRE;
    // renderengine object with Color Management enabled
    static std::unique_ptr<renderengine::gl::GLESRenderEngine> sRECM;
    // Dumb hack to avoid NPE in the EGL driver: the GraphicBuffer needs to
    // be freed *after* RenderEngine is destroyed, so that the EGL image is
    // destroyed first.
    static sp<GraphicBuffer> sCurrentBuffer;

    sp<GraphicBuffer> mBuffer;

    std::vector<uint32_t> mTexNames;
    std::vector<uint32_t> mTexNamesCM;
};

std::unique_ptr<renderengine::gl::GLESRenderEngine> RenderEngineTest::sRE = nullptr;
std::unique_ptr<renderengine::gl::GLESRenderEngine> RenderEngineTest::sRECM = nullptr;

sp<GraphicBuffer> RenderEngineTest::sCurrentBuffer = nullptr;

struct ColorSourceVariant {
    static void fillColor(renderengine::LayerSettings& layer, half r, half g, half b,
                          RenderEngineTest* /*fixture*/, bool /*useColorManagement*/ = false) {
        layer.source.solidColor = half3(r, g, b);
    }
};

struct RelaxOpaqueBufferVariant {
    static void setOpaqueBit(renderengine::LayerSettings& layer) {
        layer.source.buffer.isOpaque = false;
    }

    static uint8_t getAlphaChannel() { return 255; }
};

struct ForceOpaqueBufferVariant {
    static void setOpaqueBit(renderengine::LayerSettings& layer) {
        layer.source.buffer.isOpaque = true;
    }

    static uint8_t getAlphaChannel() {
        // The isOpaque bit will override the alpha channel, so this should be
        // arbitrary.
        return 10;
    }
};

template <typename OpaquenessVariant>
struct BufferSourceVariant {
    static void fillColor(renderengine::LayerSettings& layer, half r, half g, half b,
                          RenderEngineTest* fixture,
                          bool useColorManagement = false) {
        sp<GraphicBuffer> buf = RenderEngineTest::allocateSourceBuffer(1, 1);
        uint32_t texName;
        if (useColorManagement) {
            fixture->sRECM->genTextures(1, &texName);
            fixture->mTexNamesCM.push_back(texName);
        } else {
            fixture->sRE->genTextures(1, &texName);
            fixture->mTexNames.push_back(texName);
        }

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
        OpaquenessVariant::setOpaqueBit(layer);
    }
};

template <typename SourceVariant>
void RenderEngineTest::fillBuffer(half r, half g, half b, half a) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(layer, r, g, b, this);
    layer.alpha = a;

    layers.push_back(&layer);

    invokeDraw(settings, layers, mBuffer);
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
    settings.physicalDisplay = offsetRect();
    settings.clip = offsetRectAtZero();

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = offsetRectAtZero().toFloatRect();
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0f;

    layers.push_back(&layer);
    invokeDraw(settings, layers, mBuffer);
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
    settings.physicalDisplay = fullscreenRect();
    // Here logical space is 2x2
    settings.clip = Rect(2, 2);
    settings.orientation = orientationFlag;

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layerOne;
    Rect rectOne(0, 0, 1, 1);
    layerOne.geometry.boundaries = rectOne.toFloatRect();
    SourceVariant::fillColor(layerOne, 1.0f, 0.0f, 0.0f, this);
    layerOne.alpha = 1.0f;

    renderengine::LayerSettings layerTwo;
    Rect rectTwo(0, 1, 1, 2);
    layerTwo.geometry.boundaries = rectTwo.toFloatRect();
    SourceVariant::fillColor(layerTwo, 0.0f, 1.0f, 0.0f, this);
    layerTwo.alpha = 1.0f;

    renderengine::LayerSettings layerThree;
    Rect rectThree(1, 0, 2, 1);
    layerThree.geometry.boundaries = rectThree.toFloatRect();
    SourceVariant::fillColor(layerThree, 0.0f, 0.0f, 1.0f, this);
    layerThree.alpha = 1.0f;

    layers.push_back(&layerOne);
    layers.push_back(&layerTwo);
    layers.push_back(&layerThree);

    invokeDraw(settings, layers, mBuffer);
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

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    // Translate one pixel diagonally
    layer.geometry.positionTransform = mat4(1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1);
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    layer.alpha = 1.0f;

    layers.push_back(&layer);

    invokeDraw(settings, layers, mBuffer);
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
void RenderEngineTest::fillBufferWithColorTransform(bool useColorManagement) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    SourceVariant::fillColor(layer, 0.5f, 0.25f, 0.125f, this, useColorManagement);
    layer.alpha = 1.0f;

    // construct a fake color matrix
    // annihilate green and blue channels
    settings.colorTransform = mat4::scale(vec4(0.9f, 0, 0, 1));
    // set red channel to red + green
    layer.colorTransform = mat4(1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1);

    layer.alpha = 1.0f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(&layer);

    invokeDraw(settings, layers, mBuffer, useColorManagement);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferColorTransform() {
    fillBufferWithColorTransform<SourceVariant>();
    expectBufferColor(fullscreenRect(), 172, 0, 0, 255, 1);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferColorTransformCM() {
    fillBufferWithColorTransform<SourceVariant>(true);
    expectBufferColor(fullscreenRect(), 126, 0, 0, 255, 1);
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
    settings.colorTransform = mat4(-1, 0, 0, 0,
                                   0, -1, 0, 0,
                                   0, 0, -1, 0,
                                   1, 1, 1, 1);

    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(&layer);

    invokeDraw(settings, layers, mBuffer);
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

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    layer.geometry.roundedCornersRadius = 5.0f;
    layer.geometry.roundedCornersCrop = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0f;

    layers.push_back(&layer);

    invokeDraw(settings, layers, mBuffer);
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
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings backgroundLayer;
    backgroundLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(backgroundLayer, 0.0f, 1.0f, 0.0f, this);
    backgroundLayer.alpha = 1.0f;
    layers.push_back(&backgroundLayer);

    renderengine::LayerSettings leftLayer;
    leftLayer.geometry.boundaries =
            Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT).toFloatRect();
    SourceVariant::fillColor(leftLayer, 1.0f, 0.0f, 0.0f, this);
    leftLayer.alpha = 1.0f;
    layers.push_back(&leftLayer);

    renderengine::LayerSettings blurLayer;
    blurLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    blurLayer.backgroundBlurRadius = blurRadius;
    blurLayer.alpha = 0;
    layers.push_back(&blurLayer);

    invokeDraw(settings, layers, mBuffer);

    expectBufferColor(Rect(center - 1, center - 5, center, center + 5), 150, 150, 0, 255,
                      50 /* tolerance */);
    expectBufferColor(Rect(center, center - 5, center + 1, center + 5), 150, 150, 0, 255,
                      50 /* tolerance */);
}

template <typename SourceVariant>
void RenderEngineTest::overlayCorners() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layersFirst;

    renderengine::LayerSettings layerOne;
    layerOne.geometry.boundaries =
            FloatRect(0, 0, DEFAULT_DISPLAY_WIDTH / 3.0, DEFAULT_DISPLAY_HEIGHT / 3.0);
    SourceVariant::fillColor(layerOne, 1.0f, 0.0f, 0.0f, this);
    layerOne.alpha = 0.2;

    layersFirst.push_back(&layerOne);
    invokeDraw(settings, layersFirst, mBuffer);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3, DEFAULT_DISPLAY_HEIGHT / 3), 51, 0, 0, 51);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3 + 1, DEFAULT_DISPLAY_HEIGHT / 3 + 1,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 0, 0);

    std::vector<const renderengine::LayerSettings*> layersSecond;
    renderengine::LayerSettings layerTwo;
    layerTwo.geometry.boundaries =
            FloatRect(DEFAULT_DISPLAY_WIDTH / 3.0, DEFAULT_DISPLAY_HEIGHT / 3.0,
                      DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT);
    SourceVariant::fillColor(layerTwo, 0.0f, 1.0f, 0.0f, this);
    layerTwo.alpha = 1.0f;

    layersSecond.push_back(&layerTwo);
    invokeDraw(settings, layersSecond, mBuffer);

    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3, DEFAULT_DISPLAY_HEIGHT / 3), 0, 0, 0, 0);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3 + 1, DEFAULT_DISPLAY_HEIGHT / 3 + 1,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 255, 0, 255);
}

void RenderEngineTest::fillRedBufferTextureTransform() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    // Here will allocate a checker board texture, but transform texture
    // coordinates so that only the upper left is applied.
    sp<GraphicBuffer> buf = allocateSourceBuffer(2, 2);
    uint32_t texName;
    RenderEngineTest::sRE->genTextures(1, &texName);
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

    invokeDraw(settings, layers, mBuffer);
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
    RenderEngineTest::sRE->genTextures(1, &texName);
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

    invokeDraw(settings, layers, mBuffer);
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
    RenderEngineTest::sRE->genTextures(1, &texName);
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

    invokeDraw(settings, layers, mBuffer);
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
    invokeDraw(settings, layers, mBuffer);
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
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    // add background layer
    renderengine::LayerSettings bgLayer;
    bgLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    ColorSourceVariant::fillColor(bgLayer, backgroundColor.r / 255.0f, backgroundColor.g / 255.0f,
                                  backgroundColor.b / 255.0f, this);
    bgLayer.alpha = backgroundColor.a / 255.0f;
    layers.push_back(&bgLayer);

    // add shadow layer
    renderengine::LayerSettings shadowLayer;
    shadowLayer.geometry.boundaries = castingLayer.geometry.boundaries;
    shadowLayer.alpha = castingLayer.alpha;
    shadowLayer.shadow = shadow;
    layers.push_back(&shadowLayer);

    // add layer casting the shadow
    renderengine::LayerSettings layer = castingLayer;
    SourceVariant::fillColor(layer, casterColor.r / 255.0f, casterColor.g / 255.0f,
                             casterColor.b / 255.0f, this);
    layers.push_back(&layer);

    invokeDraw(settings, layers, mBuffer);
}

TEST_F(RenderEngineTest, drawLayers_noLayersToDraw) {
    drawEmptyLayers();
}

TEST_F(RenderEngineTest, drawLayers_nullOutputBuffer) {
    renderengine::DisplaySettings settings;
    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layers.push_back(&layer);
    base::unique_fd fence;
    status_t status = sRE->drawLayers(settings, layers, nullptr, true, base::unique_fd(), &fence);

    ASSERT_EQ(BAD_VALUE, status);
}

TEST_F(RenderEngineTest, drawLayers_nullOutputFence) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    status_t status = sRE->drawLayers(settings, layers, mBuffer->getNativeBuffer(), true,
                                      base::unique_fd(), nullptr);
    sCurrentBuffer = mBuffer;
    ASSERT_EQ(NO_ERROR, status);
    expectBufferColor(fullscreenRect(), 255, 0, 0, 255);
}

TEST_F(RenderEngineTest, drawLayers_doesNotCacheFramebuffer) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    status_t status = sRE->drawLayers(settings, layers, mBuffer->getNativeBuffer(), false,
                                      base::unique_fd(), nullptr);
    sCurrentBuffer = mBuffer;
    ASSERT_EQ(NO_ERROR, status);
    ASSERT_FALSE(sRE->isFramebufferImageCachedForTesting(mBuffer->getId()));
    expectBufferColor(fullscreenRect(), 255, 0, 0, 255);
}

TEST_F(RenderEngineTest, drawLayers_fillRedBuffer_colorSource) {
    fillRedBuffer<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillGreenBuffer_colorSource) {
    fillGreenBuffer<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBlueBuffer_colorSource) {
    fillBlueBuffer<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillRedTransparentBuffer_colorSource) {
    fillRedTransparentBuffer<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_colorSource) {
    fillBufferPhysicalOffset<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_colorSource) {
    fillBufferCheckersRotate0<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_colorSource) {
    fillBufferCheckersRotate90<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_colorSource) {
    fillBufferCheckersRotate180<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_colorSource) {
    fillBufferCheckersRotate270<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferLayerTransform_colorSource) {
    fillBufferLayerTransform<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransform_colorSource) {
    fillBufferColorTransform<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransformCM_colorSource) {
    fillBufferColorTransformCM<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_colorSource) {
    fillBufferColorTransformZeroLayerAlpha<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferRoundedCorners_colorSource) {
    fillBufferWithRoundedCorners<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_colorSource) {
    fillBufferAndBlurBackground<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_overlayCorners_colorSource) {
    overlayCorners<ColorSourceVariant>();
}

TEST_F(RenderEngineTest, drawLayers_fillRedBuffer_opaqueBufferSource) {
    fillRedBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillGreenBuffer_opaqueBufferSource) {
    fillGreenBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBlueBuffer_opaqueBufferSource) {
    fillBlueBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillRedTransparentBuffer_opaqueBufferSource) {
    fillRedTransparentBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_opaqueBufferSource) {
    fillBufferPhysicalOffset<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_opaqueBufferSource) {
    fillBufferCheckersRotate0<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_opaqueBufferSource) {
    fillBufferCheckersRotate90<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_opaqueBufferSource) {
    fillBufferCheckersRotate180<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_opaqueBufferSource) {
    fillBufferCheckersRotate270<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferLayerTransform_opaqueBufferSource) {
    fillBufferLayerTransform<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransform_opaqueBufferSource) {
    fillBufferColorTransform<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransformCM_opaqueBufferSource) {
    fillBufferColorTransformCM<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_opaqueBufferSource) {
    fillBufferColorTransformZeroLayerAlpha<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferRoundedCorners_opaqueBufferSource) {
    fillBufferWithRoundedCorners<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_opaqueBufferSource) {
    fillBufferAndBlurBackground<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_overlayCorners_opaqueBufferSource) {
    overlayCorners<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillRedBuffer_bufferSource) {
    fillRedBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillGreenBuffer_bufferSource) {
    fillGreenBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBlueBuffer_bufferSource) {
    fillBlueBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillRedTransparentBuffer_bufferSource) {
    fillRedTransparentBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_bufferSource) {
    fillBufferPhysicalOffset<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_bufferSource) {
    fillBufferCheckersRotate0<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_bufferSource) {
    fillBufferCheckersRotate90<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_bufferSource) {
    fillBufferCheckersRotate180<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_bufferSource) {
    fillBufferCheckersRotate270<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferLayerTransform_bufferSource) {
    fillBufferLayerTransform<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransform_bufferSource) {
    fillBufferColorTransform<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransformCM_bufferSource) {
    fillBufferColorTransformCM<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_bufferSource) {
    fillBufferColorTransformZeroLayerAlpha<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferRoundedCorners_bufferSource) {
    fillBufferWithRoundedCorners<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_bufferSource) {
    fillBufferAndBlurBackground<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_overlayCorners_bufferSource) {
    overlayCorners<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_F(RenderEngineTest, drawLayers_fillBufferTextureTransform) {
    fillBufferTextureTransform();
}

TEST_F(RenderEngineTest, drawLayers_fillBuffer_premultipliesAlpha) {
    fillBufferWithPremultiplyAlpha();
}

TEST_F(RenderEngineTest, drawLayers_fillBuffer_withoutPremultiplyingAlpha) {
    fillBufferWithoutPremultiplyAlpha();
}

TEST_F(RenderEngineTest, drawLayers_clearRegion) {
    clearRegion();
}

TEST_F(RenderEngineTest, drawLayers_fillsBufferAndCachesImages) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);

    layers.push_back(&layer);
    invokeDraw(settings, layers, mBuffer);
    uint64_t bufferId = layer.source.buffer.buffer->getId();
    EXPECT_TRUE(sRE->isImageCachedForTesting(bufferId));
    std::shared_ptr<renderengine::gl::ImageManager::Barrier> barrier =
            sRE->unbindExternalTextureBufferForTesting(bufferId);
    std::lock_guard<std::mutex> lock(barrier->mutex);
    ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                            [&]() REQUIRES(barrier->mutex) {
                                                return barrier->isOpen;
                                            }));
    EXPECT_FALSE(sRE->isImageCachedForTesting(bufferId));
    EXPECT_EQ(NO_ERROR, barrier->result);
}

TEST_F(RenderEngineTest, bindExternalBuffer_withNullBuffer) {
    status_t result = sRE->bindExternalTextureBuffer(0, nullptr, nullptr);
    ASSERT_EQ(BAD_VALUE, result);
}

TEST_F(RenderEngineTest, bindExternalBuffer_cachesImages) {
    sp<GraphicBuffer> buf = allocateSourceBuffer(1, 1);
    uint32_t texName;
    sRE->genTextures(1, &texName);
    mTexNames.push_back(texName);

    sRE->bindExternalTextureBuffer(texName, buf, nullptr);
    uint64_t bufferId = buf->getId();
    EXPECT_TRUE(sRE->isImageCachedForTesting(bufferId));
    std::shared_ptr<renderengine::gl::ImageManager::Barrier> barrier =
            sRE->unbindExternalTextureBufferForTesting(bufferId);
    std::lock_guard<std::mutex> lock(barrier->mutex);
    ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                            [&]() REQUIRES(barrier->mutex) {
                                                return barrier->isOpen;
                                            }));
    EXPECT_EQ(NO_ERROR, barrier->result);
    EXPECT_FALSE(sRE->isImageCachedForTesting(bufferId));
}

TEST_F(RenderEngineTest, cacheExternalBuffer_withNullBuffer) {
    std::shared_ptr<renderengine::gl::ImageManager::Barrier> barrier =
            sRE->cacheExternalTextureBufferForTesting(nullptr);
    std::lock_guard<std::mutex> lock(barrier->mutex);
    ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                            [&]() REQUIRES(barrier->mutex) {
                                                return barrier->isOpen;
                                            }));
    EXPECT_TRUE(barrier->isOpen);
    EXPECT_EQ(BAD_VALUE, barrier->result);
}

TEST_F(RenderEngineTest, cacheExternalBuffer_cachesImages) {
    sp<GraphicBuffer> buf = allocateSourceBuffer(1, 1);
    uint64_t bufferId = buf->getId();
    std::shared_ptr<renderengine::gl::ImageManager::Barrier> barrier =
            sRE->cacheExternalTextureBufferForTesting(buf);
    {
        std::lock_guard<std::mutex> lock(barrier->mutex);
        ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                                [&]() REQUIRES(barrier->mutex) {
                                                    return barrier->isOpen;
                                                }));
        EXPECT_EQ(NO_ERROR, barrier->result);
    }
    EXPECT_TRUE(sRE->isImageCachedForTesting(bufferId));
    barrier = sRE->unbindExternalTextureBufferForTesting(bufferId);
    {
        std::lock_guard<std::mutex> lock(barrier->mutex);
        ASSERT_TRUE(barrier->condition.wait_for(barrier->mutex, std::chrono::seconds(5),
                                                [&]() REQUIRES(barrier->mutex) {
                                                    return barrier->isOpen;
                                                }));
        EXPECT_EQ(NO_ERROR, barrier->result);
    }
    EXPECT_FALSE(sRE->isImageCachedForTesting(bufferId));
}

TEST_F(RenderEngineTest, drawLayers_fillShadow_casterLayerMinSize) {
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

TEST_F(RenderEngineTest, drawLayers_fillShadow_casterColorLayer) {
    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
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

TEST_F(RenderEngineTest, drawLayers_fillShadow_casterOpaqueBufferLayer) {
    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    renderengine::ShadowSettings settings =
            getShadowSettings(vec2(casterBounds.left, casterBounds.top), shadowLength,
                              false /* casterIsTranslucent */);

    drawShadow<BufferSourceVariant<ForceOpaqueBufferVariant>>(castingLayer, settings, casterColor,
                                                              backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_F(RenderEngineTest, drawLayers_fillShadow_casterWithRoundedCorner) {
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

TEST_F(RenderEngineTest, drawLayers_fillShadow_translucentCasterWithAlpha) {
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

TEST_F(RenderEngineTest, cleanupPostRender_cleansUpOnce) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    base::unique_fd fenceOne;
    sRE->drawLayers(settings, layers, mBuffer->getNativeBuffer(), true, base::unique_fd(),
                    &fenceOne);
    base::unique_fd fenceTwo;
    sRE->drawLayers(settings, layers, mBuffer->getNativeBuffer(), true, std::move(fenceOne),
                    &fenceTwo);

    const int fd = fenceTwo.get();
    if (fd >= 0) {
        sync_wait(fd, -1);
    }
    // Only cleanup the first time.
    EXPECT_TRUE(sRE->cleanupPostRender(
            renderengine::RenderEngine::CleanupMode::CLEAN_OUTPUT_RESOURCES));
    EXPECT_FALSE(sRE->cleanupPostRender(
            renderengine::RenderEngine::CleanupMode::CLEAN_OUTPUT_RESOURCES));
}

TEST_F(RenderEngineTest, cleanupPostRender_whenCleaningAll_replacesTextureMemory) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<const renderengine::LayerSettings*> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(&layer);

    base::unique_fd fence;
    sRE->drawLayers(settings, layers, mBuffer->getNativeBuffer(), true, base::unique_fd(), &fence);

    const int fd = fence.get();
    if (fd >= 0) {
        sync_wait(fd, -1);
    }

    uint64_t bufferId = layer.source.buffer.buffer->getId();
    uint32_t texName = layer.source.buffer.textureName;
    EXPECT_TRUE(sRE->isImageCachedForTesting(bufferId));
    EXPECT_EQ(bufferId, sRE->getBufferIdForTextureNameForTesting(texName));

    EXPECT_TRUE(sRE->cleanupPostRender(renderengine::RenderEngine::CleanupMode::CLEAN_ALL));

    // Now check that our view of memory is good.
    EXPECT_FALSE(sRE->isImageCachedForTesting(bufferId));
    EXPECT_EQ(std::nullopt, sRE->getBufferIdForTextureNameForTesting(bufferId));
    EXPECT_TRUE(sRE->isTextureNameKnownForTesting(texName));
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
