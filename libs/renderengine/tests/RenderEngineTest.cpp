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
#include <renderengine/ExternalTexture.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/impl/ExternalTexture.h>
#include <sync/sync.h>
#include <system/graphics-base-v1.0.h>
#include <tonemap/tonemap.h>
#include <ui/ColorSpace.h>
#include <ui/PixelFormat.h>

#include <chrono>
#include <condition_variable>
#include <fstream>

#include "../skia/SkiaGLRenderEngine.h"
#include "../skia/SkiaVkRenderEngine.h"
#include "../threaded/RenderEngineThreaded.h"

constexpr int DEFAULT_DISPLAY_WIDTH = 128;
constexpr int DEFAULT_DISPLAY_HEIGHT = 256;
constexpr int DEFAULT_DISPLAY_OFFSET = 64;
constexpr bool WRITE_BUFFER_TO_FILE_ON_FAILURE = false;

namespace android {
namespace renderengine {

namespace {

double EOTF_PQ(double channel) {
    float m1 = (2610.0 / 4096.0) / 4.0;
    float m2 = (2523.0 / 4096.0) * 128.0;
    float c1 = (3424.0 / 4096.0);
    float c2 = (2413.0 / 4096.0) * 32.0;
    float c3 = (2392.0 / 4096.0) * 32.0;

    float tmp = std::pow(std::clamp(channel, 0.0, 1.0), 1.0 / m2);
    tmp = std::fmax(tmp - c1, 0.0) / (c2 - c3 * tmp);
    return std::pow(tmp, 1.0 / m1);
}

vec3 EOTF_PQ(vec3 color) {
    return vec3(EOTF_PQ(color.r), EOTF_PQ(color.g), EOTF_PQ(color.b));
}

double EOTF_HLG(double channel) {
    const float a = 0.17883277;
    const float b = 0.28466892;
    const float c = 0.55991073;
    return channel <= 0.5 ? channel * channel / 3.0 : (exp((channel - c) / a) + b) / 12.0;
}

vec3 EOTF_HLG(vec3 color) {
    return vec3(EOTF_HLG(color.r), EOTF_HLG(color.g), EOTF_HLG(color.b));
}

double OETF_sRGB(double channel) {
    return channel <= 0.0031308 ? channel * 12.92 : (pow(channel, 1.0 / 2.4) * 1.055) - 0.055;
}

int sign(float in) {
    return in >= 0.0 ? 1 : -1;
}

vec3 OETF_sRGB(vec3 linear) {
    return vec3(sign(linear.r) * OETF_sRGB(linear.r), sign(linear.g) * OETF_sRGB(linear.g),
                sign(linear.b) * OETF_sRGB(linear.b));
}

// clang-format off
// Converts red channels to green channels, and zeroes out an existing green channel.
static const auto kRemoveGreenAndMoveRedToGreenMat4 = mat4(0, 1, 0, 0,
                                                           0, 0, 0, 0,
                                                           0, 0, 1, 0,
                                                           0, 0, 0, 1);
// clang-format on

} // namespace

class RenderEngineFactory {
public:
    virtual ~RenderEngineFactory() = default;

    virtual std::string name() = 0;
    virtual renderengine::RenderEngine::RenderEngineType type() = 0;
    virtual bool typeSupported() = 0;
    std::unique_ptr<renderengine::RenderEngine> createRenderEngine() {
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
        return renderengine::RenderEngine::create(reCreationArgs);
    }
};

class SkiaVkRenderEngineFactory : public RenderEngineFactory {
public:
    std::string name() override { return "SkiaVkRenderEngineFactory"; }

    renderengine::RenderEngine::RenderEngineType type() {
        return renderengine::RenderEngine::RenderEngineType::SKIA_VK;
    }

    bool typeSupported() override {
        return skia::SkiaVkRenderEngine::canSupportSkiaVkRenderEngine();
    }
};

class SkiaGLESRenderEngineFactory : public RenderEngineFactory {
public:
    std::string name() override { return "SkiaGLRenderEngineFactory"; }

    renderengine::RenderEngine::RenderEngineType type() {
        return renderengine::RenderEngine::RenderEngineType::SKIA_GL;
    }

    bool typeSupported() override { return true; }
};

class RenderEngineTest : public ::testing::TestWithParam<std::shared_ptr<RenderEngineFactory>> {
public:
    std::shared_ptr<renderengine::ExternalTexture> allocateDefaultBuffer() {
        return std::make_shared<
                renderengine::impl::
                        ExternalTexture>(sp<GraphicBuffer>::
                                                 make(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT,
                                                      HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                      GRALLOC_USAGE_SW_READ_OFTEN |
                                                              GRALLOC_USAGE_SW_WRITE_OFTEN |
                                                              GRALLOC_USAGE_HW_RENDER |
                                                              GRALLOC_USAGE_HW_TEXTURE,
                                                      "output"),
                                         *mRE,
                                         renderengine::impl::ExternalTexture::Usage::READABLE |
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         WRITEABLE);
    }

    // Allocates a 1x1 buffer to fill with a solid color
    std::shared_ptr<renderengine::ExternalTexture> allocateSourceBuffer(uint32_t width,
                                                                        uint32_t height) {
        return std::make_shared<
                renderengine::impl::
                        ExternalTexture>(sp<GraphicBuffer>::
                                                 make(width, height, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                      GRALLOC_USAGE_SW_READ_OFTEN |
                                                              GRALLOC_USAGE_SW_WRITE_OFTEN |
                                                              GRALLOC_USAGE_HW_TEXTURE,
                                                      "input"),
                                         *mRE,
                                         renderengine::impl::ExternalTexture::Usage::READABLE |
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         WRITEABLE);
    }

    std::shared_ptr<renderengine::ExternalTexture> allocateAndFillSourceBuffer(uint32_t width,
                                                                               uint32_t height,
                                                                               ubyte4 color) {
        const auto buffer = allocateSourceBuffer(width, height);
        uint8_t* pixels;
        buffer->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                                  reinterpret_cast<void**>(&pixels));
        for (uint32_t j = 0; j < height; j++) {
            uint8_t* dst = pixels + (buffer->getBuffer()->getStride() * j * 4);
            for (uint32_t i = 0; i < width; i++) {
                dst[0] = color.r;
                dst[1] = color.g;
                dst[2] = color.b;
                dst[3] = color.a;
                dst += 4;
            }
        }
        buffer->getBuffer()->unlock();
        return buffer;
    }

    std::shared_ptr<renderengine::ExternalTexture> allocateR8Buffer(int width, int height) {
        const auto kUsageFlags =
                static_cast<uint64_t>(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
                                      GRALLOC_USAGE_HW_TEXTURE);
        auto buffer =
                sp<GraphicBuffer>::make(static_cast<uint32_t>(width), static_cast<uint32_t>(height),
                                        android::PIXEL_FORMAT_R_8, 1u, kUsageFlags, "r8");
        if (buffer->initCheck() != 0) {
            // Devices are not required to support R8.
            return nullptr;
        }
        return std::make_shared<
                renderengine::impl::ExternalTexture>(std::move(buffer), *mRE,
                                                     renderengine::impl::ExternalTexture::Usage::
                                                             READABLE);
    }

    RenderEngineTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    ~RenderEngineTest() {
        if (WRITE_BUFFER_TO_FILE_ON_FAILURE && ::testing::Test::HasFailure()) {
            writeBufferToFile("/data/texture_out_");
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
        mBuffer->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                                   reinterpret_cast<void**>(&pixels));

        file << "P6\n";
        file << mBuffer->getBuffer()->getWidth() << "\n";
        file << mBuffer->getBuffer()->getHeight() << "\n";
        file << 255 << "\n";

        std::vector<uint8_t> outBuffer(mBuffer->getBuffer()->getWidth() *
                                       mBuffer->getBuffer()->getHeight() * 3);
        auto outPtr = reinterpret_cast<uint8_t*>(outBuffer.data());

        for (int32_t j = 0; j < mBuffer->getBuffer()->getHeight(); j++) {
            const uint8_t* src = pixels + (mBuffer->getBuffer()->getStride() * j) * 4;
            for (int32_t i = 0; i < mBuffer->getBuffer()->getWidth(); i++) {
                // Only copy R, G and B components
                outPtr[0] = src[0];
                outPtr[1] = src[1];
                outPtr[2] = src[2];
                outPtr += 3;

                src += 4;
            }
        }
        file.write(reinterpret_cast<char*>(outBuffer.data()), outBuffer.size());
        mBuffer->getBuffer()->unlock();
    }

    void expectBufferColor(const Region& region, uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
        size_t c;
        Rect const* rect = region.getArray(&c);
        for (size_t i = 0; i < c; i++, rect++) {
            expectBufferColor(*rect, r, g, b, a);
        }
    }

    void expectBufferColor(const Point& point, uint8_t r, uint8_t g, uint8_t b, uint8_t a,
                           uint8_t tolerance = 0) {
        expectBufferColor(Rect(point.x, point.y, point.x + 1, point.y + 1), r, g, b, a, tolerance);
    }

    void expectBufferColor(const Rect& rect, uint8_t r, uint8_t g, uint8_t b, uint8_t a,
                           uint8_t tolerance = 0) {
        auto generator = [=](Point) { return ubyte4(r, g, b, a); };
        expectBufferColor(rect, generator, tolerance);
    }

    using ColorGenerator = std::function<ubyte4(Point location)>;

    void expectBufferColor(const Rect& rect, ColorGenerator generator, uint8_t tolerance = 0) {
        auto colorCompare = [tolerance](const uint8_t* colorA, const uint8_t* colorB) {
            auto colorBitCompare = [tolerance](uint8_t a, uint8_t b) {
                uint8_t tmp = a >= b ? a - b : b - a;
                return tmp <= tolerance;
            };
            return std::equal(colorA, colorA + 4, colorB, colorBitCompare);
        };

        expectBufferColor(rect, generator, colorCompare);
    }

    void expectBufferColor(const Rect& region, ColorGenerator generator,
                           std::function<bool(const uint8_t* a, const uint8_t* b)> colorCompare) {
        uint8_t* pixels;
        mBuffer->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                                   reinterpret_cast<void**>(&pixels));
        int32_t maxFails = 10;
        int32_t fails = 0;
        for (int32_t j = 0; j < region.getHeight(); j++) {
            const uint8_t* src = pixels +
                    (mBuffer->getBuffer()->getStride() * (region.top + j) + region.left) * 4;
            for (int32_t i = 0; i < region.getWidth(); i++) {
                const auto location = Point(region.left + i, region.top + j);
                const ubyte4 colors = generator(location);
                const uint8_t expected[4] = {colors.r, colors.g, colors.b, colors.a};
                bool colorMatches = colorCompare(src, expected);
                EXPECT_TRUE(colorMatches)
                        << GetParam()->name().c_str() << ": "
                        << "pixel @ (" << location.x << ", " << location.y << "): "
                        << "expected (" << static_cast<uint32_t>(colors.r) << ", "
                        << static_cast<uint32_t>(colors.g) << ", "
                        << static_cast<uint32_t>(colors.b) << ", "
                        << static_cast<uint32_t>(colors.a) << "), "
                        << "got (" << static_cast<uint32_t>(src[0]) << ", "
                        << static_cast<uint32_t>(src[1]) << ", " << static_cast<uint32_t>(src[2])
                        << ", " << static_cast<uint32_t>(src[3]) << ")";
                src += 4;
                if (!colorMatches && ++fails >= maxFails) {
                    break;
                }
            }
            if (fails >= maxFails) {
                break;
            }
        }
        mBuffer->getBuffer()->unlock();
    }

    void expectAlpha(const Rect& rect, uint8_t a) {
        auto generator = [=](Point) { return ubyte4(0, 0, 0, a); };
        auto colorCompare = [](const uint8_t* colorA, const uint8_t* colorB) {
            return colorA[3] == colorB[3];
        };
        expectBufferColor(rect, generator, colorCompare);
    }

    void expectShadowColor(const renderengine::LayerSettings& castingLayer,
                           const ShadowSettings& shadow, const ubyte4& casterColor,
                           const ubyte4& backgroundColor) {
        const Rect casterRect(castingLayer.geometry.boundaries);
        Region casterRegion = Region(casterRect);
        const float casterCornerRadius = (castingLayer.geometry.roundedCornersRadius.x +
                                          castingLayer.geometry.roundedCornersRadius.y) /
                2.0;
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

    void expectShadowColorWithoutCaster(const FloatRect& casterBounds, const ShadowSettings& shadow,
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

    static ShadowSettings getShadowSettings(const vec2& casterPos, float shadowLength,
                                            bool casterIsTranslucent) {
        ShadowSettings shadow;
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

    void invokeDraw(const renderengine::DisplaySettings& settings,
                    const std::vector<renderengine::LayerSettings>& layers) {
        ftl::Future<FenceResult> future =
                mRE->drawLayers(settings, layers, mBuffer, base::unique_fd());
        ASSERT_TRUE(future.valid());

        auto result = future.get();
        ASSERT_TRUE(result.ok());

        auto fence = result.value();
        fence->waitForever(LOG_TAG);
    }

    void drawEmptyLayers() {
        renderengine::DisplaySettings settings;
        std::vector<renderengine::LayerSettings> layers;
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
    void fillBufferWithColorTransformAndSourceDataspace(const ui::Dataspace sourceDataspace);

    template <typename SourceVariant>
    void fillBufferColorTransformAndSourceDataspace();

    template <typename SourceVariant>
    void fillBufferWithColorTransformAndOutputDataspace(const ui::Dataspace outputDataspace);

    template <typename SourceVariant>
    void fillBufferColorTransformAndOutputDataspace();

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
    void fillSmallLayerAndBlurBackground();

    template <typename SourceVariant>
    void overlayCorners();

    void fillRedBufferTextureTransform();

    void fillBufferTextureTransform();

    void fillRedBufferWithPremultiplyAlpha();

    void fillBufferWithPremultiplyAlpha();

    void fillRedBufferWithoutPremultiplyAlpha();

    void fillBufferWithoutPremultiplyAlpha();

    void fillGreenColorBufferThenClearRegion();

    template <typename SourceVariant>
    void drawShadow(const renderengine::LayerSettings& castingLayer, const ShadowSettings& shadow,
                    const ubyte4& casterColor, const ubyte4& backgroundColor);

    void drawShadowWithoutCaster(const FloatRect& castingBounds, const ShadowSettings& shadow,
                                 const ubyte4& backgroundColor);

    // Tonemaps grey values from sourceDataspace -> Display P3 and checks that GPU and CPU
    // implementations are identical Also implicitly checks that the injected tonemap shader
    // compiles
    void tonemap(ui::Dataspace sourceDataspace, std::function<vec3(vec3)> eotf,
                 std::function<vec3(vec3, float)> scaleOotf);

    void initializeRenderEngine();

    std::unique_ptr<renderengine::RenderEngine> mRE;
    std::shared_ptr<renderengine::ExternalTexture> mBuffer;
};

void RenderEngineTest::initializeRenderEngine() {
    const auto& renderEngineFactory = GetParam();
    mRE = renderEngineFactory->createRenderEngine();
    mBuffer = allocateDefaultBuffer();
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
        const auto buf = fixture->allocateSourceBuffer(1, 1);

        uint8_t* pixels;
        buf->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                               reinterpret_cast<void**>(&pixels));

        for (int32_t j = 0; j < buf->getBuffer()->getHeight(); j++) {
            uint8_t* iter = pixels + (buf->getBuffer()->getStride() * j) * 4;
            for (int32_t i = 0; i < buf->getBuffer()->getWidth(); i++) {
                iter[0] = uint8_t(r * 255);
                iter[1] = uint8_t(g * 255);
                iter[2] = uint8_t(b * 255);
                iter[3] = OpaquenessVariant::getAlphaChannel();
                iter += 4;
            }
        }

        buf->getBuffer()->unlock();

        layer.source.buffer.buffer = buf;
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

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(layer, r, g, b, this);
    layer.alpha = a;

    layers.push_back(layer);

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

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = offsetRectAtZero().toFloatRect();
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0f;

    layers.push_back(layer);
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

    std::vector<renderengine::LayerSettings> layers;

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

    layers.push_back(layerOne);
    layers.push_back(layerTwo);
    layers.push_back(layerThree);

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

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    // Translate one pixel diagonally
    layer.geometry.positionTransform = mat4(1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1);
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    layer.alpha = 1.0f;

    layers.push_back(layer);

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

    std::vector<renderengine::LayerSettings> layers;

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

    layers.push_back(layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferWithColorTransformAndSourceDataspace(
        const ui::Dataspace sourceDataspace) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    SourceVariant::fillColor(layer, 0.5f, 0.25f, 0.125f, this);
    layer.sourceDataspace = sourceDataspace;
    layer.alpha = 1.0f;

    // construct a fake color matrix
    // annihilate green and blue channels
    settings.colorTransform = mat4::scale(vec4(0.9f, 0, 0, 1));
    // set red channel to red + green
    layer.colorTransform = mat4(1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1);

    layer.alpha = 1.0f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferColorTransform() {
    fillBufferWithColorTransform<SourceVariant>();
    expectBufferColor(fullscreenRect(), 172, 0, 0, 255, 1);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferColorTransformAndSourceDataspace() {
    unordered_map<ui::Dataspace, ubyte4> dataspaceToColorMap;
    dataspaceToColorMap[ui::Dataspace::V0_BT709] = {77, 0, 0, 255};
    dataspaceToColorMap[ui::Dataspace::BT2020] = {101, 0, 0, 255};
    dataspaceToColorMap[ui::Dataspace::ADOBE_RGB] = {75, 0, 0, 255};
    ui::Dataspace customizedDataspace = static_cast<ui::Dataspace>(
            ui::Dataspace::STANDARD_BT709 | ui::Dataspace::TRANSFER_GAMMA2_2 |
            ui::Dataspace::RANGE_FULL);
    dataspaceToColorMap[customizedDataspace] = {61, 0, 0, 255};
    for (const auto& [sourceDataspace, color] : dataspaceToColorMap) {
        fillBufferWithColorTransformAndSourceDataspace<SourceVariant>(sourceDataspace);
        expectBufferColor(fullscreenRect(), color.r, color.g, color.b, color.a, 1);
    }
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferWithColorTransformAndOutputDataspace(
        const ui::Dataspace outputDataspace) {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);
    settings.outputDataspace = outputDataspace;

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SCRGB_LINEAR;
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

    layers.push_back(layer);

    invokeDraw(settings, layers);
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferColorTransformAndOutputDataspace() {
    unordered_map<ui::Dataspace, ubyte4> dataspaceToColorMap;
    dataspaceToColorMap[ui::Dataspace::V0_BT709] = {198, 0, 0, 255};
    dataspaceToColorMap[ui::Dataspace::BT2020] = {187, 0, 0, 255};
    dataspaceToColorMap[ui::Dataspace::ADOBE_RGB] = {192, 0, 0, 255};
    ui::Dataspace customizedDataspace = static_cast<ui::Dataspace>(
            ui::Dataspace::STANDARD_BT709 | ui::Dataspace::TRANSFER_GAMMA2_6 |
            ui::Dataspace::RANGE_FULL);
    dataspaceToColorMap[customizedDataspace] = {205, 0, 0, 255};
    for (const auto& [outputDataspace, color] : dataspaceToColorMap) {
        fillBufferWithColorTransformAndOutputDataspace<SourceVariant>(outputDataspace);
        expectBufferColor(fullscreenRect(), color.r, color.g, color.b, color.a, 1);
    }
}

template <typename SourceVariant>
void RenderEngineTest::fillBufferWithColorTransformZeroLayerAlpha() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = Rect(1, 1);

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();
    SourceVariant::fillColor(layer, 0.5f, 0.25f, 0.125f, this);
    layer.alpha = 0;

    // construct a fake color matrix
    // simple inverse color
    settings.colorTransform = mat4(-1, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 1, 1, 1, 1);

    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(layer);

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

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    layer.geometry.roundedCornersRadius = {5.0f, 5.0f};
    layer.geometry.roundedCornersCrop = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0f;

    layers.push_back(layer);

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
    auto blurRadius = 50;
    auto center = DEFAULT_DISPLAY_WIDTH / 2;

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings backgroundLayer;
    backgroundLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    backgroundLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(backgroundLayer, 0.0f, 1.0f, 0.0f, this);
    backgroundLayer.alpha = 1.0f;
    layers.emplace_back(backgroundLayer);

    renderengine::LayerSettings leftLayer;
    leftLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    leftLayer.geometry.boundaries =
            Rect(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT).toFloatRect();
    SourceVariant::fillColor(leftLayer, 1.0f, 0.0f, 0.0f, this);
    leftLayer.alpha = 1.0f;
    layers.emplace_back(leftLayer);

    renderengine::LayerSettings blurLayer;
    blurLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    blurLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    blurLayer.backgroundBlurRadius = blurRadius;
    SourceVariant::fillColor(blurLayer, 0.0f, 0.0f, 1.0f, this);
    blurLayer.alpha = 0;
    layers.emplace_back(blurLayer);

    invokeDraw(settings, layers);

    // solid color
    expectBufferColor(Rect(0, 0, 1, 1), 255, 0, 0, 255, 0 /* tolerance */);

    if (mRE->supportsBackgroundBlur()) {
        // blurred color (downsampling should result in the center color being close to 128)
        expectBufferColor(Rect(center - 1, center - 5, center + 1, center + 5), 128, 128, 0, 255,
                          50 /* tolerance */);
    }
}

template <typename SourceVariant>
void RenderEngineTest::fillSmallLayerAndBlurBackground() {
    auto blurRadius = 50;
    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings backgroundLayer;
    backgroundLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    backgroundLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    SourceVariant::fillColor(backgroundLayer, 1.0f, 0.0f, 0.0f, this);
    backgroundLayer.alpha = 1.0f;
    layers.push_back(backgroundLayer);

    renderengine::LayerSettings blurLayer;
    blurLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    blurLayer.geometry.boundaries = FloatRect(0.f, 0.f, 1.f, 1.f);
    blurLayer.backgroundBlurRadius = blurRadius;
    SourceVariant::fillColor(blurLayer, 0.0f, 0.0f, 1.0f, this);
    blurLayer.alpha = 0;
    layers.push_back(blurLayer);

    invokeDraw(settings, layers);

    // Give a generous tolerance - the blur rectangle is very small and this test is
    // mainly concerned with ensuring that there's no device failure.
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT), 255, 0, 0, 255,
                      40 /* tolerance */);
}

template <typename SourceVariant>
void RenderEngineTest::overlayCorners() {
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<renderengine::LayerSettings> layersFirst;

    renderengine::LayerSettings layerOne;
    layerOne.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layerOne.geometry.boundaries =
            FloatRect(0, 0, DEFAULT_DISPLAY_WIDTH / 3.0, DEFAULT_DISPLAY_HEIGHT / 3.0);
    SourceVariant::fillColor(layerOne, 1.0f, 0.0f, 0.0f, this);
    layerOne.alpha = 0.2;

    layersFirst.push_back(layerOne);
    invokeDraw(settings, layersFirst);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3, DEFAULT_DISPLAY_HEIGHT / 3), 51, 0, 0, 51);
    expectBufferColor(Rect(DEFAULT_DISPLAY_WIDTH / 3 + 1, DEFAULT_DISPLAY_HEIGHT / 3 + 1,
                           DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT),
                      0, 0, 0, 0);

    std::vector<renderengine::LayerSettings> layersSecond;
    renderengine::LayerSettings layerTwo;
    layerTwo.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    layerTwo.geometry.boundaries =
            FloatRect(DEFAULT_DISPLAY_WIDTH / 3.0, DEFAULT_DISPLAY_HEIGHT / 3.0,
                      DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT);
    SourceVariant::fillColor(layerTwo, 0.0f, 1.0f, 0.0f, this);
    layerTwo.alpha = 1.0f;

    layersSecond.push_back(layerTwo);
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

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    // Here will allocate a checker board texture, but transform texture
    // coordinates so that only the upper left is applied.
    const auto buf = allocateSourceBuffer(2, 2);

    uint8_t* pixels;
    buf->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
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
    buf->getBuffer()->unlock();

    layer.source.buffer.buffer = buf;
    // Transform coordinates to only be inside the red quadrant.
    layer.source.buffer.textureTransform = mat4::scale(vec4(0.2f, 0.2f, 1.f, 1.f));
    layer.alpha = 1.0f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(layer);

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

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    const auto buf = allocateSourceBuffer(1, 1);

    uint8_t* pixels;
    buf->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                           reinterpret_cast<void**>(&pixels));
    pixels[0] = 255;
    pixels[1] = 0;
    pixels[2] = 0;
    pixels[3] = 255;
    buf->getBuffer()->unlock();

    layer.source.buffer.buffer = buf;
    layer.source.buffer.usePremultipliedAlpha = true;
    layer.alpha = 0.5f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(layer);

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

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings layer;
    const auto buf = allocateSourceBuffer(1, 1);

    uint8_t* pixels;
    buf->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                           reinterpret_cast<void**>(&pixels));
    pixels[0] = 255;
    pixels[1] = 0;
    pixels[2] = 0;
    pixels[3] = 255;
    buf->getBuffer()->unlock();

    layer.source.buffer.buffer = buf;
    layer.source.buffer.usePremultipliedAlpha = false;
    layer.alpha = 0.5f;
    layer.geometry.boundaries = Rect(1, 1).toFloatRect();

    layers.push_back(layer);

    invokeDraw(settings, layers);
}

void RenderEngineTest::fillBufferWithoutPremultiplyAlpha() {
    fillRedBufferWithoutPremultiplyAlpha();
    expectBufferColor(fullscreenRect(), 128, 0, 0, 128, 1);
}

template <typename SourceVariant>
void RenderEngineTest::drawShadow(const renderengine::LayerSettings& castingLayer,
                                  const ShadowSettings& shadow, const ubyte4& casterColor,
                                  const ubyte4& backgroundColor) {
    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<renderengine::LayerSettings> layers;

    // add background layer
    renderengine::LayerSettings bgLayer;
    bgLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    bgLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    ColorSourceVariant::fillColor(bgLayer, backgroundColor.r / 255.0f, backgroundColor.g / 255.0f,
                                  backgroundColor.b / 255.0f, this);
    bgLayer.alpha = backgroundColor.a / 255.0f;
    layers.push_back(bgLayer);

    // add shadow layer
    renderengine::LayerSettings shadowLayer;
    shadowLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    shadowLayer.geometry.boundaries = castingLayer.geometry.boundaries;
    shadowLayer.alpha = castingLayer.alpha;
    shadowLayer.shadow = shadow;
    layers.push_back(shadowLayer);

    // add layer casting the shadow
    renderengine::LayerSettings layer = castingLayer;
    layer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    SourceVariant::fillColor(layer, casterColor.r / 255.0f, casterColor.g / 255.0f,
                             casterColor.b / 255.0f, this);
    layers.push_back(layer);

    invokeDraw(settings, layers);
}

void RenderEngineTest::drawShadowWithoutCaster(const FloatRect& castingBounds,
                                               const ShadowSettings& shadow,
                                               const ubyte4& backgroundColor) {
    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    std::vector<renderengine::LayerSettings> layers;

    // add background layer
    renderengine::LayerSettings bgLayer;
    bgLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    bgLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    ColorSourceVariant::fillColor(bgLayer, backgroundColor.r / 255.0f, backgroundColor.g / 255.0f,
                                  backgroundColor.b / 255.0f, this);
    bgLayer.alpha = backgroundColor.a / 255.0f;
    layers.push_back(bgLayer);

    // add shadow layer
    renderengine::LayerSettings shadowLayer;
    shadowLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    shadowLayer.geometry.boundaries = castingBounds;
    shadowLayer.skipContentDraw = true;
    shadowLayer.alpha = 1.0f;
    ColorSourceVariant::fillColor(shadowLayer, 0, 0, 0, this);
    shadowLayer.shadow = shadow;
    layers.push_back(shadowLayer);

    invokeDraw(settings, layers);
}

void RenderEngineTest::tonemap(ui::Dataspace sourceDataspace, std::function<vec3(vec3)> eotf,
                               std::function<vec3(vec3, float)> scaleOotf) {
    constexpr int32_t kGreyLevels = 256;

    const auto rect = Rect(0, 0, kGreyLevels, 1);

    constexpr float kMaxLuminance = 750.f;
    constexpr float kCurrentLuminanceNits = 500.f;
    const renderengine::DisplaySettings display{
            .physicalDisplay = rect,
            .clip = rect,
            .maxLuminance = kMaxLuminance,
            .currentLuminanceNits = kCurrentLuminanceNits,
            .outputDataspace = ui::Dataspace::DISPLAY_P3,
    };

    auto buf = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(kGreyLevels, 1,
                                                             HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                             GRALLOC_USAGE_SW_READ_OFTEN |
                                                                     GRALLOC_USAGE_SW_WRITE_OFTEN |
                                                                     GRALLOC_USAGE_HW_RENDER |
                                                                     GRALLOC_USAGE_HW_TEXTURE,
                                                             "input"),
                                     *mRE,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    ASSERT_EQ(0, buf->getBuffer()->initCheck());
    {
        uint8_t* pixels;
        buf->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                               reinterpret_cast<void**>(&pixels));

        uint8_t color = 0;
        for (int32_t j = 0; j < buf->getBuffer()->getHeight(); j++) {
            uint8_t* dest = pixels + (buf->getBuffer()->getStride() * j * 4);
            for (int32_t i = 0; i < buf->getBuffer()->getWidth(); i++) {
                dest[0] = color;
                dest[1] = color;
                dest[2] = color;
                dest[3] = 255;
                color++;
                dest += 4;
            }
        }
        buf->getBuffer()->unlock();
    }

    mBuffer = std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::make(kGreyLevels, 1,
                                                             HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                             GRALLOC_USAGE_SW_READ_OFTEN |
                                                                     GRALLOC_USAGE_SW_WRITE_OFTEN |
                                                                     GRALLOC_USAGE_HW_RENDER |
                                                                     GRALLOC_USAGE_HW_TEXTURE,
                                                             "output"),
                                     *mRE,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
    ASSERT_EQ(0, mBuffer->getBuffer()->initCheck());

    const renderengine::LayerSettings layer{.geometry.boundaries = rect.toFloatRect(),
                                            .source =
                                                    renderengine::PixelSource{
                                                            .buffer =
                                                                    renderengine::Buffer{
                                                                            .buffer =
                                                                                    std::move(buf),
                                                                            .usePremultipliedAlpha =
                                                                                    true,
                                                                    },
                                                    },
                                            .alpha = 1.0f,
                                            .sourceDataspace = sourceDataspace};

    std::vector<renderengine::LayerSettings> layers{layer};
    invokeDraw(display, layers);

    ColorSpace displayP3 = ColorSpace::DisplayP3();
    ColorSpace bt2020 = ColorSpace::BT2020();

    tonemap::Metadata metadata{.displayMaxLuminance = 750.0f};

    auto generator = [=](Point location) {
        const double normColor = static_cast<double>(location.x) / (kGreyLevels - 1);
        const vec3 rgb = vec3(normColor, normColor, normColor);

        const vec3 linearRGB = eotf(rgb);

        const vec3 xyz = bt2020.getRGBtoXYZ() * linearRGB;

        const vec3 scaledXYZ = scaleOotf(xyz, kCurrentLuminanceNits);
        const auto gains =
                tonemap::getToneMapper()
                        ->lookupTonemapGain(static_cast<aidl::android::hardware::graphics::common::
                                                                Dataspace>(sourceDataspace),
                                            static_cast<aidl::android::hardware::graphics::common::
                                                                Dataspace>(
                                                    ui::Dataspace::DISPLAY_P3),
                                            {tonemap::
                                                     Color{.linearRGB =
                                                                   scaleOotf(linearRGB,
                                                                             kCurrentLuminanceNits),
                                                           .xyz = scaledXYZ}},
                                            metadata);
        EXPECT_EQ(1, gains.size());
        const double gain = gains.front();
        const vec3 normalizedXYZ = scaledXYZ * gain / metadata.displayMaxLuminance;

        const vec3 targetRGB = OETF_sRGB(displayP3.getXYZtoRGB() * normalizedXYZ) * 255;
        return ubyte4(static_cast<uint8_t>(targetRGB.r), static_cast<uint8_t>(targetRGB.g),
                      static_cast<uint8_t>(targetRGB.b), 255);
    };

    expectBufferColor(Rect(kGreyLevels, 1), generator, 2);
}

INSTANTIATE_TEST_SUITE_P(PerRenderEngineType, RenderEngineTest,
                         testing::Values(std::make_shared<SkiaGLESRenderEngineFactory>(),
                                         std::make_shared<SkiaVkRenderEngineFactory>()));

TEST_P(RenderEngineTest, drawLayers_noLayersToDraw) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    drawEmptyLayers();
}

TEST_P(RenderEngineTest, drawLayers_fillRedBufferAndEmptyBuffer) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    // add a red layer
    renderengine::LayerSettings layerOne{
            .geometry.boundaries = fullscreenRect().toFloatRect(),
            .source.solidColor = half3(1.0f, 0.0f, 0.0f),
            .alpha = 1.f,
    };

    std::vector<renderengine::LayerSettings> layersFirst{layerOne};
    invokeDraw(settings, layersFirst);
    expectBufferColor(fullscreenRect(), 255, 0, 0, 255);

    // re-draw with an empty layer above it, and we get a transparent black one
    std::vector<renderengine::LayerSettings> layersSecond;
    invokeDraw(settings, layersSecond);
    expectBufferColor(fullscreenRect(), 0, 0, 0, 0);
}

TEST_P(RenderEngineTest, drawLayers_withoutBuffers_withColorTransform) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();

    // 255, 255, 255, 255 is full opaque white.
    const ubyte4 backgroundColor(static_cast<uint8_t>(255), static_cast<uint8_t>(255),
                                 static_cast<uint8_t>(255), static_cast<uint8_t>(255));
    // Create layer with given color.
    renderengine::LayerSettings bgLayer;
    bgLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    bgLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    bgLayer.source.solidColor = half3(backgroundColor.r / 255.0f, backgroundColor.g / 255.0f,
                                      backgroundColor.b / 255.0f);
    bgLayer.alpha = backgroundColor.a / 255.0f;
    // Transform the red color.
    bgLayer.colorTransform = mat4(-1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1);

    std::vector<renderengine::LayerSettings> layers;
    layers.push_back(bgLayer);

    invokeDraw(settings, layers);

    // Expect to see full opaque pixel (with inverted red from the transform).
    expectBufferColor(Rect(0, 0, 10, 10), 0.f, backgroundColor.g, backgroundColor.b,
                      backgroundColor.a);
}

TEST_P(RenderEngineTest, drawLayers_nullOutputBuffer) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    std::vector<renderengine::LayerSettings> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layers.push_back(layer);
    ftl::Future<FenceResult> future = mRE->drawLayers(settings, layers, nullptr, base::unique_fd());

    ASSERT_TRUE(future.valid());
    auto result = future.get();
    ASSERT_FALSE(result.ok());
    ASSERT_EQ(BAD_VALUE, result.error());
}

TEST_P(RenderEngineTest, drawLayers_fillRedBuffer_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillRedBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillGreenBuffer_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillGreenBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBlueBuffer_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBlueBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedTransparentBuffer_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillRedTransparentBuffer<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferPhysicalOffset<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate0<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate90<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate180<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate270<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferLayerTransform_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferLayerTransform<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferColorTransform<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_sourceDataspace) {
    const auto& renderEngineFactory = GetParam();
    // skip for non color management
    if (!renderEngineFactory->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();
    fillBufferColorTransformAndSourceDataspace<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_outputDataspace) {
    const auto& renderEngineFactory = GetParam();
    // skip for non color management
    if (!renderEngineFactory->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();
    fillBufferColorTransformAndOutputDataspace<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferRoundedCorners_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferWithRoundedCorners<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferColorTransformZeroLayerAlpha<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferAndBlurBackground<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillSmallLayerAndBlurBackground_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillSmallLayerAndBlurBackground<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_overlayCorners_colorSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    overlayCorners<ColorSourceVariant>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedBuffer_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillRedBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillGreenBuffer_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillGreenBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBlueBuffer_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBlueBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedTransparentBuffer_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillRedTransparentBuffer<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferPhysicalOffset<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate0<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate90<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate180<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate270<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferLayerTransform_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferLayerTransform<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferColorTransform<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformAndSourceDataspace_opaqueBufferSource) {
    const auto& renderEngineFactory = GetParam();
    // skip for non color management
    if (!renderEngineFactory->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();
    fillBufferColorTransformAndSourceDataspace<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformAndOutputDataspace_opaqueBufferSource) {
    const auto& renderEngineFactory = GetParam();
    // skip for non color management
    if (!renderEngineFactory->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();
    fillBufferColorTransformAndOutputDataspace<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferRoundedCorners_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferWithRoundedCorners<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferColorTransformZeroLayerAlpha<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferAndBlurBackground<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillSmallLayerAndBlurBackground_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillSmallLayerAndBlurBackground<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_overlayCorners_opaqueBufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    overlayCorners<BufferSourceVariant<ForceOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedBuffer_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillRedBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillGreenBuffer_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillGreenBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBlueBuffer_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBlueBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillRedTransparentBuffer_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillRedTransparentBuffer<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferPhysicalOffset_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferPhysicalOffset<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate0_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate0<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate90_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate90<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate180_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate180<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferCheckersRotate270_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferCheckersRotate270<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferLayerTransform_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferLayerTransform<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransform_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferColorTransform<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformAndSourceDataspace_bufferSource) {
    const auto& renderEngineFactory = GetParam();
    // skip for non color management
    if (!renderEngineFactory->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();
    fillBufferColorTransformAndSourceDataspace<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformAndOutputDataspace_bufferSource) {
    const auto& renderEngineFactory = GetParam();
    // skip for non color management
    if (!renderEngineFactory->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();
    fillBufferColorTransformAndOutputDataspace<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferRoundedCorners_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferWithRoundedCorners<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferColorTransformZeroLayerAlpha_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferColorTransformZeroLayerAlpha<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferAndBlurBackground_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferAndBlurBackground<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillSmallLayerAndBlurBackground_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillSmallLayerAndBlurBackground<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_overlayCorners_bufferSource) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    overlayCorners<BufferSourceVariant<RelaxOpaqueBufferVariant>>();
}

TEST_P(RenderEngineTest, drawLayers_fillBufferTextureTransform) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferTextureTransform();
}

TEST_P(RenderEngineTest, drawLayers_fillBuffer_premultipliesAlpha) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferWithPremultiplyAlpha();
}

TEST_P(RenderEngineTest, drawLayers_fillBuffer_withoutPremultiplyingAlpha) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();
    fillBufferWithoutPremultiplyAlpha();
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_castsWithoutCasterLayer) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ubyte4 backgroundColor(static_cast<uint8_t>(255), static_cast<uint8_t>(255),
                                 static_cast<uint8_t>(255), static_cast<uint8_t>(255));
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    ShadowSettings settings = getShadowSettings(vec2(casterBounds.left, casterBounds.top),
                                                shadowLength, false /* casterIsTranslucent */);

    drawShadowWithoutCaster(casterBounds.toFloatRect(), settings, backgroundColor);
    expectShadowColorWithoutCaster(casterBounds.toFloatRect(), settings, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterLayerMinSize) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ubyte4 casterColor(static_cast<uint8_t>(255), static_cast<uint8_t>(0),
                             static_cast<uint8_t>(0), static_cast<uint8_t>(255));
    const ubyte4 backgroundColor(static_cast<uint8_t>(255), static_cast<uint8_t>(255),
                                 static_cast<uint8_t>(255), static_cast<uint8_t>(255));
    const float shadowLength = 5.0f;
    Rect casterBounds(1, 1);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    ShadowSettings settings = getShadowSettings(vec2(casterBounds.left, casterBounds.top),
                                                shadowLength, false /* casterIsTranslucent */);

    drawShadow<ColorSourceVariant>(castingLayer, settings, casterColor, backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterColorLayer) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ubyte4 casterColor(static_cast<uint8_t>(255), static_cast<uint8_t>(0),
                             static_cast<uint8_t>(0), static_cast<uint8_t>(255));
    const ubyte4 backgroundColor(static_cast<uint8_t>(255), static_cast<uint8_t>(255),
                                 static_cast<uint8_t>(255), static_cast<uint8_t>(255));
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    ShadowSettings settings = getShadowSettings(vec2(casterBounds.left, casterBounds.top),
                                                shadowLength, false /* casterIsTranslucent */);

    drawShadow<ColorSourceVariant>(castingLayer, settings, casterColor, backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterOpaqueBufferLayer) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ubyte4 casterColor(static_cast<uint8_t>(255), static_cast<uint8_t>(0),
                             static_cast<uint8_t>(0), static_cast<uint8_t>(255));
    const ubyte4 backgroundColor(static_cast<uint8_t>(255), static_cast<uint8_t>(255),
                                 static_cast<uint8_t>(255), static_cast<uint8_t>(255));
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    ShadowSettings settings = getShadowSettings(vec2(casterBounds.left, casterBounds.top),
                                                shadowLength, false /* casterIsTranslucent */);

    drawShadow<BufferSourceVariant<ForceOpaqueBufferVariant>>(castingLayer, settings, casterColor,
                                                              backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_casterWithRoundedCorner) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ubyte4 casterColor(static_cast<uint8_t>(255), static_cast<uint8_t>(0),
                             static_cast<uint8_t>(0), static_cast<uint8_t>(255));
    const ubyte4 backgroundColor(static_cast<uint8_t>(255), static_cast<uint8_t>(255),
                                 static_cast<uint8_t>(255), static_cast<uint8_t>(255));
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.geometry.roundedCornersRadius = {3.0f, 3.0f};
    castingLayer.geometry.roundedCornersCrop = casterBounds.toFloatRect();
    castingLayer.alpha = 1.0f;
    ShadowSettings settings = getShadowSettings(vec2(casterBounds.left, casterBounds.top),
                                                shadowLength, false /* casterIsTranslucent */);

    drawShadow<BufferSourceVariant<ForceOpaqueBufferVariant>>(castingLayer, settings, casterColor,
                                                              backgroundColor);
    expectShadowColor(castingLayer, settings, casterColor, backgroundColor);
}

TEST_P(RenderEngineTest, drawLayers_fillShadow_translucentCasterWithAlpha) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ubyte4 casterColor(255, 0, 0, 255);
    const ubyte4 backgroundColor(255, 255, 255, 255);
    const float shadowLength = 5.0f;
    Rect casterBounds(DEFAULT_DISPLAY_WIDTH / 3.0f, DEFAULT_DISPLAY_HEIGHT / 3.0f);
    casterBounds.offsetBy(shadowLength + 1, shadowLength + 1);
    renderengine::LayerSettings castingLayer;
    castingLayer.geometry.boundaries = casterBounds.toFloatRect();
    castingLayer.alpha = 0.5f;
    ShadowSettings settings = getShadowSettings(vec2(casterBounds.left, casterBounds.top),
                                                shadowLength, true /* casterIsTranslucent */);

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
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<renderengine::LayerSettings> layers;
    renderengine::LayerSettings layer;
    layer.geometry.boundaries = fullscreenRect().toFloatRect();
    BufferSourceVariant<ForceOpaqueBufferVariant>::fillColor(layer, 1.0f, 0.0f, 0.0f, this);
    layer.alpha = 1.0;
    layers.push_back(layer);

    ftl::Future<FenceResult> futureOne =
            mRE->drawLayers(settings, layers, mBuffer, base::unique_fd());
    ASSERT_TRUE(futureOne.valid());
    auto resultOne = futureOne.get();
    ASSERT_TRUE(resultOne.ok());
    auto fenceOne = resultOne.value();

    ftl::Future<FenceResult> futureTwo =
            mRE->drawLayers(settings, layers, mBuffer, base::unique_fd(fenceOne->dup()));
    ASSERT_TRUE(futureTwo.valid());
    auto resultTwo = futureTwo.get();
    ASSERT_TRUE(resultTwo.ok());
    auto fenceTwo = resultTwo.value();
    fenceTwo->waitForever(LOG_TAG);

    // Only cleanup the first time.
    if (mRE->canSkipPostRenderCleanup()) {
        // Skia's Vk backend may keep the texture alive beyond drawLayersInternal, so
        // it never gets added to the cleanup list. In those cases, we can skip.
        EXPECT_TRUE(GetParam()->type() == renderengine::RenderEngine::RenderEngineType::SKIA_VK);
    } else {
        mRE->cleanupPostRender();
        EXPECT_TRUE(mRE->canSkipPostRenderCleanup());
    }
}

TEST_P(RenderEngineTest, testRoundedCornersCrop) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings redLayer;
    redLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    redLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    redLayer.geometry.roundedCornersRadius = {5.0f, 5.0f};

    redLayer.geometry.roundedCornersCrop = fullscreenRect().toFloatRect();
    // Red background.
    redLayer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    redLayer.alpha = 1.0f;

    layers.push_back(redLayer);

    // Green layer with 1/3 size.
    renderengine::LayerSettings greenLayer;
    greenLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    greenLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    greenLayer.geometry.roundedCornersRadius = {5.0f, 5.0f};
    // Bottom right corner is not going to be rounded.
    greenLayer.geometry.roundedCornersCrop =
            Rect(DEFAULT_DISPLAY_WIDTH / 3, DEFAULT_DISPLAY_HEIGHT / 3, DEFAULT_DISPLAY_HEIGHT,
                 DEFAULT_DISPLAY_HEIGHT)
                    .toFloatRect();
    greenLayer.source.solidColor = half3(0.0f, 1.0f, 0.0f);
    greenLayer.alpha = 1.0f;

    layers.push_back(greenLayer);

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

TEST_P(RenderEngineTest, testRoundedCornersParentCrop) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings redLayer;
    redLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    redLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    redLayer.geometry.roundedCornersRadius = {5.0f, 5.0f};
    redLayer.geometry.roundedCornersCrop = fullscreenRect().toFloatRect();
    // Red background.
    redLayer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    redLayer.alpha = 1.0f;

    layers.push_back(redLayer);

    // Green layer with 1/2 size with parent crop rect.
    renderengine::LayerSettings greenLayer = redLayer;
    greenLayer.geometry.boundaries =
            FloatRect(0, 0, DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT / 2);
    greenLayer.source.solidColor = half3(0.0f, 1.0f, 0.0f);

    layers.push_back(greenLayer);

    invokeDraw(settings, layers);

    // Due to roundedCornersRadius, the corners are untouched.
    expectBufferColor(Point(0, 0), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, 0), 0, 0, 0, 0);
    expectBufferColor(Point(0, DEFAULT_DISPLAY_HEIGHT - 1), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, DEFAULT_DISPLAY_HEIGHT - 1), 0, 0, 0, 0);

    // top middle should be green and the bottom middle red
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH / 2, 0), 0, 255, 0, 255);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2), 255, 0, 0, 255);

    // the bottom edge of the green layer should not be rounded
    expectBufferColor(Point(0, (DEFAULT_DISPLAY_HEIGHT / 2) - 1), 0, 255, 0, 255);
}

TEST_P(RenderEngineTest, testRoundedCornersParentCropSmallBounds) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings redLayer;
    redLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    redLayer.geometry.boundaries = FloatRect(0, 0, DEFAULT_DISPLAY_WIDTH, 32);
    redLayer.geometry.roundedCornersRadius = {64.0f, 64.0f};
    redLayer.geometry.roundedCornersCrop = FloatRect(0, 0, DEFAULT_DISPLAY_WIDTH, 128);
    // Red background.
    redLayer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    redLayer.alpha = 1.0f;

    layers.push_back(redLayer);
    invokeDraw(settings, layers);

    // Due to roundedCornersRadius, the top corners are untouched.
    expectBufferColor(Point(0, 0), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, 0), 0, 0, 0, 0);

    // ensure that the entire height of the red layer was clipped by the rounded corners crop.
    expectBufferColor(Point(0, 31), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, 31), 0, 0, 0, 0);

    // the bottom middle should be red
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH / 2, 31), 255, 0, 0, 255);
}

TEST_P(RenderEngineTest, testRoundedCornersXY) {
    if (GetParam()->type() != renderengine::RenderEngine::RenderEngineType::SKIA_GL) {
        GTEST_SKIP();
    }

    initializeRenderEngine();

    renderengine::DisplaySettings settings;
    settings.physicalDisplay = fullscreenRect();
    settings.clip = fullscreenRect();
    settings.outputDataspace = ui::Dataspace::V0_SRGB_LINEAR;

    std::vector<renderengine::LayerSettings> layers;

    renderengine::LayerSettings redLayer;
    redLayer.sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR;
    redLayer.geometry.boundaries = fullscreenRect().toFloatRect();
    redLayer.geometry.roundedCornersRadius = {5.0f, 20.0f};
    redLayer.geometry.roundedCornersCrop = fullscreenRect().toFloatRect();
    // Red background.
    redLayer.source.solidColor = half3(1.0f, 0.0f, 0.0f);
    redLayer.alpha = 1.0f;

    layers.push_back(redLayer);

    invokeDraw(settings, layers);

    // Due to roundedCornersRadius, the corners are untouched.
    expectBufferColor(Point(0, 0), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, 0), 0, 0, 0, 0);
    expectBufferColor(Point(0, DEFAULT_DISPLAY_HEIGHT - 1), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, DEFAULT_DISPLAY_HEIGHT - 1), 0, 0, 0, 0);

    // Y-axis draws a larger radius, check that its untouched as well
    expectBufferColor(Point(0, DEFAULT_DISPLAY_HEIGHT - 5), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, DEFAULT_DISPLAY_HEIGHT - 5), 0, 0, 0, 0);
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH - 1, 5), 0, 0, 0, 0);
    expectBufferColor(Point(0, 5), 0, 0, 0, 0);

    //  middle should be red
    expectBufferColor(Point(DEFAULT_DISPLAY_WIDTH / 2, DEFAULT_DISPLAY_HEIGHT / 2), 255, 0, 0, 255);
}

TEST_P(RenderEngineTest, testClear) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const auto rect = fullscreenRect();
    const renderengine::DisplaySettings display{
            .physicalDisplay = rect,
            .clip = rect,
    };

    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source.solidColor = half3(1.0f, 0.0f, 0.0f),
            .alpha = 1.0f,
    };

    // This mimics prepareClearClientComposition. This layer should overwrite
    // the redLayer, so that the buffer is transparent, rather than red.
    const renderengine::LayerSettings clearLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source.solidColor = half3(0.0f, 0.0f, 0.0f),
            .alpha = 0.0f,
            .disableBlending = true,
    };

    std::vector<renderengine::LayerSettings> layers{redLayer, clearLayer};
    invokeDraw(display, layers);
    expectBufferColor(rect, 0, 0, 0, 0);
}

TEST_P(RenderEngineTest, testDisableBlendingBuffer) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const auto rect = Rect(0, 0, 1, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = rect,
            .clip = rect,
    };

    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source.solidColor = half3(1.0f, 0.0f, 0.0f),
            .alpha = 1.0f,
    };

    // The next layer will overwrite redLayer with a GraphicBuffer that is green
    // applied with a translucent alpha.
    const auto buf = allocateSourceBuffer(1, 1);
    {
        uint8_t* pixels;
        buf->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                               reinterpret_cast<void**>(&pixels));
        pixels[0] = 0;
        pixels[1] = 255;
        pixels[2] = 0;
        pixels[3] = 255;
        buf->getBuffer()->unlock();
    }

    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = buf,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 0.5f,
            .disableBlending = true,
    };

    std::vector<renderengine::LayerSettings> layers{redLayer, greenLayer};
    invokeDraw(display, layers);
    expectBufferColor(rect, 0, 128, 0, 128);
}

TEST_P(RenderEngineTest, testBorder) {
    if (GetParam()->type() != renderengine::RenderEngine::RenderEngineType::SKIA_GL) {
        GTEST_SKIP();
    }

    initializeRenderEngine();

    const ui::Dataspace dataspace = ui::Dataspace::V0_SRGB;

    const auto displayRect = Rect(1080, 2280);
    renderengine::DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .outputDataspace = dataspace,
    };
    display.borderInfoList.clear();
    renderengine::BorderRenderInfo info;
    info.combinedRegion = Region(Rect(99, 99, 199, 199));
    info.width = 20.0f;
    info.color = half4{1.0f, 128.0f / 255.0f, 0.0f, 1.0f};
    display.borderInfoList.emplace_back(info);

    const auto greenBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 255, 0, 255));
    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = FloatRect(0.f, 0.f, 1.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = greenBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            .whitePointNits = 200.f,
    };

    std::vector<renderengine::LayerSettings> layers;
    layers.emplace_back(greenLayer);
    invokeDraw(display, layers);

    expectBufferColor(Rect(99, 99, 101, 101), 255, 128, 0, 255, 1);
}

TEST_P(RenderEngineTest, testDimming) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ui::Dataspace dataspace = ui::Dataspace::V0_SRGB_LINEAR;

    const auto displayRect = Rect(3, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .outputDataspace = dataspace,
            .targetLuminanceNits = 1000.f,
    };

    const auto greenBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 255, 0, 255));
    const auto blueBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 0, 255, 255));
    const auto redBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(255, 0, 0, 255));

    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = FloatRect(0.f, 0.f, 1.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = greenBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            .whitePointNits = 200.f,
    };

    const renderengine::LayerSettings blueLayer{
            .geometry.boundaries = FloatRect(1.f, 0.f, 2.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = blueBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            .whitePointNits = 1000.f / 51.f,
    };

    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = FloatRect(2.f, 0.f, 3.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = redBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            // When the white point is not set for a layer, just ignore it and treat it as the same
            // as the max layer
            .whitePointNits = -1.f,
    };

    std::vector<renderengine::LayerSettings> layers{greenLayer, blueLayer, redLayer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(1, 1), 0, 51, 0, 255, 1);
    expectBufferColor(Rect(1, 0, 2, 1), 0, 0, 5, 255, 1);
    expectBufferColor(Rect(2, 0, 3, 1), 51, 0, 0, 255, 1);
}

TEST_P(RenderEngineTest, testDimming_inGammaSpace) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ui::Dataspace dataspace = static_cast<ui::Dataspace>(ui::Dataspace::STANDARD_BT709 |
                                                               ui::Dataspace::TRANSFER_GAMMA2_2 |
                                                               ui::Dataspace::RANGE_FULL);

    const auto displayRect = Rect(3, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .outputDataspace = dataspace,
            .targetLuminanceNits = 1000.f,
            .dimmingStage = aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF,
    };

    const auto greenBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 255, 0, 255));
    const auto blueBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 0, 255, 255));
    const auto redBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(255, 0, 0, 255));

    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = FloatRect(0.f, 0.f, 1.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = greenBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            .whitePointNits = 200.f,
    };

    const renderengine::LayerSettings blueLayer{
            .geometry.boundaries = FloatRect(1.f, 0.f, 2.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = blueBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            .whitePointNits = 1000.f / 51.f,
    };

    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = FloatRect(2.f, 0.f, 3.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = redBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            // When the white point is not set for a layer, just ignore it and treat it as the same
            // as the max layer
            .whitePointNits = -1.f,
    };

    std::vector<renderengine::LayerSettings> layers{greenLayer, blueLayer, redLayer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(1, 1), 0, 122, 0, 255, 1);
    expectBufferColor(Rect(1, 0, 2, 1), 0, 0, 42, 255, 1);
    expectBufferColor(Rect(2, 0, 3, 1), 122, 0, 0, 255, 1);
}

TEST_P(RenderEngineTest, testDimming_inGammaSpace_withDisplayColorTransform) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ui::Dataspace dataspace = static_cast<ui::Dataspace>(ui::Dataspace::STANDARD_BT709 |
                                                               ui::Dataspace::TRANSFER_GAMMA2_2 |
                                                               ui::Dataspace::RANGE_FULL);

    const auto displayRect = Rect(3, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .outputDataspace = dataspace,
            .colorTransform = kRemoveGreenAndMoveRedToGreenMat4,
            .targetLuminanceNits = 1000.f,
            .dimmingStage = aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF,
    };

    const auto greenBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 255, 0, 255));
    const auto blueBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 0, 255, 255));
    const auto redBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(255, 0, 0, 255));

    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = FloatRect(0.f, 0.f, 1.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = greenBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            .whitePointNits = 200.f,
    };

    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = FloatRect(1.f, 0.f, 2.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = redBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            // When the white point is not set for a layer, just ignore it and treat it as the same
            // as the max layer
            .whitePointNits = -1.f,
    };

    std::vector<renderengine::LayerSettings> layers{greenLayer, redLayer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(1, 1), 0, 0, 0, 255, 1);
    expectBufferColor(Rect(1, 0, 2, 1), 0, 122, 0, 255, 1);
}

TEST_P(RenderEngineTest, testDimming_inGammaSpace_withDisplayColorTransform_deviceHandles) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const ui::Dataspace dataspace = static_cast<ui::Dataspace>(ui::Dataspace::STANDARD_BT709 |
                                                               ui::Dataspace::TRANSFER_GAMMA2_2 |
                                                               ui::Dataspace::RANGE_FULL);

    const auto displayRect = Rect(3, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .outputDataspace = dataspace,
            .colorTransform = kRemoveGreenAndMoveRedToGreenMat4,
            .deviceHandlesColorTransform = true,
            .targetLuminanceNits = 1000.f,
            .dimmingStage = aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF,
    };

    const auto greenBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 255, 0, 255));
    const auto blueBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 0, 255, 255));
    const auto redBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(255, 0, 0, 255));

    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = FloatRect(0.f, 0.f, 1.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = greenBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            .whitePointNits = 200.f,
    };

    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = FloatRect(1.f, 0.f, 2.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = redBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = dataspace,
            // When the white point is not set for a layer, just ignore it and treat it as the same
            // as the max layer
            .whitePointNits = -1.f,
    };

    std::vector<renderengine::LayerSettings> layers{greenLayer, redLayer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(1, 1), 0, 122, 0, 255, 1);
    expectBufferColor(Rect(1, 0, 2, 1), 122, 0, 0, 255, 1);
}

TEST_P(RenderEngineTest, testDimming_withoutTargetLuminance) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const auto displayRect = Rect(2, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .outputDataspace = ui::Dataspace::V0_SRGB_LINEAR,
            .targetLuminanceNits = -1.f,
    };

    const auto greenBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 255, 0, 255));
    const auto blueBuffer = allocateAndFillSourceBuffer(1, 1, ubyte4(0, 0, 255, 255));

    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = FloatRect(0.f, 0.f, 1.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = greenBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR,
            .whitePointNits = 200.f,
    };

    const renderengine::LayerSettings blueLayer{
            .geometry.boundaries = FloatRect(1.f, 0.f, 2.f, 1.f),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = blueBuffer,
                                            .usePremultipliedAlpha = true,
                                    },
                    },
            .alpha = 1.0f,
            .sourceDataspace = ui::Dataspace::V0_SRGB_LINEAR,
            .whitePointNits = 1000.f,
    };

    std::vector<renderengine::LayerSettings> layers{greenLayer, blueLayer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(1, 1), 0, 51, 0, 255, 1);
    expectBufferColor(Rect(1, 0, 2, 1), 0, 0, 255, 255);
}

TEST_P(RenderEngineTest, test_isOpaque) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const auto rect = Rect(0, 0, 1, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = rect,
            .clip = rect,
            .outputDataspace = ui::Dataspace::DISPLAY_P3,
    };

    // Create an unpremul buffer that is green with no alpha. Using isOpaque
    // should make the green show.
    const auto buf = allocateSourceBuffer(1, 1);
    {
        uint8_t* pixels;
        buf->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                               reinterpret_cast<void**>(&pixels));
        pixels[0] = 0;
        pixels[1] = 255;
        pixels[2] = 0;
        pixels[3] = 0;
        buf->getBuffer()->unlock();
    }

    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = buf,
                                            // Although the pixels are not
                                            // premultiplied in practice, this
                                            // matches the input we see.
                                            .usePremultipliedAlpha = true,
                                            .isOpaque = true,
                                    },
                    },
            .alpha = 1.0f,
    };

    std::vector<renderengine::LayerSettings> layers{greenLayer};
    invokeDraw(display, layers);

    expectBufferColor(rect, 117, 251, 76, 255);
}

TEST_P(RenderEngineTest, test_tonemapPQMatches) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();

    tonemap(
            static_cast<ui::Dataspace>(HAL_DATASPACE_STANDARD_BT2020 |
                                       HAL_DATASPACE_TRANSFER_ST2084 | HAL_DATASPACE_RANGE_FULL),
            [](vec3 color) { return EOTF_PQ(color); },
            [](vec3 color, float) {
                static constexpr float kMaxPQLuminance = 10000.f;
                return color * kMaxPQLuminance;
            });
}

TEST_P(RenderEngineTest, test_tonemapHLGMatches) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }

    initializeRenderEngine();

    tonemap(
            static_cast<ui::Dataspace>(HAL_DATASPACE_STANDARD_BT2020 | HAL_DATASPACE_TRANSFER_HLG |
                                       HAL_DATASPACE_RANGE_FULL),
            [](vec3 color) { return EOTF_HLG(color); },
            [](vec3 color, float currentLuminaceNits) {
                static constexpr float kMaxHLGLuminance = 1000.f;
                return color * kMaxHLGLuminance;
            });
}

TEST_P(RenderEngineTest, r8_behaves_as_mask) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const auto r8Buffer = allocateR8Buffer(2, 1);
    if (!r8Buffer) {
        GTEST_SKIP() << "Test is only necessary on devices that support r8";
        return;
    }
    {
        uint8_t* pixels;
        r8Buffer->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                                    reinterpret_cast<void**>(&pixels));
        // This will be drawn on top of a green buffer. We'll verify that 255
        // results in keeping the original green and 0 results in black.
        pixels[0] = 0;
        pixels[1] = 255;
        r8Buffer->getBuffer()->unlock();
    }

    const auto rect = Rect(0, 0, 2, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = rect,
            .clip = rect,
            .outputDataspace = ui::Dataspace::SRGB,
    };

    const auto greenBuffer = allocateAndFillSourceBuffer(2, 1, ubyte4(0, 255, 0, 255));
    const renderengine::LayerSettings greenLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = greenBuffer,
                                    },
                    },
            .alpha = 1.0f,
    };
    const renderengine::LayerSettings r8Layer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = r8Buffer,
                                    },
                    },
            .alpha = 1.0f,
    };

    std::vector<renderengine::LayerSettings> layers{greenLayer, r8Layer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(0, 0, 1, 1), 0,   0, 0, 255);
    expectBufferColor(Rect(1, 0, 2, 1), 0, 255, 0, 255);
}

TEST_P(RenderEngineTest, r8_respects_color_transform) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const auto r8Buffer = allocateR8Buffer(2, 1);
    if (!r8Buffer) {
        GTEST_SKIP() << "Test is only necessary on devices that support r8";
        return;
    }
    {
        uint8_t* pixels;
        r8Buffer->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                                    reinterpret_cast<void**>(&pixels));
        pixels[0] = 0;
        pixels[1] = 255;
        r8Buffer->getBuffer()->unlock();
    }

    const auto rect = Rect(0, 0, 2, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = rect,
            .clip = rect,
            .outputDataspace = ui::Dataspace::SRGB,
            // Verify that the R8 layer respects the color transform when
            // deviceHandlesColorTransform is false. This transform converts
            // pure red to pure green. That will occur when the R8 buffer is
            // 255. When the R8 buffer is 0, it will still change to black, as
            // with r8_behaves_as_mask.
            .colorTransform = kRemoveGreenAndMoveRedToGreenMat4,
            .deviceHandlesColorTransform = false,
    };

    const auto redBuffer = allocateAndFillSourceBuffer(2, 1, ubyte4(255, 0, 0, 255));
    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = redBuffer,
                                    },
                    },
            .alpha = 1.0f,
    };
    const renderengine::LayerSettings r8Layer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = r8Buffer,
                                    },
                    },
            .alpha = 1.0f,
    };

    std::vector<renderengine::LayerSettings> layers{redLayer, r8Layer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(0, 0, 1, 1), 0,   0, 0, 255);
    expectBufferColor(Rect(1, 0, 2, 1), 0, 255, 0, 255);
}

TEST_P(RenderEngineTest, r8_respects_color_transform_when_device_handles) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    const auto r8Buffer = allocateR8Buffer(2, 1);
    if (!r8Buffer) {
        GTEST_SKIP() << "Test is only necessary on devices that support r8";
        return;
    }
    {
        uint8_t* pixels;
        r8Buffer->getBuffer()->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                                    reinterpret_cast<void**>(&pixels));
        pixels[0] = 0;
        pixels[1] = 255;
        r8Buffer->getBuffer()->unlock();
    }

    const auto rect = Rect(0, 0, 2, 1);
    const renderengine::DisplaySettings display{
            .physicalDisplay = rect,
            .clip = rect,
            .outputDataspace = ui::Dataspace::SRGB,
            // If deviceHandlesColorTransform is true, pixels where the A8
            // buffer is opaque are unaffected. If the colorTransform is
            // invertible, pixels where the A8 buffer are transparent have the
            // inverse applied to them so that the DPU will convert them back to
            // black. Test with an arbitrary, invertible matrix.
            .colorTransform = mat4(1, 0, 0, 2,
                                   3, 1, 2, 5,
                                   0, 5, 3, 0,
                                   0, 1, 0, 2),
            .deviceHandlesColorTransform = true,
    };

    const auto redBuffer = allocateAndFillSourceBuffer(2, 1, ubyte4(255, 0, 0, 255));
    const renderengine::LayerSettings redLayer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = redBuffer,
                                    },
                    },
            .alpha = 1.0f,
    };
    const renderengine::LayerSettings r8Layer{
            .geometry.boundaries = rect.toFloatRect(),
            .source =
                    renderengine::PixelSource{
                            .buffer =
                                    renderengine::Buffer{
                                            .buffer = r8Buffer,
                                    },
                    },
            .alpha = 1.0f,
    };

    std::vector<renderengine::LayerSettings> layers{redLayer, r8Layer};
    invokeDraw(display, layers);

    expectBufferColor(Rect(1, 0, 2, 1), 255, 0, 0, 255); // Still red.
    expectBufferColor(Rect(0, 0, 1, 1), 0,  70, 0, 255);
}

TEST_P(RenderEngineTest, primeShaderCache) {
    if (!GetParam()->typeSupported()) {
        GTEST_SKIP();
    }
    initializeRenderEngine();

    auto fut = mRE->primeCache(false);
    if (fut.valid()) {
        fut.wait();
    }

    static constexpr int kMinimumExpectedShadersCompiled = 60;
    ASSERT_GT(static_cast<skia::SkiaGLRenderEngine*>(mRE.get())->reportShadersCompiled(),
              kMinimumExpectedShadersCompiled);
}
} // namespace renderengine
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
