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
#include "Cache.h"
#include "AutoBackendTexture.h"
#include "SkiaRenderEngine.h"
#include "android-base/unique_fd.h"
#include "renderengine/DisplaySettings.h"
#include "renderengine/LayerSettings.h"
#include "ui/GraphicBuffer.h"
#include "ui/GraphicTypes.h"
#include "ui/PixelFormat.h"
#include "ui/Rect.h"
#include "utils/Timers.h"

namespace android::renderengine::skia {

namespace {
// Warming shader cache, not framebuffer cache.
constexpr bool kUseFrameBufferCache = false;

// clang-format off
// Any non-identity matrix will do.
const auto kScaleAndTranslate = mat4(0.7f,   0.f, 0.f, 0.f,
                                     0.f,  0.7f, 0.f, 0.f,
                                     0.f,   0.f, 1.f, 0.f,
                                   67.3f, 52.2f, 0.f, 1.f);
const auto kScaleAsymmetric = mat4(0.8f, 0.f,  0.f, 0.f,
                                   0.f,  1.1f, 0.f, 0.f,
                                   0.f,  0.f,  1.f, 0.f,
                                   0.f,  0.f,  0.f, 1.f);
// clang-format on
// When setting layer.sourceDataspace, whether it matches the destination or not determines whether
// a color correction effect is added to the shader.
constexpr auto kDestDataSpace = ui::Dataspace::SRGB;
constexpr auto kOtherDataSpace = ui::Dataspace::DISPLAY_P3;
} // namespace

static void drawShadowLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                             const std::shared_ptr<ExternalTexture>& dstTexture) {
    // Somewhat arbitrary dimensions, but on screen and slightly shorter, based
    // on actual use.
    FloatRect rect(0, 0, display.physicalDisplay.width(), display.physicalDisplay.height() - 30);
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                            .roundedCornersCrop = rect,
                    },
            // drawShadow ignores alpha
            .shadow =
                    ShadowSettings{
                            .ambientColor = vec4(0, 0, 0, 0.00935997f),
                            .spotColor = vec4(0, 0, 0, 0.0455841f),
                            .lightPos = vec3(370.508f, -1527.03f, 1650.f),
                            .lightRadius = 2200.0f,
                            .length = 0.955342f,
                    },
            // important that this matches dest so the general shadow fragment shader doesn't
            // have color correction added, and important that it be srgb, so the *vertex* shader
            // doesn't have color correction added.
            .sourceDataspace = kDestDataSpace,
            // setting this is mandatory for shadows and blurs
            .skipContentDraw = true,
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    // The identity matrix will generate the fast shader
    renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache, base::unique_fd(),
                             nullptr);
    // This matrix, which has different scales for x and y, will
    // generate the slower (more general case) version, which has variants for translucent
    // casters and rounded rects.
    layer.geometry.positionTransform = kScaleAsymmetric;
    for (auto translucent : {false, true}) {
        layer.shadow.casterIsTranslucent = translucent;
        renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                 base::unique_fd(), nullptr);
    }
}

static void drawImageLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            const std::shared_ptr<ExternalTexture>& dstTexture,
                            const std::shared_ptr<ExternalTexture>& srcTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            // The position transform doesn't matter when the reduced shader mode
                            // in in effect. A matrix transform stage is always included.
                            .positionTransform = mat4(),
                            .boundaries = rect,
                            .roundedCornersCrop = rect,
                    },
            .source = PixelSource{.buffer =
                                          Buffer{
                                                  .buffer = srcTexture,
                                                  .maxLuminanceNits = 1000.f,
                                          }},
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    for (auto dataspace : {kDestDataSpace, kOtherDataSpace}) {
        layer.sourceDataspace = dataspace;
        for (float roundedCornersRadius : {0.0f, 50.0f}) {
            // roundedCornersCrop is always set, but the radius triggers the behavior
            layer.geometry.roundedCornersRadius = roundedCornersRadius;
            for (bool isOpaque : {true, false}) {
                layer.source.buffer.isOpaque = isOpaque;
                for (auto alpha : {half(.2f), half(1.0f)}) {
                    layer.alpha = alpha;
                    renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                             base::unique_fd(), nullptr);
                }
            }
        }
    }
}

static void drawSolidLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            const std::shared_ptr<ExternalTexture>& dstTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                    },
            .source =
                    PixelSource{
                            .solidColor = half3(0.1f, 0.2f, 0.3f),
                    },
            .alpha = 0.5,
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    for (auto transform : {mat4(), kScaleAndTranslate}) {
        layer.geometry.positionTransform = transform;
        for (float roundedCornersRadius : {0.0f, 50.f}) {
            layer.geometry.roundedCornersRadius = roundedCornersRadius;
            renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                     base::unique_fd(), nullptr);
        }
    }
}

static void drawBlurLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                           const std::shared_ptr<ExternalTexture>& dstTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                    },
            .alpha = 1,
            // setting this is mandatory for shadows and blurs
            .skipContentDraw = true,
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    // Different blur code is invoked for radii less and greater than 30 pixels
    for (int radius : {9, 60}) {
        layer.backgroundBlurRadius = radius;
        renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                 base::unique_fd(), nullptr);
    }
}

// The unique feature of these layers is that the boundary is slightly smaller than the rounded
// rect crop, so the rounded edges intersect that boundary and require a different clipping method.
// For buffers, this is done with a stage that computes coverage and it will differ for round and
// elliptical corners.
static void drawClippedLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                              const std::shared_ptr<ExternalTexture>& dstTexture,
                              const std::shared_ptr<ExternalTexture>& srcTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height() - 20); // boundary is smaller

    PixelSource bufferSource{.buffer = Buffer{
                                     .buffer = srcTexture,
                                     .isOpaque = 0,
                                     .maxLuminanceNits = 1000.f,
                             }};
    PixelSource bufferOpaque{.buffer = Buffer{
                                     .buffer = srcTexture,
                                     .isOpaque = 1,
                                     .maxLuminanceNits = 1000.f,
                             }};
    PixelSource colorSource{.solidColor = half3(0.1f, 0.2f, 0.3f)};

    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                            .roundedCornersRadius = 27, // larger than the 20 above.
                            .roundedCornersCrop =
                                    FloatRect(0, 0, displayRect.width(), displayRect.height()),
                    },
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    for (auto pixelSource : {bufferSource, bufferOpaque, colorSource}) {
        layer.source = pixelSource;
        for (auto dataspace : {kDestDataSpace, kOtherDataSpace}) {
            layer.sourceDataspace = dataspace;
            // Produce a CircularRRect clip and an EllipticalRRect clip
            for (auto transform : {kScaleAndTranslate, kScaleAsymmetric}) {
                layer.geometry.positionTransform = transform;
                // In real use, I saw alpha of 1.0 and 0.999, probably a mistake, but cache both
                // shaders.
                for (float alpha : {0.5f, 1.f}) {
                    layer.alpha = alpha,
                    renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                             base::unique_fd(), nullptr);
                }
            }
        }
    }
}

//
// The collection of shaders cached here were found by using perfetto to record shader compiles
// during actions that involve RenderEngine, logging the layer settings, and the shader code
// and reproducing those settings here.
//
// It is helpful when debugging this to turn on
// in SkGLRenderEngine.cpp:
//    kPrintLayerSettings = true
//    kFlushAfterEveryLayer = true
// in external/skia/src/gpu/gl/builders/GrGLShaderStringBuilder.cpp
//    gPrintSKSL = true
//
// TODO(b/184631553) cache the shader involved in youtube pip return.
void Cache::primeShaderCache(SkiaRenderEngine* renderengine) {
    const int previousCount = renderengine->reportShadersCompiled();
    if (previousCount) {
        ALOGD("%d Shaders already compiled before Cache::primeShaderCache ran\n", previousCount);
    }

    // The loop is beneficial for debugging and should otherwise be optimized out by the compiler.
    // Adding additional bounds to the loop is useful for verifying that the size of the dst buffer
    // does not impact the shader compilation counts by triggering different behaviors in RE/Skia.
    for (SkSize bounds : {SkSize::Make(128, 128), /*SkSize::Make(1080, 2340)*/}) {
        const nsecs_t timeBefore = systemTime();
        // The dimensions should not matter, so long as we draw inside them.
        const Rect displayRect(0, 0, bounds.fWidth, bounds.fHeight);
        DisplaySettings display{
                .physicalDisplay = displayRect,
                .clip = displayRect,
                .maxLuminance = 500,
                .outputDataspace = kDestDataSpace,
        };

        const int64_t usage = GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;

        sp<GraphicBuffer> dstBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888,
                                  1, usage, "primeShaderCache_dst");

        const auto dstTexture =
                std::make_shared<ExternalTexture>(dstBuffer, *renderengine,
                                                  ExternalTexture::Usage::WRITEABLE);
        // This buffer will be the source for the call to drawImageLayers. Draw
        // something to it as a placeholder for what an app draws. We should draw
        // something, but the details are not important. Make use of the shadow layer drawing step
        // to populate it.
        sp<GraphicBuffer> srcBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888,
                                  1, usage, "drawImageLayer_src");

        const auto srcTexture =
                std::make_shared<ExternalTexture>(srcBuffer, *renderengine,
                                                  ExternalTexture::Usage::READABLE |
                                                          ExternalTexture::Usage::WRITEABLE);

        drawSolidLayers(renderengine, display, dstTexture);
        drawShadowLayers(renderengine, display, srcTexture);

        if (renderengine->supportsBackgroundBlur()) {
            drawBlurLayers(renderengine, display, dstTexture);
        }

        // should be the same as AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE;
        const int64_t usageExternal = GRALLOC_USAGE_HW_TEXTURE;
        sp<GraphicBuffer> externalBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888,
                                  1, usageExternal, "primeShaderCache_external");
        const auto externalTexture =
                std::make_shared<ExternalTexture>(externalBuffer, *renderengine,
                                                  ExternalTexture::Usage::READABLE);

        // Another external texture with a different pixel format triggers useIsOpaqueWorkaround
        sp<GraphicBuffer> f16ExternalBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_FP16,
                                  1, usageExternal, "primeShaderCache_external_f16");
        const auto f16ExternalTexture =
                std::make_shared<ExternalTexture>(f16ExternalBuffer, *renderengine,
                                                  ExternalTexture::Usage::READABLE);

        // The majority of shaders are related to sampling images.
        // These need to be generated with various source textures
        // The F16 texture may not be usable on all devices, so check first that it was created with
        // the requested usage bit.
        auto textures = {srcTexture, externalTexture};
        auto texturesWithF16 = {srcTexture, externalTexture, f16ExternalTexture};
        bool canUsef16 = f16ExternalBuffer->getUsage() & GRALLOC_USAGE_HW_TEXTURE;

        for (auto texture : canUsef16 ? texturesWithF16 : textures) {
            drawImageLayers(renderengine, display, dstTexture, texture);
            // Draw layers for b/185569240.
            drawClippedLayers(renderengine, display, dstTexture, texture);
        }

        const nsecs_t timeAfter = systemTime();
        const float compileTimeMs = static_cast<float>(timeAfter - timeBefore) / 1.0E6;
        const int shadersCompiled = renderengine->reportShadersCompiled();
        ALOGD("Shader cache generated %d shaders in %f ms\n", shadersCompiled, compileTimeMs);
    }
}

} // namespace android::renderengine::skia
