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

#include <android/hardware_buffer.h>

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
// clang-format on
// When choosing dataspaces below, whether the match the destination or not determined whether
// a color correction effect is added to the shader. There may be other additional shader details
// for particular color spaces.
// TODO(b/184842383) figure out which color related shaders are necessary
constexpr auto kDestDataSpace = ui::Dataspace::SRGB;
} // namespace

static void drawShadowLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                             sp<GraphicBuffer> dstBuffer) {
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
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    // The identity matrix will generate the fast shader
    renderengine->drawLayers(display, layers, dstBuffer, kUseFrameBufferCache, base::unique_fd(),
                             nullptr);
    // This matrix, which has different scales for x and y, will
    // generate the slower (more general case) version, which has variants for translucent
    // casters and rounded rects.
    // clang-format off
    layer.geometry.positionTransform = mat4(0.7f, 0.f,  0.f, 0.f,
                                            0.f, 0.8f, 0.f, 0.f,
                                            0.f, 0.f,  1.f, 0.f,
                                            0.f, 0.f,  0.f, 1.f);
    // clang-format on
    for (auto translucent : {false, true}) {
        layer.shadow.casterIsTranslucent = translucent;
        renderengine->drawLayers(display, layers, dstBuffer, kUseFrameBufferCache,
                                 base::unique_fd(), nullptr);
    }
}

static void drawImageLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            sp<GraphicBuffer> dstBuffer, sp<GraphicBuffer> srcBuffer) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                            .roundedCornersCrop = rect,
                    },
            .source = PixelSource{.buffer =
                                          Buffer{
                                                  .buffer = srcBuffer,
                                                  .maxMasteringLuminance = 1000.f,
                                                  .maxContentLuminance = 1000.f,
                                          }},
    };

    auto threeCornerRadii = {0.0f, 0.05f, 50.f};
    auto oneCornerRadius = {50.f};

    // Test both drawRect and drawRRect
    auto layers = std::vector<const LayerSettings*>{&layer};
    for (bool identity : {true, false}) {
        layer.geometry.positionTransform = identity ? mat4() : kScaleAndTranslate;
        // Corner radii less than 0.5 creates a special shader. This likely occurs in real usage
        // due to animating corner radius.
        // For the non-idenity matrix, only the large corner radius will create a new shader.
        for (float roundedCornersRadius : identity ? threeCornerRadii : oneCornerRadius) {
            // roundedCornersCrop is always set, but it is this radius that triggers the behavior
            layer.geometry.roundedCornersRadius = roundedCornersRadius;
            for (bool isOpaque : {true, false}) {
                layer.source.buffer.isOpaque = isOpaque;
                for (auto alpha : {half(.23999f), half(1.0f)}) {
                    layer.alpha = alpha;
                    renderengine->drawLayers(display, layers, dstBuffer, kUseFrameBufferCache,
                                             base::unique_fd(), nullptr);
                }
            }
        }
    }
}

static void drawSolidLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            sp<GraphicBuffer> dstBuffer) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                    },
            .alpha = 1,
            .source =
                    PixelSource{
                            .solidColor = half3(0.1f, 0.2f, 0.3f),
                    },
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    for (auto transform : {mat4(), kScaleAndTranslate}) {
        layer.geometry.positionTransform = transform;
        for (float roundedCornersRadius : {0.0f, 0.05f, 50.f}) {
            layer.geometry.roundedCornersRadius = roundedCornersRadius;
            renderengine->drawLayers(display, layers, dstBuffer, kUseFrameBufferCache,
                                     base::unique_fd(), nullptr);
        }
    }
}

static void drawBlurLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                           sp<GraphicBuffer> dstBuffer) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                    },
            .alpha = 1,
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    for (int radius : {9, 60}) {
        layer.backgroundBlurRadius = radius;
        renderengine->drawLayers(display, layers, dstBuffer, kUseFrameBufferCache,
                                 base::unique_fd(), nullptr);
    }
}

namespace {

struct AHardwareBuffer_deleter {
    void operator()(AHardwareBuffer* ahb) const { AHardwareBuffer_release(ahb); }
};

std::unique_ptr<AHardwareBuffer, AHardwareBuffer_deleter> makeAHardwareBuffer() {
    AHardwareBuffer* buffer = nullptr;

    int w = 32;
    int h = 32;

    AHardwareBuffer_Desc hwbDesc;
    hwbDesc.width = w;
    hwbDesc.height = h;
    hwbDesc.layers = 1;
    hwbDesc.usage = AHARDWAREBUFFER_USAGE_CPU_READ_NEVER | AHARDWAREBUFFER_USAGE_CPU_WRITE_NEVER |
            AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE;
    hwbDesc.format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM;
    // The following three are not used in the allocate
    hwbDesc.stride = 0;
    hwbDesc.rfu0 = 0;
    hwbDesc.rfu1 = 0;

    if (int error = AHardwareBuffer_allocate(&hwbDesc, &buffer)) {
        ALOGE("Failed to allocated hardware buffer, error: %d", error);
        if (buffer) {
            AHardwareBuffer_release(buffer);
        }
        return nullptr;
    }
    return std::unique_ptr<AHardwareBuffer, AHardwareBuffer_deleter>(buffer);
}
} // namespace

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
    const nsecs_t timeBefore = systemTime();
    // The dimensions should not matter, so long as we draw inside them.
    const Rect displayRect(0, 0, 1080, 2340);
    DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .maxLuminance = 500,
            .outputDataspace = kDestDataSpace,
    };

    const int64_t usage = GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;

    sp<GraphicBuffer> dstBuffer =
            new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888, 1,
                              usage, "primeShaderCache_dst");
    // This buffer will be the source for the call to drawImageLayers. Draw
    // something to it as a placeholder for what an app draws. We should draw
    // something, but the details are not important. Make use of the shadow layer drawing step
    // to populate it.
    sp<GraphicBuffer> srcBuffer =
            new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888, 1,
                              usage, "drawImageLayer_src");

    drawSolidLayers(renderengine, display, dstBuffer);
    drawShadowLayers(renderengine, display, srcBuffer);
    drawBlurLayers(renderengine, display, dstBuffer);
    // The majority of shaders are related to sampling images.
    drawImageLayers(renderengine, display, dstBuffer, srcBuffer);

    // Draw image layers again sampling from an AHardwareBuffer if it is possible to create one.
    if (auto ahb = makeAHardwareBuffer()) {
        sp<GraphicBuffer> externalBuffer = GraphicBuffer::fromAHardwareBuffer(ahb.get());
        // TODO(b/184665179) doubles number of image shader compilations, but only somewhere
        // between 6 and 8 will occur in real uses.
        drawImageLayers(renderengine, display, dstBuffer, externalBuffer);
        renderengine->unbindExternalTextureBuffer(externalBuffer->getId());
    }

    renderengine->unbindExternalTextureBuffer(srcBuffer->getId());

    const nsecs_t timeAfter = systemTime();
    const float compileTimeMs = static_cast<float>(timeAfter - timeBefore) / 1.0E6;
    const int shadersCompiled = renderengine->reportShadersCompiled();
    ALOGD("Shader cache generated %d shaders in %f ms\n", shadersCompiled, compileTimeMs);
}

} // namespace android::renderengine::skia
