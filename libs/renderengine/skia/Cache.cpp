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

// Warming shader cache, not framebuffer cache.
constexpr bool kUseFrameBufferCache = false;

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
    };

    auto layers = std::vector<const LayerSettings*>{&layer};
    // The identity matrix will generate the fast shaders, and the second matrix
    // (based on one seen while going from dialer to the home screen) will
    // generate the slower (more general case) version. If we also need a
    // slow version without color correction, we should use this matrix with
    // display.outputDataspace set to SRGB.
    bool identity = true;
    for (const mat4 transform : { mat4(), mat4(0.728872f,   0.f,          0.f, 0.f,
                                               0.f,         0.727627f,    0.f, 0.f,
                                               0.f,         0.f,          1.f, 0.f,
                                               167.355743f, 1852.257812f, 0.f, 1.f) }) {
        layer.geometry.positionTransform = transform;
        renderengine->drawLayers(display, layers, dstBuffer, kUseFrameBufferCache,
                                 base::unique_fd(), nullptr);
        identity = false;
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

    // This matrix is based on actual data seen when opening the dialer.
    //  translate and scale creates new shaders when combined with rounded corners
    // clang-format off
    auto scale_and_translate = mat4(.19f,    .0f,  .0f,  .0f,
                                     .0f,   .19f,  .0f,  .0f,
                                     .0f,    .0f,  1.f,  .0f,
                                   169.f, 1527.f,  .0f,  1.f);
    // clang-format on

    // Test both drawRect and drawRRect
    auto layers = std::vector<const LayerSettings*>{&layer};
    for (auto transform : {mat4(), scale_and_translate}) {
        layer.geometry.positionTransform = transform;
        // fractional corner radius creates a shader that is used during home button swipe
        for (float roundedCornersRadius : {0.0f, 0.05f, 500.f}) {
            // roundedCornersCrop is always set, but it is this radius that triggers the behavior
            layer.geometry.roundedCornersRadius = roundedCornersRadius;
            // No need to check UNKNOWN, which is treated as SRGB.
            for (auto dataspace : {ui::Dataspace::SRGB, ui::Dataspace::DISPLAY_P3}) {
                layer.sourceDataspace = dataspace;
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
    renderengine->drawLayers(display, layers, dstBuffer, kUseFrameBufferCache, base::unique_fd(),
                             nullptr);
}

void Cache::primeShaderCache(SkiaRenderEngine* renderengine) {
    const nsecs_t timeBefore = systemTime();
    // The dimensions should not matter, so long as we draw inside them.
    const Rect displayRect(0, 0, 1080, 2340);
    DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .maxLuminance = 500,
            .outputDataspace = ui::Dataspace::DISPLAY_P3,
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
    drawImageLayers(renderengine, display, dstBuffer, srcBuffer);
    const nsecs_t timeAfter = systemTime();
    const float compileTimeMs = static_cast<float>(timeAfter - timeBefore) / 1.0E6;
    ALOGD("shader cache generated in %f ms\n", compileTimeMs);
}

} // namespace android::renderengine::skia
