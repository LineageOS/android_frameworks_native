/*
 * Copyright 2013 The Android Open Source Project
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

#include <renderengine/RenderEngine.h>

#include "renderengine/ExternalTexture.h"
#include "skia/GaneshVkRenderEngine.h"
#include "skia/GraphiteVkRenderEngine.h"
#include "skia/SkiaGLRenderEngine.h"
#include "threaded/RenderEngineThreaded.h"

#include <com_android_graphics_surfaceflinger_flags.h>
#include <cutils/properties.h>
#include <log/log.h>

// TODO: b/341728634 - Clean up conditional compilation.
#if COM_ANDROID_GRAPHICS_SURFACEFLINGER_FLAGS(GRAPHITE_RENDERENGINE) || \
        COM_ANDROID_GRAPHICS_SURFACEFLINGER_FLAGS(FORCE_COMPILE_GRAPHITE_RENDERENGINE)
#define COMPILE_GRAPHITE_RENDERENGINE 1
#else
#define COMPILE_GRAPHITE_RENDERENGINE 0
#endif

namespace android {
namespace renderengine {

std::unique_ptr<RenderEngine> RenderEngine::create(const RenderEngineCreationArgs& args) {
    threaded::CreateInstanceFactory createInstanceFactory;

// TODO: b/341728634 - Clean up conditional compilation.
#if COMPILE_GRAPHITE_RENDERENGINE
    const RenderEngine::SkiaBackend actualSkiaBackend = args.skiaBackend;
#else
    if (args.skiaBackend == RenderEngine::SkiaBackend::GRAPHITE) {
        ALOGE("RenderEngine with Graphite Skia backend was requested, but Graphite was not "
              "included in the build. Falling back to Ganesh (%s)",
              args.graphicsApi == RenderEngine::GraphicsApi::GL ? "GL" : "Vulkan");
    }
    const RenderEngine::SkiaBackend actualSkiaBackend = RenderEngine::SkiaBackend::GANESH;
#endif

    ALOGD("%sRenderEngine with %s Backend (%s)", args.threaded == Threaded::YES ? "Threaded " : "",
          args.graphicsApi == GraphicsApi::GL ? "SkiaGL" : "SkiaVK",
          actualSkiaBackend == SkiaBackend::GANESH ? "Ganesh" : "Graphite");

// TODO: b/341728634 - Clean up conditional compilation.
#if COMPILE_GRAPHITE_RENDERENGINE
    if (actualSkiaBackend == SkiaBackend::GRAPHITE) {
        createInstanceFactory = [args]() {
            return android::renderengine::skia::GraphiteVkRenderEngine::create(args);
        };
    } else
#endif
    { // GANESH
        if (args.graphicsApi == GraphicsApi::VK) {
            createInstanceFactory = [args]() {
                return android::renderengine::skia::GaneshVkRenderEngine::create(args);
            };
        } else { // GL
            createInstanceFactory = [args]() {
                return android::renderengine::skia::SkiaGLRenderEngine::create(args);
            };
        }
    }

    if (args.threaded == Threaded::YES) {
        return renderengine::threaded::RenderEngineThreaded::create(createInstanceFactory);
    } else {
        return createInstanceFactory();
    }
}

RenderEngine::~RenderEngine() = default;

void RenderEngine::validateInputBufferUsage(const sp<GraphicBuffer>& buffer) {
    LOG_ALWAYS_FATAL_IF(!(buffer->getUsage() & GraphicBuffer::USAGE_HW_TEXTURE),
                        "input buffer not gpu readable");
}

void RenderEngine::validateOutputBufferUsage(const sp<GraphicBuffer>& buffer) {
    LOG_ALWAYS_FATAL_IF(!(buffer->getUsage() & GraphicBuffer::USAGE_HW_RENDER),
                        "output buffer not gpu writeable");
}

ftl::Future<FenceResult> RenderEngine::drawLayers(const DisplaySettings& display,
                                                  const std::vector<LayerSettings>& layers,
                                                  const std::shared_ptr<ExternalTexture>& buffer,
                                                  base::unique_fd&& bufferFence) {
    const auto resultPromise = std::make_shared<std::promise<FenceResult>>();
    std::future<FenceResult> resultFuture = resultPromise->get_future();
    updateProtectedContext(layers, buffer);
    drawLayersInternal(std::move(resultPromise), display, layers, buffer, std::move(bufferFence));
    return resultFuture;
}

void RenderEngine::updateProtectedContext(const std::vector<LayerSettings>& layers,
                                          const std::shared_ptr<ExternalTexture>& buffer) {
    const bool needsProtectedContext =
            (buffer && (buffer->getUsage() & GRALLOC_USAGE_PROTECTED)) ||
            std::any_of(layers.begin(), layers.end(), [](const LayerSettings& layer) {
                const std::shared_ptr<ExternalTexture>& buffer = layer.source.buffer.buffer;
                return buffer && (buffer->getUsage() & GRALLOC_USAGE_PROTECTED);
            });
    useProtectedContext(needsProtectedContext);
}

} // namespace renderengine
} // namespace android
