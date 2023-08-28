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

#include <cutils/properties.h>
#include <log/log.h>
#include "gl/GLESRenderEngine.h"
#include "renderengine/ExternalTexture.h"
#include "threaded/RenderEngineThreaded.h"

#include "skia/SkiaGLRenderEngine.h"
#include "skia/SkiaVkRenderEngine.h"

namespace android {
namespace renderengine {

std::unique_ptr<RenderEngine> RenderEngine::create(const RenderEngineCreationArgs& args) {
    switch (args.renderEngineType) {
        case RenderEngineType::THREADED:
            ALOGD("Threaded RenderEngine with GLES Backend");
            return renderengine::threaded::RenderEngineThreaded::create(
                    [args]() { return android::renderengine::gl::GLESRenderEngine::create(args); },
                    args.renderEngineType);
        case RenderEngineType::SKIA_GL:
            ALOGD("RenderEngine with SkiaGL Backend");
            return renderengine::skia::SkiaGLRenderEngine::create(args);
        case RenderEngineType::SKIA_VK:
            ALOGD("RenderEngine with SkiaVK Backend");
            return renderengine::skia::SkiaVkRenderEngine::create(args);
        case RenderEngineType::SKIA_GL_THREADED: {
            ALOGD("Threaded RenderEngine with SkiaGL Backend");
            return renderengine::threaded::RenderEngineThreaded::create(
                    [args]() {
                        return android::renderengine::skia::SkiaGLRenderEngine::create(args);
                    },
                    args.renderEngineType);
        }
        case RenderEngineType::SKIA_VK_THREADED:
            ALOGD("Threaded RenderEngine with SkiaVK Backend");
            return renderengine::threaded::RenderEngineThreaded::create(
                    [args]() {
                        return android::renderengine::skia::SkiaVkRenderEngine::create(args);
                    },
                    args.renderEngineType);
        case RenderEngineType::GLES:
        default:
            ALOGD("RenderEngine with GLES Backend");
            return renderengine::gl::GLESRenderEngine::create(args);
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
                                                  const bool useFramebufferCache,
                                                  base::unique_fd&& bufferFence) {
    const auto resultPromise = std::make_shared<std::promise<FenceResult>>();
    std::future<FenceResult> resultFuture = resultPromise->get_future();
    updateProtectedContext(layers, buffer);
    drawLayersInternal(std::move(resultPromise), display, layers, buffer, useFramebufferCache,
                       std::move(bufferFence));
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
