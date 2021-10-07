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
#include "threaded/RenderEngineThreaded.h"

#include "skia/SkiaGLRenderEngine.h"

namespace android {
namespace renderengine {

std::unique_ptr<RenderEngine> RenderEngine::create(const RenderEngineCreationArgs& args) {
    RenderEngineType renderEngineType = args.renderEngineType;

    // Keep the ability to override by PROPERTIES:
    char prop[PROPERTY_VALUE_MAX];
    property_get(PROPERTY_DEBUG_RENDERENGINE_BACKEND, prop, "");
    if (strcmp(prop, "gles") == 0) {
        renderEngineType = RenderEngineType::GLES;
    }
    if (strcmp(prop, "threaded") == 0) {
        renderEngineType = RenderEngineType::THREADED;
    }
    if (strcmp(prop, "skiagl") == 0) {
        renderEngineType = RenderEngineType::SKIA_GL;
    }
    if (strcmp(prop, "skiaglthreaded") == 0) {
        renderEngineType = RenderEngineType::SKIA_GL_THREADED;
    }

    switch (renderEngineType) {
        case RenderEngineType::THREADED:
            ALOGD("Threaded RenderEngine with GLES Backend");
            return renderengine::threaded::RenderEngineThreaded::create(
                    [args]() { return android::renderengine::gl::GLESRenderEngine::create(args); },
                    renderEngineType);
        case RenderEngineType::SKIA_GL:
            ALOGD("RenderEngine with SkiaGL Backend");
            return renderengine::skia::SkiaGLRenderEngine::create(args);
        case RenderEngineType::SKIA_GL_THREADED: {
            // These need to be recreated, since they are a constant reference, and we need to
            // let SkiaRE know that it's running as threaded, and all GL operation will happen on
            // the same thread.
            RenderEngineCreationArgs skiaArgs =
                    RenderEngineCreationArgs::Builder()
                            .setPixelFormat(args.pixelFormat)
                            .setImageCacheSize(args.imageCacheSize)
                            .setUseColorManagerment(args.useColorManagement)
                            .setEnableProtectedContext(args.enableProtectedContext)
                            .setPrecacheToneMapperShaderOnly(args.precacheToneMapperShaderOnly)
                            .setSupportsBackgroundBlur(args.supportsBackgroundBlur)
                            .setContextPriority(args.contextPriority)
                            .setRenderEngineType(renderEngineType)
                            .build();
            ALOGD("Threaded RenderEngine with SkiaGL Backend");
            return renderengine::threaded::RenderEngineThreaded::create(
                    [skiaArgs]() {
                        return android::renderengine::skia::SkiaGLRenderEngine::create(skiaArgs);
                    },
                    renderEngineType);
        }
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

} // namespace renderengine
} // namespace android
