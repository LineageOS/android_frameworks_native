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
                    [args]() { return android::renderengine::gl::GLESRenderEngine::create(args); });
        case RenderEngineType::SKIA_GL:
            return renderengine::skia::SkiaGLRenderEngine::create(args);
        case RenderEngineType::SKIA_GL_THREADED:
            return renderengine::threaded::RenderEngineThreaded::create([args]() {
                return android::renderengine::skia::SkiaGLRenderEngine::create(args);
            });
        case RenderEngineType::GLES:
        default:
            ALOGD("RenderEngine with GLES Backend");
            return renderengine::gl::GLESRenderEngine::create(args);
    }
}

RenderEngine::~RenderEngine() = default;

} // namespace renderengine
} // namespace android
