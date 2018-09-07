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

#include <vector>

#include <log/log.h>
#include <private/gui/SyncFeatures.h>
#include <renderengine/Image.h>
#include <renderengine/Mesh.h>
#include <renderengine/Surface.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <utils/KeyedVector.h>
#include "gl/GLES20RenderEngine.h"
#include "gl/GLExtensions.h"
#include "gl/ProgramCache.h"

using namespace android::renderengine::gl;

extern "C" EGLAPI const char* eglQueryStringImplementationANDROID(EGLDisplay dpy, EGLint name);

namespace android {
namespace renderengine {

std::unique_ptr<impl::RenderEngine> RenderEngine::create(int hwcFormat, uint32_t featureFlags) {
    return renderengine::gl::GLES20RenderEngine::create(hwcFormat, featureFlags);
}

RenderEngine::~RenderEngine() = default;

namespace impl {

RenderEngine::RenderEngine(uint32_t featureFlags)
      : mFeatureFlags(featureFlags) {}

RenderEngine::~RenderEngine() = default;

bool RenderEngine::useNativeFenceSync() const {
    return SyncFeatures::getInstance().useNativeFenceSync();
}

bool RenderEngine::useWaitSync() const {
    return SyncFeatures::getInstance().useWaitSync();
}

}  // namespace impl
}  // namespace renderengine
}  // namespace android
