/*
 * Copyright 2019 The Android Open Source Project
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

#pragma once

#include <ui/GraphicTypes.h>
#include "../GLESRenderEngine.h"
#include "../GLFramebuffer.h"
#include "GenericProgram.h"

using namespace std;

namespace android {
namespace renderengine {
namespace gl {

class BlurFilter {
public:
    // Downsample FBO to improve performance
    static constexpr float kFboScale = 0.35f;

    explicit BlurFilter(GLESRenderEngine& engine);
    virtual ~BlurFilter(){};

    // Set up render targets, redirecting output to offscreen texture.
    status_t setAsDrawTarget(const DisplaySettings&);
    // Allocate any textures needed for the filter.
    virtual void allocateTextures() = 0;
    // Execute blur passes, rendering to offscreen texture.
    virtual status_t prepare(uint32_t radius) = 0;
    // Render blur to the bound framebuffer (screen).
    status_t render();

protected:
    void drawMesh(GLuint uv, GLuint position);
    string getSimpleFragShader() const;
    string getVertexShader() const;

    GLESRenderEngine& mEngine;
    // Frame buffer holding the composited background.
    GLFramebuffer mCompositionFbo;
    // Frame buffer holding the blur result.
    GLFramebuffer mBlurredFbo;

private:
    bool mTexturesAllocated = false;

    GenericProgram mSimpleProgram;
    GLuint mSPosLoc;
    GLuint mSUvLoc;
    GLuint mSTextureLoc;
};

} // namespace gl
} // namespace renderengine
} // namespace android
