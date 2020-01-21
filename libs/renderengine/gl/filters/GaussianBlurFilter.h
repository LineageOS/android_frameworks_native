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
#include "BlurFilter.h"
#include "GenericProgram.h"

using namespace std;

namespace android {
namespace renderengine {
namespace gl {

class GaussianBlurFilter : public BlurFilter {
public:
    explicit GaussianBlurFilter(GLESRenderEngine& engine);
    status_t prepare(uint32_t radius) override;
    void allocateTextures() override;

private:
    string getFragmentShader(bool horizontal) const;

    // Initial, vertical render pass
    GLFramebuffer mVerticalPassFbo;

    // Vertical pass and its uniforms
    GenericProgram mVerticalProgram;
    GLuint mVPosLoc;
    GLuint mVUvLoc;
    GLuint mVTextureLoc;
    GLuint mVSizeLoc;
    GLuint mVRadiusLoc;

    // Horizontal pass and its uniforms
    GenericProgram mHorizontalProgram;
    GLuint mHPosLoc;
    GLuint mHUvLoc;
    GLuint mHTextureLoc;
    GLuint mHSizeLoc;
    GLuint mHRadiusLoc;
};

} // namespace gl
} // namespace renderengine
} // namespace android