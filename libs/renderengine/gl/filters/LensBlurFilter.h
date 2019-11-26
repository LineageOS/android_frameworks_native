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

class LensBlurFilter : public BlurFilter {
public:
    explicit LensBlurFilter(GLESRenderEngine& engine);
    status_t prepare(uint32_t radius) override;
    void allocateTextures() override;

private:
    string getFragmentShader(bool forComposition) const;

    // Intermediate render pass
    GLFramebuffer mVerticalDiagonalPassFbo;

    // Vertical/diagonal pass and its uniforms
    GenericProgram mVerticalDiagonalProgram;
    GLuint mVDPosLoc;
    GLuint mVDUvLoc;
    GLuint mVDTexture0Loc;
    GLuint mVDSizeLoc;
    GLuint mVDRadiusLoc;
    GLuint mVDNumSamplesLoc;

    // Blur composition pass and its uniforms
    GenericProgram mCombinedProgram;
    GLuint mCPosLoc;
    GLuint mCUvLoc;
    GLuint mCTexture0Loc;
    GLuint mCTexture1Loc;
    GLuint mCSizeLoc;
    GLuint mCRadiusLoc;
    GLuint mCNumSamplesLoc;
};

} // namespace gl
} // namespace renderengine
} // namespace android