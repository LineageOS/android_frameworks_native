/*
 * Copyright 2020 The Android Open Source Project
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

class KawaseBlurFilter : public BlurFilter {
public:
    static constexpr uint32_t kMaxPasses = 6;

    explicit KawaseBlurFilter(GLESRenderEngine& engine);
    status_t prepare() override;
    void allocateTextures() override;

private:
    string getFragmentShader() const;
    void blit(GLFramebuffer& read, GLFramebuffer& draw) const;

    GLFramebuffer mFbo;

    GenericProgram mProgram;
    GLuint mPosLoc;
    GLuint mUvLoc;
    GLuint mTextureLoc;
    GLuint mOffsetLoc;
};

} // namespace gl
} // namespace renderengine
} // namespace android
