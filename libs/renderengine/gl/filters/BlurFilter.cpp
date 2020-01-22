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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "BlurFilter.h"
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <GLES3/gl3ext.h>
#include <ui/GraphicTypes.h>
#include <cstdint>

#include <utils/Trace.h>

namespace android {
namespace renderengine {
namespace gl {

BlurFilter::BlurFilter(GLESRenderEngine& engine)
      : mEngine(engine), mCompositionFbo(engine), mBlurredFbo(engine), mSimpleProgram(engine) {
    mSimpleProgram.compile(getVertexShader(), getSimpleFragShader());
    mSPosLoc = mSimpleProgram.getAttributeLocation("aPosition");
    mSUvLoc = mSimpleProgram.getAttributeLocation("aUV");
    mSTextureLoc = mSimpleProgram.getUniformLocation("uTexture");
}

status_t BlurFilter::setAsDrawTarget(const DisplaySettings& display) {
    ATRACE_NAME("BlurFilter::setAsDrawTarget");

    if (!mTexturesAllocated) {
        const uint32_t fboWidth = floorf(display.physicalDisplay.width() * kFboScale);
        const uint32_t fboHeight = floorf(display.physicalDisplay.height() * kFboScale);
        mCompositionFbo.allocateBuffers(fboWidth, fboHeight);
        mBlurredFbo.allocateBuffers(fboWidth, fboHeight);
        allocateTextures();
        mTexturesAllocated = true;
    }

    if (mBlurredFbo.getStatus() != GL_FRAMEBUFFER_COMPLETE) {
        ALOGE("Invalid blur buffer");
        return mBlurredFbo.getStatus();
    }
    if (mCompositionFbo.getStatus() != GL_FRAMEBUFFER_COMPLETE) {
        ALOGE("Invalid composition buffer");
        return mCompositionFbo.getStatus();
    }

    mCompositionFbo.bind();
    glViewport(0, 0, mCompositionFbo.getBufferWidth(), mCompositionFbo.getBufferHeight());
    return NO_ERROR;
}

void BlurFilter::drawMesh(GLuint uv, GLuint position) {
    GLfloat positions[] = {-1.0f, -1.0f, -1.0f, 1.0f, 1.0f, 1.0f, 1.0f, -1.0f};
    GLfloat texCoords[] = {0.0, 0.0, 0.0, 1.0f, 1.0f, 1.0f, 1.0f, 0};

    // set attributes
    glEnableVertexAttribArray(uv);
    glVertexAttribPointer(uv, 2 /* size */, GL_FLOAT, GL_FALSE, 0, texCoords);
    glEnableVertexAttribArray(position);
    glVertexAttribPointer(position, 2 /* size */, GL_FLOAT, GL_FALSE, 2 * sizeof(GLfloat),
                          positions);

    // draw mesh
    glDrawArrays(GL_TRIANGLE_FAN, 0 /* first */, 4 /* count */);
    mEngine.checkErrors("Drawing blur mesh");
}

status_t BlurFilter::render() {
    ATRACE_NAME("BlurFilter::render");

    // Now let's scale our blur up
    mSimpleProgram.useProgram();
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mBlurredFbo.getTextureName());
    glUniform1i(mSTextureLoc, 0);
    mEngine.checkErrors("Setting final pass uniforms");

    drawMesh(mSUvLoc, mSPosLoc);

    glUseProgram(0);
    return NO_ERROR;
}

string BlurFilter::getVertexShader() const {
    return R"SHADER(
        #version 310 es
        precision lowp float;

        in vec2 aPosition;
        in mediump vec2 aUV;
        out mediump vec2 vUV;

        void main() {
            vUV = aUV;
            gl_Position = vec4(aPosition, 0.0, 1.0);
        }
    )SHADER";
}

string BlurFilter::getSimpleFragShader() const {
    string shader = R"SHADER(
        #version 310 es
        precision lowp float;

        in mediump vec2 vUV;
        out vec4 fragColor;

        uniform sampler2D uTexture;

        void main() {
            fragColor = texture(uTexture, vUV);
        }
    )SHADER";
    return shader;
}

} // namespace gl
} // namespace renderengine
} // namespace android
