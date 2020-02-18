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
      : mEngine(engine), mCompositionFbo(engine), mBlurredFbo(engine), mMixProgram(engine) {
    mMixProgram.compile(getVertexShader(), getMixFragShader());
    mMPosLoc = mMixProgram.getAttributeLocation("aPosition");
    mMUvLoc = mMixProgram.getAttributeLocation("aUV");
    mMTextureLoc = mMixProgram.getUniformLocation("uTexture");
    mMCompositionTextureLoc = mMixProgram.getUniformLocation("uCompositionTexture");
    mMMixLoc = mMixProgram.getUniformLocation("uMix");
}

status_t BlurFilter::setAsDrawTarget(const DisplaySettings& display, uint32_t radius) {
    ATRACE_NAME("BlurFilter::setAsDrawTarget");
    mRadius = radius;

    if (!mTexturesAllocated) {
        mDisplayWidth = display.physicalDisplay.width();
        mDisplayHeight = display.physicalDisplay.height();
        mCompositionFbo.allocateBuffers(mDisplayWidth, mDisplayHeight);

        const uint32_t fboWidth = floorf(mDisplayWidth * kFboScale);
        const uint32_t fboHeight = floorf(mDisplayHeight * kFboScale);
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
    static constexpr auto size = 2.0f;
    static constexpr auto translation = 1.0f;
    GLfloat positions[] = {
        translation-size, -translation-size,
        translation-size, -translation+size,
        translation+size, -translation+size
    };
    GLfloat texCoords[] = {
        0.0f, 0.0f-translation,
        0.0f, size-translation,
        size, size-translation
    };

    // set attributes
    glEnableVertexAttribArray(uv);
    glVertexAttribPointer(uv, 2 /* size */, GL_FLOAT, GL_FALSE, 0, texCoords);
    glEnableVertexAttribArray(position);
    glVertexAttribPointer(position, 2 /* size */, GL_FLOAT, GL_FALSE, 2 * sizeof(GLfloat),
                          positions);

    // draw mesh
    glDrawArrays(GL_TRIANGLES, 0 /* first */, 3 /* count */);
    mEngine.checkErrors("Drawing blur mesh");
}

status_t BlurFilter::render(bool multiPass) {
    ATRACE_NAME("BlurFilter::render");

    // Now let's scale our blur up. It will be interpolated with the larger composited
    // texture for the first frames, to hide downscaling artifacts.
    GLfloat mix = fmin(1.0, mRadius / kMaxCrossFadeRadius);

    // When doing multiple passes, we cannot try to read mCompositionFbo, given that we'll
    // be writing onto it. Let's disable the crossfade, otherwise we'd need 1 extra frame buffer,
    // as large as the screen size.
    if (mix >= 1 || multiPass) {
        mBlurredFbo.bindAsReadBuffer();
        glBlitFramebuffer(0, 0, mBlurredFbo.getBufferWidth(), mBlurredFbo.getBufferHeight(), 0, 0,
                          mDisplayWidth, mDisplayHeight, GL_COLOR_BUFFER_BIT, GL_LINEAR);
        glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
        return NO_ERROR;
    }

    mMixProgram.useProgram();
    glUniform1f(mMMixLoc, mix);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mBlurredFbo.getTextureName());
    glUniform1i(mMTextureLoc, 0);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, mCompositionFbo.getTextureName());
    glUniform1i(mMCompositionTextureLoc, 1);
    mEngine.checkErrors("Setting final pass uniforms");

    drawMesh(mMUvLoc, mMPosLoc);

    glUseProgram(0);
    glActiveTexture(GL_TEXTURE0);
    return NO_ERROR;
}

string BlurFilter::getVertexShader() const {
    return R"SHADER(#version 310 es

        in vec2 aPosition;
        in highp vec2 aUV;
        out highp vec2 vUV;

        void main() {
            vUV = aUV;
            gl_Position = vec4(aPosition, 0.0, 1.0);
        }
    )SHADER";
}

string BlurFilter::getMixFragShader() const {
    string shader = R"SHADER(#version 310 es
        precision mediump float;

        in highp vec2 vUV;
        out vec4 fragColor;

        uniform sampler2D uCompositionTexture;
        uniform sampler2D uTexture;
        uniform float uMix;

        void main() {
            vec4 blurred = texture(uTexture, vUV);
            vec4 composition = texture(uCompositionTexture, vUV);
            fragColor = mix(composition, blurred, uMix);
        }
    )SHADER";
    return shader;
}

} // namespace gl
} // namespace renderengine
} // namespace android
