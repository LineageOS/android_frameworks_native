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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "KawaseBlurFilter.h"
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <GLES3/gl3ext.h>
#include <ui/GraphicTypes.h>

#include <utils/Trace.h>

namespace android {
namespace renderengine {
namespace gl {

KawaseBlurFilter::KawaseBlurFilter(GLESRenderEngine& engine)
      : BlurFilter(engine), mFbo(engine), mProgram(engine) {
    mProgram.compile(getVertexShader(), getFragmentShader());
    mPosLoc = mProgram.getAttributeLocation("aPosition");
    mUvLoc = mProgram.getAttributeLocation("aUV");
    mTextureLoc = mProgram.getUniformLocation("uTexture");
    mOffsetLoc = mProgram.getUniformLocation("uOffset");
}

void KawaseBlurFilter::allocateTextures() {
    mFbo.allocateBuffers(mBlurredFbo.getBufferWidth(), mBlurredFbo.getBufferHeight());
}

status_t KawaseBlurFilter::prepare() {
    ATRACE_NAME("KawaseBlurFilter::prepare");

    if (mFbo.getStatus() != GL_FRAMEBUFFER_COMPLETE) {
        ALOGE("Invalid FBO");
        return mFbo.getStatus();
    }
    if (!mProgram.isValid()) {
        ALOGE("Invalid shader");
        return GL_INVALID_OPERATION;
    }

    blit(mCompositionFbo, mBlurredFbo);

    // Kawase is an approximation of Gaussian, but it behaves differently from it.
    // A radius transformation is required for approximating them, and also to introduce
    // non-integer steps, necessary to smoothly interpolate large radii.
    auto radius = mRadius / 6.0f;

    // Calculate how many passes we'll do, based on the radius.
    // Too many passes will make the operation expensive.
    auto passes = min(kMaxPasses, (uint32_t)ceil(radius));

    // We'll ping pong between our textures, to accumulate the result of various offsets.
    mProgram.useProgram();
    GLFramebuffer* draw = &mFbo;
    GLFramebuffer* read = &mBlurredFbo;
    float stepX = radius / (float)mCompositionFbo.getBufferWidth() / (float)passes;
    float stepY = radius / (float)mCompositionFbo.getBufferHeight() / (float)passes;
    glActiveTexture(GL_TEXTURE0);
    glUniform1i(mTextureLoc, 0);
    for (auto i = 0; i < passes; i++) {
        ATRACE_NAME("KawaseBlurFilter::renderPass");
        draw->bind();

        glViewport(0, 0, draw->getBufferWidth(), draw->getBufferHeight());
        glBindTexture(GL_TEXTURE_2D, read->getTextureName());
        glUniform2f(mOffsetLoc, stepX * i, stepY * i);
        mEngine.checkErrors("Setting uniforms");

        drawMesh(mUvLoc, mPosLoc);

        // Swap buffers for next iteration
        auto tmp = draw;
        draw = read;
        read = tmp;
    }

    // Copy texture, given that we're expected to end on mBlurredFbo.
    if (draw == &mBlurredFbo) {
        blit(mFbo, mBlurredFbo);
    }

    // Cleanup
    glBindFramebuffer(GL_FRAMEBUFFER, 0);

    return NO_ERROR;
}

string KawaseBlurFilter::getFragmentShader() const {
    return R"SHADER(#version 310 es
        precision mediump float;

        uniform sampler2D uTexture;
        uniform vec2 uOffset;

        highp in vec2 vUV;
        out vec4 fragColor;

        void main() {
            fragColor  = texture(uTexture, vUV, 0.0);
            fragColor += texture(uTexture, vUV + vec2( uOffset.x,  uOffset.y), 0.0);
            fragColor += texture(uTexture, vUV + vec2( uOffset.x, -uOffset.y), 0.0);
            fragColor += texture(uTexture, vUV + vec2(-uOffset.x,  uOffset.y), 0.0);
            fragColor += texture(uTexture, vUV + vec2(-uOffset.x, -uOffset.y), 0.0);

            fragColor = vec4(fragColor.rgb * 0.2, 1.0);
        }
    )SHADER";
}

void KawaseBlurFilter::blit(GLFramebuffer& read, GLFramebuffer& draw) const {
    read.bindAsReadBuffer();
    draw.bindAsDrawBuffer();
    glBlitFramebuffer(0, 0, read.getBufferWidth(), read.getBufferHeight(), 0, 0,
                      draw.getBufferWidth(), draw.getBufferHeight(), GL_COLOR_BUFFER_BIT,
                      GL_LINEAR);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

} // namespace gl
} // namespace renderengine
} // namespace android
