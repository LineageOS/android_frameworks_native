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

#include "GaussianBlurFilter.h"
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <GLES3/gl3ext.h>
#include <ui/GraphicTypes.h>
#include <cstdint>

#include <utils/Trace.h>

#define PI 3.14159265359
#define THETA 0.352
#define K 1.0 / (2.0 * THETA * THETA)

namespace android {
namespace renderengine {
namespace gl {

GaussianBlurFilter::GaussianBlurFilter(GLESRenderEngine& engine)
      : BlurFilter(engine),
        mVerticalPassFbo(engine),
        mVerticalProgram(engine),
        mHorizontalProgram(engine) {
    mVerticalProgram.compile(getVertexShader(), getFragmentShader(false));
    mVPosLoc = mVerticalProgram.getAttributeLocation("aPosition");
    mVUvLoc = mVerticalProgram.getAttributeLocation("aUV");
    mVTextureLoc = mVerticalProgram.getUniformLocation("uTexture");
    mVIncrementLoc = mVerticalProgram.getUniformLocation("uIncrement");
    mVNumSamplesLoc = mVerticalProgram.getUniformLocation("uSamples");
    mVGaussianWeightLoc = mVerticalProgram.getUniformLocation("uGaussianWeights");

    mHorizontalProgram.compile(getVertexShader(), getFragmentShader(true));
    mHPosLoc = mHorizontalProgram.getAttributeLocation("aPosition");
    mHUvLoc = mHorizontalProgram.getAttributeLocation("aUV");
    mHTextureLoc = mHorizontalProgram.getUniformLocation("uTexture");
    mHIncrementLoc = mHorizontalProgram.getUniformLocation("uIncrement");
    mHNumSamplesLoc = mHorizontalProgram.getUniformLocation("uSamples");
    mHGaussianWeightLoc = mHorizontalProgram.getUniformLocation("uGaussianWeights");
}

void GaussianBlurFilter::allocateTextures() {
    mVerticalPassFbo.allocateBuffers(mBlurredFbo.getBufferWidth(), mBlurredFbo.getBufferHeight());
}

status_t GaussianBlurFilter::prepare() {
    ATRACE_NAME("GaussianBlurFilter::prepare");

    if (mVerticalPassFbo.getStatus() != GL_FRAMEBUFFER_COMPLETE) {
        ALOGE("Invalid vertical FBO");
        return mVerticalPassFbo.getStatus();
    }
    if (!mVerticalProgram.isValid()) {
        ALOGE("Invalid vertical shader");
        return GL_INVALID_OPERATION;
    }
    if (!mHorizontalProgram.isValid()) {
        ALOGE("Invalid horizontal shader");
        return GL_INVALID_OPERATION;
    }

    mCompositionFbo.bindAsReadBuffer();
    mBlurredFbo.bindAsDrawBuffer();
    glBlitFramebuffer(0, 0, mCompositionFbo.getBufferWidth(), mCompositionFbo.getBufferHeight(), 0,
                      0, mBlurredFbo.getBufferWidth(), mBlurredFbo.getBufferHeight(),
                      GL_COLOR_BUFFER_BIT, GL_LINEAR);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);

    // First, we'll apply the vertical pass, that receives the flattened background layers.
    mVerticalPassFbo.bind();
    mVerticalProgram.useProgram();

    // Precompute gaussian bell curve, and send it to the shader to avoid
    // unnecessary computations.
    auto samples = min(mRadius, kNumSamples);
    GLfloat gaussianWeights[kNumSamples] = {};
    for (size_t i = 0; i < samples; i++) {
        float normalized = float(i) / samples;
        gaussianWeights[i] = (float)exp(-K * normalized * normalized);
    }

    // set uniforms
    auto width = mVerticalPassFbo.getBufferWidth();
    auto height = mVerticalPassFbo.getBufferHeight();
    auto radiusF = fmax(1.0f, mRadius * kFboScale);
    glViewport(0, 0, width, height);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mBlurredFbo.getTextureName());
    glUniform1i(mVTextureLoc, 0);
    glUniform2f(mVIncrementLoc, radiusF / (width * 2.0f), radiusF / (height * 2.0f));
    glUniform1i(mVNumSamplesLoc, samples);
    glUniform1fv(mVGaussianWeightLoc, kNumSamples, gaussianWeights);
    mEngine.checkErrors("Setting vertical-diagonal pass uniforms");

    drawMesh(mVUvLoc, mVPosLoc);

    // Blur vertically on a secondary pass
    mBlurredFbo.bind();
    mHorizontalProgram.useProgram();

    // set uniforms
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mVerticalPassFbo.getTextureName());
    glUniform1i(mHTextureLoc, 0);
    glUniform2f(mHIncrementLoc, radiusF / (width * 2.0f), radiusF / (height * 2.0f));
    glUniform1i(mHNumSamplesLoc, samples);
    glUniform1fv(mHGaussianWeightLoc, kNumSamples, gaussianWeights);
    mEngine.checkErrors("Setting vertical pass uniforms");

    drawMesh(mHUvLoc, mHPosLoc);

    // reset active texture
    mBlurredFbo.unbind();
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, 0);

    // unbind program
    glUseProgram(0);

    return NO_ERROR;
}

string GaussianBlurFilter::getFragmentShader(bool horizontal) const {
    stringstream shader;
    shader << "#version 310 es\n"
           << "#define DIRECTION " << (horizontal ? "1" : "0") << "\n"
           << "#define NUM_SAMPLES " << kNumSamples <<
            R"SHADER(
        precision mediump float;

        uniform sampler2D uTexture;
        uniform vec2 uIncrement;
        uniform float[NUM_SAMPLES] uGaussianWeights;
        uniform int uSamples;

        highp in vec2 vUV;
        out vec4 fragColor;

        vec3 gaussianBlur(sampler2D texture, highp vec2 uv, float inc, vec2 direction) {
            float totalWeight = 0.0;
            vec3 blurred = vec3(0.0);
            float fSamples = 1.0 / float(uSamples);

            for (int i = -uSamples; i <= uSamples; i++) {
                float weight = uGaussianWeights[abs(i)];
                float normalized = float(i) * fSamples;
                float radInc = inc * normalized;
                blurred += weight * (texture(texture, radInc * direction + uv, 0.0)).rgb;
                totalWeight += weight;
            }

            return blurred / totalWeight;
        }

        void main() {
            #if DIRECTION == 1
            vec3 color = gaussianBlur(uTexture, vUV, uIncrement.x, vec2(1.0, 0.0));
            #else
            vec3 color = gaussianBlur(uTexture, vUV, uIncrement.y, vec2(0.0, 1.0));
            #endif
            fragColor = vec4(color, 1.0);
        }

    )SHADER";
    return shader.str();
}

} // namespace gl
} // namespace renderengine
} // namespace android
