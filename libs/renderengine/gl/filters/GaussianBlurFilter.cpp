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
    mVGaussianOffsetLoc = mVerticalProgram.getUniformLocation("uGaussianOffsets");
    mVNumSamplesLoc = mVerticalProgram.getUniformLocation("uSamples");
    mVGaussianWeightLoc = mVerticalProgram.getUniformLocation("uGaussianWeights");

    mHorizontalProgram.compile(getVertexShader(), getFragmentShader(true));
    mHPosLoc = mHorizontalProgram.getAttributeLocation("aPosition");
    mHUvLoc = mHorizontalProgram.getAttributeLocation("aUV");
    mHTextureLoc = mHorizontalProgram.getUniformLocation("uTexture");
    mHGaussianOffsetLoc = mHorizontalProgram.getUniformLocation("uGaussianOffsets");
    mHNumSamplesLoc = mHorizontalProgram.getUniformLocation("uSamples");
    mHGaussianWeightLoc = mHorizontalProgram.getUniformLocation("uGaussianWeights");
}

void GaussianBlurFilter::allocateTextures() {
    mVerticalPassFbo.allocateBuffers(mBlurredFbo.getBufferWidth(), mBlurredFbo.getBufferHeight());
}

static void calculateLinearGaussian(uint32_t samples, double dimension,
                                    GLfloat* gaussianLinearOffsets, GLfloat* gaussianWeights,
                                    GLfloat* gaussianLinearWeights) {
    // The central point in the symmetric bell curve is not offset.
    // This decision allows one less sampling in the GPU.
    gaussianLinearWeights[0] = gaussianWeights[0];
    gaussianLinearOffsets[0] = 0.0;

    // Calculate the linear weights.
    // This is a vector reduction where an element of the packed reduced array
    // contains the sum of two adjacent members of the original packed array.
    // We start preserving the element 1 of the array and then perform sum for
    // every other (i+=2) element of the gaussianWeights array.
    gaussianLinearWeights[1] = gaussianWeights[1];
    const auto start = 1 + ((samples - 1) & 0x1);
    for (size_t i = start; i < samples; i += 2) {
        gaussianLinearWeights[start + i / 2] = gaussianWeights[i] + gaussianWeights[i + 1];
    }

    // Calculate the texture coordinates offsets as an average of the initial offsets,
    // weighted by the Gaussian weights as described in the original article.
    gaussianLinearOffsets[1] = 1.0 / dimension;
    for (size_t i = start; i < samples; i += 2) {
        GLfloat offset_1 = float(i) / dimension;
        GLfloat offset_2 = float(i + 1) / dimension;
        gaussianLinearOffsets[start + i / 2] =
                (offset_1 * gaussianWeights[i] + offset_2 * gaussianWeights[i + 1]) /
                gaussianLinearWeights[start + i / 2];
    }
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

    // Precompute gaussian bell curve, and send it to the shader to avoid unnecessary computations.
    double radiusD = fmax(1.0, mRadius * kFboScale);
    auto samples = int(fmin(radiusD, kNumSamples));
    GLfloat gaussianWeights[kNumSamples] = {};

    gaussianWeights[0] = 1.0f;
    auto totalWeight = gaussianWeights[0];

    // Gaussian weights calculation.
    for (size_t i = 1; i < samples; i++) {
        const double normalized = i / radiusD;
        gaussianWeights[i] = (float)exp(-K * normalized * normalized);
        totalWeight += 2.0 * gaussianWeights[i];
    }

    // Gaussian weights normalization to avoid work in the GPU.
    for (size_t i = 0; i < samples; i++) {
        gaussianWeights[i] /= totalWeight;
    }

    auto width = mVerticalPassFbo.getBufferWidth();
    auto height = mVerticalPassFbo.getBufferHeight();
    glViewport(0, 0, width, height);

    // Allocate space for the corrected Gaussian weights and offsets.
    // We could use less space, but let's keep the code simple.
    GLfloat gaussianLinearWeights[kNumSamples] = {};
    GLfloat gaussianLinearOffsets[kNumSamples] = {};

    // Calculate the weights and offsets for the vertical pass.
    // This only need to be called every time mRadius or height changes, so it could be optimized.
    calculateLinearGaussian(samples, double(height), gaussianLinearOffsets, gaussianWeights,
                            gaussianLinearWeights);
    // set uniforms
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mBlurredFbo.getTextureName());
    glUniform1i(mVTextureLoc, 0);
    glUniform1i(mVNumSamplesLoc, 1 + (samples + 1) / 2);
    glUniform1fv(mVGaussianWeightLoc, kNumSamples, gaussianLinearWeights);
    glUniform1fv(mVGaussianOffsetLoc, kNumSamples, gaussianLinearOffsets);
    mEngine.checkErrors("Setting vertical pass uniforms");

    drawMesh(mVUvLoc, mVPosLoc);

    // Blur vertically on a secondary pass
    mBlurredFbo.bind();
    mHorizontalProgram.useProgram();

    // Calculate the weights and offsets for the horizontal pass.
    // This only needs to be called every time mRadius or width change, so it could be optimized.
    calculateLinearGaussian(samples, double(width), gaussianLinearOffsets, gaussianWeights,
                            gaussianLinearWeights);
    // set uniforms
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mVerticalPassFbo.getTextureName());
    glUniform1i(mHTextureLoc, 0);
    glUniform1i(mHNumSamplesLoc, 1 + (samples + 1) / 2);
    glUniform1fv(mHGaussianWeightLoc, kNumSamples, gaussianLinearWeights);
    glUniform1fv(mHGaussianOffsetLoc, kNumSamples, gaussianLinearOffsets);
    mEngine.checkErrors("Setting horizontal pass uniforms");

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
           << "#define NUM_SAMPLES " << 1 + (kNumSamples + 1) / 2 <<
            R"SHADER(
        precision mediump float;

        uniform sampler2D uTexture;
        uniform float[NUM_SAMPLES] uGaussianWeights;
        uniform float[NUM_SAMPLES] uGaussianOffsets;
        uniform int uSamples;

        highp in vec2 vUV;
        out vec4 fragColor;

        void main() {
            #if DIRECTION == 1
            const vec2 direction = vec2(1.0, 0.0);
            #else
            const vec2 direction = vec2(0.0, 1.0);
            #endif

            // Iteration zero outside loop to avoid sampling the central point twice.
            vec4 blurred = uGaussianWeights[0] * (texture(uTexture, vUV, 0.0));

            // Iterate one side of the bell to halve the loop iterations.
            for (int i = 1; i <= uSamples; i++) {
                vec2 offset = uGaussianOffsets[i] * direction;
                blurred += uGaussianWeights[i] * (texture(uTexture, vUV + offset, 0.0));
                blurred += uGaussianWeights[i] * (texture(uTexture, vUV - offset, 0.0));
            }

            fragColor = vec4(blurred.rgb, 1.0);
        }
    )SHADER";
    return shader.str();
}

} // namespace gl
} // namespace renderengine
} // namespace android
