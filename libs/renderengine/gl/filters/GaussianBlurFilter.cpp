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
    mVSizeLoc = mVerticalProgram.getUniformLocation("uSize");
    mVRadiusLoc = mVerticalProgram.getUniformLocation("uRadius");

    mHorizontalProgram.compile(getVertexShader(), getFragmentShader(true));
    mHPosLoc = mHorizontalProgram.getAttributeLocation("aPosition");
    mHUvLoc = mHorizontalProgram.getAttributeLocation("aUV");
    mHTextureLoc = mHorizontalProgram.getUniformLocation("uTexture");
    mHSizeLoc = mHorizontalProgram.getUniformLocation("uSize");
    mHRadiusLoc = mHorizontalProgram.getUniformLocation("uRadius");
}

void GaussianBlurFilter::allocateTextures() {
    mVerticalPassFbo.allocateBuffers(mBlurredFbo.getBufferWidth(), mBlurredFbo.getBufferHeight());
}

status_t GaussianBlurFilter::prepare(uint32_t radius) {
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

    // First, we'll apply the vertical pass, that receives the flattened background layers.
    mVerticalPassFbo.bind();
    mVerticalProgram.useProgram();

    // set uniforms
    auto width = mVerticalPassFbo.getBufferWidth();
    auto height = mVerticalPassFbo.getBufferHeight();
    glViewport(0, 0, width, height);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mCompositionFbo.getTextureName());
    glUniform1i(mVTextureLoc, 0);
    glUniform2f(mVSizeLoc, width, height);
    glUniform1f(mVRadiusLoc, radius * kFboScale);
    mEngine.checkErrors("Setting vertical-diagonal pass uniforms");

    drawMesh(mVUvLoc, mVPosLoc);

    // Blur vertically on a secondary pass
    mBlurredFbo.bind();
    mHorizontalProgram.useProgram();

    // set uniforms
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mVerticalPassFbo.getTextureName());
    glUniform1i(mHTextureLoc, 0);
    glUniform2f(mHSizeLoc, width, height);
    glUniform1f(mHRadiusLoc, radius * kFboScale);
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
    string shader = "#version 310 es\n#define DIRECTION ";
    shader += (horizontal ? "1" : "0");
    shader += R"SHADER(
        precision lowp float;

        uniform sampler2D uTexture;
        uniform vec2 uSize;
        uniform float uRadius;

        in mediump vec2 vUV;

        out vec4 fragColor;

        #define PI 3.14159265359
        #define THETA 0.352
        #define MU 0.0
        #define A 1.0 / (THETA * sqrt(2.0 * PI))
        #define K 1.0 / (2.0 * THETA * THETA)
        #define MAX_SAMPLES 12

        float gaussianBellCurve(float x) {
            float tmp = (x - MU);
            return exp(-K * tmp * tmp);
        }

        vec3 gaussianBlur(sampler2D texture, mediump vec2 uv, float size,
                          vec2 direction, float radius) {
            float totalWeight = 0.0;
            vec3 blurred = vec3(0.);
            int samples = min(int(floor(radius / 2.0)), MAX_SAMPLES);
            float inc = radius / (size * 2.0);

            for (int i = -samples; i <= samples; i++) {
                float normalized = (float(i) / float(samples));
                float weight = gaussianBellCurve(normalized);
                float radInc = inc * normalized;
                blurred += weight * (texture(texture, uv + radInc * direction)).rgb;;
                totalWeight += weight;
            }

            return blurred / totalWeight;
        }

        void main() {
            #if DIRECTION == 1
            vec3 color = gaussianBlur(uTexture, vUV, uSize.x, vec2(1.0, 0.0), uRadius);
            #else
            vec3 color = gaussianBlur(uTexture, vUV, uSize.y, vec2(0.0, 1.0), uRadius);
            #endif
            fragColor = vec4(color.r, color.g, color.b, texture(uTexture, vUV).a);
        }

    )SHADER";
    return shader;
}

} // namespace gl
} // namespace renderengine
} // namespace android
