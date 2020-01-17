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

#include "LensBlurFilter.h"
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

// Number of blur samples in shader (for loop)
static constexpr auto kNumSamples = 12;

LensBlurFilter::LensBlurFilter(GLESRenderEngine& engine)
      : BlurFilter(engine),
        mVerticalDiagonalPassFbo(engine, true /* multiTarget */),
        mVerticalDiagonalProgram(engine),
        mCombinedProgram(engine) {
    mVerticalDiagonalProgram.compile(getVertexShader(), getFragmentShader(false));
    mCombinedProgram.compile(getVertexShader(), getFragmentShader(true));

    mVDPosLoc = mVerticalDiagonalProgram.getAttributeLocation("aPosition");
    mVDUvLoc = mVerticalDiagonalProgram.getAttributeLocation("aUV");
    mVDTexture0Loc = mVerticalDiagonalProgram.getUniformLocation("uTexture0");
    mVDSizeLoc = mVerticalDiagonalProgram.getUniformLocation("uSize");
    mVDRadiusLoc = mVerticalDiagonalProgram.getUniformLocation("uRadius");
    mVDNumSamplesLoc = mVerticalDiagonalProgram.getUniformLocation("uNumSamples");

    mCPosLoc = mCombinedProgram.getAttributeLocation("aPosition");
    mCUvLoc = mCombinedProgram.getAttributeLocation("aUV");
    mCTexture0Loc = mCombinedProgram.getUniformLocation("uTexture0");
    mCTexture1Loc = mCombinedProgram.getUniformLocation("uTexture1");
    mCSizeLoc = mCombinedProgram.getUniformLocation("uSize");
    mCRadiusLoc = mCombinedProgram.getUniformLocation("uRadius");
    mCNumSamplesLoc = mCombinedProgram.getUniformLocation("uNumSamples");
}

void LensBlurFilter::allocateTextures() {
    mVerticalDiagonalPassFbo.allocateBuffers(mBlurredFbo.getBufferWidth(),
                                             mBlurredFbo.getBufferHeight());
}

status_t LensBlurFilter::prepare() {
    ATRACE_NAME("LensBlurFilter::prepare");

    if (mVerticalDiagonalPassFbo.getStatus() != GL_FRAMEBUFFER_COMPLETE) {
        ALOGE("Invalid vertical-diagonal FBO");
        return mVerticalDiagonalPassFbo.getStatus();
    }
    if (!mVerticalDiagonalProgram.isValid()) {
        ALOGE("Invalid vertical-diagonal shader");
        return GL_INVALID_OPERATION;
    }
    if (!mCombinedProgram.isValid()) {
        ALOGE("Invalid blur shader");
        return GL_INVALID_OPERATION;
    }

    // First, we'll apply the vertical/diagonal pass, that receives the flattened background layers,
    // and writes the output to two textures (vertical and diagonal.)
    mVerticalDiagonalPassFbo.bind();
    mVerticalDiagonalProgram.useProgram();

    // set uniforms
    auto width = mVerticalDiagonalPassFbo.getBufferWidth();
    auto height = mVerticalDiagonalPassFbo.getBufferHeight();
    auto radiusF = fmax(1.0f, mRadius * kFboScale);
    glViewport(0, 0, width, height);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mCompositionFbo.getTextureName());
    glUniform1i(mVDTexture0Loc, 0);
    glUniform2f(mVDSizeLoc, mDisplayWidth, mDisplayHeight);
    glUniform1f(mVDRadiusLoc, radiusF);
    glUniform1i(mVDNumSamplesLoc, kNumSamples);
    mEngine.checkErrors("Setting vertical-diagonal pass uniforms");

    drawMesh(mVDUvLoc, mVDPosLoc);

    // Now we'll combine the multi render pass into a blurred image
    mBlurredFbo.bind();
    mCombinedProgram.useProgram();

    // set uniforms
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mVerticalDiagonalPassFbo.getTextureName());
    glUniform1i(mCTexture0Loc, 0);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, mVerticalDiagonalPassFbo.getSecondaryTextureName());
    glUniform1i(mCTexture1Loc, 1);
    glUniform2f(mCSizeLoc, mDisplayWidth, mDisplayHeight);
    glUniform1f(mCRadiusLoc, radiusF);
    glUniform1i(mCNumSamplesLoc, kNumSamples);
    mEngine.checkErrors("Setting vertical pass uniforms");

    drawMesh(mCUvLoc, mCPosLoc);

    // reset active texture
    mBlurredFbo.unbind();
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, 0);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, 0);

    // unbind program
    glUseProgram(0);

    return NO_ERROR;
}

string LensBlurFilter::getFragmentShader(bool forComposition) const {
    string shader = "#version 310 es\n#define DIRECTION ";
    shader += (forComposition ? "1" : "0");
    shader += R"SHADER(
        precision mediump float;
        #define PI 3.14159265359

        uniform sampler2D uTexture0;
        uniform vec2 uSize;
        uniform float uRadius;
        uniform int uNumSamples;

        highp in vec2 vUV;

        #if DIRECTION == 0
        layout(location = 0) out vec4 fragColor0;
        layout(location = 1) out vec4 fragColor1;
        #else
        uniform sampler2D uTexture1;
        out vec4 fragColor;
        #endif

        const vec2 verticalMult = vec2(cos(PI / 2.0), sin(PI / 2.0));
        const vec2 diagonalMult = vec2(cos(-PI / 6.0), sin(-PI / 6.0));
        const vec2 diagonal2Mult = vec2(cos(-5.0 * PI / 6.0), sin(-5.0 * PI / 6.0));

        vec3 blur(const sampler2D tex, vec2 uv, const vec2 direction, float radius,
                  int samples, float intensity) {
            vec3 finalColor = vec3(0.0);
            uv += direction * 0.5;

            for (int i = 0; i < samples; i++){
                float delta = radius * float(i) / float(samples);
                vec3 color = texture(tex, uv + direction * delta).rgb;
                color.rgb *= intensity;
                finalColor += color;
            }

            return finalColor / float(samples);
        }

        vec3 blur(const sampler2D tex, vec2 uv, const vec2 direction, float radius,
                  int samples) {
            return blur(tex, uv, direction, radius, samples, 1.0);
        }

        vec4[2] verticalDiagonalLensBlur (vec2 uv, sampler2D texture, vec2 resolution,
                                          float radius, int samples) {
            // Vertical Blur
            vec2 blurDirV = 1.0 / resolution.xy * verticalMult;
            vec3 colorV = blur(texture, uv, blurDirV, radius, samples);

            // Diagonal Blur
            vec2 blurDirD = 1.0 / resolution.xy * diagonalMult;
            vec3 colorD = blur(texture, uv, blurDirD, radius, samples);

            vec4 composed[2];
            composed[0] = vec4(colorV, 1.0);
            // added * 0.5, to remap
            composed[1] = vec4((colorD + colorV) * 0.5, 1.0);

            return composed;
        }

        vec4 rhombiLensBlur (vec2 uv, sampler2D texture0, sampler2D texture1, vec2 resolution,
                             float radius, int samples) {
            vec2 blurDirection1 = 1.0 / resolution.xy * diagonalMult;
            vec3 color1 = blur(texture0, uv, blurDirection1, radius, samples);

            vec2 blurDirection2 = 1.0 / resolution.xy * diagonal2Mult;
            vec3 color2 = blur(texture1, uv, blurDirection2, radius, samples, 2.0);

            return vec4((color1 + color2) * 0.33, 1.0);
        }

        void main() {
            #if DIRECTION == 0
            // First pass: outputs two textures
            vec4 colorOut[] = verticalDiagonalLensBlur(vUV, uTexture0, uSize, uRadius, uNumSamples);
            fragColor0 = colorOut[0];
            fragColor1 = colorOut[1];
            #else
            // Second pass: combines both textures into a blurred one.
            fragColor = rhombiLensBlur(vUV, uTexture0, uTexture1, uSize, uRadius, uNumSamples);
            #endif
        }

    )SHADER";
    return shader;
}

} // namespace gl
} // namespace renderengine
} // namespace android
