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

status_t LensBlurFilter::prepare(uint32_t radius) {
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
    glViewport(0, 0, width, height);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, mCompositionFbo.getTextureName());
    glUniform1i(mVDTexture0Loc, 0);
    glUniform2f(mVDSizeLoc, width, height);
    glUniform1f(mVDRadiusLoc, radius * kFboScale);
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
    glUniform2f(mCSizeLoc, width, height);
    glUniform1f(mCRadiusLoc, radius * kFboScale);
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
        precision lowp float;

        #define BOKEH_ANGLE 0.0
        #define PI 3.14159265359

        uniform sampler2D uTexture0;
        uniform vec2 uSize;
        uniform float uRadius;
        uniform int uNumSamples;

        in mediump vec2 vUV;

        #if DIRECTION == 0
        layout(location = 0) out vec4 fragColor0;
        layout(location = 1) out vec4 fragColor1;
        #else
        uniform sampler2D uTexture1;
        out vec4 fragColor;
        #endif

        vec4 blur(const sampler2D tex, in vec2 uv, const vec2 direction, float radius,
                  in int samples, float intensity) {
            vec4 finalColor = vec4(vec3(0.0), 1.0);
            float blurAmount = 0.0;
            uv += direction * 0.5;

            for (int i = 0; i < samples; i++){
                float delta = radius * float(i) / float(samples);
                vec4 color = texture(tex, uv + direction * delta);
                color.rgb *= intensity;
                color *= color.a;
                blurAmount += color.a;
                finalColor += color;
            }

            return finalColor / blurAmount;
        }

        vec4 blur(const sampler2D tex, in vec2 uv, const vec2 direction, float radius,
                  in int samples) {
            return blur(tex, uv, direction, radius, samples, 1.0);
        }

        vec4[2] verticalDiagonalLensBlur (vec2 uv, sampler2D texture, vec2 resolution,
                                          float radius, int samples) {
            float coc = texture(texture, uv).a;

            // Vertical Blur
            vec2 blurDirV = (coc / resolution.xy) * vec2(cos(BOKEH_ANGLE + PI / 2.0),
                sin(BOKEH_ANGLE + PI / 2.0));
            vec3 colorV = blur(texture, uv, blurDirV, radius, samples).rgb * coc;

            // Diagonal Blur
            vec2 blurDirD = (coc / resolution.xy) * vec2(cos(BOKEH_ANGLE - PI / 6.0),
                sin(BOKEH_ANGLE - PI / 6.0));
            vec3 colorD = blur(texture, uv, blurDirD, radius, samples).rgb * coc;

            vec4 composed[2];
            composed[0] = vec4(colorV, coc);
            // added * 0.5, to remap
            composed[1] = vec4((colorD + colorV) * 0.5, coc);

            return composed;
        }

        vec4 rhombiLensBlur (vec2 uv, sampler2D texture0, sampler2D texture1, vec2 resolution,
                             float radius, int samples) {
            float coc1 = texture(texture0, uv).a;
            float coc2 = texture(texture1, uv).a;

            vec2 blurDirection1 = coc1 / resolution.xy * vec2(cos(BOKEH_ANGLE - PI / 6.0), sin(BOKEH_ANGLE - PI / 6.0));
            vec3 color1 = blur(texture0, uv, blurDirection1, radius, samples).rgb * coc1;

            vec2 blurDirection2 = coc2 / resolution.xy * vec2(cos(BOKEH_ANGLE - 5.0 * PI / 6.0), sin(BOKEH_ANGLE - 5.0 * PI / 6.0));
            vec3 color2 = blur(texture1, uv, blurDirection2, radius, samples, 2.0).rgb * coc2;

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
