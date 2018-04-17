/*
 * Copyright 2013 The Android Open Source Project
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

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>

#include <utils/String8.h>

#include "Description.h"
#include "Program.h"
#include "ProgramCache.h"

namespace android {
// -----------------------------------------------------------------------------------------------

/*
 * A simple formatter class to automatically add the endl and
 * manage the indentation.
 */

class Formatter;
static Formatter& indent(Formatter& f);
static Formatter& dedent(Formatter& f);

class Formatter {
    String8 mString;
    int mIndent;
    typedef Formatter& (*FormaterManipFunc)(Formatter&);
    friend Formatter& indent(Formatter& f);
    friend Formatter& dedent(Formatter& f);

public:
    Formatter() : mIndent(0) {}

    String8 getString() const { return mString; }

    friend Formatter& operator<<(Formatter& out, const char* in) {
        for (int i = 0; i < out.mIndent; i++) {
            out.mString.append("    ");
        }
        out.mString.append(in);
        out.mString.append("\n");
        return out;
    }
    friend inline Formatter& operator<<(Formatter& out, const String8& in) {
        return operator<<(out, in.string());
    }
    friend inline Formatter& operator<<(Formatter& to, FormaterManipFunc func) {
        return (*func)(to);
    }
};
Formatter& indent(Formatter& f) {
    f.mIndent++;
    return f;
}
Formatter& dedent(Formatter& f) {
    f.mIndent--;
    return f;
}

// -----------------------------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE(ProgramCache)

ProgramCache::ProgramCache() {
    // Until surfaceflinger has a dependable blob cache on the filesystem,
    // generate shaders on initialization so as to avoid jank.
    primeCache();
}

ProgramCache::~ProgramCache() {}

void ProgramCache::primeCache() {
    uint32_t shaderCount = 0;
    uint32_t keyMask = Key::BLEND_MASK | Key::OPACITY_MASK | Key::ALPHA_MASK | Key::TEXTURE_MASK;
    // Prime the cache for all combinations of the above masks,
    // leaving off the experimental color matrix mask options.

    nsecs_t timeBefore = systemTime();
    for (uint32_t keyVal = 0; keyVal <= keyMask; keyVal++) {
        Key shaderKey;
        shaderKey.set(keyMask, keyVal);
        uint32_t tex = shaderKey.getTextureTarget();
        if (tex != Key::TEXTURE_OFF && tex != Key::TEXTURE_EXT && tex != Key::TEXTURE_2D) {
            continue;
        }
        Program* program = mCache.valueFor(shaderKey);
        if (program == nullptr) {
            program = generateProgram(shaderKey);
            mCache.add(shaderKey, program);
            shaderCount++;
        }
    }
    nsecs_t timeAfter = systemTime();
    float compileTimeMs = static_cast<float>(timeAfter - timeBefore) / 1.0E6;
    ALOGD("shader cache generated - %u shaders in %f ms\n", shaderCount, compileTimeMs);
}

ProgramCache::Key ProgramCache::computeKey(const Description& description) {
    Key needs;
    needs.set(Key::TEXTURE_MASK,
              !description.mTextureEnabled
                      ? Key::TEXTURE_OFF
                      : description.mTexture.getTextureTarget() == GL_TEXTURE_EXTERNAL_OES
                              ? Key::TEXTURE_EXT
                              : description.mTexture.getTextureTarget() == GL_TEXTURE_2D
                                      ? Key::TEXTURE_2D
                                      : Key::TEXTURE_OFF)
            .set(Key::ALPHA_MASK,
                 (description.mColor.a < 1) ? Key::ALPHA_LT_ONE : Key::ALPHA_EQ_ONE)
            .set(Key::BLEND_MASK,
                 description.mPremultipliedAlpha ? Key::BLEND_PREMULT : Key::BLEND_NORMAL)
            .set(Key::OPACITY_MASK,
                 description.mOpaque ? Key::OPACITY_OPAQUE : Key::OPACITY_TRANSLUCENT)
            .set(Key::COLOR_MATRIX_MASK,
                 description.mColorMatrixEnabled ? Key::COLOR_MATRIX_ON : Key::COLOR_MATRIX_OFF);

    needs.set(Key::Y410_BT2020_MASK,
              description.mY410BT2020 ? Key::Y410_BT2020_ON : Key::Y410_BT2020_OFF);

    if (needs.hasColorMatrix()) {
        switch (description.mInputTransferFunction) {
            case Description::TransferFunction::LINEAR:
            default:
                needs.set(Key::INPUT_TF_MASK, Key::INPUT_TF_LINEAR);
                break;
            case Description::TransferFunction::SRGB:
                needs.set(Key::INPUT_TF_MASK, Key::INPUT_TF_SRGB);
                break;
            case Description::TransferFunction::ST2084:
                needs.set(Key::INPUT_TF_MASK, Key::INPUT_TF_ST2084);
                break;
            case Description::TransferFunction::HLG:
                needs.set(Key::INPUT_TF_MASK, Key::INPUT_TF_HLG);
                break;
        }

        switch (description.mOutputTransferFunction) {
            case Description::TransferFunction::LINEAR:
            default:
                needs.set(Key::OUTPUT_TF_MASK, Key::OUTPUT_TF_LINEAR);
                break;
            case Description::TransferFunction::SRGB:
                needs.set(Key::OUTPUT_TF_MASK, Key::OUTPUT_TF_SRGB);
                break;
            case Description::TransferFunction::ST2084:
                needs.set(Key::OUTPUT_TF_MASK, Key::OUTPUT_TF_ST2084);
                break;
            case Description::TransferFunction::HLG:
                needs.set(Key::OUTPUT_TF_MASK, Key::OUTPUT_TF_HLG);
                break;
        }
    }

    return needs;
}

String8 ProgramCache::generateVertexShader(const Key& needs) {
    Formatter vs;
    if (needs.isTexturing()) {
        vs << "attribute vec4 texCoords;"
           << "varying vec2 outTexCoords;";
    }
    vs << "attribute vec4 position;"
       << "uniform mat4 projection;"
       << "uniform mat4 texture;"
       << "void main(void) {" << indent << "gl_Position = projection * position;";
    if (needs.isTexturing()) {
        vs << "outTexCoords = (texture * texCoords).st;";
    }
    vs << dedent << "}";
    return vs.getString();
}

String8 ProgramCache::generateFragmentShader(const Key& needs) {
    Formatter fs;
    if (needs.getTextureTarget() == Key::TEXTURE_EXT) {
        fs << "#extension GL_OES_EGL_image_external : require";
    }

    // default precision is required-ish in fragment shaders
    fs << "precision mediump float;";

    if (needs.getTextureTarget() == Key::TEXTURE_EXT) {
        fs << "uniform samplerExternalOES sampler;"
           << "varying vec2 outTexCoords;";
    } else if (needs.getTextureTarget() == Key::TEXTURE_2D) {
        fs << "uniform sampler2D sampler;"
           << "varying vec2 outTexCoords;";
    }

    if (needs.getTextureTarget() == Key::TEXTURE_OFF || needs.hasAlpha()) {
        fs << "uniform vec4 color;";
    }

    if (needs.isY410BT2020()) {
        fs << R"__SHADER__(
            vec3 convertY410BT2020(const vec3 color) {
                const vec3 offset = vec3(0.0625, 0.5, 0.5);
                const mat3 transform = mat3(
                    vec3(1.1678,  1.1678, 1.1678),
                    vec3(   0.0, -0.1878, 2.1481),
                    vec3(1.6836, -0.6523,   0.0));
                // Y is in G, U is in R, and V is in B
                return clamp(transform * (color.grb - offset), 0.0, 1.0);
            }
            )__SHADER__";
    }

    if (needs.hasColorMatrix()) {
        fs << "uniform mat4 colorMatrix;";

        // Generate EOTF that converts signal values to relative display light,
        // both normalized to [0, 1].
        switch (needs.getInputTF()) {
            case Key::INPUT_TF_LINEAR:
            default:
                fs << R"__SHADER__(
                    vec3 EOTF(const vec3 linear) {
                        return linear;
                    }
                )__SHADER__";
                break;
            case Key::INPUT_TF_SRGB:
                fs << R"__SHADER__(
                    float EOTF_sRGB(float srgb) {
                        return srgb <= 0.04045 ? srgb / 12.92 : pow((srgb + 0.055) / 1.055, 2.4);
                    }

                    vec3 EOTF_sRGB(const vec3 srgb) {
                        return vec3(EOTF_sRGB(srgb.r), EOTF_sRGB(srgb.g), EOTF_sRGB(srgb.b));
                    }

                    vec3 EOTF(const vec3 srgb) {
                        return sign(srgb.rgb) * EOTF_sRGB(abs(srgb.rgb));
                    }
                )__SHADER__";
                break;
            case Key::INPUT_TF_ST2084:
                fs << R"__SHADER__(
                    vec3 EOTF(const highp vec3 color) {
                        const highp float m1 = (2610.0 / 4096.0) / 4.0;
                        const highp float m2 = (2523.0 / 4096.0) * 128.0;
                        const highp float c1 = (3424.0 / 4096.0);
                        const highp float c2 = (2413.0 / 4096.0) * 32.0;
                        const highp float c3 = (2392.0 / 4096.0) * 32.0;

                        highp vec3 tmp = pow(color, 1.0 / vec3(m2));
                        tmp = max(tmp - c1, 0.0) / (c2 - c3 * tmp);
                        return pow(tmp, 1.0 / vec3(m1));
                    }
                    )__SHADER__";
                break;
          case Key::INPUT_TF_HLG:
              fs << R"__SHADER__(
                  highp float EOTF_channel(const highp float channel) {
                      const highp float a = 0.17883277;
                      const highp float b = 0.28466892;
                      const highp float c = 0.55991073;
                      return channel <= 0.5 ? channel * channel / 3.0 :
                              (exp((channel - c) / a) + b) / 12.0;
                  }

                  vec3 EOTF(const highp vec3 color) {
                      return vec3(EOTF_channel(color.r), EOTF_channel(color.g),
                              EOTF_channel(color.b));
                  }
                  )__SHADER__";
              break;
        }

        fs << R"__SHADER__(
            highp float CalculateY(const highp vec3 color) {
                // BT2020 standard uses the unadjusted KR = 0.2627,
                // KB = 0.0593 luminance interpretation for RGB conversion.
                return color.r * 0.262700 + color.g * 0.677998 +
                        color.b * 0.059302;
            }
        )__SHADER__";

        // Generate OOTF that modifies the relative display light.
        switch(needs.getInputTF()) {
            case Key::INPUT_TF_ST2084:
                fs << R"__SHADER__(
                    highp vec3 OOTF(const highp vec3 color) {
                        const float maxLumi = 10000.0;
                        const float maxMasteringLumi = 1000.0;
                        const float maxContentLumi = 1000.0;
                        const float maxInLumi = min(maxMasteringLumi, maxContentLumi);
                        const float maxOutLumi = 500.0;

                        // Calculate Y value in XYZ color space.
                        float colorY = CalculateY(color);

                        // convert to nits first
                        float nits = colorY * maxLumi;

                        // clamp to max input luminance
                        nits = clamp(nits, 0.0, maxInLumi);

                        // scale [0.0, maxInLumi] to [0.0, maxOutLumi]
                        if (maxInLumi <= maxOutLumi) {
                            nits *= maxOutLumi / maxInLumi;
                        } else {
                            // three control points
                            const float x0 = 10.0;
                            const float y0 = 17.0;
                            const float x1 = maxOutLumi * 0.75;
                            const float y1 = x1;
                            const float x2 = x1 + (maxInLumi - x1) / 2.0;
                            const float y2 = y1 + (maxOutLumi - y1) * 0.75;

                            // horizontal distances between the last three control points
                            const float h12 = x2 - x1;
                            const float h23 = maxInLumi - x2;
                            // tangents at the last three control points
                            const float m1 = (y2 - y1) / h12;
                            const float m3 = (maxOutLumi - y2) / h23;
                            const float m2 = (m1 + m3) / 2.0;

                            if (nits < x0) {
                                // scale [0.0, x0] to [0.0, y0] linearly
                                const float slope = y0 / x0;
                                nits *= slope;
                            } else if (nits < x1) {
                                // scale [x0, x1] to [y0, y1] linearly
                                const float slope = (y1 - y0) / (x1 - x0);
                                nits = y0 + (nits - x0) * slope;
                            } else if (nits < x2) {
                                // scale [x1, x2] to [y1, y2] using Hermite interp
                                float t = (nits - x1) / h12;
                                nits = (y1 * (1.0 + 2.0 * t) + h12 * m1 * t) * (1.0 - t) * (1.0 - t) +
                                       (y2 * (3.0 - 2.0 * t) + h12 * m2 * (t - 1.0)) * t * t;
                            } else {
                                // scale [x2, maxInLumi] to [y2, maxOutLumi] using Hermite interp
                                float t = (nits - x2) / h23;
                                nits = (y2 * (1.0 + 2.0 * t) + h23 * m2 * t) * (1.0 - t) * (1.0 - t) +
                                       (maxOutLumi * (3.0 - 2.0 * t) + h23 * m3 * (t - 1.0)) * t * t;
                            }
                        }

                        // convert back to [0.0, 1.0]
                        float targetY = nits / maxOutLumi;
                        return color * (targetY / max(1e-6, colorY));
                    }
                )__SHADER__";
                break;
            case Key::INPUT_TF_HLG:
                fs << R"__SHADER__(
                    highp vec3 OOTF(const highp vec3 color) {
                        const float maxOutLumi = 500.0;
                        const float gamma = 1.2 + 0.42 * log(maxOutLumi / 1000.0) / log(10.0);
                        // The formula is:
                        // alpha * pow(Y, gamma - 1.0) * color + beta;
                        // where alpha is 1.0, beta is 0.0 as recommended in
                        // Rec. ITU-R BT.2100-1 TABLE 5.
                        return pow(CalculateY(color), gamma - 1.0) * color;
                    }
                )__SHADER__";
                break;
            default:
                fs << R"__SHADER__(
                    highp vec3 OOTF(const highp vec3 color) {
                        return color;
                    }
                )__SHADER__";
        }

        // Generate OETF that converts relative display light to signal values,
        // both normalized to [0, 1]
        switch (needs.getOutputTF()) {
            case Key::OUTPUT_TF_LINEAR:
            default:
                fs << R"__SHADER__(
                    vec3 OETF(const vec3 linear) {
                        return linear;
                    }
                )__SHADER__";
                break;
            case Key::OUTPUT_TF_SRGB:
                fs << R"__SHADER__(
                    float OETF_sRGB(const float linear) {
                        return linear <= 0.0031308 ?
                                linear * 12.92 : (pow(linear, 1.0 / 2.4) * 1.055) - 0.055;
                    }

                    vec3 OETF_sRGB(const vec3 linear) {
                        return vec3(OETF_sRGB(linear.r), OETF_sRGB(linear.g), OETF_sRGB(linear.b));
                    }

                    vec3 OETF(const vec3 linear) {
                        return sign(linear.rgb) * OETF_sRGB(abs(linear.rgb));
                    }
                )__SHADER__";
                break;
            case Key::OUTPUT_TF_ST2084:
                fs << R"__SHADER__(
                    vec3 OETF(const vec3 linear) {
                        const float m1 = (2610.0 / 4096.0) / 4.0;
                        const float m2 = (2523.0 / 4096.0) * 128.0;
                        const float c1 = (3424.0 / 4096.0);
                        const float c2 = (2413.0 / 4096.0) * 32.0;
                        const float c3 = (2392.0 / 4096.0) * 32.0;

                        vec3 tmp = pow(linear, vec3(m1));
                        tmp = (c1 + c2 * tmp) / (1.0 + c3 * tmp);
                        return pow(tmp, vec3(m2));
                    }
                )__SHADER__";
                break;
            case Key::OUTPUT_TF_HLG:
                fs << R"__SHADER__(
                    highp float OETF_channel(const highp float channel) {
                        const highp float a = 0.17883277;
                        const highp float b = 0.28466892;
                        const highp float c = 0.55991073;
                        return channel <= 1.0 / 12.0 ? sqrt(3.0 * channel) :
                                a * log(12.0 * channel - b) + c;
                    }

                    vec3 OETF(const highp vec3 color) {
                        return vec3(OETF_channel(color.r), OETF_channel(color.g),
                                OETF_channel(color.b));
                    }
                )__SHADER__";
                break;
        }
    }

    fs << "void main(void) {" << indent;
    if (needs.isTexturing()) {
        fs << "gl_FragColor = texture2D(sampler, outTexCoords);";
        if (needs.isY410BT2020()) {
            fs << "gl_FragColor.rgb = convertY410BT2020(gl_FragColor.rgb);";
        }
    } else {
        fs << "gl_FragColor.rgb = color.rgb;";
        fs << "gl_FragColor.a = 1.0;";
    }
    if (needs.isOpaque()) {
        fs << "gl_FragColor.a = 1.0;";
    }
    if (needs.hasAlpha()) {
        // modulate the current alpha value with alpha set
        if (needs.isPremultiplied()) {
            // ... and the color too if we're premultiplied
            fs << "gl_FragColor *= color.a;";
        } else {
            fs << "gl_FragColor.a *= color.a;";
        }
    }

    if (needs.hasColorMatrix()) {
        if (!needs.isOpaque() && needs.isPremultiplied()) {
            // un-premultiply if needed before linearization
            // avoid divide by 0 by adding 0.5/256 to the alpha channel
            fs << "gl_FragColor.rgb = gl_FragColor.rgb / (gl_FragColor.a + 0.0019);";
        }
        fs << "vec4 transformed = colorMatrix * vec4(OOTF(EOTF(gl_FragColor.rgb)), 1);";
        // the transformation from a wider colorspace to a narrower one can
        // result in >1.0 or <0.0 pixel values
        fs << "transformed.rgb = clamp(transformed.rgb, 0.0, 1.0);";
        // We assume the last row is always {0,0,0,1} and we skip the division by w
        fs << "gl_FragColor.rgb = OETF(transformed.rgb);";
        if (!needs.isOpaque() && needs.isPremultiplied()) {
            // and re-premultiply if needed after gamma correction
            fs << "gl_FragColor.rgb = gl_FragColor.rgb * (gl_FragColor.a + 0.0019);";
        }
    }

    fs << dedent << "}";
    return fs.getString();
}

Program* ProgramCache::generateProgram(const Key& needs) {
    // vertex shader
    String8 vs = generateVertexShader(needs);

    // fragment shader
    String8 fs = generateFragmentShader(needs);

    Program* program = new Program(needs, vs.string(), fs.string());
    return program;
}

void ProgramCache::useProgram(const Description& description) {
    // generate the key for the shader based on the description
    Key needs(computeKey(description));

    // look-up the program in the cache
    Program* program = mCache.valueFor(needs);
    if (program == nullptr) {
        // we didn't find our program, so generate one...
        nsecs_t time = -systemTime();
        program = generateProgram(needs);
        mCache.add(needs, program);
        time += systemTime();

        // ALOGD(">>> generated new program: needs=%08X, time=%u ms (%d programs)",
        //        needs.mNeeds, uint32_t(ns2ms(time)), mCache.size());
    }

    // here we have a suitable program for this description
    if (program->isValid()) {
        program->use();
        program->setUniforms(description);
    }
}

} /* namespace android */
