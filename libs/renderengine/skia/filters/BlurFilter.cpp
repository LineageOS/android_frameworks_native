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

#include "BlurFilter.h"
#include <SkCanvas.h>
#include <SkData.h>
#include <SkPaint.h>
#include <SkRRect.h>
#include <SkRuntimeEffect.h>
#include <SkSize.h>
#include <SkString.h>
#include <SkSurface.h>
#include <log/log.h>
#include <utils/Trace.h>

namespace android {
namespace renderengine {
namespace skia {

BlurFilter::BlurFilter() {
    SkString blurString(R"(
        in shader input;
        uniform float2 in_blurOffset;

        half4 main(float2 xy) {
            half4 c = sample(input, xy);
            c += sample(input, xy + float2( in_blurOffset.x,  in_blurOffset.y));
            c += sample(input, xy + float2( in_blurOffset.x, -in_blurOffset.y));
            c += sample(input, xy + float2(-in_blurOffset.x,  in_blurOffset.y));
            c += sample(input, xy + float2(-in_blurOffset.x, -in_blurOffset.y));

            return half4(c.rgb * 0.2, 1.0);
        }
    )");

    auto [blurEffect, error] = SkRuntimeEffect::Make(blurString);
    if (!blurEffect) {
        LOG_ALWAYS_FATAL("RuntimeShader error: %s", error.c_str());
    }
    mBlurEffect = std::move(blurEffect);

    SkString mixString(R"(
        in shader blurredInput;
        in shader originalInput;
        uniform float mixFactor;

        half4 main(float2 xy) {
            return half4(mix(sample(originalInput), sample(blurredInput), mixFactor));
        }
    )");

    auto [mixEffect, mixError] = SkRuntimeEffect::Make(mixString);
    if (!mixEffect) {
        LOG_ALWAYS_FATAL("RuntimeShader error: %s", mixError.c_str());
    }
    mMixEffect = std::move(mixEffect);
}

sk_sp<SkImage> BlurFilter::generate(GrRecordingContext* context, const uint32_t blurRadius,
                                    const sk_sp<SkImage> input, const SkRect& blurRect) const {
    // Kawase is an approximation of Gaussian, but it behaves differently from it.
    // A radius transformation is required for approximating them, and also to introduce
    // non-integer steps, necessary to smoothly interpolate large radii.
    float tmpRadius = (float)blurRadius / 6.0f;
    float numberOfPasses = std::min(kMaxPasses, (uint32_t)ceil(tmpRadius));
    float radiusByPasses = tmpRadius / (float)numberOfPasses;

    // create blur surface with the bit depth and colorspace of the original surface
    SkImageInfo scaledInfo = input->imageInfo().makeWH(blurRect.width() * kInputScale,
                                                       blurRect.height() * kInputScale);

    const float stepX = radiusByPasses;
    const float stepY = radiusByPasses;

    // For sampling Skia's API expects the inverse of what logically seems appropriate. In this
    // case you might expect Translate(blurRect.fLeft, blurRect.fTop) X Scale(kInverseInputScale)
    // but instead we must do the inverse.
    SkMatrix blurMatrix = SkMatrix::Translate(-blurRect.fLeft, -blurRect.fTop);
    blurMatrix.postScale(kInputScale, kInputScale);

    // start by downscaling and doing the first blur pass
    SkSamplingOptions linear(SkFilterMode::kLinear, SkMipmapMode::kNone);
    SkRuntimeShaderBuilder blurBuilder(mBlurEffect);
    blurBuilder.child("input") =
            input->makeShader(SkTileMode::kClamp, SkTileMode::kClamp, linear, blurMatrix);
    blurBuilder.uniform("in_blurOffset") = SkV2{stepX * kInputScale, stepY * kInputScale};

    sk_sp<SkImage> tmpBlur(blurBuilder.makeImage(context, nullptr, scaledInfo, false));

    // And now we'll build our chain of scaled blur stages
    for (auto i = 1; i < numberOfPasses; i++) {
        const float stepScale = (float)i * kInputScale;
        blurBuilder.child("input") =
                tmpBlur->makeShader(SkTileMode::kClamp, SkTileMode::kClamp, linear);
        blurBuilder.uniform("in_blurOffset") = SkV2{stepX * stepScale, stepY * stepScale};
        tmpBlur = blurBuilder.makeImage(context, nullptr, scaledInfo, false);
    }

    return tmpBlur;
}

static SkMatrix getShaderTransform(const SkCanvas* canvas, const SkRect& blurRect, float scale) {
    // 1. Apply the blur shader matrix, which scales up the blured surface to its real size
    auto matrix = SkMatrix::Scale(scale, scale);
    // 2. Since the blurred surface has the size of the layer, we align it with the
    // top left corner of the layer position.
    matrix.postConcat(SkMatrix::Translate(blurRect.fLeft, blurRect.fTop));
    // 3. Finally, apply the inverse canvas matrix. The snapshot made in the BlurFilter is in the
    // original surface orientation. The inverse matrix has to be applied to align the blur
    // surface with the current orientation/position of the canvas.
    SkMatrix drawInverse;
    if (canvas != nullptr && canvas->getTotalMatrix().invert(&drawInverse)) {
        matrix.postConcat(drawInverse);
    }
    return matrix;
}

void BlurFilter::drawBlurRegion(SkCanvas* canvas, const BlurRegion& effectRegion,
                                const SkRect& blurRect, sk_sp<SkImage> blurredImage,
                                sk_sp<SkImage> input) {
    ATRACE_CALL();

    SkPaint paint;
    paint.setAlphaf(effectRegion.alpha);
    if (effectRegion.alpha == 1.0f) {
        paint.setBlendMode(SkBlendMode::kSrc);
    }

    const auto blurMatrix = getShaderTransform(canvas, blurRect, kInverseInputScale);
    SkSamplingOptions linearSampling(SkFilterMode::kLinear, SkMipmapMode::kNone);
    const auto blurShader = blurredImage->makeShader(SkTileMode::kClamp, SkTileMode::kClamp,
                                                     linearSampling, &blurMatrix);

    if (effectRegion.blurRadius < kMaxCrossFadeRadius) {
        // For sampling Skia's API expects the inverse of what logically seems appropriate. In this
        // case you might expect the matrix to simply be the canvas matrix.
        SkMatrix inputMatrix;
        if (!canvas->getTotalMatrix().invert(&inputMatrix)) {
            ALOGE("matrix was unable to be inverted");
        }

        SkRuntimeShaderBuilder blurBuilder(mMixEffect);
        blurBuilder.child("blurredInput") = blurShader;
        blurBuilder.child("originalInput") =
                input->makeShader(SkTileMode::kClamp, SkTileMode::kClamp, linearSampling,
                                  inputMatrix);
        blurBuilder.uniform("mixFactor") = effectRegion.blurRadius / kMaxCrossFadeRadius;

        paint.setShader(blurBuilder.makeShader(nullptr, true));
    } else {
        paint.setShader(blurShader);
    }

    // TODO we should AA at least the drawRoundRect which would mean no SRC blending
    // TODO this round rect calculation doesn't match the one used to draw in RenderEngine
    auto rect = SkRect::MakeLTRB(effectRegion.left, effectRegion.top, effectRegion.right,
                                 effectRegion.bottom);

    if (effectRegion.cornerRadiusTL > 0 || effectRegion.cornerRadiusTR > 0 ||
        effectRegion.cornerRadiusBL > 0 || effectRegion.cornerRadiusBR > 0) {
        const SkVector radii[4] =
                {SkVector::Make(effectRegion.cornerRadiusTL, effectRegion.cornerRadiusTL),
                 SkVector::Make(effectRegion.cornerRadiusTR, effectRegion.cornerRadiusTR),
                 SkVector::Make(effectRegion.cornerRadiusBL, effectRegion.cornerRadiusBL),
                 SkVector::Make(effectRegion.cornerRadiusBR, effectRegion.cornerRadiusBR)};
        SkRRect roundedRect;
        roundedRect.setRectRadii(rect, radii);
        canvas->drawRRect(roundedRect, paint);
    } else {
        canvas->drawRect(rect, paint);
    }
}

} // namespace skia
} // namespace renderengine
} // namespace android
