/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <ui/ColorSpace.h>

using namespace std::placeholders;

namespace android {

ColorSpace::ColorSpace(
        const std::string& name,
        const mat3& rgbToXYZ,
        transfer_function OETF,
        transfer_function EOTF,
        clamping_function clamper) noexcept
        : mName(name)
        , mRGBtoXYZ(rgbToXYZ)
        , mXYZtoRGB(inverse(rgbToXYZ))
        , mOETF(std::move(OETF))
        , mEOTF(std::move(EOTF))
        , mClamper(std::move(clamper)) {

    float3 r(rgbToXYZ * float3{1, 0, 0});
    float3 g(rgbToXYZ * float3{0, 1, 0});
    float3 b(rgbToXYZ * float3{0, 0, 1});

    mPrimaries[0] = r.xy / dot(r, float3{1});
    mPrimaries[1] = g.xy / dot(g, float3{1});
    mPrimaries[2] = b.xy / dot(b, float3{1});

    float3 w(rgbToXYZ * float3{1});
    mWhitePoint = w.xy / dot(w, float3{1});
}

ColorSpace::ColorSpace(
        const std::string& name,
        const std::array<float2, 3>& primaries,
        const float2& whitePoint,
        transfer_function OETF,
        transfer_function EOTF,
        clamping_function clamper) noexcept
        : mName(name)
        , mRGBtoXYZ(computeXYZMatrix(primaries, whitePoint))
        , mXYZtoRGB(inverse(mRGBtoXYZ))
        , mOETF(std::move(OETF))
        , mEOTF(std::move(EOTF))
        , mClamper(std::move(clamper))
        , mPrimaries(primaries)
        , mWhitePoint(whitePoint) {
}

constexpr mat3 ColorSpace::computeXYZMatrix(
        const std::array<float2, 3>& primaries, const float2& whitePoint) {
    const float2& R = primaries[0];
    const float2& G = primaries[1];
    const float2& B = primaries[2];
    const float2& W = whitePoint;        

    float oneRxRy = (1 - R.x) / R.y;
    float oneGxGy = (1 - G.x) / G.y;
    float oneBxBy = (1 - B.x) / B.y;
    float oneWxWy = (1 - W.x) / W.y;

    float RxRy = R.x / R.y;
    float GxGy = G.x / G.y;
    float BxBy = B.x / B.y;
    float WxWy = W.x / W.y;

    float BY =
            ((oneWxWy - oneRxRy) * (GxGy - RxRy) - (WxWy - RxRy) * (oneGxGy - oneRxRy)) /
            ((oneBxBy - oneRxRy) * (GxGy - RxRy) - (BxBy - RxRy) * (oneGxGy - oneRxRy));
    float GY = (WxWy - RxRy - BY * (BxBy - RxRy)) / (GxGy - RxRy);
    float RY = 1 - GY - BY;

    float RYRy = RY / R.y;
    float GYGy = GY / G.y;
    float BYBy = BY / B.y;

    return {
        float3{RYRy * R.x, RY, RYRy * (1 - R.x - R.y)},
        float3{GYGy * G.x, GY, GYGy * (1 - G.x - G.y)},
        float3{BYBy * B.x, BY, BYBy * (1 - B.x - B.y)}
    };
}

static constexpr float rcpResponse(float x, float g,float a, float b, float c, float d) {
    return x >= d * c ? std::pow(x / a, 1.0f / g) - b / a : x / c;
}

static constexpr float response(float x, float g, float a, float b, float c, float d) {
    return x >= d ? std::pow(a * x + b, g) : c * x;
}

static float absRcpResponse(float x, float g,float a, float b, float c, float d) {
    return std::copysign(rcpResponse(std::abs(x), g, a, b, c, d), x);
}

static float absResponse(float x, float g, float a, float b, float c, float d) {
    return std::copysign(response(std::abs(x), g, a, b, c, d), x);
}

const ColorSpace ColorSpace::sRGB() {
    return {
        "sRGB IEC61966-2.1",
        {{float2{0.640f, 0.330f}, {0.300f, 0.600f}, {0.150f, 0.060f}}},
        {0.3127f, 0.3290f},
        std::bind(rcpResponse, _1, 2.4f, 1 / 1.055f, 0.055f / 1.055f, 1 / 12.92f, 0.04045f),
        std::bind(response,    _1, 2.4f, 1 / 1.055f, 0.055f / 1.055f, 1 / 12.92f, 0.04045f)
    };
}

const ColorSpace ColorSpace::linearSRGB() {
    return {
        "sRGB IEC61966-2.1 (Linear)",
        {{float2{0.640f, 0.330f}, {0.300f, 0.600f}, {0.150f, 0.060f}}},
        {0.3127f, 0.3290f}
    };
}

const ColorSpace ColorSpace::extendedSRGB() {
    return {
        "scRGB-nl IEC 61966-2-2:2003",
        {{float2{0.640f, 0.330f}, {0.300f, 0.600f}, {0.150f, 0.060f}}},
        {0.3127f, 0.3290f},
        std::bind(absRcpResponse, _1, 2.4f, 1 / 1.055f, 0.055f / 1.055f, 1 / 12.92f, 0.04045f),
        std::bind(absResponse,    _1, 2.4f, 1 / 1.055f, 0.055f / 1.055f, 1 / 12.92f, 0.04045f),
        [](float x){return x;}
    };
}

const ColorSpace ColorSpace::linearExtendedSRGB() {
    return {
        "scRGB IEC 61966-2-2:2003",
        {{float2{0.640f, 0.330f}, {0.300f, 0.600f}, {0.150f, 0.060f}}},
        {0.3127f, 0.3290f},
        linearReponse,
        linearReponse,
        [](float x){return x;}
    };
}

const ColorSpace ColorSpace::NTSC() {
    return {
        "NTSC (1953)",
        {{float2{0.67f, 0.33f}, {0.21f, 0.71f}, {0.14f, 0.08f}}},
        {0.310f, 0.316f},
        std::bind(rcpResponse, _1, 1 / 0.45f, 1 / 1.099f, 0.099f / 1.099f, 1 / 4.5f, 0.081f),
        std::bind(response,    _1, 1 / 0.45f, 1 / 1.099f, 0.099f / 1.099f, 1 / 4.5f, 0.081f)
    };
}

const ColorSpace ColorSpace::BT709() {
    return {
        "Rec. ITU-R BT.709-5",
        {{float2{0.640f, 0.330f}, {0.300f, 0.600f}, {0.150f, 0.060f}}},
        {0.3127f, 0.3290f},
        std::bind(rcpResponse, _1, 1 / 0.45f, 1 / 1.099f, 0.099f / 1.099f, 1 / 4.5f, 0.081f),
        std::bind(response,    _1, 1 / 0.45f, 1 / 1.099f, 0.099f / 1.099f, 1 / 4.5f, 0.081f)
    };
}

const ColorSpace ColorSpace::BT2020() {
    return {
        "Rec. ITU-R BT.2020-1",
        {{float2{0.708f, 0.292f}, {0.170f, 0.797f}, {0.131f, 0.046f}}},
        {0.3127f, 0.3290f},
        std::bind(rcpResponse, _1, 1 / 0.45f, 1 / 1.099f, 0.099f / 1.099f, 1 / 4.5f, 0.081f),
        std::bind(response,    _1, 1 / 0.45f, 1 / 1.099f, 0.099f / 1.099f, 1 / 4.5f, 0.081f)
    };
}

const ColorSpace ColorSpace::AdobeRGB() {
    return {
        "Adobe RGB (1998)",
        {{float2{0.64f, 0.33f}, {0.21f, 0.71f}, {0.15f, 0.06f}}},
        {0.3127f, 0.3290f},
        std::bind(saturate<float>, std::bind(powf, _1, 1.0f / 2.2f)),
        std::bind(saturate<float>, std::bind(powf, _1, 2.2f))
    };
}

const ColorSpace ColorSpace::ProPhotoRGB() {
    return {
        "ROMM RGB ISO 22028-2:2013",
        {{float2{0.7347f, 0.2653f}, {0.1596f, 0.8404f}, {0.0366f, 0.0001f}}},
        {0.3457f, 0.3585f},
        std::bind(rcpResponse, _1, 1.8f, 1.0f, 0.0f, 1 / 16.0f, 0.031248f),
        std::bind(response,    _1, 1.8f, 1.0f, 0.0f, 1 / 16.0f, 0.031248f)
    };
}

const ColorSpace ColorSpace::DisplayP3() {
    return {
        "Display P3",
        {{float2{0.680f, 0.320f}, {0.265f, 0.690f}, {0.150f, 0.060f}}},
        {0.3127f, 0.3290f},
        std::bind(rcpResponse, _1, 2.4f, 1 / 1.055f, 0.055f / 1.055f, 1 / 12.92f, 0.04045f),
        std::bind(response,    _1, 2.4f, 1 / 1.055f, 0.055f / 1.055f, 1 / 12.92f, 0.04045f)
    };
}

const ColorSpace ColorSpace::DCIP3() {
    return {
        "SMPTE RP 431-2-2007 DCI (P3)",
        {{float2{0.680f, 0.320f}, {0.265f, 0.690f}, {0.150f, 0.060f}}},
        {0.3127f, 0.3290f},
        std::bind(powf, _1, 1.0f / 2.6f),
        std::bind(powf, _1, 2.6f)
    };
}

const ColorSpace ColorSpace::ACES() {
    return {
        "SMPTE ST 2065-1:2012 ACES",
        {{float2{0.73470f, 0.26530f}, {0.0f, 1.0f}, {0.00010f, -0.0770f}}},
        {0.32168f, 0.33767f}
    };
}

const ColorSpace ColorSpace::ACEScg() {
    return {
        "Academy S-2014-004 ACEScg",
        {{float2{0.713f, 0.293f}, {0.165f, 0.830f}, {0.128f, 0.044f}}},
        {0.32168f, 0.33767f}
    };
}

}; // namespace android
