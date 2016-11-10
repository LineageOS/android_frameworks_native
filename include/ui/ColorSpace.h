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

#ifndef ANDROID_UI_COLOR_SPACE
#define ANDROID_UI_COLOR_SPACE

#include <array>
#include <cmath>
#include <functional>
#include <string>

#include <ui/mat3.h>
#include <ui/scalar.h>
#include <ui/vec2.h>
#include <ui/vec3.h>

namespace android {

class ColorSpace {
public:
    typedef std::function<float(float)> transfer_function;
    typedef std::function<float(float)> clamping_function;

    /**
     * Creates a named color space with the specified RGB->XYZ
     * conversion matrix. The white point and primaries will be
     * computed from the supplied matrix.
     *
     * The default transfer functions are a linear response x->x
     * and the default clamping function is a simple saturate
     * (clamp(x, 0, 1)).
     */
    ColorSpace(
            const std::string& name,
            const mat3& rgbToXYZ,
            transfer_function OETF = linearReponse,
            transfer_function EOTF = linearReponse,
            clamping_function clamper = saturate<float>
    ) noexcept;

    /**
     * Creates a named color space with the specified primaries
     * and white point. The RGB<>XYZ conversion matrices are
     * computed from the primaries and white point.
     *
     * The default transfer functions are a linear response x->x
     * and the default clamping function is a simple saturate
     * (clamp(x, 0, 1)).
     */
    ColorSpace(
            const std::string& name,
            const std::array<float2, 3>& primaries,
            const float2& whitePoint,
            transfer_function OETF = linearReponse,
            transfer_function EOTF = linearReponse,
            clamping_function clamper = saturate<float>
    ) noexcept;

    ColorSpace() noexcept = delete;

    /**
     * Encodes the supplied RGB value using this color space's
     * opto-electronic transfer function.
     */
    constexpr float3 fromLinear(const float3& v) const noexcept {
        return apply(v, mOETF);
    }

    /**
     * Decodes the supplied RGB value using this color space's
     * electro-optical transfer function.
     */
    constexpr float3 toLinear(const float3& v) const noexcept {
        return apply(v, mEOTF);
    }

    /**
     * Converts the supplied XYZ value to RGB. The returned value
     * is encoded with this color space's opto-electronic transfer
     * function and clamped by this color space's clamping function.
     */
    constexpr float3 xyzToRGB(const float3& xyz) const noexcept {
        return apply(fromLinear(mXYZtoRGB * xyz), mClamper);
    }

    /**
     * Converts the supplied RGB value to XYZ. The input RGB value
     * is decoded using this color space's electro-optical function
     * before being converted to XYZ. The returned result is clamped
     * by this color space's clamping function.
     */
    constexpr float3 rgbToXYZ(const float3& rgb) const noexcept {
        return apply(mRGBtoXYZ * toLinear(rgb), mClamper);
    }

    constexpr const std::string& getName() const noexcept {
        return mName;
    }

    constexpr const mat3& getRGBtoXYZ() const noexcept {
        return mRGBtoXYZ;
    }

    constexpr const mat3& getXYZtoRGB() const noexcept {
        return mXYZtoRGB;
    }

    constexpr const transfer_function& getOETF() const noexcept {
        return mOETF;
    }

    constexpr const transfer_function& getEOTF() const noexcept {
        return mEOTF;
    }

    constexpr const clamping_function& getClamper() const noexcept {
        return mClamper;
    }

    constexpr const std::array<float2, 3>& getPrimaries() const noexcept {
        return mPrimaries;
    }

    constexpr const float2& getWhitePoint() const noexcept {
        return mWhitePoint;
    }

    /**
     * Converts the supplied XYZ value to xyY.
     */
    static constexpr float2 xyY(const float3& XYZ) {
        return XYZ.xy / dot(XYZ, float3{1});
    }

    /**
     * Converts the supplied xyY value to XYZ.
     */
    static constexpr float3 XYZ(const float3& xyY) {
        return float3{(xyY.x * xyY.z) / xyY.y, xyY.z, ((1 - xyY.x - xyY.y) * xyY.z) / xyY.y};
    }

    static const ColorSpace sRGB();
    static const ColorSpace linearSRGB();
    static const ColorSpace extendedSRGB();
    static const ColorSpace linearExtendedSRGB();
    static const ColorSpace NTSC();
    static const ColorSpace BT709();
    static const ColorSpace BT2020();
    static const ColorSpace AdobeRGB();
    static const ColorSpace ProPhotoRGB();
    static const ColorSpace DisplayP3();
    static const ColorSpace DCIP3();
    static const ColorSpace ACES();
    static const ColorSpace ACEScg();

private:
    static constexpr mat3 computeXYZMatrix(
            const std::array<float2, 3>& primaries, const float2& whitePoint);

    static constexpr float linearReponse(float v) {
        return v;
    }

    const std::string mName;

    const mat3 mRGBtoXYZ;
    const mat3 mXYZtoRGB;

    const transfer_function mOETF;
    const transfer_function mEOTF;
    const clamping_function mClamper;

    std::array<float2, 3> mPrimaries;
    float2 mWhitePoint;
};

}; // namespace android

#endif // ANDROID_UI_COLOR_SPACE
