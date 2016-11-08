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

#ifndef UI_SCALAR_H
#define UI_SCALAR_H

#include <algorithm>
#include <cmath>

namespace android {

template<typename T>
static constexpr T saturate(T v) noexcept {
    return T(std::min(T(1), std::max(T(0), v)));
}

template<typename T>
static constexpr T clamp(T v, T min, T max) noexcept {
    return T(std::min(max, std::max(min, v)));
}

template<typename T>
static constexpr T mix(T x, T y, T a) noexcept {
    return x * (T(1) - a) + y * a;
}

template<typename T>
static constexpr T lerp(T x, T y, T a) noexcept {
    return mix(x, y, a);
}

namespace details {
    static int asInt(float x) {
        return *reinterpret_cast<int*>(&x);
    }

    static float asFloat(int x) {
        return *reinterpret_cast<float*>(&x);
    }

    static constexpr float inversesqrtNewtonRaphson(float x, float inverseSqrtX) {
        return inverseSqrtX * (-x * 0.5f * (inverseSqrtX * inverseSqrtX) + 1.5f);
    }

    static constexpr float rcpNewtonRaphson(float x, float rcpX) {
        return rcpX * (-rcpX * x + 2.0f);
    }

    static const float inverseSqrtFast(float f, int c) {
        int v = details::asInt(f);
        v = c - (v >> 1);
        return details::asFloat(v);
    }

    static const float rcpFast(float f, int c) {
        int v = details::asInt(f);
        v = c - v;
        return details::asFloat(v);
    }
} // namespace details

/**
 * Approximates an inverse square root using a specified
 * number of Newton-Raphson iterations. The number of iterations
 * can be:
 *
 * - 0, with a precision of ~3.4% over the full range
 * - 1, with a precision of ~0.2% over the full range
 * - 2, with a precision of ~4e-4% over the full range
 */
template<int>
static float inversesqrtFast(float f) noexcept;

template<>
float inversesqrtFast<0>(float f) noexcept {
    return details::inverseSqrtFast(f, 0x5f3759df);
}

template<>
float inversesqrtFast<1>(float f) noexcept {
    float x = details::inverseSqrtFast(f, 0x5f375a86);
    return details::inversesqrtNewtonRaphson(f, x);
}

template<>
float inversesqrtFast<2>(float f) noexcept {
    float x = details::inverseSqrtFast(f, 0x5f375a86);
    x = details::inversesqrtNewtonRaphson(f, x);
    x = details::inversesqrtNewtonRaphson(f, x);
    return x;
}

/**
 * Approximates a square root using a specified number of
 * Newton-Raphson iterations. The number of iterations can be:
 *
 * - 0, with a precision of ~0.7% over the full range
 * - 1, with a precision of ~0.2% over the full range
 * - 2, with a precision of ~4e-4% over the full range
 */
template<int>
static float sqrtFast(float f) noexcept;

template<>
float sqrtFast<0>(float f) noexcept {
    int v = details::asInt(f);
    v = 0x1fbd1df5 + (v >> 1);
    return details::asFloat(v);
}

template<>
float sqrtFast<1>(float f) noexcept {
    return f * inversesqrtFast<1>(f);
}

template<>
float sqrtFast<2>(float f) noexcept {
    return f * inversesqrtFast<2>(f);
}

/**
 * Approximates a reciprocal using a specified number
 * of Newton-Raphson iterations. The number of iterations
 * can be:
 *
 * - 0, with a precision of ~0.4% over the full range
 * - 1, with a precision of ~0.02% over the full range
 * - 2, with a precision of ~5e-5% over the full range
 */
template<int>
static float rcpFast(float f) noexcept;

template<>
float rcpFast<0>(float f) noexcept {
    return details::rcpFast(f, 0x7ef311c2);
}

template<>
float rcpFast<1>(float f) noexcept {
    float x = details::rcpFast(f, 0x7ef311c3);
    return details::rcpNewtonRaphson(f, x);
}

template<>
float rcpFast<2>(float f) noexcept {
    float x = details::rcpFast(f, 0x7ef312ac);
    x = details::rcpNewtonRaphson(f, x);
    x = details::rcpNewtonRaphson(f, x);
    return x;
}

} // namespace std

#endif // UI_SCALAR_H
