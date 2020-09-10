/*
 * Copyright (C) 2019 The Android Open Source Project
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
#pragma once

#include <ui/ColorSpace.h>

namespace android {

namespace {

struct Color {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;

    static const Color RED;
    static const Color GREEN;
    static const Color BLUE;
    static const Color WHITE;
    static const Color BLACK;
    static const Color TRANSPARENT;
};

const Color Color::RED{255, 0, 0, 255};
const Color Color::GREEN{0, 255, 0, 255};
const Color Color::BLUE{0, 0, 255, 255};
const Color Color::WHITE{255, 255, 255, 255};
const Color Color::BLACK{0, 0, 0, 255};
const Color Color::TRANSPARENT{0, 0, 0, 0};

class ColorTransformHelper {
public:
    static void DegammaColorSingle(half& s) {
        if (s <= 0.03928f)
            s = s / 12.92f;
        else
            s = pow((s + 0.055f) / 1.055f, 2.4f);
    }

    static void DegammaColor(half3& color) {
        DegammaColorSingle(color.r);
        DegammaColorSingle(color.g);
        DegammaColorSingle(color.b);
    }

    static void GammaColorSingle(half& s) {
        if (s <= 0.0031308f) {
            s = s * 12.92f;
        } else {
            s = 1.055f * pow(s, (1.0f / 2.4f)) - 0.055f;
        }
    }

    static void GammaColor(half3& color) {
        GammaColorSingle(color.r);
        GammaColorSingle(color.g);
        GammaColorSingle(color.b);
    }

    static void applyMatrix(half3& color, const mat3& mat) {
        half3 ret = half3(0);

        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                ret[i] = ret[i] + color[j] * mat[j][i];
            }
        }
        color = ret;
    }
};
} // namespace
} // namespace android
