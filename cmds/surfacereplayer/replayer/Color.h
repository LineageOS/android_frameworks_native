/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_SURFACEREPLAYER_COLOR_H
#define ANDROID_SURFACEREPLAYER_COLOR_H

#include <cmath>
#include <cstdlib>

namespace android {

typedef struct RGB {
    RGB() = default;
    RGB(uint8_t rIn, uint8_t gIn, uint8_t bIn) : r(rIn), g(gIn), b(bIn) {}

    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
} RGB;

typedef struct HSV {
    HSV() = default;
    HSV(double hIn, double sIn, double vIn) : h(hIn), s(sIn), v(vIn) {}

    double h = 0;
    double s = 0;
    double v = 0;
} HSV;

static inline RGB HSVToRGB(HSV hsv) {
    using namespace std;
    double r = 0, g = 0, b = 0;

    if (hsv.s == 0) {
        r = hsv.v;
        g = hsv.v;
        b = hsv.v;
    } else {
        hsv.h = static_cast<int>(hsv.h) % 360;
        hsv.h = hsv.h / 60;

        int i = static_cast<int>(trunc(hsv.h));
        double f = hsv.h - i;

        double x = hsv.v * (1.0 - hsv.s);
        double y = hsv.v * (1.0 - (hsv.s * f));
        double z = hsv.v * (1.0 - (hsv.s * (1.0 - f)));

        switch (i) {
            case 0:
                r = hsv.v;
                g = z;
                b = x;
                break;

            case 1:
                r = y;
                g = hsv.v;
                b = x;
                break;

            case 2:
                r = x;
                g = hsv.v;
                b = z;
                break;

            case 3:
                r = x;
                g = y;
                b = hsv.v;
                break;

            case 4:
                r = z;
                g = x;
                b = hsv.v;
                break;

            default:
                r = hsv.v;
                g = x;
                b = y;
                break;
        }
    }

    return RGB(round(r * 255), round(g * 255), round(b * 255));
}
}
#endif
