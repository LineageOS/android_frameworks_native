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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <chrono>

#include <android/native_window.h>
#include <binder/IPCThreadState.h>
#include <gtest/gtest.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <ui/GraphicBuffer.h>
#include <ui/Rect.h>

#include "ColorUtils.h"

namespace android {

namespace {

using namespace std::chrono_literals;
using Transaction = SurfaceComposerClient::Transaction;

std::ostream& operator<<(std::ostream& os, const Color& color) {
    os << int(color.r) << ", " << int(color.g) << ", " << int(color.b) << ", " << int(color.a);
    return os;
}

class TransactionUtils {
public:
    // Fill a region with the specified color.
    static void fillANativeWindowBufferColor(const ANativeWindow_Buffer& buffer, const Rect& rect,
                                             const Color& color) {
        Rect r(0, 0, buffer.width, buffer.height);
        if (!r.intersect(rect, &r)) {
            return;
        }

        int32_t width = r.right - r.left;
        int32_t height = r.bottom - r.top;

        for (int32_t row = 0; row < height; row++) {
            uint8_t* dst = static_cast<uint8_t*>(buffer.bits) +
                    (buffer.stride * (r.top + row) + r.left) * 4;
            for (int32_t column = 0; column < width; column++) {
                dst[0] = color.r;
                dst[1] = color.g;
                dst[2] = color.b;
                dst[3] = color.a;
                dst += 4;
            }
        }
    }

    // Fill a region with the specified color.
    static void fillGraphicBufferColor(const sp<GraphicBuffer>& buffer, const Rect& rect,
                                       const Color& color) {
        Rect r(0, 0, buffer->width, buffer->height);
        if (!r.intersect(rect, &r)) {
            return;
        }

        int32_t width = r.right - r.left;
        int32_t height = r.bottom - r.top;

        uint8_t* pixels;
        buffer->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                     reinterpret_cast<void**>(&pixels));

        for (int32_t row = 0; row < height; row++) {
            uint8_t* dst = pixels + (buffer->getStride() * (r.top + row) + r.left) * 4;
            for (int32_t column = 0; column < width; column++) {
                dst[0] = color.r;
                dst[1] = color.g;
                dst[2] = color.b;
                dst[3] = color.a;
                dst += 4;
            }
        }
        buffer->unlock();
    }

    // Check if a region has the specified color.
    static void expectBufferColor(const sp<GraphicBuffer>& outBuffer, uint8_t* pixels,
                                  const Rect& rect, const Color& color, uint8_t tolerance) {
        int32_t x = rect.left;
        int32_t y = rect.top;
        int32_t width = rect.right - rect.left;
        int32_t height = rect.bottom - rect.top;

        int32_t bufferWidth = int32_t(outBuffer->getWidth());
        int32_t bufferHeight = int32_t(outBuffer->getHeight());
        if (x + width > bufferWidth) {
            x = std::min(x, bufferWidth);
            width = bufferWidth - x;
        }
        if (y + height > bufferHeight) {
            y = std::min(y, bufferHeight);
            height = bufferHeight - y;
        }

        auto colorCompare = [tolerance](uint8_t a, uint8_t b) {
            uint8_t tmp = a >= b ? a - b : b - a;
            return tmp <= tolerance;
        };
        for (int32_t j = 0; j < height; j++) {
            const uint8_t* src = pixels + (outBuffer->getStride() * (y + j) + x) * 4;
            for (int32_t i = 0; i < width; i++) {
                const uint8_t expected[4] = {color.r, color.g, color.b, color.a};
                EXPECT_TRUE(std::equal(src, src + 4, expected, colorCompare))
                        << "pixel @ (" << x + i << ", " << y + j << "): "
                        << "expected (" << color << "), "
                        << "got (" << Color{src[0], src[1], src[2], src[3]} << ")";
                src += 4;
            }
        }
    }

    static void fillSurfaceRGBA8(const sp<SurfaceControl>& sc, const Color& color,
                                 bool unlock = true) {
        fillSurfaceRGBA8(sc, color.r, color.g, color.b, unlock);
    }

    // Fill an RGBA_8888 formatted surface with a single color.
    static void fillSurfaceRGBA8(const sp<SurfaceControl>& sc, uint8_t r, uint8_t g, uint8_t b,
                                 bool unlock = true) {
        ANativeWindow_Buffer outBuffer;
        sp<Surface> s = sc->getSurface();
        ASSERT_TRUE(s != nullptr);
        ASSERT_EQ(NO_ERROR, s->lock(&outBuffer, nullptr));
        uint8_t* img = reinterpret_cast<uint8_t*>(outBuffer.bits);
        for (int y = 0; y < outBuffer.height; y++) {
            for (int x = 0; x < outBuffer.width; x++) {
                uint8_t* pixel = img + (4 * (y * outBuffer.stride + x));
                pixel[0] = r;
                pixel[1] = g;
                pixel[2] = b;
                pixel[3] = 255;
            }
        }
        if (unlock) {
            ASSERT_EQ(NO_ERROR, s->unlockAndPost());
        }
    }
};

enum class RenderPath { SCREENSHOT, VIRTUAL_DISPLAY };

// Environment for starting up binder threads. This is required for testing
// virtual displays, as BufferQueue parameters may be queried over binder.
class BinderEnvironment : public ::testing::Environment {
public:
    void SetUp() override { ProcessState::self()->startThreadPool(); }
};

/** RAII Wrapper around get/seteuid */
class UIDFaker {
    uid_t oldId;

public:
    UIDFaker(uid_t uid) {
        oldId = geteuid();
        seteuid(uid);
    }
    ~UIDFaker() { seteuid(oldId); }
};
} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"