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

#include <ui/Rect.h>
#include <utils/String8.h>
#include "TransactionUtils.h"

namespace android {

namespace {

// A ScreenCapture is a screenshot from SurfaceFlinger that can be used to check
// individual pixel values for testing purposes.
class ScreenCapture : public RefBase {
public:
    static void captureScreen(std::unique_ptr<ScreenCapture>* sc) {
        captureScreen(sc, SurfaceComposerClient::getInternalDisplayToken());
    }

    static void captureScreen(std::unique_ptr<ScreenCapture>* sc, sp<IBinder> displayToken) {
        const auto sf = ComposerService::getComposerService();
        SurfaceComposerClient::Transaction().apply(true);

        sp<GraphicBuffer> outBuffer;
        ASSERT_EQ(NO_ERROR, sf->captureScreen(displayToken, &outBuffer, Rect(), 0, 0, false));
        *sc = std::make_unique<ScreenCapture>(outBuffer);
    }

    static void captureLayers(std::unique_ptr<ScreenCapture>* sc, sp<IBinder>& parentHandle,
                              Rect crop = Rect::EMPTY_RECT, float frameScale = 1.0) {
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        SurfaceComposerClient::Transaction().apply(true);

        sp<GraphicBuffer> outBuffer;
        ASSERT_EQ(NO_ERROR, sf->captureLayers(parentHandle, &outBuffer, crop, frameScale));
        *sc = std::make_unique<ScreenCapture>(outBuffer);
    }

    static void captureChildLayers(std::unique_ptr<ScreenCapture>* sc, sp<IBinder>& parentHandle,
                                   Rect crop = Rect::EMPTY_RECT, float frameScale = 1.0) {
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        SurfaceComposerClient::Transaction().apply(true);

        sp<GraphicBuffer> outBuffer;
        ASSERT_EQ(NO_ERROR, sf->captureLayers(parentHandle, &outBuffer, crop, frameScale, true));
        *sc = std::make_unique<ScreenCapture>(outBuffer);
    }

    static void captureChildLayersExcluding(
            std::unique_ptr<ScreenCapture>* sc, sp<IBinder>& parentHandle,
            std::unordered_set<sp<IBinder>, ISurfaceComposer::SpHash<IBinder>> excludeLayers) {
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        SurfaceComposerClient::Transaction().apply(true);

        sp<GraphicBuffer> outBuffer;
        ASSERT_EQ(NO_ERROR,
                  sf->captureLayers(parentHandle, &outBuffer, ui::Dataspace::V0_SRGB,
                                    ui::PixelFormat::RGBA_8888, Rect::EMPTY_RECT, excludeLayers,
                                    1.0f, true));
        *sc = std::make_unique<ScreenCapture>(outBuffer);
    }

    void expectColor(const Rect& rect, const Color& color, uint8_t tolerance = 0) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mOutBuffer->getPixelFormat());
        TransactionUtils::expectBufferColor(mOutBuffer, mPixels, rect, color, tolerance);
    }

    void expectBorder(const Rect& rect, const Color& color, uint8_t tolerance = 0) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mOutBuffer->getPixelFormat());
        const bool leftBorder = rect.left > 0;
        const bool topBorder = rect.top > 0;
        const bool rightBorder = rect.right < int32_t(mOutBuffer->getWidth());
        const bool bottomBorder = rect.bottom < int32_t(mOutBuffer->getHeight());

        if (topBorder) {
            Rect top(rect.left, rect.top - 1, rect.right, rect.top);
            if (leftBorder) {
                top.left -= 1;
            }
            if (rightBorder) {
                top.right += 1;
            }
            expectColor(top, color, tolerance);
        }
        if (leftBorder) {
            Rect left(rect.left - 1, rect.top, rect.left, rect.bottom);
            expectColor(left, color, tolerance);
        }
        if (rightBorder) {
            Rect right(rect.right, rect.top, rect.right + 1, rect.bottom);
            expectColor(right, color, tolerance);
        }
        if (bottomBorder) {
            Rect bottom(rect.left, rect.bottom, rect.right, rect.bottom + 1);
            if (leftBorder) {
                bottom.left -= 1;
            }
            if (rightBorder) {
                bottom.right += 1;
            }
            expectColor(bottom, color, tolerance);
        }
    }

    void expectQuadrant(const Rect& rect, const Color& topLeft, const Color& topRight,
                        const Color& bottomLeft, const Color& bottomRight, bool filtered = false,
                        uint8_t tolerance = 0) {
        ASSERT_TRUE((rect.right - rect.left) % 2 == 0 && (rect.bottom - rect.top) % 2 == 0);

        const int32_t centerX = rect.left + (rect.right - rect.left) / 2;
        const int32_t centerY = rect.top + (rect.bottom - rect.top) / 2;
        // avoid checking borders due to unspecified filtering behavior
        const int32_t offsetX = filtered ? 2 : 0;
        const int32_t offsetY = filtered ? 2 : 0;
        expectColor(Rect(rect.left, rect.top, centerX - offsetX, centerY - offsetY), topLeft,
                    tolerance);
        expectColor(Rect(centerX + offsetX, rect.top, rect.right, centerY - offsetY), topRight,
                    tolerance);
        expectColor(Rect(rect.left, centerY + offsetY, centerX - offsetX, rect.bottom), bottomLeft,
                    tolerance);
        expectColor(Rect(centerX + offsetX, centerY + offsetY, rect.right, rect.bottom),
                    bottomRight, tolerance);
    }

    void checkPixel(uint32_t x, uint32_t y, uint8_t r, uint8_t g, uint8_t b) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mOutBuffer->getPixelFormat());
        const uint8_t* pixel = mPixels + (4 * (y * mOutBuffer->getStride() + x));
        if (r != pixel[0] || g != pixel[1] || b != pixel[2]) {
            String8 err(String8::format("pixel @ (%3d, %3d): "
                                        "expected [%3d, %3d, %3d], got [%3d, %3d, %3d]",
                                        x, y, r, g, b, pixel[0], pixel[1], pixel[2]));
            EXPECT_EQ(String8(), err) << err.string();
        }
    }

    void expectFGColor(uint32_t x, uint32_t y) { checkPixel(x, y, 195, 63, 63); }

    void expectBGColor(uint32_t x, uint32_t y) { checkPixel(x, y, 63, 63, 195); }

    void expectChildColor(uint32_t x, uint32_t y) { checkPixel(x, y, 200, 200, 200); }

    explicit ScreenCapture(const sp<GraphicBuffer>& outBuffer) : mOutBuffer(outBuffer) {
        mOutBuffer->lock(GRALLOC_USAGE_SW_READ_OFTEN, reinterpret_cast<void**>(&mPixels));
    }

    ~ScreenCapture() { mOutBuffer->unlock(); }

private:
    sp<GraphicBuffer> mOutBuffer;
    uint8_t* mPixels = nullptr;
};
} // namespace
} // namespace android
