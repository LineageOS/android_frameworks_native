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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <algorithm>

#include "RefreshRateOverlay.h"
#include "Client.h"
#include "Layer.h"

#include <SkBlendMode.h>
#include <SkPaint.h>
#include <SkRect.h>
#include <SkSurface.h>
#include <gui/IProducerListener.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>

#undef LOG_TAG
#define LOG_TAG "RefreshRateOverlay"

namespace android {

void RefreshRateOverlay::SevenSegmentDrawer::drawSegment(Segment segment, int left, SkColor& color,
                                                         SkCanvas& canvas) {
    const SkRect rect = [&]() {
        switch (segment) {
            case Segment::Upper:
                return SkRect::MakeLTRB(left, 0, left + DIGIT_WIDTH, DIGIT_SPACE);
            case Segment::UpperLeft:
                return SkRect::MakeLTRB(left, 0, left + DIGIT_SPACE, DIGIT_HEIGHT / 2);
            case Segment::UpperRight:
                return SkRect::MakeLTRB(left + DIGIT_WIDTH - DIGIT_SPACE, 0, left + DIGIT_WIDTH,
                                        DIGIT_HEIGHT / 2);
            case Segment::Middle:
                return SkRect::MakeLTRB(left, DIGIT_HEIGHT / 2 - DIGIT_SPACE / 2,
                                        left + DIGIT_WIDTH, DIGIT_HEIGHT / 2 + DIGIT_SPACE / 2);
            case Segment::LowerLeft:
                return SkRect::MakeLTRB(left, DIGIT_HEIGHT / 2, left + DIGIT_SPACE, DIGIT_HEIGHT);
            case Segment::LowerRight:
                return SkRect::MakeLTRB(left + DIGIT_WIDTH - DIGIT_SPACE, DIGIT_HEIGHT / 2,
                                        left + DIGIT_WIDTH, DIGIT_HEIGHT);
            case Segment::Bottom:
                return SkRect::MakeLTRB(left, DIGIT_HEIGHT - DIGIT_SPACE, left + DIGIT_WIDTH,
                                        DIGIT_HEIGHT);
        }
    }();

    SkPaint paint;
    paint.setColor(color);
    paint.setBlendMode(SkBlendMode::kSrc);
    canvas.drawRect(rect, paint);
}

void RefreshRateOverlay::SevenSegmentDrawer::drawDigit(int digit, int left, SkColor& color,
                                                       SkCanvas& canvas) {
    if (digit < 0 || digit > 9) return;

    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::Upper, left, color, canvas);
    if (digit == 0 || digit == 4 || digit == 5 || digit == 6 || digit == 8 || digit == 9)
        drawSegment(Segment::UpperLeft, left, color, canvas);
    if (digit == 0 || digit == 1 || digit == 2 || digit == 3 || digit == 4 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::UpperRight, left, color, canvas);
    if (digit == 2 || digit == 3 || digit == 4 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Middle, left, color, canvas);
    if (digit == 0 || digit == 2 || digit == 6 || digit == 8)
        drawSegment(Segment::LowerLeft, left, color, canvas);
    if (digit == 0 || digit == 1 || digit == 3 || digit == 4 || digit == 5 || digit == 6 ||
        digit == 7 || digit == 8 || digit == 9)
        drawSegment(Segment::LowerRight, left, color, canvas);
    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Bottom, left, color, canvas);
}

std::vector<sp<GraphicBuffer>> RefreshRateOverlay::SevenSegmentDrawer::draw(
        int number, SkColor& color, ui::Transform::RotationFlags rotation, bool showSpinner) {
    if (number < 0 || number > 1000) return {};

    const auto hundreds = number / 100;
    const auto tens = (number / 10) % 10;
    const auto ones = number % 10;

    std::vector<sp<GraphicBuffer>> buffers;
    const auto loopCount = showSpinner ? 6 : 1;
    for (int i = 0; i < loopCount; i++) {
        // Pre-rotate the buffer before it reaches SurfaceFlinger.
        SkMatrix canvasTransform = SkMatrix();
        auto [bufferWidth, bufferHeight] = [&] {
            switch (rotation) {
                case ui::Transform::ROT_90:
                    canvasTransform.setTranslate(BUFFER_HEIGHT, 0);
                    canvasTransform.preRotate(90);
                    return std::make_tuple(BUFFER_HEIGHT, BUFFER_WIDTH);
                case ui::Transform::ROT_270:
                    canvasTransform.setRotate(270, BUFFER_WIDTH / 2.0, BUFFER_WIDTH / 2.0);
                    return std::make_tuple(BUFFER_HEIGHT, BUFFER_WIDTH);
                default:
                    return std::make_tuple(BUFFER_WIDTH, BUFFER_HEIGHT);
            }
        }();
        sp<GraphicBuffer> buffer =
                new GraphicBuffer(bufferWidth, bufferHeight, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                  GRALLOC_USAGE_SW_WRITE_RARELY | GRALLOC_USAGE_HW_COMPOSER |
                                          GRALLOC_USAGE_HW_TEXTURE,
                                  "RefreshRateOverlayBuffer");
        const status_t bufferStatus = buffer->initCheck();
        LOG_ALWAYS_FATAL_IF(bufferStatus != OK, "RefreshRateOverlay: Buffer failed to allocate: %d",
                            bufferStatus);

        sk_sp<SkSurface> surface = SkSurface::MakeRasterN32Premul(bufferWidth, bufferHeight);
        SkCanvas* canvas = surface->getCanvas();
        canvas->setMatrix(canvasTransform);

        int left = 0;
        if (hundreds != 0) {
            drawDigit(hundreds, left, color, *canvas);
        }
        left += DIGIT_WIDTH + DIGIT_SPACE;

        if (tens != 0) {
            drawDigit(tens, left, color, *canvas);
        }
        left += DIGIT_WIDTH + DIGIT_SPACE;

        drawDigit(ones, left, color, *canvas);
        left += DIGIT_WIDTH + DIGIT_SPACE;

        if (showSpinner) {
            switch (i) {
                case 0:
                    drawSegment(Segment::Upper, left, color, *canvas);
                    break;
                case 1:
                    drawSegment(Segment::UpperRight, left, color, *canvas);
                    break;
                case 2:
                    drawSegment(Segment::LowerRight, left, color, *canvas);
                    break;
                case 3:
                    drawSegment(Segment::Bottom, left, color, *canvas);
                    break;
                case 4:
                    drawSegment(Segment::LowerLeft, left, color, *canvas);
                    break;
                case 5:
                    drawSegment(Segment::UpperLeft, left, color, *canvas);
                    break;
            }
        }

        void* pixels = nullptr;
        buffer->lock(GRALLOC_USAGE_SW_WRITE_RARELY, reinterpret_cast<void**>(&pixels));
        const SkImageInfo& imageInfo = surface->imageInfo();
        size_t dstRowBytes = buffer->getStride() * imageInfo.bytesPerPixel();
        canvas->readPixels(imageInfo, pixels, dstRowBytes, 0, 0);
        buffer->unlock();
        buffers.emplace_back(buffer);
    }
    return buffers;
}

RefreshRateOverlay::RefreshRateOverlay(SurfaceFlinger& flinger, uint32_t lowFps, uint32_t highFps,
                                       bool showSpinner)
      : mFlinger(flinger),
        mClient(new Client(&mFlinger)),
        mShowSpinner(showSpinner),
        mLowFps(lowFps),
        mHighFps(highFps) {
    createLayer();
}

bool RefreshRateOverlay::createLayer() {
    mSurfaceControl =
            SurfaceComposerClient::getDefault()
                    ->createSurface(String8("RefreshRateOverlay"), SevenSegmentDrawer::getWidth(),
                                    SevenSegmentDrawer::getHeight(), PIXEL_FORMAT_RGBA_8888,
                                    ISurfaceComposerClient::eFXSurfaceBufferState);

    if (!mSurfaceControl) {
        ALOGE("failed to create buffer state layer");
        return false;
    }

    SurfaceComposerClient::Transaction t;
    t.setFrameRate(mSurfaceControl, 0.0f,
                   static_cast<int8_t>(Layer::FrameRateCompatibility::NoVote),
                   static_cast<int8_t>(scheduler::Seamlessness::OnlySeamless));
    t.setLayer(mSurfaceControl, INT32_MAX - 2);
    t.apply();

    return true;
}

const std::vector<sp<GraphicBuffer>>& RefreshRateOverlay::getOrCreateBuffers(uint32_t fps) {
    ui::Transform::RotationFlags transformHint =
            static_cast<ui::Transform::RotationFlags>(mSurfaceControl->getTransformHint());
    // Tell SurfaceFlinger about the pre-rotation on the buffer.
    const auto transform = [&] {
        switch (transformHint) {
            case ui::Transform::ROT_90:
                return ui::Transform::ROT_270;
            case ui::Transform::ROT_270:
                return ui::Transform::ROT_90;
            default:
                return ui::Transform::ROT_0;
        }
    }();

    SurfaceComposerClient::Transaction t;
    t.setTransform(mSurfaceControl, transform);
    t.apply();

    if (mBufferCache.find(transformHint) == mBufferCache.end() ||
        mBufferCache.at(transformHint).find(fps) == mBufferCache.at(transformHint).end()) {
        // Ensure the range is > 0, so we don't divide by 0.
        const auto rangeLength = std::max(1u, mHighFps - mLowFps);
        // Clip values outside the range [mLowFps, mHighFps]. The current fps may be outside
        // of this range if the display has changed its set of supported refresh rates.
        fps = std::max(fps, mLowFps);
        fps = std::min(fps, mHighFps);
        const auto fpsScale = static_cast<float>(fps - mLowFps) / rangeLength;
        SkColor4f colorBase = SkColor4f::FromColor(HIGH_FPS_COLOR) * fpsScale;
        SkColor4f lowFpsColor = SkColor4f::FromColor(LOW_FPS_COLOR) * (1 - fpsScale);
        colorBase.fR = colorBase.fR + lowFpsColor.fR;
        colorBase.fG = colorBase.fG + lowFpsColor.fG;
        colorBase.fB = colorBase.fB + lowFpsColor.fB;
        colorBase.fA = ALPHA;
        SkColor color = colorBase.toSkColor();
        auto buffers = SevenSegmentDrawer::draw(fps, color, transformHint, mShowSpinner);
        mBufferCache[transformHint].emplace(fps, buffers);
    }

    return mBufferCache[transformHint][fps];
}

void RefreshRateOverlay::setViewport(ui::Size viewport) {
    constexpr int32_t kMaxWidth = 1000;
    const auto width = std::min(kMaxWidth, std::min(viewport.width, viewport.height));
    const auto height = 2 * width;
    Rect frame((3 * width) >> 4, height >> 5);
    frame.offsetBy(width >> 5, height >> 4);

    SurfaceComposerClient::Transaction t;
    t.setMatrix(mSurfaceControl,
                frame.getWidth() / static_cast<float>(SevenSegmentDrawer::getWidth()), 0, 0,
                frame.getHeight() / static_cast<float>(SevenSegmentDrawer::getHeight()));
    t.setPosition(mSurfaceControl, frame.left, frame.top);
    t.apply();
}

void RefreshRateOverlay::setLayerStack(ui::LayerStack stack) {
    SurfaceComposerClient::Transaction t;
    t.setLayerStack(mSurfaceControl, stack);
    t.apply();
}

void RefreshRateOverlay::changeRefreshRate(const Fps& fps) {
    mCurrentFps = fps.getIntValue();
    auto buffer = getOrCreateBuffers(*mCurrentFps)[mFrame];
    SurfaceComposerClient::Transaction t;
    t.setBuffer(mSurfaceControl, buffer);
    t.apply();
}

void RefreshRateOverlay::onInvalidate() {
    if (!mCurrentFps.has_value()) return;

    const auto& buffers = getOrCreateBuffers(*mCurrentFps);
    mFrame = (mFrame + 1) % buffers.size();
    auto buffer = buffers[mFrame];
    SurfaceComposerClient::Transaction t;
    t.setBuffer(mSurfaceControl, buffer);
    t.apply();
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
