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

#include <algorithm>

#include "BackgroundExecutor.h"
#include "Client.h"
#include "Layer.h"
#include "RefreshRateOverlay.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <SkCanvas.h>
#include <SkPaint.h>
#pragma clang diagnostic pop
#include <SkBlendMode.h>
#include <SkRect.h>
#include <SkSurface.h>
#include <gui/SurfaceControl.h>

#undef LOG_TAG
#define LOG_TAG "RefreshRateOverlay"

namespace android {
namespace {

constexpr int kDigitWidth = 64;
constexpr int kDigitHeight = 100;
constexpr int kDigitSpace = 16;

constexpr int kMaxDigits = /*displayFps*/ 3 + /*renderFps*/ 3 + /*spinner*/ 1;
constexpr int kBufferWidth = kMaxDigits * kDigitWidth + (kMaxDigits - 1) * kDigitSpace;
constexpr int kBufferHeight = kDigitHeight;

} // namespace

SurfaceControlHolder::~SurfaceControlHolder() {
    // Hand the sp<SurfaceControl> to the helper thread to release the last
    // reference. This makes sure that the SurfaceControl is destructed without
    // SurfaceFlinger::mStateLock held.
    BackgroundExecutor::getInstance().sendCallbacks(
            {[sc = std::move(mSurfaceControl)]() mutable { sc.clear(); }});
}

void RefreshRateOverlay::SevenSegmentDrawer::drawSegment(Segment segment, int left, SkColor color,
                                                         SkCanvas& canvas) {
    const SkRect rect = [&]() {
        switch (segment) {
            case Segment::Upper:
                return SkRect::MakeLTRB(left, 0, left + kDigitWidth, kDigitSpace);
            case Segment::UpperLeft:
                return SkRect::MakeLTRB(left, 0, left + kDigitSpace, kDigitHeight / 2);
            case Segment::UpperRight:
                return SkRect::MakeLTRB(left + kDigitWidth - kDigitSpace, 0, left + kDigitWidth,
                                        kDigitHeight / 2);
            case Segment::Middle:
                return SkRect::MakeLTRB(left, kDigitHeight / 2 - kDigitSpace / 2,
                                        left + kDigitWidth, kDigitHeight / 2 + kDigitSpace / 2);
            case Segment::LowerLeft:
                return SkRect::MakeLTRB(left, kDigitHeight / 2, left + kDigitSpace, kDigitHeight);
            case Segment::LowerRight:
                return SkRect::MakeLTRB(left + kDigitWidth - kDigitSpace, kDigitHeight / 2,
                                        left + kDigitWidth, kDigitHeight);
            case Segment::Bottom:
                return SkRect::MakeLTRB(left, kDigitHeight - kDigitSpace, left + kDigitWidth,
                                        kDigitHeight);
        }
    }();

    SkPaint paint;
    paint.setColor(color);
    paint.setBlendMode(SkBlendMode::kSrc);
    canvas.drawRect(rect, paint);
}

void RefreshRateOverlay::SevenSegmentDrawer::drawDigit(int digit, int left, SkColor color,
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

auto RefreshRateOverlay::SevenSegmentDrawer::draw(int displayFps, int renderFps, SkColor color,
                                                  ui::Transform::RotationFlags rotation,
                                                  ftl::Flags<Features> features) -> Buffers {
    const size_t loopCount = features.test(Features::Spinner) ? 6 : 1;

    Buffers buffers;
    buffers.reserve(loopCount);

    for (size_t i = 0; i < loopCount; i++) {
        // Pre-rotate the buffer before it reaches SurfaceFlinger.
        SkMatrix canvasTransform = SkMatrix();
        const auto [bufferWidth, bufferHeight] = [&]() -> std::pair<int, int> {
            switch (rotation) {
                case ui::Transform::ROT_90:
                    canvasTransform.setTranslate(kBufferHeight, 0);
                    canvasTransform.preRotate(90.f);
                    return {kBufferHeight, kBufferWidth};
                case ui::Transform::ROT_270:
                    canvasTransform.setRotate(270.f, kBufferWidth / 2.f, kBufferWidth / 2.f);
                    return {kBufferHeight, kBufferWidth};
                default:
                    return {kBufferWidth, kBufferHeight};
            }
        }();

        const auto kUsageFlags =
                static_cast<uint64_t>(GRALLOC_USAGE_SW_WRITE_RARELY | GRALLOC_USAGE_HW_COMPOSER |
                                      GRALLOC_USAGE_HW_TEXTURE);
        sp<GraphicBuffer> buffer = sp<GraphicBuffer>::make(static_cast<uint32_t>(bufferWidth),
                                                           static_cast<uint32_t>(bufferHeight),
                                                           HAL_PIXEL_FORMAT_RGBA_8888, 1u,
                                                           kUsageFlags, "RefreshRateOverlayBuffer");

        const status_t bufferStatus = buffer->initCheck();
        LOG_ALWAYS_FATAL_IF(bufferStatus != OK, "RefreshRateOverlay: Buffer failed to allocate: %d",
                            bufferStatus);

        sk_sp<SkSurface> surface = SkSurface::MakeRasterN32Premul(bufferWidth, bufferHeight);
        SkCanvas* canvas = surface->getCanvas();
        canvas->setMatrix(canvasTransform);

        int left = 0;
        drawNumber(displayFps, left, color, *canvas);
        left += 3 * (kDigitWidth + kDigitSpace);
        if (features.test(Features::Spinner)) {
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

        left += kDigitWidth + kDigitSpace;

        if (features.test(Features::RenderRate)) {
            drawNumber(renderFps, left, color, *canvas);
        }
        left += 3 * (kDigitWidth + kDigitSpace);

        void* pixels = nullptr;
        buffer->lock(GRALLOC_USAGE_SW_WRITE_RARELY, reinterpret_cast<void**>(&pixels));

        const SkImageInfo& imageInfo = surface->imageInfo();
        const size_t dstRowBytes =
                buffer->getStride() * static_cast<size_t>(imageInfo.bytesPerPixel());

        canvas->readPixels(imageInfo, pixels, dstRowBytes, 0, 0);
        buffer->unlock();
        buffers.push_back(std::move(buffer));
    }
    return buffers;
}

void RefreshRateOverlay::SevenSegmentDrawer::drawNumber(int number, int left, SkColor color,
                                                        SkCanvas& canvas) {
    if (number < 0 || number >= 1000) return;

    if (number >= 100) {
        drawDigit(number / 100, left, color, canvas);
    }
    left += kDigitWidth + kDigitSpace;

    if (number >= 10) {
        drawDigit((number / 10) % 10, left, color, canvas);
    }
    left += kDigitWidth + kDigitSpace;

    drawDigit(number % 10, left, color, canvas);
}

std::unique_ptr<SurfaceControlHolder> createSurfaceControlHolder() {
    sp<SurfaceControl> surfaceControl =
            SurfaceComposerClient::getDefault()
                    ->createSurface(String8("RefreshRateOverlay"), kBufferWidth, kBufferHeight,
                                    PIXEL_FORMAT_RGBA_8888,
                                    ISurfaceComposerClient::eFXSurfaceBufferState);
    return std::make_unique<SurfaceControlHolder>(std::move(surfaceControl));
}

RefreshRateOverlay::RefreshRateOverlay(FpsRange fpsRange, ftl::Flags<Features> features)
      : mFpsRange(fpsRange), mFeatures(features), mSurfaceControl(createSurfaceControlHolder()) {
    if (!mSurfaceControl) {
        ALOGE("%s: Failed to create buffer state layer", __func__);
        return;
    }

    createTransaction()
            .setLayer(mSurfaceControl->get(), INT32_MAX - 2)
            .setTrustedOverlay(mSurfaceControl->get(), true)
            .apply();
}

auto RefreshRateOverlay::getOrCreateBuffers(Fps displayFps, Fps renderFps) -> const Buffers& {
    static const Buffers kNoBuffers;
    if (!mSurfaceControl) return kNoBuffers;

    // avoid caching different render rates if RenderRate is anyway not visible
    if (!mFeatures.test(Features::RenderRate)) {
        renderFps = 0_Hz;
    }

    const auto transformHint =
            static_cast<ui::Transform::RotationFlags>(mSurfaceControl->get()->getTransformHint());

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

    createTransaction().setTransform(mSurfaceControl->get(), transform).apply();

    BufferCache::const_iterator it =
            mBufferCache.find({displayFps.getIntValue(), renderFps.getIntValue(), transformHint});
    if (it == mBufferCache.end()) {
        // HWC minFps is not known by the framework in order
        // to consider lower rates we set minFps to 0.
        const int minFps = isSetByHwc() ? 0 : mFpsRange.min.getIntValue();
        const int maxFps = mFpsRange.max.getIntValue();

        // Clamp to the range. The current displayFps may be outside of this range if the display
        // has changed its set of supported refresh rates.
        const int displayIntFps = std::clamp(displayFps.getIntValue(), minFps, maxFps);
        const int renderIntFps = renderFps.getIntValue();

        // Ensure non-zero range to avoid division by zero.
        const float fpsScale =
                static_cast<float>(displayIntFps - minFps) / std::max(1, maxFps - minFps);

        constexpr SkColor kMinFpsColor = SK_ColorRED;
        constexpr SkColor kMaxFpsColor = SK_ColorGREEN;
        constexpr float kAlpha = 0.8f;

        SkColor4f colorBase = SkColor4f::FromColor(kMaxFpsColor) * fpsScale;
        const SkColor4f minFpsColor = SkColor4f::FromColor(kMinFpsColor) * (1 - fpsScale);

        colorBase.fR = colorBase.fR + minFpsColor.fR;
        colorBase.fG = colorBase.fG + minFpsColor.fG;
        colorBase.fB = colorBase.fB + minFpsColor.fB;
        colorBase.fA = kAlpha;

        const SkColor color = colorBase.toSkColor();

        auto buffers = SevenSegmentDrawer::draw(displayIntFps, renderIntFps, color, transformHint,
                                                mFeatures);
        it = mBufferCache
                     .try_emplace({displayIntFps, renderIntFps, transformHint}, std::move(buffers))
                     .first;
    }

    return it->second;
}

void RefreshRateOverlay::setViewport(ui::Size viewport) {
    constexpr int32_t kMaxWidth = 1000;
    const auto width = std::min({kMaxWidth, viewport.width, viewport.height});
    const auto height = 2 * width;
    Rect frame((5 * width) >> 4, height >> 5);

    if (!mFeatures.test(Features::ShowInMiddle)) {
        frame.offsetBy(width >> 5, height >> 4);
    } else {
        frame.offsetBy(width >> 1, height >> 4);
    }

    createTransaction()
            .setMatrix(mSurfaceControl->get(), frame.getWidth() / static_cast<float>(kBufferWidth),
                       0, 0, frame.getHeight() / static_cast<float>(kBufferHeight))
            .setPosition(mSurfaceControl->get(), frame.left, frame.top)
            .apply();
}

void RefreshRateOverlay::setLayerStack(ui::LayerStack stack) {
    createTransaction().setLayerStack(mSurfaceControl->get(), stack).apply();
}

void RefreshRateOverlay::changeRefreshRate(Fps displayFps, Fps renderFps) {
    mDisplayFps = displayFps;
    mRenderFps = renderFps;
    const auto buffer = getOrCreateBuffers(displayFps, renderFps)[mFrame];
    createTransaction().setBuffer(mSurfaceControl->get(), buffer).apply();
}

void RefreshRateOverlay::animate() {
    if (!mFeatures.test(Features::Spinner) || !mDisplayFps) return;

    const auto& buffers = getOrCreateBuffers(*mDisplayFps, *mRenderFps);
    mFrame = (mFrame + 1) % buffers.size();
    const auto buffer = buffers[mFrame];
    createTransaction().setBuffer(mSurfaceControl->get(), buffer).apply();
}

SurfaceComposerClient::Transaction RefreshRateOverlay::createTransaction() const {
    constexpr float kFrameRate = 0.f;
    constexpr int8_t kCompatibility = ANATIVEWINDOW_FRAME_RATE_NO_VOTE;
    constexpr int8_t kSeamlessness = ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS;

    const sp<SurfaceControl>& surface = mSurfaceControl->get();

    SurfaceComposerClient::Transaction transaction;
    if (isSetByHwc()) {
        transaction.setFlags(surface, layer_state_t::eLayerIsRefreshRateIndicator,
                             layer_state_t::eLayerIsRefreshRateIndicator);
        // Disable overlay layer caching when refresh rate is updated by the HWC.
        transaction.setCachingHint(surface, gui::CachingHint::Disabled);
    }
    transaction.setFrameRate(surface, kFrameRate, kCompatibility, kSeamlessness);
    return transaction;
}

} // namespace android
