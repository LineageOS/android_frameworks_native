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

#include <gui/IProducerListener.h>

#undef LOG_TAG
#define LOG_TAG "RefreshRateOverlay"

namespace android {

void RefreshRateOverlay::SevenSegmentDrawer::drawRect(const Rect& r, const half4& color,
                                                      const sp<GraphicBuffer>& buffer,
                                                      uint8_t* pixels) {
    for (int32_t j = r.top; j < r.bottom; j++) {
        if (j >= buffer->getHeight()) {
            break;
        }

        for (int32_t i = r.left; i < r.right; i++) {
            if (i >= buffer->getWidth()) {
                break;
            }

            uint8_t* iter = pixels + 4 * (i + (buffer->getStride() * j));
            iter[0] = uint8_t(color.r * 255);
            iter[1] = uint8_t(color.g * 255);
            iter[2] = uint8_t(color.b * 255);
            iter[3] = uint8_t(color.a * 255);
        }
    }
}

void RefreshRateOverlay::SevenSegmentDrawer::drawSegment(Segment segment, int left,
                                                         const half4& color,
                                                         const sp<GraphicBuffer>& buffer,
                                                         uint8_t* pixels) {
    const Rect rect = [&]() {
        switch (segment) {
            case Segment::Upper:
                return Rect(left, 0, left + DIGIT_WIDTH, DIGIT_SPACE);
            case Segment::UpperLeft:
                return Rect(left, 0, left + DIGIT_SPACE, DIGIT_HEIGHT / 2);
            case Segment::UpperRight:
                return Rect(left + DIGIT_WIDTH - DIGIT_SPACE, 0, left + DIGIT_WIDTH,
                            DIGIT_HEIGHT / 2);
            case Segment::Middle:
                return Rect(left, DIGIT_HEIGHT / 2 - DIGIT_SPACE / 2, left + DIGIT_WIDTH,
                            DIGIT_HEIGHT / 2 + DIGIT_SPACE / 2);
            case Segment::LowerLeft:
                return Rect(left, DIGIT_HEIGHT / 2, left + DIGIT_SPACE, DIGIT_HEIGHT);
            case Segment::LowerRight:
                return Rect(left + DIGIT_WIDTH - DIGIT_SPACE, DIGIT_HEIGHT / 2, left + DIGIT_WIDTH,
                            DIGIT_HEIGHT);
            case Segment::Buttom:
                return Rect(left, DIGIT_HEIGHT - DIGIT_SPACE, left + DIGIT_WIDTH, DIGIT_HEIGHT);
        }
    }();

    drawRect(rect, color, buffer, pixels);
}

void RefreshRateOverlay::SevenSegmentDrawer::drawDigit(int digit, int left, const half4& color,
                                                       const sp<GraphicBuffer>& buffer,
                                                       uint8_t* pixels) {
    if (digit < 0 || digit > 9) return;

    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::Upper, left, color, buffer, pixels);
    if (digit == 0 || digit == 4 || digit == 5 || digit == 6 || digit == 8 || digit == 9)
        drawSegment(Segment::UpperLeft, left, color, buffer, pixels);
    if (digit == 0 || digit == 1 || digit == 2 || digit == 3 || digit == 4 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::UpperRight, left, color, buffer, pixels);
    if (digit == 2 || digit == 3 || digit == 4 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Middle, left, color, buffer, pixels);
    if (digit == 0 || digit == 2 || digit == 6 || digit == 8)
        drawSegment(Segment::LowerLeft, left, color, buffer, pixels);
    if (digit == 0 || digit == 1 || digit == 3 || digit == 4 || digit == 5 || digit == 6 ||
        digit == 7 || digit == 8 || digit == 9)
        drawSegment(Segment::LowerRight, left, color, buffer, pixels);
    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Buttom, left, color, buffer, pixels);
}

std::vector<sp<GraphicBuffer>> RefreshRateOverlay::SevenSegmentDrawer::drawNumber(
        int number, const half4& color, bool showSpinner) {
    if (number < 0 || number > 1000) return {};

    const auto hundreds = number / 100;
    const auto tens = (number / 10) % 10;
    const auto ones = number % 10;

    std::vector<sp<GraphicBuffer>> buffers;
    const auto loopCount = showSpinner ? 6 : 1;
    for (int i = 0; i < loopCount; i++) {
        sp<GraphicBuffer> buffer =
                new GraphicBuffer(BUFFER_WIDTH, BUFFER_HEIGHT, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                  GRALLOC_USAGE_SW_WRITE_RARELY | GRALLOC_USAGE_HW_COMPOSER |
                                          GRALLOC_USAGE_HW_TEXTURE,
                                  "RefreshRateOverlayBuffer");
        const status_t bufferStatus = buffer->initCheck();
        LOG_ALWAYS_FATAL_IF(bufferStatus != OK, "RefreshRateOverlay: Buffer failed to allocate: %d",
                            bufferStatus);
        uint8_t* pixels;
        buffer->lock(GRALLOC_USAGE_SW_WRITE_RARELY, reinterpret_cast<void**>(&pixels));
        // Clear buffer content
        drawRect(Rect(BUFFER_WIDTH, BUFFER_HEIGHT), half4(0), buffer, pixels);
        int left = 0;
        if (hundreds != 0) {
            drawDigit(hundreds, left, color, buffer, pixels);
        }
        left += DIGIT_WIDTH + DIGIT_SPACE;

        if (tens != 0) {
            drawDigit(tens, left, color, buffer, pixels);
        }
        left += DIGIT_WIDTH + DIGIT_SPACE;

        drawDigit(ones, left, color, buffer, pixels);
        left += DIGIT_WIDTH + DIGIT_SPACE;

        if (showSpinner) {
            switch (i) {
                case 0:
                    drawSegment(Segment::Upper, left, color, buffer, pixels);
                    break;
                case 1:
                    drawSegment(Segment::UpperRight, left, color, buffer, pixels);
                    break;
                case 2:
                    drawSegment(Segment::LowerRight, left, color, buffer, pixels);
                    break;
                case 3:
                    drawSegment(Segment::Buttom, left, color, buffer, pixels);
                    break;
                case 4:
                    drawSegment(Segment::LowerLeft, left, color, buffer, pixels);
                    break;
                case 5:
                    drawSegment(Segment::UpperLeft, left, color, buffer, pixels);
                    break;
            }
        }

        buffer->unlock();
        buffers.emplace_back(buffer);
    }
    return buffers;
}

RefreshRateOverlay::RefreshRateOverlay(SurfaceFlinger& flinger, bool showSpinner)
      : mFlinger(flinger), mClient(new Client(&mFlinger)), mShowSpinner(showSpinner) {
    createLayer();
    reset();
}

bool RefreshRateOverlay::createLayer() {
    int32_t layerId;
    const status_t ret =
            mFlinger.createLayer(String8("RefreshRateOverlay"), mClient,
                                 SevenSegmentDrawer::getWidth(), SevenSegmentDrawer::getHeight(),
                                 PIXEL_FORMAT_RGBA_8888,
                                 ISurfaceComposerClient::eFXSurfaceBufferState, LayerMetadata(),
                                 &mIBinder, &mGbp, nullptr, &layerId);
    if (ret) {
        ALOGE("failed to create buffer state layer");
        return false;
    }

    Mutex::Autolock _l(mFlinger.mStateLock);
    mLayer = mClient->getLayerUser(mIBinder);
    mLayer->setFrameRate(Layer::FrameRate(Fps(0.0f), Layer::FrameRateCompatibility::NoVote));

    // setting Layer's Z requires resorting layersSortedByZ
    ssize_t idx = mFlinger.mCurrentState.layersSortedByZ.indexOf(mLayer);
    if (mLayer->setLayer(INT32_MAX - 2) && idx >= 0) {
        mFlinger.mCurrentState.layersSortedByZ.removeAt(idx);
        mFlinger.mCurrentState.layersSortedByZ.add(mLayer);
    }

    return true;
}

const std::vector<sp<GraphicBuffer>>& RefreshRateOverlay::getOrCreateBuffers(uint32_t fps) {
    if (mBufferCache.find(fps) == mBufferCache.end()) {
        // Ensure the range is > 0, so we don't divide by 0.
        const auto rangeLength = std::max(1u, mHighFps - mLowFps);
        // Clip values outside the range [mLowFps, mHighFps]. The current fps may be outside
        // of this range if the display has changed its set of supported refresh rates.
        fps = std::max(fps, mLowFps);
        fps = std::min(fps, mHighFps);
        const auto fpsScale = static_cast<float>(fps - mLowFps) / rangeLength;
        half4 color;
        color.r = HIGH_FPS_COLOR.r * fpsScale + LOW_FPS_COLOR.r * (1 - fpsScale);
        color.g = HIGH_FPS_COLOR.g * fpsScale + LOW_FPS_COLOR.g * (1 - fpsScale);
        color.b = HIGH_FPS_COLOR.b * fpsScale + LOW_FPS_COLOR.b * (1 - fpsScale);
        color.a = ALPHA;
        mBufferCache.emplace(fps, SevenSegmentDrawer::drawNumber(fps, color, mShowSpinner));
    }

    return mBufferCache[fps];
}

void RefreshRateOverlay::setViewport(ui::Size viewport) {
    Rect frame((3 * viewport.width) >> 4, viewport.height >> 5);
    frame.offsetBy(viewport.width >> 5, viewport.height >> 4);
    mLayer->setFrame(frame);

    mFlinger.mTransactionFlags.fetch_or(eTransactionMask);
}

void RefreshRateOverlay::changeRefreshRate(const Fps& fps) {
    mCurrentFps = fps.getIntValue();
    auto buffer = getOrCreateBuffers(*mCurrentFps)[mFrame];
    mLayer->setBuffer(buffer, Fence::NO_FENCE, 0, 0, true, {},
                      mLayer->getHeadFrameNumber(-1 /* expectedPresentTime */),
                      std::nullopt /* dequeueTime */, FrameTimelineInfo{});

    mFlinger.mTransactionFlags.fetch_or(eTransactionMask);
}

void RefreshRateOverlay::onInvalidate() {
    if (!mCurrentFps.has_value()) return;

    const auto& buffers = getOrCreateBuffers(*mCurrentFps);
    mFrame = (mFrame + 1) % buffers.size();
    auto buffer = buffers[mFrame];
    mLayer->setBuffer(buffer, Fence::NO_FENCE, 0, 0, true, {},
                      mLayer->getHeadFrameNumber(-1 /* expectedPresentTime */),
                      std::nullopt /* dequeueTime */, FrameTimelineInfo{});

    mFlinger.mTransactionFlags.fetch_or(eTransactionMask);
}

void RefreshRateOverlay::reset() {
    mBufferCache.clear();
    const auto range = mFlinger.mRefreshRateConfigs->getSupportedRefreshRateRange();
    mLowFps = range.min.getIntValue();
    mHighFps = range.max.getIntValue();
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
