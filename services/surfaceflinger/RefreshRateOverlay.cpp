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

#include <common/FlagManager.h>
#include "Client.h"
#include "Layer.h"
#include "RefreshRateOverlay.h"

#include <SkSurface.h>

#undef LOG_TAG
#define LOG_TAG "RefreshRateOverlay"

namespace android {

auto RefreshRateOverlay::draw(int refreshRate, int renderFps, bool idle, SkColor color,
                              ui::Transform::RotationFlags rotation, ftl::Flags<Features> features)
        -> Buffers {
    const size_t loopCount = features.test(Features::Spinner) ? 6 : 1;
    const bool isSetByHwc = features.test(Features::SetByHwc);

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

        sk_sp<SkSurface> surface = SkSurfaces::Raster(
                SkImageInfo::MakeN32Premul(bufferWidth, bufferHeight));
        SkCanvas* canvas = surface->getCanvas();
        canvas->setMatrix(canvasTransform);

        int left = 0;
        if (idle && !isSetByHwc) {
            drawDash(left, *canvas);
        } else {
            drawNumber(refreshRate, left, color, *canvas);
        }
        left += 3 * (kDigitWidth + kDigitSpace);
        if (features.test(Features::Spinner)) {
            switch (i) {
                case 0:
                    SegmentDrawer::drawSegment(SegmentDrawer::Segment::Upper, left, color, *canvas);
                    break;
                case 1:
                    SegmentDrawer::drawSegment(SegmentDrawer::Segment::UpperRight, left, color,
                                               *canvas);
                    break;
                case 2:
                    SegmentDrawer::drawSegment(SegmentDrawer::Segment::LowerRight, left, color,
                                               *canvas);
                    break;
                case 3:
                    SegmentDrawer::drawSegment(SegmentDrawer::Segment::Bottom, left, color,
                                               *canvas);
                    break;
                case 4:
                    SegmentDrawer::drawSegment(SegmentDrawer::Segment::LowerLeft, left, color,
                                               *canvas);
                    break;
                case 5:
                    SegmentDrawer::drawSegment(SegmentDrawer::Segment::UpperLeft, left, color,
                                               *canvas);
                    break;
            }
        }

        left += kDigitWidth + kDigitSpace;

        if (features.test(Features::RenderRate)) {
            if (idle) {
                drawDash(left, *canvas);
            } else {
                drawNumber(renderFps, left, color, *canvas);
            }
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

void RefreshRateOverlay::drawNumber(int number, int left, SkColor color, SkCanvas& canvas) {
    if (number < 0 || number >= 1000) return;

    if (number >= 100) {
        SegmentDrawer::drawDigit(number / 100, left, color, canvas);
    }
    left += kDigitWidth + kDigitSpace;

    if (number >= 10) {
        SegmentDrawer::drawDigit((number / 10) % 10, left, color, canvas);
    }
    left += kDigitWidth + kDigitSpace;

    SegmentDrawer::drawDigit(number % 10, left, color, canvas);
}

void RefreshRateOverlay::drawDash(int left, SkCanvas& canvas) {
    left += kDigitWidth + kDigitSpace;
    SegmentDrawer::drawSegment(SegmentDrawer::Segment::Middle, left, SK_ColorRED, canvas);

    left += kDigitWidth + kDigitSpace;
    SegmentDrawer::drawSegment(SegmentDrawer::Segment::Middle, left, SK_ColorRED, canvas);
}

std::unique_ptr<RefreshRateOverlay> RefreshRateOverlay::create(FpsRange range,
                                                               ftl::Flags<Features> features) {
    std::unique_ptr<RefreshRateOverlay> overlay =
            std::make_unique<RefreshRateOverlay>(ConstructorTag{}, range, features);
    if (overlay->initCheck()) {
        return overlay;
    }

    ALOGE("%s: Failed to create RefreshRateOverlay", __func__);
    return {};
}

RefreshRateOverlay::RefreshRateOverlay(ConstructorTag, FpsRange fpsRange,
                                       ftl::Flags<Features> features)
      : mFpsRange(fpsRange),
        mFeatures(features),
        mSurfaceControl(
                SurfaceControlHolder::createSurfaceControlHolder(String8("RefreshRateOverlay"))) {
    if (!mSurfaceControl) {
        ALOGE("%s: Failed to create buffer state layer", __func__);
        return;
    }

    createTransaction()
            .setLayer(mSurfaceControl->get(), INT32_MAX - 2)
            .setTrustedOverlay(mSurfaceControl->get(), true)
            .apply();
}

bool RefreshRateOverlay::initCheck() const {
    return mSurfaceControl != nullptr;
}

auto RefreshRateOverlay::getOrCreateBuffers(Fps refreshRate, Fps renderFps, bool idle)
        -> const Buffers& {
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

    BufferCache::const_iterator it = mBufferCache.find(
            {refreshRate.getIntValue(), renderFps.getIntValue(), transformHint, idle});
    if (it == mBufferCache.end()) {
        const int maxFps = mFpsRange.max.getIntValue();

        // Clamp to supported refresh rate range: the current refresh rate may be outside of this
        // range if the display has changed its set of supported refresh rates.
        const int refreshIntFps = std::clamp(refreshRate.getIntValue(), 0, maxFps);
        const int renderIntFps = renderFps.getIntValue();
        const float fpsScale = static_cast<float>(refreshIntFps) / maxFps;

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

        auto buffers = draw(refreshIntFps, renderIntFps, idle, color, transformHint, mFeatures);
        it = mBufferCache
                     .try_emplace({refreshIntFps, renderIntFps, transformHint, idle},
                     std::move(buffers)).first;
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

void RefreshRateOverlay::changeRefreshRate(Fps refreshRate, Fps renderFps) {
    mRefreshRate = refreshRate;
    mRenderFps = renderFps;
    const auto buffer = getOrCreateBuffers(refreshRate, renderFps, mIsVrrIdle)[mFrame];
    createTransaction().setBuffer(mSurfaceControl->get(), buffer).apply();
}

void RefreshRateOverlay::onVrrIdle(bool idle) {
    mIsVrrIdle = idle;
    if (!mRefreshRate || !mRenderFps) return;

    const auto buffer = getOrCreateBuffers(*mRefreshRate, *mRenderFps, mIsVrrIdle)[mFrame];
    createTransaction().setBuffer(mSurfaceControl->get(), buffer).apply();
}

void RefreshRateOverlay::changeRenderRate(Fps renderFps) {
    if (mFeatures.test(Features::RenderRate) && mRefreshRate &&
        FlagManager::getInstance().misc1()) {
        mRenderFps = renderFps;
        const auto buffer = getOrCreateBuffers(*mRefreshRate, renderFps, mIsVrrIdle)[mFrame];
        createTransaction().setBuffer(mSurfaceControl->get(), buffer).apply();
    }
}

void RefreshRateOverlay::animate() {
    if (!mFeatures.test(Features::Spinner) || !mRefreshRate) return;

    const auto& buffers = getOrCreateBuffers(*mRefreshRate, *mRenderFps, mIsVrrIdle);
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
