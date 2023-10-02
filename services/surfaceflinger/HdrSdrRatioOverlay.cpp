/**
 * Copyright (C) 2023 The Android Open Source Project
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
// #define LOG_NDEBUG 0
#include <algorithm>

#include "HdrSdrRatioOverlay.h"

#include <SkSurface.h>

#undef LOG_TAG
#define LOG_TAG "HdrSdrRatioOverlay"

namespace android {

void HdrSdrRatioOverlay::drawNumber(float number, int left, SkColor color, SkCanvas& canvas) {
    if (!isfinite(number) || number >= 10.f) return;
    // We assume that the number range is [1.f, 10.f)
    // and the decimal places are 2.
    int value = static_cast<int>(number * 100);
    SegmentDrawer::drawDigit(value / 100, left, color, canvas);

    left += kDigitWidth + kDigitSpace;
    SegmentDrawer::drawSegment(SegmentDrawer::Segment::DecimalPoint, left, color, canvas);
    left += kDigitWidth + kDigitSpace;

    SegmentDrawer::drawDigit((value / 10) % 10, left, color, canvas);
    left += kDigitWidth + kDigitSpace;
    SegmentDrawer::drawDigit(value % 10, left, color, canvas);
}

sp<GraphicBuffer> HdrSdrRatioOverlay::draw(float currentHdrSdrRatio, SkColor color,
                                           ui::Transform::RotationFlags rotation,
                                           sp<GraphicBuffer>& ringBuffer) {
    const int32_t bufferWidth = kBufferWidth;
    const int32_t bufferHeight = kBufferWidth;

    const auto kUsageFlags = static_cast<uint64_t>(
            GRALLOC_USAGE_SW_WRITE_RARELY | GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_TEXTURE);

    // ring buffers here to do double-buffered rendering to avoid
    // possible tearing and also to reduce memory take-up.
    if (ringBuffer == nullptr) {
        ringBuffer = sp<GraphicBuffer>::make(static_cast<uint32_t>(bufferWidth),
                                             static_cast<uint32_t>(bufferHeight),
                                             HAL_PIXEL_FORMAT_RGBA_8888, 1u, kUsageFlags,
                                             "HdrSdrRatioOverlayBuffer");
    }

    auto& buffer = ringBuffer;

    SkMatrix canvasTransform = SkMatrix();
    switch (rotation) {
        case ui::Transform::ROT_90:
            canvasTransform.setTranslate(bufferHeight, 0);
            canvasTransform.preRotate(90.f);
            break;
        case ui::Transform::ROT_270:
            canvasTransform.setRotate(270.f, bufferWidth / 2.f, bufferWidth / 2.f);
            break;
        default:
            break;
    }

    const status_t bufferStatus = buffer->initCheck();
    LOG_ALWAYS_FATAL_IF(bufferStatus != OK, "HdrSdrRatioOverlay: Buffer failed to allocate: %d",
                        bufferStatus);

    sk_sp<SkSurface> surface =
            SkSurfaces::Raster(SkImageInfo::MakeN32Premul(bufferWidth, bufferHeight));
    SkCanvas* canvas = surface->getCanvas();
    canvas->setMatrix(canvasTransform);

    drawNumber(currentHdrSdrRatio, 0, color, *canvas);

    void* pixels = nullptr;
    buffer->lock(GRALLOC_USAGE_SW_WRITE_RARELY, reinterpret_cast<void**>(&pixels));

    const SkImageInfo& imageInfo = surface->imageInfo();
    const size_t dstRowBytes = buffer->getStride() * static_cast<size_t>(imageInfo.bytesPerPixel());

    canvas->readPixels(imageInfo, pixels, dstRowBytes, 0, 0);
    buffer->unlock();
    return buffer;
}

std::unique_ptr<HdrSdrRatioOverlay> HdrSdrRatioOverlay::create() {
    std::unique_ptr<HdrSdrRatioOverlay> overlay =
            std::make_unique<HdrSdrRatioOverlay>(ConstructorTag{});
    if (overlay->initCheck()) {
        return overlay;
    }

    ALOGE("%s: Failed to create HdrSdrRatioOverlay", __func__);
    return {};
}

HdrSdrRatioOverlay::HdrSdrRatioOverlay(ConstructorTag)
      : mSurfaceControl(
                SurfaceControlHolder::createSurfaceControlHolder(String8("HdrSdrRatioOverlay"))) {
    if (!mSurfaceControl) {
        ALOGE("%s: Failed to create buffer state layer", __func__);
        return;
    }
    SurfaceComposerClient::Transaction()
            .setLayer(mSurfaceControl->get(), INT32_MAX - 2)
            .setTrustedOverlay(mSurfaceControl->get(), true)
            .apply();
}

bool HdrSdrRatioOverlay::initCheck() const {
    return mSurfaceControl != nullptr;
}

void HdrSdrRatioOverlay::changeHdrSdrRatio(float currentHdrSdrRatio) {
    mCurrentHdrSdrRatio = currentHdrSdrRatio;
    animate();
}

void HdrSdrRatioOverlay::setLayerStack(ui::LayerStack stack) {
    SurfaceComposerClient::Transaction().setLayerStack(mSurfaceControl->get(), stack).apply();
}

void HdrSdrRatioOverlay::setViewport(ui::Size viewport) {
    constexpr int32_t kMaxWidth = 1000;
    const auto width = std::min({kMaxWidth, viewport.width, viewport.height});
    const auto height = 2 * width;
    Rect frame((5 * width) >> 4, height >> 5);
    // set the ratio frame to the top right of the screen
    frame.offsetBy(viewport.width - frame.width(), height >> 4);

    SurfaceComposerClient::Transaction()
            .setMatrix(mSurfaceControl->get(), frame.getWidth() / static_cast<float>(kBufferWidth),
                       0, 0, frame.getHeight() / static_cast<float>(kBufferHeight))
            .setPosition(mSurfaceControl->get(), frame.left, frame.top)
            .apply();
}

auto HdrSdrRatioOverlay::getOrCreateBuffers(float currentHdrSdrRatio) -> const sp<GraphicBuffer> {
    static const sp<GraphicBuffer> kNoBuffer;
    if (!mSurfaceControl) return kNoBuffer;

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

    SurfaceComposerClient::Transaction().setTransform(mSurfaceControl->get(), transform).apply();

    constexpr SkColor kMinRatioColor = SK_ColorBLUE;
    constexpr SkColor kMaxRatioColor = SK_ColorGREEN;
    constexpr float kAlpha = 0.8f;

    // 9.f is picked here as ratio range, given that we assume that
    // hdr/sdr ratio is [1.f, 10.f)
    const float scale = currentHdrSdrRatio / 9.f;

    SkColor4f colorBase = SkColor4f::FromColor(kMaxRatioColor) * scale;
    const SkColor4f minRatioColor = SkColor4f::FromColor(kMinRatioColor) * (1 - scale);

    colorBase.fR = colorBase.fR + minRatioColor.fR;
    colorBase.fG = colorBase.fG + minRatioColor.fG;
    colorBase.fB = colorBase.fB + minRatioColor.fB;
    colorBase.fA = kAlpha;

    const SkColor color = colorBase.toSkColor();

    auto buffer = draw(currentHdrSdrRatio, color, transformHint, mRingBuffer[mIndex]);
    mIndex = (mIndex + 1) % 2;
    return buffer;
}

void HdrSdrRatioOverlay::animate() {
    if (!std::isfinite(mCurrentHdrSdrRatio) || mCurrentHdrSdrRatio < 1.0f) return;
    SurfaceComposerClient::Transaction()
            .setBuffer(mSurfaceControl->get(), getOrCreateBuffers(mCurrentHdrSdrRatio))
            .apply();
}

} // namespace android