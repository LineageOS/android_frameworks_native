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
#pragma once

#include "BackgroundExecutor.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <SkCanvas.h>
#include <SkPaint.h>
#pragma clang diagnostic pop

#include <gui/SurfaceComposerClient.h>
#include <utils/StrongPointer.h>

namespace android {

inline constexpr int kDigitWidth = 64;
inline constexpr int kDigitHeight = 100;
inline constexpr int kDigitSpace = 16;

// HdrSdrRatioOverlay re-uses this value though it doesn't really need such amount buffer.
// for output good-looking and code conciseness.
inline constexpr int kMaxDigits = /*displayFps*/ 3 + /*renderFps*/ 3 + /*spinner*/ 1;
inline constexpr int kBufferWidth = kMaxDigits * kDigitWidth + (kMaxDigits - 1) * kDigitSpace;
inline constexpr int kBufferHeight = kDigitHeight;

class SurfaceControl;

// Helper class to delete the SurfaceControl on a helper thread as
// SurfaceControl assumes its destruction happens without SurfaceFlinger::mStateLock held.
class SurfaceControlHolder {
public:
    explicit SurfaceControlHolder(sp<SurfaceControl> sc) : mSurfaceControl(std::move(sc)){};

    ~SurfaceControlHolder() {
        // Hand the sp<SurfaceControl> to the helper thread to release the last
        // reference. This makes sure that the SurfaceControl is destructed without
        // SurfaceFlinger::mStateLock held.
        BackgroundExecutor::getInstance().sendCallbacks(
                {[sc = std::move(mSurfaceControl)]() mutable { sc.clear(); }});
    }

    static std::unique_ptr<SurfaceControlHolder> createSurfaceControlHolder(const String8& name) {
        sp<SurfaceControl> surfaceControl =
                SurfaceComposerClient::getDefault()
                        ->createSurface(name, kBufferWidth, kBufferHeight, PIXEL_FORMAT_RGBA_8888,
                                        ISurfaceComposerClient::eFXSurfaceBufferState);
        return std::make_unique<SurfaceControlHolder>(std::move(surfaceControl));
    }

    const sp<SurfaceControl>& get() const { return mSurfaceControl; }

private:
    sp<SurfaceControl> mSurfaceControl;
};

// Helper class to draw digit and decimal point.
class SegmentDrawer {
public:
    enum class Segment {
        Upper,
        UpperLeft,
        UpperRight,
        Middle,
        LowerLeft,
        LowerRight,
        Bottom,
        DecimalPoint
    };
    static void drawSegment(Segment segment, int left, SkColor color, SkCanvas& canvas) {
        const SkRect rect = [&]() {
            switch (segment) {
                case Segment::Upper:
                    return SkRect::MakeLTRB(left, 0, left + kDigitWidth, kDigitSpace);
                case Segment::UpperLeft:
                    return SkRect::MakeLTRB(left, 0, left + kDigitSpace, kDigitHeight / 2.);
                case Segment::UpperRight:
                    return SkRect::MakeLTRB(left + kDigitWidth - kDigitSpace, 0, left + kDigitWidth,
                                            kDigitHeight / 2.);
                case Segment::Middle:
                    return SkRect::MakeLTRB(left, kDigitHeight / 2. - kDigitSpace / 2.,
                                            left + kDigitWidth,
                                            kDigitHeight / 2. + kDigitSpace / 2.);
                case Segment::LowerLeft:
                    return SkRect::MakeLTRB(left, kDigitHeight / 2., left + kDigitSpace,
                                            kDigitHeight);
                case Segment::LowerRight:
                    return SkRect::MakeLTRB(left + kDigitWidth - kDigitSpace, kDigitHeight / 2.,
                                            left + kDigitWidth, kDigitHeight);
                case Segment::Bottom:
                    return SkRect::MakeLTRB(left, kDigitHeight - kDigitSpace, left + kDigitWidth,
                                            kDigitHeight);
                case Segment::DecimalPoint:
                    return SkRect::MakeLTRB(left, kDigitHeight - kDigitSpace, left + kDigitSpace,
                                            kDigitHeight);
            }
        }();

        SkPaint paint;
        paint.setColor(color);
        paint.setBlendMode(SkBlendMode::kSrc);
        canvas.drawRect(rect, paint);
    }

    static void drawDigit(int digit, int left, SkColor color, SkCanvas& canvas) {
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
};

} // namespace android
