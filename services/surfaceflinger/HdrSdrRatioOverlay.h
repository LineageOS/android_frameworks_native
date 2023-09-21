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

#pragma once

#include "Utils/OverlayUtils.h"

#include <ui/Size.h>
#include <utils/StrongPointer.h>

class SkCanvas;

namespace android {
class HdrSdrRatioOverlay {
public:
    HdrSdrRatioOverlay();
    void setLayerStack(ui::LayerStack);
    void setViewport(ui::Size);
    void animate();
    void changeHdrSdrRatio(float currentRatio);

private:
    float mCurrentHdrSdrRatio = 1.f;

    static sp<GraphicBuffer> draw(float currentHdrSdrRatio, SkColor, ui::Transform::RotationFlags,
                                  sp<GraphicBuffer>& ringBufer);
    static void drawNumber(float number, int left, SkColor, SkCanvas&);

    const sp<GraphicBuffer> getOrCreateBuffers(float currentHdrSdrRatio);

    const std::unique_ptr<SurfaceControlHolder> mSurfaceControl;

    size_t mIndex = 0;
    std::array<sp<GraphicBuffer>, 2> mRingBuffer;
};
} // namespace android
