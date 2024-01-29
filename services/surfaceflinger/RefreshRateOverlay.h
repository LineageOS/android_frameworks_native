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

#pragma once

#include "Utils/OverlayUtils.h"

#include <vector>

#include <ftl/flags.h>
#include <ftl/small_map.h>
#include <ui/LayerStack.h>
#include <ui/Size.h>
#include <ui/Transform.h>
#include <utils/StrongPointer.h>

#include <scheduler/Fps.h>

class SkCanvas;

namespace android {

class GraphicBuffer;
class SurfaceFlinger;

class RefreshRateOverlay {
private:
    // Effectively making the constructor private, while keeping std::make_unique work
    struct ConstructorTag {};

public:
    enum class Features {
        Spinner = 1 << 0,
        RenderRate = 1 << 1,
        ShowInMiddle = 1 << 2,
        SetByHwc = 1 << 3,
    };

    static std::unique_ptr<RefreshRateOverlay> create(FpsRange, ftl::Flags<Features>);

    void setLayerStack(ui::LayerStack);
    void setViewport(ui::Size);
    void changeRefreshRate(Fps, Fps);
    void changeRenderRate(Fps);
    void animate();
    bool isSetByHwc() const { return mFeatures.test(RefreshRateOverlay::Features::SetByHwc); }

    RefreshRateOverlay(ConstructorTag, FpsRange, ftl::Flags<Features>);

private:
    bool initCheck() const;

    using Buffers = std::vector<sp<GraphicBuffer>>;

    static Buffers draw(int vsyncRate, int renderFps, SkColor, ui::Transform::RotationFlags,
                        ftl::Flags<Features>);
    static void drawNumber(int number, int left, SkColor, SkCanvas&);

    const Buffers& getOrCreateBuffers(Fps, Fps);

    SurfaceComposerClient::Transaction createTransaction() const;

    struct Key {
        int vsyncRate;
        int renderFps;
        ui::Transform::RotationFlags flags;

        bool operator==(Key other) const {
            return vsyncRate == other.vsyncRate && renderFps == other.renderFps &&
                    flags == other.flags;
        }
    };

    using BufferCache = ftl::SmallMap<Key, Buffers, 9>;
    BufferCache mBufferCache;

    std::optional<Fps> mVsyncRate;
    std::optional<Fps> mRenderFps;
    size_t mFrame = 0;

    const FpsRange mFpsRange; // For color interpolation.
    const ftl::Flags<Features> mFeatures;

    const std::unique_ptr<SurfaceControlHolder> mSurfaceControl;
};

} // namespace android
