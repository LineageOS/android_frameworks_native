/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef ANDROID_COLOR_LAYER_H
#define ANDROID_COLOR_LAYER_H

#include <stdint.h>
#include <sys/types.h>

#include "Layer.h"

// ---------------------------------------------------------------------------

namespace android {

class ColorLayer : public Layer {
public:
    ColorLayer(SurfaceFlinger* flinger, const sp<Client>& client, const String8& name, uint32_t w,
               uint32_t h, uint32_t flags);
    virtual ~ColorLayer() = default;

    virtual const char* getTypeId() const { return "ColorLayer"; }
    virtual void onDraw(const RenderArea& renderArea, const Region& clip,
                        bool useIdentityTransform) const;
    bool isVisible() const override;
    virtual bool isOpaque(const Layer::State&) const { return false; }
    virtual bool isFixedSize() const { return true; }

    void notifyAvailableFrames() override {}
    PixelFormat getPixelFormat() const override { return PIXEL_FORMAT_NONE; }
    uint32_t getEffectiveScalingMode() const override { return 0; }
    void releasePendingBuffer(nsecs_t) override {}
    Region latchBuffer(bool&, nsecs_t) override { return Region(); }
    void useSurfaceDamage() override {}
    void useEmptyDamage() override {}
    bool isBufferLatched() const override { return false; }
    bool onPreComposition(nsecs_t) override { return true; }
    void abandon() override {}
    void setPerFrameData(const sp<const DisplayDevice>& displayDevice) override;
    void setDefaultBufferSize(uint32_t /*w*/, uint32_t /*h*/) override {}
    bool shouldPresentNow(const DispSync& /*dispSync*/) const override { return false; }
    bool onPostComposition(const std::shared_ptr<FenceTime>& /*glDoneFence*/,
                           const std::shared_ptr<FenceTime>& /*presentFence*/,
                           const CompositorTiming& /*compositorTiming*/) override {
        return false;
    }
    void setTransformHint(uint32_t /*orientation*/) const override {}
    std::vector<OccupancyTracker::Segment> getOccupancyHistory(bool /*forceFlush*/) override {
        return {};
    }
    bool getTransformToDisplayInverse() const override { return false; }
};

// ---------------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_COLOR_LAYER_H
