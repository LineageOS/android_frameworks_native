/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "BufferLayerConsumer.h"
#include "Client.h"
#include "Layer.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/HWComposerBufferCache.h"
#include "FrameTracker.h"
#include "LayerVector.h"
#include "MonitoredProducer.h"
#include "SurfaceFlinger.h"

#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <renderengine/Mesh.h>
#include <renderengine/Texture.h>
#include <ui/FrameStats.h>
#include <ui/GraphicBuffer.h>
#include <ui/PixelFormat.h>
#include <ui/Region.h>

#include <utils/RefBase.h>
#include <utils/String8.h>
#include <utils/Timers.h>

#include <system/window.h> // For NATIVE_WINDOW_SCALING_MODE_FREEZE

#include <stdint.h>
#include <sys/types.h>
#include <list>

namespace android {

class BufferLayer : public Layer {
public:
    explicit BufferLayer(const LayerCreationArgs& args);
    ~BufferLayer() override;

    // -----------------------------------------------------------------------
    // Overriden from Layer
    // -----------------------------------------------------------------------
public:
    // If we have received a new buffer this frame, we will pass its surface
    // damage down to hardware composer. Otherwise, we must send a region with
    // one empty rect.
    void useSurfaceDamage() override;
    void useEmptyDamage() override;

    // getTypeId - Provide unique string for each class type in the Layer
    // hierarchy
    const char* getTypeId() const override { return "BufferLayer"; }

    bool isOpaque(const Layer::State& s) const override;

    // isVisible - true if this layer is visible, false otherwise
    bool isVisible() const override EXCLUDES(mStateMutex);

    // isFixedSize - true if content has a fixed size
    bool isFixedSize() const override;

    // onDraw - draws the surface.
    void onDraw(const RenderArea& renderArea, const Region& clip,
                bool useIdentityTransform) override;

    bool isHdrY410() const override;

    void setPerFrameData(DisplayId displayId, const ui::Transform& transform, const Rect& viewport,
                         int32_t supportedPerFrameMetadata) override;

    bool onPreComposition(nsecs_t refreshStartTime) override;
    bool onPostComposition(const std::optional<DisplayId>& displayId,
                           const std::shared_ptr<FenceTime>& glDoneFence,
                           const std::shared_ptr<FenceTime>& presentFence,
                           const CompositorTiming& compositorTiming) override EXCLUDES(mStateMutex);

    // latchBuffer - called each time the screen is redrawn and returns whether
    // the visible regions need to be recomputed (this is a fairly heavy
    // operation, so this should be set only if needed). Typically this is used
    // to figure out if the content or size of a surface has changed.
    // If there was a GL composition step rendering the previous frame, then
    // releaseFence will be populated with a native fence that fires when
    // composition has completed.
    Region latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime,
                       const sp<Fence>& releaseFence) override EXCLUDES(mStateMutex);

    bool isBufferLatched() const override { return mRefreshPending; }

    void notifyAvailableFrames() override;

    bool hasReadyFrame() const override EXCLUDES(mStateMutex);

    // Returns the current scaling mode, unless mOverrideScalingMode
    // is set, in which case, it returns mOverrideScalingMode
    uint32_t getEffectiveScalingMode() const override;
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Functions that must be implemented by derived classes
    // -----------------------------------------------------------------------
private:
    virtual bool fenceHasSignaled() const EXCLUDES(mStateMutex) = 0;

    virtual nsecs_t getDesiredPresentTime() = 0;
    std::shared_ptr<FenceTime> getCurrentFenceTime() const EXCLUDES(mStateMutex) {
        Mutex::Autolock lock(mStateMutex);
        return getCurrentFenceTimeLocked();
    }

    virtual std::shared_ptr<FenceTime> getCurrentFenceTimeLocked() const REQUIRES(mStateMutex) = 0;

    virtual void getDrawingTransformMatrix(float *matrix) = 0;
    virtual uint32_t getDrawingTransform() const REQUIRES(mStateMutex) = 0;
    virtual ui::Dataspace getDrawingDataSpace() const REQUIRES(mStateMutex) = 0;
    virtual Rect getDrawingCrop() const REQUIRES(mStateMutex) = 0;
    virtual uint32_t getDrawingScalingMode() const = 0;
    virtual Region getDrawingSurfaceDamage() const EXCLUDES(mStateMutex) = 0;
    virtual const HdrMetadata& getDrawingHdrMetadata() const EXCLUDES(mStateMutex) = 0;
    virtual int getDrawingApi() const EXCLUDES(mStateMutex) = 0;
    virtual PixelFormat getPixelFormat() const = 0;

    virtual uint64_t getFrameNumber() const = 0;

    virtual bool getAutoRefresh() const = 0;
    virtual bool getSidebandStreamChanged() const = 0;

    virtual std::optional<Region> latchSidebandStream(bool& recomputeVisibleRegions)
            EXCLUDES(mStateMutex) = 0;

    virtual bool hasFrameUpdateLocked() const REQUIRES(mStateMutex) = 0;

    virtual void setFilteringEnabled(bool enabled) = 0;

    virtual status_t bindTextureImage() EXCLUDES(mStateMutex) = 0;
    virtual status_t updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime,
                                    const sp<Fence>& flushFence) REQUIRES(mStateMutex) = 0;

    virtual status_t updateActiveBuffer() REQUIRES(mStateMutex) = 0;
    virtual status_t updateFrameNumber(nsecs_t latchTime) = 0;

    virtual void setHwcLayerBuffer(DisplayId displayId) EXCLUDES(mStateMutex) = 0;

    // -----------------------------------------------------------------------

public:
    // isProtected - true if the layer may contain protected content in the
    // GRALLOC_USAGE_PROTECTED sense.
    bool isProtected() const;

protected:
    // Loads the corresponding system property once per process
    static bool latchUnsignaledBuffers();

    // Check all of the local sync points to ensure that all transactions
    // which need to have been applied prior to the frame which is about to
    // be latched have signaled
    bool allTransactionsSignaled() REQUIRES(mStateMutex);

    static bool getOpacityForFormat(uint32_t format);

    bool hasFrameUpdate() const EXCLUDES(mStateMutex) {
        Mutex::Autolock lock(mStateMutex);
        return hasFrameUpdateLocked();
    }

    // from GLES
    const uint32_t mTextureName;

private:
    // needsLinearFiltering - true if this surface's state requires filtering
    bool needsFiltering(const RenderArea& renderArea) const;

    // drawing
    void drawWithOpenGL(const RenderArea& renderArea, bool useIdentityTransform) const
            EXCLUDES(mStateMutex);

    uint64_t getHeadFrameNumber() const EXCLUDES(mStateMutex);

    uint64_t getHeadFrameNumberLocked() const REQUIRES(mStateMutex);

    uint32_t mCurrentScalingMode{NATIVE_WINDOW_SCALING_MODE_FREEZE};

    // main thread.
    bool mBufferLatched{false}; // TODO: Use mActiveBuffer?

    // The texture used to draw the layer in GLES composition mode
    mutable renderengine::Texture mTexture;

    bool mRefreshPending{false};

    Rect getBufferSize(const State& s) const override REQUIRES(mStateMutex);
};

} // namespace android
