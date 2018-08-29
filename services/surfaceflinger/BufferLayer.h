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

#include <stdint.h>
#include <sys/types.h>
#include <list>

namespace android {

class BufferLayer : public Layer {
public:
    BufferLayer(SurfaceFlinger* flinger, const sp<Client>& client, const String8& name, uint32_t w,
                uint32_t h, uint32_t flags);

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
    bool isVisible() const override;

    // isFixedSize - true if content has a fixed size
    bool isFixedSize() const override;

    // onDraw - draws the surface.
    void onDraw(const RenderArea& renderArea, const Region& clip,
                bool useIdentityTransform) override;

    bool isHdrY410() const override;

    void setPerFrameData(const sp<const DisplayDevice>& displayDevice) override;

    bool onPreComposition(nsecs_t refreshStartTime) override;
    bool onPostComposition(const std::shared_ptr<FenceTime>& glDoneFence,
                           const std::shared_ptr<FenceTime>& presentFence,
                           const CompositorTiming& compositorTiming) override;

    // latchBuffer - called each time the screen is redrawn and returns whether
    // the visible regions need to be recomputed (this is a fairly heavy
    // operation, so this should be set only if needed). Typically this is used
    // to figure out if the content or size of a surface has changed.
    Region latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime) override;

    bool isBufferLatched() const override { return mRefreshPending; }

    void notifyAvailableFrames() override;

    bool hasReadyFrame() const override;

    // Returns the current scaling mode, unless mOverrideScalingMode
    // is set, in which case, it returns mOverrideScalingMode
    uint32_t getEffectiveScalingMode() const override;
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Functions that must be implemented by derived classes
    // -----------------------------------------------------------------------
private:
    virtual bool fenceHasSignaled() const = 0;

    virtual nsecs_t getDesiredPresentTime() = 0;
    virtual std::shared_ptr<FenceTime> getCurrentFenceTime() const = 0;

    virtual void getDrawingTransformMatrix(float *matrix) = 0;
    virtual uint32_t getDrawingTransform() const = 0;
    virtual ui::Dataspace getDrawingDataSpace() const = 0;
    virtual Rect getDrawingCrop() const = 0;
    virtual uint32_t getDrawingScalingMode() const = 0;
    virtual Region getDrawingSurfaceDamage() const = 0;
    virtual const HdrMetadata& getDrawingHdrMetadata() const = 0;
    virtual int getDrawingApi() const = 0;
    virtual PixelFormat getPixelFormat() const = 0;

    virtual uint64_t getFrameNumber() const = 0;

    virtual bool getAutoRefresh() const = 0;
    virtual bool getSidebandStreamChanged() const = 0;

    virtual std::optional<Region> latchSidebandStream(bool& recomputeVisibleRegions) = 0;

    virtual bool hasDrawingBuffer() const = 0;

    virtual void setFilteringEnabled(bool enabled) = 0;

    virtual status_t bindTextureImage() const = 0;
    virtual status_t updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime) = 0;

    virtual status_t updateActiveBuffer() = 0;
    virtual status_t updateFrameNumber(nsecs_t latchTime) = 0;

    virtual void setHwcLayerBuffer(const sp<const DisplayDevice>& display) = 0;

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
    bool allTransactionsSignaled();

    static bool getOpacityForFormat(uint32_t format);

    // from GLES
    const uint32_t mTextureName;

private:
    // needsLinearFiltering - true if this surface's state requires filtering
    bool needsFiltering(const RenderArea& renderArea) const;

    // drawing
    void drawWithOpenGL(const RenderArea& renderArea, bool useIdentityTransform) const;

    uint64_t getHeadFrameNumber() const;

    uint32_t mCurrentScalingMode;

    // main thread.
    bool mBufferLatched; // TODO: Use mActiveBuffer?

    // The texture used to draw the layer in GLES composition mode
    mutable renderengine::Texture mTexture;

    bool mRefreshPending;
};

} // namespace android
