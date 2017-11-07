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

#include "Layer.h"
#include "Client.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/HWComposerBufferCache.h"
#include "FrameTracker.h"
#include "LayerVector.h"
#include "MonitoredProducer.h"
#include "RenderEngine/Mesh.h"
#include "RenderEngine/Texture.h"
#include "SurfaceFlinger.h"
#include "SurfaceFlingerConsumer.h"
#include "Transform.h"

#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>

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

/*
 * A new BufferQueue and a new SurfaceFlingerConsumer are created when the
 * BufferLayer is first referenced.
 *
 * This also implements onFrameAvailable(), which notifies SurfaceFlinger
 * that new data has arrived.
 */
class BufferLayer : public Layer, public SurfaceFlingerConsumer::ContentsChangedListener {
public:
    BufferLayer(SurfaceFlinger* flinger, const sp<Client>& client, const String8& name, uint32_t w,
                uint32_t h, uint32_t flags);

    ~BufferLayer() override;

    // -----------------------------------------------------------------------
    // Overriden from Layer
    // -----------------------------------------------------------------------

    /*
     * getTypeId - Provide unique string for each class type in the Layer
     * hierarchy
     */
    const char* getTypeId() const override { return "BufferLayer"; }

    /*
     * isProtected - true if the layer may contain protected content in the
     * GRALLOC_USAGE_PROTECTED sense.
     */
    bool isProtected() const;

    /*
     * isVisible - true if this layer is visible, false otherwise
     */
    bool isVisible() const override;

    /*
     * isFixedSize - true if content has a fixed size
     */
    bool isFixedSize() const override;

    // the this layer's size and format
    status_t setBuffers(uint32_t w, uint32_t h, PixelFormat format, uint32_t flags);

    /*
     * onDraw - draws the surface.
     */
    void onDraw(const RenderArea& renderArea, const Region& clip,
                bool useIdentityTransform) const override;

    bool onPreComposition(nsecs_t refreshStartTime) override;

#ifdef USE_HWC2
    // If a buffer was replaced this frame, release the former buffer
    void releasePendingBuffer(nsecs_t dequeueReadyTime);
#endif

    /*
     * latchBuffer - called each time the screen is redrawn and returns whether
     * the visible regions need to be recomputed (this is a fairly heavy
     * operation, so this should be set only if needed). Typically this is used
     * to figure out if the content or size of a surface has changed.
     */
    Region latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime) override;
    bool isBufferLatched() const override { return mRefreshPending; }

#ifdef USE_HWC2
    void setPerFrameData(const sp<const DisplayDevice>& displayDevice);
#else
    void setPerFrameData(const sp<const DisplayDevice>& hw, HWComposer::HWCLayerInterface& layer);
#endif
    bool isOpaque(const Layer::State& s) const override;

private:
    void onFirstRef() override;

    // Interface implementation for
    // SurfaceFlingerConsumer::ContentsChangedListener
    void onFrameAvailable(const BufferItem& item) override;
    void onFrameReplaced(const BufferItem& item) override;
    void onSidebandStreamChanged() override;

    // needsLinearFiltering - true if this surface's state requires filtering
    bool needsFiltering(const RenderArea& renderArea) const;

    static bool getOpacityForFormat(uint32_t format);

    // drawing
    void drawWithOpenGL(const RenderArea& renderArea,
            bool useIdentityTransform) const;

    // Temporary - Used only for LEGACY camera mode.
    uint32_t getProducerStickyTransform() const;

    // Loads the corresponding system property once per process
    static bool latchUnsignaledBuffers();

    uint64_t getHeadFrameNumber() const;
    bool headFenceHasSignaled() const;

    // Returns the current scaling mode, unless mOverrideScalingMode
    // is set, in which case, it returns mOverrideScalingMode
    uint32_t getEffectiveScalingMode() const override;

public:
    void notifyAvailableFrames() override;

    PixelFormat getPixelFormat() const override { return mFormat; }
    sp<IGraphicBufferProducer> getProducer() const;

private:
    // Check all of the local sync points to ensure that all transactions
    // which need to have been applied prior to the frame which is about to
    // be latched have signaled
    bool allTransactionsSignaled();
    sp<IGraphicBufferProducer> mProducer;

    // constants
    uint32_t mTextureName; // from GLES
    PixelFormat mFormat;

    // main thread
    uint32_t mCurrentScalingMode;
    bool mBufferLatched = false;   // TODO: Use mActiveBuffer?
    uint64_t mPreviousFrameNumber; // Only accessed on the main thread.
    // The texture used to draw the layer in GLES composition mode
    mutable Texture mTexture;

    bool mUpdateTexImageFailed; // This is only accessed on the main thread.
    bool mRefreshPending;
};

} // namespace android
