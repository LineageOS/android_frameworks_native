/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <sys/types.h>
#include <cstdint>
#include <list>
#include <stack>

#include <android/gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <renderengine/Image.h>
#include <renderengine/Mesh.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/Texture.h>
#include <system/window.h> // For NATIVE_WINDOW_SCALING_MODE_FREEZE
#include <ui/FrameStats.h>
#include <ui/GraphicBuffer.h>
#include <ui/PixelFormat.h>
#include <ui/Region.h>
#include <utils/RefBase.h>
#include <utils/String8.h>
#include <utils/Timers.h>

#include "Client.h"
#include "DisplayHardware/HWComposer.h"
#include "FrameTimeline.h"
#include "FrameTracker.h"
#include "HwcSlotGenerator.h"
#include "Layer.h"
#include "LayerVector.h"
#include "SurfaceFlinger.h"

namespace android {

class SlotGenerationTest;

class BufferStateLayer : public Layer {
public:
    explicit BufferStateLayer(const LayerCreationArgs&);

    ~BufferStateLayer() override;

    // Implements Layer.
    sp<compositionengine::LayerFE> getCompositionEngineLayerFE() const override;
    compositionengine::LayerFECompositionState* editCompositionState() override;

    // If we have received a new buffer this frame, we will pass its surface
    // damage down to hardware composer. Otherwise, we must send a region with
    // one empty rect.
    void useSurfaceDamage() override;
    void useEmptyDamage() override;

    bool isOpaque(const Layer::State& s) const override;
    bool canReceiveInput() const override;

    // isVisible - true if this layer is visible, false otherwise
    bool isVisible() const override;

    // isProtected - true if the layer may contain protected content in the
    // GRALLOC_USAGE_PROTECTED sense.
    bool isProtected() const override;

    bool usesSourceCrop() const override { return true; }

    bool isHdrY410() const override;

    void onPostComposition(const DisplayDevice*, const std::shared_ptr<FenceTime>& glDoneFence,
                           const std::shared_ptr<FenceTime>& presentFence,
                           const CompositorTiming&) override;

    // latchBuffer - called each time the screen is redrawn and returns whether
    // the visible regions need to be recomputed (this is a fairly heavy
    // operation, so this should be set only if needed). Typically this is used
    // to figure out if the content or size of a surface has changed.
    bool latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime) override;
    bool hasReadyFrame() const override;

    // Calls latchBuffer if the buffer has a frame queued and then releases the buffer.
    // This is used if the buffer is just latched and releases to free up the buffer
    // and will not be shown on screen.
    // Should only be called on the main thread.
    void latchAndReleaseBuffer() override;

    bool getTransformToDisplayInverse() const override;

    Rect getBufferCrop() const override;

    uint32_t getBufferTransform() const override;

    ui::Dataspace getDataSpace() const override;

    sp<GraphicBuffer> getBuffer() const override;
    const std::shared_ptr<renderengine::ExternalTexture>& getExternalTexture() const override;

    ui::Transform::RotationFlags getTransformHint() const override { return mTransformHint; }

    // Implements Layer.
    const char* getType() const override { return "BufferStateLayer"; }

    void onLayerDisplayed(ftl::SharedFuture<FenceResult>) override;

    void releasePendingBuffer(nsecs_t dequeueReadyTime) override;

    Region getActiveTransparentRegion(const Layer::State& s) const override {
        return s.transparentRegionHint;
    }
    Rect getCrop(const Layer::State& s) const;

    bool setTransform(uint32_t transform) override;
    bool setTransformToDisplayInverse(bool transformToDisplayInverse) override;
    bool setCrop(const Rect& crop) override;
    bool setBuffer(std::shared_ptr<renderengine::ExternalTexture>& /* buffer */,
                   const BufferData& bufferData, nsecs_t postTime, nsecs_t desiredPresentTime,
                   bool isAutoTimestamp, std::optional<nsecs_t> dequeueTime,
                   const FrameTimelineInfo& info) override;
    bool setDataspace(ui::Dataspace dataspace) override;
    bool setHdrMetadata(const HdrMetadata& hdrMetadata) override;
    bool setSurfaceDamageRegion(const Region& surfaceDamage) override;
    bool setApi(int32_t api) override;
    bool setSidebandStream(const sp<NativeHandle>& sidebandStream) override;
    bool setTransactionCompletedListeners(const std::vector<sp<CallbackHandle>>& handles) override;
    bool setPosition(float /*x*/, float /*y*/) override;
    bool setMatrix(const layer_state_t::matrix22_t& /*matrix*/);

    // Override to ignore legacy layer state properties that are not used by BufferStateLayer
    bool setSize(uint32_t /*w*/, uint32_t /*h*/) override { return false; }
    bool setTransparentRegionHint(const Region& transparent) override;

    // BufferStateLayers can return Rect::INVALID_RECT if the layer does not have a display frame
    // and its parent layer is not bounded
    Rect getBufferSize(const State& s) const override;
    FloatRect computeSourceBounds(const FloatRect& parentBounds) const override;
    void setAutoRefresh(bool autoRefresh) override;

    bool setBufferCrop(const Rect& bufferCrop) override;
    bool setDestinationFrame(const Rect& destinationFrame) override;
    bool updateGeometry() override;

    bool fenceHasSignaled() const;
    bool onPreComposition(nsecs_t) override;

    // See mPendingBufferTransactions
    void decrementPendingBufferCount();
    std::atomic<int32_t>* getPendingBufferCounter() override { return &mPendingBufferTransactions; }
    std::string getPendingBufferCounterName() override { return mBlastTransactionName; }

protected:
    void gatherBufferInfo();
    void onSurfaceFrameCreated(const std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame);
    ui::Transform getInputTransform() const override;
    Rect getInputBounds() const override;

    struct BufferInfo {
        nsecs_t mDesiredPresentTime;
        std::shared_ptr<FenceTime> mFenceTime;
        sp<Fence> mFence;
        uint32_t mTransform{0};
        ui::Dataspace mDataspace{ui::Dataspace::UNKNOWN};
        Rect mCrop;
        uint32_t mScaleMode{NATIVE_WINDOW_SCALING_MODE_FREEZE};
        Region mSurfaceDamage;
        HdrMetadata mHdrMetadata;
        int mApi;
        PixelFormat mPixelFormat{PIXEL_FORMAT_NONE};
        bool mTransformToDisplayInverse{false};

        std::shared_ptr<renderengine::ExternalTexture> mBuffer;
        uint64_t mFrameNumber;
        int mBufferSlot{BufferQueue::INVALID_BUFFER_SLOT};

        bool mFrameLatencyNeeded{false};
    };

    BufferInfo mBufferInfo;

    std::optional<compositionengine::LayerFE::LayerSettings> prepareClientComposition(
            compositionengine::LayerFE::ClientCompositionTargetSettings&) override;

    /*
     * compositionengine::LayerFE overrides
     */
    const compositionengine::LayerFECompositionState* getCompositionState() const override;
    void preparePerFrameCompositionState() override;

    static bool getOpacityForFormat(PixelFormat format);

    // from graphics API
    const uint32_t mTextureName;
    ui::Dataspace translateDataspace(ui::Dataspace dataspace);
    void setInitialValuesForClone(const sp<Layer>& clonedFrom);
    void updateCloneBufferInfo() override;
    uint64_t mPreviousFrameNumber = 0;

    void setTransformHint(ui::Transform::RotationFlags displayTransformHint) override;

    // Transform hint provided to the producer. This must be accessed holding
    // the mStateLock.
    ui::Transform::RotationFlags mTransformHint = ui::Transform::ROT_0;

    bool getAutoRefresh() const { return mDrawingState.autoRefresh; }
    bool getSidebandStreamChanged() const { return mSidebandStreamChanged; }

    std::atomic<bool> mSidebandStreamChanged{false};

private:
    friend class SlotGenerationTest;
    friend class TransactionFrameTracerTest;
    friend class TransactionSurfaceFrameTest;

    // We generate InputWindowHandles for all non-cursor buffered layers regardless of whether they
    // have an InputChannel. This is to enable the InputDispatcher to do PID based occlusion
    // detection.
    bool needsInputInfo() const override { return !mPotentialCursor; }

    // Returns true if this layer requires filtering
    bool needsFiltering(const DisplayDevice*) const override;
    bool needsFilteringForScreenshots(const DisplayDevice*,
                                      const ui::Transform& inverseParentTransform) const override;

    PixelFormat getPixelFormat() const;

    // Computes the transform matrix using the setFilteringEnabled to determine whether the
    // transform matrix should be computed for use with bilinear filtering.
    void getDrawingTransformMatrix(bool filteringEnabled, float outMatrix[16]);

    std::unique_ptr<compositionengine::LayerFECompositionState> mCompositionState;

    inline void tracePendingBufferCount(int32_t pendingBuffers);

    bool updateFrameEventHistory(const sp<Fence>& acquireFence, nsecs_t postedTime,
                                 nsecs_t requestedPresentTime);

    // Latch sideband stream and returns true if the dirty region should be updated.
    bool latchSidebandStream(bool& recomputeVisibleRegions);

    bool hasFrameUpdate() const;

    void updateTexImage(nsecs_t latchTime);

    sp<Layer> createClone() override;

    // Crop that applies to the buffer
    Rect computeBufferCrop(const State& s);

    bool willPresentCurrentTransaction() const;

    // Returns true if the transformed buffer size does not match the layer size and we need
    // to apply filtering.
    bool bufferNeedsFiltering() const;

    bool simpleBufferUpdate(const layer_state_t& s) const override;

    void callReleaseBufferCallback(const sp<ITransactionCompletedListener>& listener,
                                   const sp<GraphicBuffer>& buffer, uint64_t framenumber,
                                   const sp<Fence>& releaseFence,
                                   uint32_t currentMaxAcquiredBufferCount);

    ReleaseCallbackId mPreviousReleaseCallbackId = ReleaseCallbackId::INVALID_ID;
    uint64_t mPreviousReleasedFrameNumber = 0;

    uint64_t mPreviousBarrierFrameNumber = 0;

    bool mReleasePreviousBuffer = false;

    // Stores the last set acquire fence signal time used to populate the callback handle's acquire
    // time.
    std::variant<nsecs_t, sp<Fence>> mCallbackHandleAcquireTimeOrFence = -1;

    std::deque<std::shared_ptr<android::frametimeline::SurfaceFrame>> mPendingJankClassifications;
    // An upper bound on the number of SurfaceFrames in the pending classifications deque.
    static constexpr int kPendingClassificationMaxSurfaceFrames = 25;

    const std::string mBlastTransactionName{"BufferTX - " + mName};
    // This integer is incremented everytime a buffer arrives at the server for this layer,
    // and decremented when a buffer is dropped or latched. When changed the integer is exported
    // to systrace with ATRACE_INT and mBlastTransactionName. This way when debugging perf it is
    // possible to see when a buffer arrived at the server, and in which frame it latched.
    //
    // You can understand the trace this way:
    //     - If the integer increases, a buffer arrived at the server.
    //     - If the integer decreases in latchBuffer, that buffer was latched
    //     - If the integer decreases in setBuffer or doTransaction, a buffer was dropped
    std::atomic<int32_t> mPendingBufferTransactions{0};

    // Contains requested position and matrix updates. This will be applied if the client does
    // not specify a destination frame.
    ui::Transform mRequestedTransform;

    sp<HwcSlotGenerator> mHwcSlotGenerator;
};

} // namespace android
