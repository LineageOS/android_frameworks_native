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

#include "BufferLayer.h"
#include "Layer.h"

#include <gui/GLConsumer.h>
#include <renderengine/Image.h>
#include <renderengine/RenderEngine.h>
#include <system/window.h>
#include <utils/String8.h>

namespace android {

class BufferStateLayer : public BufferLayer {
public:
    explicit BufferStateLayer(const LayerCreationArgs&);
    ~BufferStateLayer() override;

    // -----------------------------------------------------------------------
    // Interface implementation for Layer
    // -----------------------------------------------------------------------
    void onLayerDisplayed(const sp<Fence>& releaseFence) override;
    void setTransformHint(uint32_t orientation) const override;
    void releasePendingBuffer(nsecs_t dequeueReadyTime) override;

    bool shouldPresentNow(nsecs_t expectedPresentTime) const override;

    bool getTransformToDisplayInverse() const override;

    uint32_t doTransactionResize(uint32_t flags, Layer::State* /*stateToCommit*/) override {
        return flags;
    }
    void pushPendingState() override;
    bool applyPendingStates(Layer::State* stateToCommit) override;

    uint32_t getActiveWidth(const Layer::State& s) const override { return s.active.w; }
    uint32_t getActiveHeight(const Layer::State& s) const override { return s.active.h; }
    ui::Transform getActiveTransform(const Layer::State& s) const override {
        return s.active.transform;
    }
    Region getActiveTransparentRegion(const Layer::State& s) const override {
        return s.transparentRegionHint;
    }
    Rect getCrop(const Layer::State& s) const;

    bool setTransform(uint32_t transform) override;
    bool setTransformToDisplayInverse(bool transformToDisplayInverse) override;
    bool setCrop(const Rect& crop) override;
    bool setBuffer(const sp<GraphicBuffer>& buffer) override;
    bool setAcquireFence(const sp<Fence>& fence) override;
    bool setDataspace(ui::Dataspace dataspace) override;
    bool setHdrMetadata(const HdrMetadata& hdrMetadata) override;
    bool setSurfaceDamageRegion(const Region& surfaceDamage) override;
    bool setApi(int32_t api) override;
    bool setSidebandStream(const sp<NativeHandle>& sidebandStream) override;
    bool setTransactionCompletedListeners(const std::vector<sp<CallbackHandle>>& handles) override;

    bool setSize(uint32_t w, uint32_t h) override;
    bool setPosition(float x, float y, bool immediate) override;
    bool setTransparentRegionHint(const Region& transparent) override;
    bool setMatrix(const layer_state_t::matrix22_t& matrix,
                   bool allowNonRectPreservingTransforms) override;

    // Override to ignore legacy layer state properties that are not used by BufferStateLayer
    bool setCrop_legacy(const Rect& /*crop*/, bool /*immediate*/) override { return false; };
    void deferTransactionUntil_legacy(const sp<IBinder>& /*barrierHandle*/,
                                      uint64_t /*frameNumber*/) override {}
    void deferTransactionUntil_legacy(const sp<Layer>& /*barrierLayer*/,
                                      uint64_t /*frameNumber*/) override {}
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Interface implementation for BufferLayer
    // -----------------------------------------------------------------------
    bool fenceHasSignaled() const override;

private:
    nsecs_t getDesiredPresentTime() override;
    std::shared_ptr<FenceTime> getCurrentFenceTime() const override;

    void getDrawingTransformMatrix(float *matrix) override;
    uint32_t getDrawingTransform() const override;
    ui::Dataspace getDrawingDataSpace() const override;
    Rect getDrawingCrop() const override;
    uint32_t getDrawingScalingMode() const override;
    Region getDrawingSurfaceDamage() const override;
    const HdrMetadata& getDrawingHdrMetadata() const override;
    int getDrawingApi() const override;
    PixelFormat getPixelFormat() const override;

    uint64_t getFrameNumber() const override;

    bool getAutoRefresh() const override;
    bool getSidebandStreamChanged() const override;

    std::optional<Region> latchSidebandStream(bool& recomputeVisibleRegions) override;

    bool hasFrameUpdate() const override;

    void setFilteringEnabled(bool enabled) override;

    status_t bindTextureImage() override;
    status_t updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime,
                            const sp<Fence>& releaseFence) override;

    status_t updateActiveBuffer() override;
    status_t updateFrameNumber(nsecs_t latchTime) override;

    void setHwcLayerBuffer(DisplayId displayId) override;

private:
    void onFirstRef() override;
    bool willPresentCurrentTransaction() const;

    static const std::array<float, 16> IDENTITY_MATRIX;

    std::unique_ptr<renderengine::Image> mTextureImage;

    std::array<float, 16> mTransformMatrix{IDENTITY_MATRIX};

    std::atomic<bool> mSidebandStreamChanged{false};

    uint32_t mFrameNumber{0};

    sp<Fence> mPreviousReleaseFence;

    bool mCurrentStateModified = false;
    bool mReleasePreviousBuffer = false;
    nsecs_t mCallbackHandleAcquireTime = -1;

    // TODO(marissaw): support sticky transform for LEGACY camera mode
};

} // namespace android
