/*
 * Copyright 2016 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "SurfaceInterceptor"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "Layer.h"
#include "SurfaceFlinger.h"
#include "SurfaceInterceptor.h"

#include <cutils/log.h>

#include <utils/Trace.h>

#include <fstream>

namespace android {

// ----------------------------------------------------------------------------

void SurfaceInterceptor::enable(const SortedVector<sp<Layer>>& layers) {
    ATRACE_CALL();
    if (mEnabled) {
        return;
    }
    mEnabled = true;
    saveExistingLayers(layers);
}

void SurfaceInterceptor::disable() {
    ATRACE_CALL();
    if (!mEnabled) {
        return;
    }
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    mEnabled = false;
    status_t err(writeProtoFileLocked());
    ALOGE_IF(err == PERMISSION_DENIED, "Could not save the proto file! Permission denied");
    ALOGE_IF(err == NOT_ENOUGH_DATA, "Could not save the proto file! There are missing fields");
    mTrace.Clear();
}

void SurfaceInterceptor::saveExistingLayers(const SortedVector<sp<Layer>>& layers) {
    ATRACE_CALL();
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    for (const auto& layer : layers) {
        saveLayerCreateLocked(layer);
        saveInitialLayerStateLocked(layer);
    }
}

void SurfaceInterceptor::saveInitialLayerStateLocked(const sp<const Layer>& layer) {
    ATRACE_CALL();
    if (layer == nullptr) {
        return;
    }
    Increment* increment(addTraceIncrementLocked());
    Transaction* transaction(increment->mutable_transaction());
    transaction->set_synchronous(layer->mTransactionFlags & BnSurfaceComposer::eSynchronous);
    transaction->set_animation(layer->mTransactionFlags & BnSurfaceComposer::eAnimation);

    const int32_t layerId(getLayerId(layer));
    addPositionLocked(transaction, layerId, layer->mCurrentState.active.transform.tx(),
            layer->mCurrentState.active.transform.ty());
    addDepthLocked(transaction, layerId, layer->mCurrentState.z);
    addSizeLocked(transaction, layerId, layer->mCurrentState.active.w,
            layer->mCurrentState.active.h);
    addAlphaLocked(transaction, layerId, layer->mCurrentState.alpha);
    addTransparentRegionLocked(transaction, layerId, layer->mCurrentState.activeTransparentRegion);
    addLayerStackLocked(transaction, layerId, layer->mCurrentState.layerStack);
    addCropLocked(transaction, layerId, layer->mCurrentState.crop);
    if (layer->mCurrentState.handle != NULL) {
        addDeferTransactionLocked(transaction, layerId, layer->mCurrentState.handle,
                layer->mCurrentState.frameNumber);
    }
    addFinalCropLocked(transaction, layerId, layer->mCurrentState.finalCrop);
    addOverrideScalingModeLocked(transaction, layerId, layer->getEffectiveScalingMode());
    addFlagsLocked(transaction, layerId, layer->mCurrentState.flags);
}

status_t SurfaceInterceptor::writeProtoFileLocked() {
    ATRACE_CALL();
    std::ofstream output(mOutputFileName, std::ios::out | std::ios::trunc | std::ios::binary);
    // SerializeToOstream returns false when it's missing required data or when it could not write
    if (!mTrace.IsInitialized()) {
        return NOT_ENOUGH_DATA;
    }
    if (!mTrace.SerializeToOstream(&output)) {
        return PERMISSION_DENIED;
    }
    return NO_ERROR;
}

void SurfaceInterceptor::setOutputFileName(const std::string& outputFileName) {
    mOutputFileName = outputFileName;
}

const sp<const Layer> SurfaceInterceptor::getLayer(const sp<const IBinder>& handle) {
    const auto layerHandle(static_cast<const Layer::Handle*>(handle.get()));
    const sp<const Layer> layer(layerHandle->owner.promote());
    // layer could be a nullptr at this point
    return layer;
}

const std::string SurfaceInterceptor::getLayerName(const sp<const Layer>& layer) {
    return layer->getName().string();
}

int32_t SurfaceInterceptor::getLayerId(const sp<const Layer>& layer) {
    return layer->sequence;
}

Increment* SurfaceInterceptor::addTraceIncrementLocked() {
    Increment* increment(mTrace.add_increment());
    increment->set_time_stamp(systemTime());
    return increment;
}

Change* SurfaceInterceptor::addChangeLocked(Transaction* transaction, int32_t layerId) {
    Change* change(transaction->add_change());
    change->set_id(layerId);
    return change;
}

void SurfaceInterceptor::setProtoRectLocked(Rectangle* protoRect, const Rect& rect) {
    protoRect->set_left(rect.left);
    protoRect->set_top(rect.top);
    protoRect->set_right(rect.right);
    protoRect->set_bottom(rect.bottom);
}

void SurfaceInterceptor::addPositionLocked(Transaction* transaction, int32_t layerId, float x,
        float y)
{
    Change* change(addChangeLocked(transaction, layerId));
    PositionChange* posChange(change->mutable_position());
    posChange->set_x(x);
    posChange->set_y(y);
}

void SurfaceInterceptor::addDepthLocked(Transaction* transaction, int32_t layerId, uint32_t z) {
    Change* change(addChangeLocked(transaction, layerId));
    LayerChange* depthChange(change->mutable_layer());
    depthChange->set_layer(z);
}

void SurfaceInterceptor::addSizeLocked(Transaction* transaction, int32_t layerId, uint32_t w,
        uint32_t h)
{
    Change* change(addChangeLocked(transaction, layerId));
    SizeChange* sizeChange(change->mutable_size());
    sizeChange->set_w(w);
    sizeChange->set_h(h);
}

void SurfaceInterceptor::addAlphaLocked(Transaction* transaction, int32_t layerId, float alpha) {
    Change* change(addChangeLocked(transaction, layerId));
    AlphaChange* alphaChange(change->mutable_alpha());
    alphaChange->set_alpha(alpha);
}

void SurfaceInterceptor::addMatrixLocked(Transaction* transaction, int32_t layerId,
        const layer_state_t::matrix22_t& matrix)
{
    Change* change(addChangeLocked(transaction, layerId));
    MatrixChange* matrixChange(change->mutable_matrix());
    matrixChange->set_dsdx(matrix.dsdx);
    matrixChange->set_dtdx(matrix.dtdx);
    matrixChange->set_dsdy(matrix.dsdy);
    matrixChange->set_dtdy(matrix.dtdy);
}

void SurfaceInterceptor::addTransparentRegionLocked(Transaction* transaction, int32_t layerId,
        const Region& transRegion)
{
    Change* change(addChangeLocked(transaction, layerId));
    TransparentRegionHintChange* transparentChange(change->mutable_transparent_region_hint());

    for (const auto& rect : transRegion) {
        Rectangle* protoRect(transparentChange->add_region());
        setProtoRectLocked(protoRect, rect);
    }
}

void SurfaceInterceptor::addFlagsLocked(Transaction* transaction, int32_t layerId, uint8_t flags) {
    // There can be multiple flags changed
    if (flags & layer_state_t::eLayerHidden) {
        Change* change(addChangeLocked(transaction, layerId));
        HiddenFlagChange* flagChange(change->mutable_hidden_flag());
        flagChange->set_hidden_flag(true);
    }
    if (flags & layer_state_t::eLayerOpaque) {
        Change* change(addChangeLocked(transaction, layerId));
        OpaqueFlagChange* flagChange(change->mutable_opaque_flag());
        flagChange->set_opaque_flag(true);
    }
    if (flags & layer_state_t::eLayerSecure) {
        Change* change(addChangeLocked(transaction, layerId));
        SecureFlagChange* flagChange(change->mutable_secure_flag());
        flagChange->set_secure_flag(true);
    }
}

void SurfaceInterceptor::addLayerStackLocked(Transaction* transaction, int32_t layerId,
        uint32_t layerStack)
{
    Change* change(addChangeLocked(transaction, layerId));
    LayerStackChange* layerStackChange(change->mutable_layer_stack());
    layerStackChange->set_layer_stack(layerStack);
}

void SurfaceInterceptor::addCropLocked(Transaction* transaction, int32_t layerId,
        const Rect& rect)
{
    Change* change(addChangeLocked(transaction, layerId));
    CropChange* cropChange(change->mutable_crop());
    Rectangle* protoRect(cropChange->mutable_rectangle());
    setProtoRectLocked(protoRect, rect);
}

void SurfaceInterceptor::addFinalCropLocked(Transaction* transaction, int32_t layerId,
        const Rect& rect)
{
    Change* change(addChangeLocked(transaction, layerId));
    FinalCropChange* finalCropChange(change->mutable_final_crop());
    Rectangle* protoRect(finalCropChange->mutable_rectangle());
    setProtoRectLocked(protoRect, rect);
}

void SurfaceInterceptor::addDeferTransactionLocked(Transaction* transaction, int32_t layerId,
        const sp<const IBinder>& handle, uint64_t frameNumber)
{
    Change* change(addChangeLocked(transaction, layerId));
    const sp<const Layer> layer(getLayer(handle));
    if (layer == nullptr) {
        ALOGE("An existing layer could not be retrieved with the handle"
                " for the deferred transaction");
        return;
    }
    DeferredTransactionChange* deferTransaction(change->mutable_deferred_transaction());
    deferTransaction->set_layer_id(getLayerId(layer));
    deferTransaction->set_frame_number(frameNumber);
}

void SurfaceInterceptor::addOverrideScalingModeLocked(Transaction* transaction, int32_t layerId,
        int32_t overrideScalingMode)
{
    Change* change(addChangeLocked(transaction, layerId));
    OverrideScalingModeChange* overrideChange(change->mutable_override_scaling_mode());
    overrideChange->set_override_scaling_mode(overrideScalingMode);
}

void SurfaceInterceptor::addChangedPropertiesLocked(Transaction* transaction,
        const layer_state_t& state)
{
    const sp<const Layer> layer(getLayer(state.surface));
    if (layer == nullptr) {
        ALOGE("An existing layer could not be retrieved with the surface "
                "from the layer_state_t surface in the update transaction");
        return;
    }

    const int32_t layerId(getLayerId(layer));

    if (state.what & layer_state_t::ePositionChanged) {
        addPositionLocked(transaction, layerId, state.x, state.y);
    }
    if (state.what & layer_state_t::eLayerChanged) {
        addDepthLocked(transaction, layerId, state.z);
    }
    if (state.what & layer_state_t::eSizeChanged) {
        addSizeLocked(transaction, layerId, state.w, state.h);
    }
    if (state.what & layer_state_t::eAlphaChanged) {
        addAlphaLocked(transaction, layerId, state.alpha);
    }
    if (state.what & layer_state_t::eMatrixChanged) {
        addMatrixLocked(transaction, layerId, state.matrix);
    }
    if (state.what & layer_state_t::eTransparentRegionChanged) {
        addTransparentRegionLocked(transaction, layerId, state.transparentRegion);
    }
    if (state.what & layer_state_t::eFlagsChanged) {
        addFlagsLocked(transaction, layerId, state.flags);
    }
    if (state.what & layer_state_t::eLayerStackChanged) {
        addLayerStackLocked(transaction, layerId, state.layerStack);
    }
    if (state.what & layer_state_t::eCropChanged) {
        addCropLocked(transaction, layerId, state.crop);
    }
    if (state.what & layer_state_t::eDeferTransaction) {
        addDeferTransactionLocked(transaction, layerId, state.handle, state.frameNumber);
    }
    if (state.what & layer_state_t::eFinalCropChanged) {
        addFinalCropLocked(transaction, layerId, state.finalCrop);
    }
    if (state.what & layer_state_t::eOverrideScalingModeChanged) {
        addOverrideScalingModeLocked(transaction, layerId, state.overrideScalingMode);
    }
}

void SurfaceInterceptor::addUpdatedLayersLocked(Increment* increment, uint32_t flags,
        const Vector<ComposerState>& stateUpdates)
{
    Transaction* transaction(increment->mutable_transaction());
    transaction->set_synchronous(flags & BnSurfaceComposer::eSynchronous);
    transaction->set_animation(flags & BnSurfaceComposer::eAnimation);
    for (const auto& compState: stateUpdates) {
        addChangedPropertiesLocked(transaction, compState.state);
    }
}

void SurfaceInterceptor::addCreatedLayerLocked(Increment* increment, const sp<const Layer>& layer) {
    Create* create(increment->mutable_create());
    create->set_id(getLayerId(layer));
    create->set_name(getLayerName(layer));
    create->set_w(layer->mCurrentState.active.w);
    create->set_h(layer->mCurrentState.active.h);
}

void SurfaceInterceptor::addDeletedLayerLocked(Increment* increment, const sp<const Layer>& layer) {
    Delete* deleteLayer(increment->mutable_delete_());
    deleteLayer->set_id(getLayerId(layer));
}

void SurfaceInterceptor::addUpdatedBufferLocked(Increment* increment, const sp<const Layer>& layer,
        uint32_t width, uint32_t height, uint64_t frameNumber)
{
    BufferUpdate* update(increment->mutable_buffer_update());
    update->set_id(getLayerId(layer));
    update->set_w(width);
    update->set_h(height);
    update->set_frame_number(frameNumber);
}

void SurfaceInterceptor::addUpdatedVsyncLocked(Increment* increment, nsecs_t timestamp) {
    VSyncEvent* event(increment->mutable_vsync_event());
    event->set_when(timestamp);
}

void SurfaceInterceptor::saveLayerUpdates(const Vector<ComposerState>& stateUpdates,
        uint32_t flags)
{
    ATRACE_CALL();
    if (!mEnabled || stateUpdates.size() <= 0) {
        return;
    }
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    addUpdatedLayersLocked(addTraceIncrementLocked(), flags, stateUpdates);
}

void SurfaceInterceptor::saveLayerCreate(const sp<const Layer>& layer) {
    ATRACE_CALL();
    if (!mEnabled || layer == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    addCreatedLayerLocked(addTraceIncrementLocked(), layer);
}

void SurfaceInterceptor::saveLayerCreateLocked(const sp<const Layer>& layer) {
    if (!mEnabled || layer == nullptr) {
        return;
    }
    addCreatedLayerLocked(addTraceIncrementLocked(), layer);
}

void SurfaceInterceptor::saveLayerDelete(const sp<const Layer>& layer) {
    ATRACE_CALL();
    if (!mEnabled || layer == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    addDeletedLayerLocked(addTraceIncrementLocked(), layer);
}

void SurfaceInterceptor::saveBufferUpdate(const sp<const Layer>& layer, uint32_t width,
        uint32_t height, uint64_t frameNumber)
{
    ATRACE_CALL();
    if (!mEnabled || layer == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    addUpdatedBufferLocked(addTraceIncrementLocked(), layer, width, height, frameNumber);
}

void SurfaceInterceptor::saveVSyncEvent(nsecs_t timestamp) {
    if (!mEnabled) {
        return;
    }
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    addUpdatedVsyncLocked(addTraceIncrementLocked(), timestamp);
}

} // namespace android
