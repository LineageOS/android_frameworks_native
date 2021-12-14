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

#ifndef ANDROID_SURFACEINTERCEPTOR_H
#define ANDROID_SURFACEINTERCEPTOR_H

#include <frameworks/native/cmds/surfacereplayer/proto/src/trace.pb.h>

#include <mutex>

#include <binder/IBinder.h>

#include <gui/LayerState.h>

#include <utils/KeyedVector.h>
#include <utils/SortedVector.h>
#include <utils/StrongPointer.h>
#include <utils/Vector.h>

#include "DisplayDevice.h"

namespace android {

class BufferItem;
class Layer;
class SurfaceFlinger;
struct ComposerState;
struct DisplayDeviceState;
struct DisplayState;
struct layer_state_t;
using Transaction = surfaceflinger::Transaction;
using Trace = surfaceflinger::Trace;
using Rectangle = surfaceflinger::Rectangle;
using SurfaceChange = surfaceflinger::SurfaceChange;
using Increment = surfaceflinger::Increment;
using DisplayChange = surfaceflinger::DisplayChange;

constexpr auto DEFAULT_FILENAME = "/data/misc/wmtrace/transaction_trace.pb";

class SurfaceInterceptor : public IBinder::DeathRecipient {
public:
    virtual ~SurfaceInterceptor();

    // Both vectors are used to capture the current state of SF as the initial snapshot in the trace
    virtual void enable(const SortedVector<sp<Layer>>& layers,
                        const DefaultKeyedVector<wp<IBinder>, DisplayDeviceState>& displays) = 0;
    virtual void disable() = 0;
    virtual bool isEnabled() = 0;

    virtual void addTransactionTraceListener(
            const sp<gui::ITransactionTraceListener>& listener) = 0;
    virtual void binderDied(const wp<IBinder>& who) = 0;

    // Intercept display and surface transactions
    virtual void saveTransaction(
            const Vector<ComposerState>& stateUpdates,
            const DefaultKeyedVector<wp<IBinder>, DisplayDeviceState>& displays,
            const Vector<DisplayState>& changedDisplays, uint32_t flags, int originPid,
            int originUid, uint64_t transactionId) = 0;

    // Intercept surface data
    virtual void saveSurfaceCreation(const sp<const Layer>& layer) = 0;
    virtual void saveSurfaceDeletion(const sp<const Layer>& layer) = 0;
    virtual void saveBufferUpdate(int32_t layerId, uint32_t width, uint32_t height,
                                  uint64_t frameNumber) = 0;

    // Intercept display data
    virtual void saveDisplayCreation(const DisplayDeviceState& info) = 0;
    virtual void saveDisplayDeletion(int32_t sequenceId) = 0;
    virtual void savePowerModeUpdate(int32_t sequenceId, int32_t mode) = 0;
    virtual void saveVSyncEvent(nsecs_t timestamp) = 0;
};

namespace impl {

/*
 * SurfaceInterceptor intercepts and stores incoming streams of window
 * properties on SurfaceFlinger.
 */
class SurfaceInterceptor final : public android::SurfaceInterceptor {
public:
    SurfaceInterceptor() = default;
    ~SurfaceInterceptor() override = default;

    // Both vectors are used to capture the current state of SF as the initial snapshot in the trace
    void enable(const SortedVector<sp<Layer>>& layers,
                const DefaultKeyedVector<wp<IBinder>, DisplayDeviceState>& displays) override;
    void disable() override;
    bool isEnabled() override;

    void addTransactionTraceListener(const sp<gui::ITransactionTraceListener>& listener) override;
    void binderDied(const wp<IBinder>& who) override;

    // Intercept display and surface transactions
    void saveTransaction(const Vector<ComposerState>& stateUpdates,
                         const DefaultKeyedVector<wp<IBinder>, DisplayDeviceState>& displays,
                         const Vector<DisplayState>& changedDisplays, uint32_t flags, int originPid,
                         int originUid, uint64_t transactionId) override;

    // Intercept surface data
    void saveSurfaceCreation(const sp<const Layer>& layer) override;
    void saveSurfaceDeletion(const sp<const Layer>& layer) override;
    void saveBufferUpdate(int32_t layerId, uint32_t width, uint32_t height,
                          uint64_t frameNumber) override;

    // Intercept display data
    void saveDisplayCreation(const DisplayDeviceState& info) override;
    void saveDisplayDeletion(int32_t sequenceId) override;
    void savePowerModeUpdate(int32_t sequenceId, int32_t mode) override;
    void saveVSyncEvent(nsecs_t timestamp) override;

private:
    // The creation increments of Surfaces and Displays do not contain enough information to capture
    // the initial state of each object, so a transaction with all of the missing properties is
    // performed at the initial snapshot for each display and surface.
    void saveExistingDisplaysLocked(
            const DefaultKeyedVector< wp<IBinder>, DisplayDeviceState>& displays);
    void saveExistingSurfacesLocked(const SortedVector<sp<Layer>>& layers);
    void addInitialSurfaceStateLocked(Increment* increment, const sp<const Layer>& layer);
    void addInitialDisplayStateLocked(Increment* increment, const DisplayDeviceState& display);

    status_t writeProtoFileLocked();
    const sp<const Layer> getLayer(const wp<IBinder>& weakHandle) const;
    int32_t getLayerId(const sp<const Layer>& layer) const;
    int32_t getLayerIdFromWeakRef(const wp<const Layer>& layer) const;
    int32_t getLayerIdFromHandle(const sp<IBinder>& weakHandle) const;

    Increment* createTraceIncrementLocked();
    void addSurfaceCreationLocked(Increment* increment, const sp<const Layer>& layer);
    void addSurfaceDeletionLocked(Increment* increment, const sp<const Layer>& layer);
    void addBufferUpdateLocked(Increment* increment, int32_t layerId, uint32_t width,
            uint32_t height, uint64_t frameNumber);
    void addVSyncUpdateLocked(Increment* increment, nsecs_t timestamp);
    void addDisplayCreationLocked(Increment* increment, const DisplayDeviceState& info);
    void addDisplayDeletionLocked(Increment* increment, int32_t sequenceId);
    void addPowerModeUpdateLocked(Increment* increment, int32_t sequenceId, int32_t mode);

    // Add surface transactions to the trace
    SurfaceChange* createSurfaceChangeLocked(Transaction* transaction, int32_t layerId);
    void setProtoRectLocked(Rectangle* protoRect, const Rect& rect);
    void addPositionLocked(Transaction* transaction, int32_t layerId, float x, float y);
    void addDepthLocked(Transaction* transaction, int32_t layerId, uint32_t z);
    void addSizeLocked(Transaction* transaction, int32_t layerId, uint32_t w, uint32_t h);
    void addAlphaLocked(Transaction* transaction, int32_t layerId, float alpha);
    void addMatrixLocked(Transaction* transaction, int32_t layerId,
            const layer_state_t::matrix22_t& matrix);
    void addTransparentRegionLocked(Transaction* transaction, int32_t layerId,
            const Region& transRegion);
    void addFlagsLocked(Transaction* transaction, int32_t layerId, uint8_t flags, uint8_t mask);
    void addLayerStackLocked(Transaction* transaction, int32_t layerId, uint32_t layerStack);
    void addCropLocked(Transaction* transaction, int32_t layerId, const Rect& rect);
    void addCornerRadiusLocked(Transaction* transaction, int32_t layerId, float cornerRadius);
    void addBackgroundBlurRadiusLocked(Transaction* transaction, int32_t layerId,
                                       int32_t backgroundBlurRadius);
    void addBlurRegionsLocked(Transaction* transaction, int32_t layerId,
                              const std::vector<BlurRegion>& effectRegions);
    void addSurfaceChangesLocked(Transaction* transaction, const layer_state_t& state);
    void addTransactionLocked(Increment* increment, const Vector<ComposerState>& stateUpdates,
                              const DefaultKeyedVector<wp<IBinder>, DisplayDeviceState>& displays,
                              const Vector<DisplayState>& changedDisplays,
                              uint32_t transactionFlags, int originPid, int originUid,
                              uint64_t transactionId);
    void addReparentLocked(Transaction* transaction, int32_t layerId, int32_t parentId);
    void addRelativeParentLocked(Transaction* transaction, int32_t layerId, int32_t parentId,
                                 int z);
    void addShadowRadiusLocked(Transaction* transaction, int32_t layerId, float shadowRadius);
    void addTrustedOverlayLocked(Transaction* transaction, int32_t layerId, bool isTrustedOverlay);

    // Add display transactions to the trace
    DisplayChange* createDisplayChangeLocked(Transaction* transaction, int32_t sequenceId);
    void addDisplaySurfaceLocked(Transaction* transaction, int32_t sequenceId,
            const sp<const IGraphicBufferProducer>& surface);
    void addDisplayLayerStackLocked(Transaction* transaction, int32_t sequenceId,
            uint32_t layerStack);
    void addDisplaySizeLocked(Transaction* transaction, int32_t sequenceId, uint32_t w,
            uint32_t h);
    void addDisplayProjectionLocked(Transaction* transaction, int32_t sequenceId,
            int32_t orientation, const Rect& viewport, const Rect& frame);
    void addDisplayChangesLocked(Transaction* transaction,
            const DisplayState& state, int32_t sequenceId);

    // Add transaction origin to trace
    void setTransactionOriginLocked(Transaction* transaction, int32_t pid, int32_t uid);

    bool mEnabled {false};
    std::string mOutputFileName {DEFAULT_FILENAME};
    std::mutex mTraceMutex {};
    Trace mTrace {};
    std::mutex mListenersMutex;
    std::map<wp<IBinder>, sp<gui::ITransactionTraceListener>> mTraceToggledListeners
            GUARDED_BY(mListenersMutex);
};

} // namespace impl

} // namespace android

#endif // ANDROID_SURFACEINTERCEPTOR_H
