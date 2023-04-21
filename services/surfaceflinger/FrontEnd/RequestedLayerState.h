/*
 * Copyright 2022 The Android Open Source Project
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

#include <aidl/android/hardware/graphics/composer3/Composition.h>
#include <ftl/flags.h>
#include <gui/LayerState.h>
#include <renderengine/ExternalTexture.h>
#include "Scheduler/LayerInfo.h"

#include "LayerCreationArgs.h"
#include "TransactionState.h"

namespace android::surfaceflinger::frontend {

// Stores client requested states for a layer.
// This struct does not store any other states or states pertaining to
// other layers. Links to other layers that are part of the client
// requested state such as parent are translated to layer id so
// we can avoid extending the lifetime of layer handles.
struct RequestedLayerState : layer_state_t {
    // Changes in state after merging with new state. This includes additional state
    // changes found in layer_state_t::what.
    enum class Changes : uint32_t {
        Created = 1u << 0,
        Destroyed = 1u << 1,
        Hierarchy = 1u << 2,
        Geometry = 1u << 3,
        Content = 1u << 4,
        Input = 1u << 5,
        Z = 1u << 6,
        Mirror = 1u << 7,
        Parent = 1u << 8,
        RelativeParent = 1u << 9,
        Metadata = 1u << 10,
        Visibility = 1u << 11,
        AffectsChildren = 1u << 12,
        FrameRate = 1u << 13,
        VisibleRegion = 1u << 14,
        Buffer = 1u << 15,
        SidebandStream = 1u << 16,
        Animation = 1u << 17,
    };
    static Rect reduce(const Rect& win, const Region& exclude);
    RequestedLayerState(const LayerCreationArgs&);
    void merge(const ResolvedComposerState&);
    void clearChanges();

    // Currently we only care about the primary display
    ui::Transform getTransform(uint32_t displayRotationFlags) const;
    ui::Size getUnrotatedBufferSize(uint32_t displayRotationFlags) const;
    bool canBeDestroyed() const;
    bool isRoot() const;
    bool isHiddenByPolicy() const;
    half4 getColor() const;
    Rect getBufferSize(uint32_t displayRotationFlags) const;
    Rect getCroppedBufferSize(const Rect& bufferSize) const;
    Rect getBufferCrop() const;
    std::string getDebugString() const;
    std::string getDebugStringShort() const;
    aidl::android::hardware::graphics::composer3::Composition getCompositionType() const;
    bool hasValidRelativeParent() const;
    bool hasInputInfo() const;
    bool hasBlur() const;
    bool hasFrameUpdate() const;
    bool hasReadyFrame() const;
    bool hasSidebandStreamFrame() const;
    bool willReleaseBufferOnLatch() const;

    // Layer serial number.  This gives layers an explicit ordering, so we
    // have a stable sort order when their layer stack and Z-order are
    // the same.
    const uint32_t id;
    const std::string name;
    bool canBeRoot = false;
    const uint32_t layerCreationFlags;
    const uint32_t textureName;
    // The owner of the layer. If created from a non system process, it will be the calling uid.
    // If created from a system process, the value can be passed in.
    const uid_t ownerUid;
    // The owner pid of the layer. If created from a non system process, it will be the calling pid.
    // If created from a system process, the value can be passed in.
    const pid_t ownerPid;
    bool dataspaceRequested;
    bool hasColorTransform;
    bool premultipliedAlpha{true};
    // This layer can be a cursor on some displays.
    bool potentialCursor{false};
    bool protectedByApp{false}; // application requires protected path to external sink
    ui::Transform requestedTransform;
    std::shared_ptr<FenceTime> acquireFenceTime;
    std::shared_ptr<renderengine::ExternalTexture> externalTexture;
    gui::GameMode gameMode;
    scheduler::LayerInfo::FrameRate requestedFrameRate;
    uint32_t parentId = UNASSIGNED_LAYER_ID;
    uint32_t relativeParentId = UNASSIGNED_LAYER_ID;
    uint32_t layerIdToMirror = UNASSIGNED_LAYER_ID;
    ui::LayerStack layerStackToMirror = ui::INVALID_LAYER_STACK;
    uint32_t touchCropId = UNASSIGNED_LAYER_ID;
    uint32_t bgColorLayerId = UNASSIGNED_LAYER_ID;
    uint64_t barrierFrameNumber = 0;
    uint32_t barrierProducerId = 0;

    // book keeping states
    bool handleAlive = true;
    bool isRelativeOf = false;
    std::vector<uint32_t> mirrorIds{};
    ftl::Flags<RequestedLayerState::Changes> changes;
    bool bgColorLayer = false;
};

} // namespace android::surfaceflinger::frontend
