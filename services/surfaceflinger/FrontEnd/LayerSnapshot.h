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

#include <compositionengine/LayerFECompositionState.h>
#include <renderengine/LayerSettings.h>
#include "LayerHierarchy.h"
#include "RequestedLayerState.h"
#include "Scheduler/LayerInfo.h"
#include "android-base/stringprintf.h"

namespace android::surfaceflinger::frontend {

struct RoundedCornerState {
    RoundedCornerState() = default;
    RoundedCornerState(const FloatRect& cropRect, const vec2& radius)
          : cropRect(cropRect), radius(radius) {}

    // Rounded rectangle in local layer coordinate space.
    FloatRect cropRect = FloatRect();
    // Radius of the rounded rectangle.
    vec2 radius;
    bool hasRoundedCorners() const { return radius.x > 0.0f && radius.y > 0.0f; }
    bool operator==(RoundedCornerState const& rhs) const {
        return cropRect == rhs.cropRect && radius == rhs.radius;
    }
};

struct ChildState {
    bool hasValidFrameRate = false;
};

// LayerSnapshot stores Layer state used by CompositionEngine and RenderEngine. Composition
// Engine uses a pointer to LayerSnapshot (as LayerFECompositionState*) and the LayerSettings
// passed to Render Engine are created using properties stored on this struct.
struct LayerSnapshot : public compositionengine::LayerFECompositionState {
    LayerSnapshot() = default;
    LayerSnapshot(const RequestedLayerState&, const LayerHierarchy::TraversalPath&);

    LayerHierarchy::TraversalPath path;
    size_t globalZ = std::numeric_limits<ssize_t>::max();
    bool invalidTransform = false;
    bool isHiddenByPolicyFromParent = false;
    bool isHiddenByPolicyFromRelativeParent = false;
    ftl::Flags<RequestedLayerState::Changes> changes;
    // Some consumers of this snapshot (input, layer traces) rely on each snapshot to be unique.
    // For mirrored layers, snapshots will have the same sequence so this unique id provides
    // an alternative identifier when needed.
    uint32_t uniqueSequence;
    // Layer id used to create this snapshot. Multiple snapshots will have the same sequence if they
    // generated from the same layer, for example when mirroring.
    int32_t sequence;
    std::string name;
    uint32_t textureName;
    bool contentOpaque;
    bool layerOpaqueFlagSet;
    RoundedCornerState roundedCorner;
    FloatRect transformedBounds;
    Rect transformedBoundsWithoutTransparentRegion;
    renderengine::ShadowSettings shadowSettings;
    bool premultipliedAlpha;
    bool isHdrY410;
    ui::Transform parentTransform;
    Rect bufferSize;
    Rect croppedBufferSize;
    std::shared_ptr<renderengine::ExternalTexture> externalTexture;
    gui::LayerMetadata layerMetadata;
    gui::LayerMetadata relativeLayerMetadata;
    bool hasReadyFrame;
    ui::Transform localTransformInverse;
    gui::WindowInfo inputInfo;
    ui::Transform localTransform;
    gui::DropInputMode dropInputMode;
    bool isTrustedOverlay;
    gui::GameMode gameMode;
    scheduler::LayerInfo::FrameRate frameRate;
    ui::Transform::RotationFlags fixedTransformHint;
    std::optional<ui::Transform::RotationFlags> transformHint;
    bool handleSkipScreenshotFlag = false;
    int32_t frameRateSelectionPriority;
    LayerHierarchy::TraversalPath mirrorRootPath;
    bool unreachable = true;
    uint32_t touchCropId;
    uid_t uid;
    pid_t pid;
    ChildState childState;

    static bool isOpaqueFormat(PixelFormat format);
    static bool isTransformValid(const ui::Transform& t);

    bool canReceiveInput() const;
    bool drawShadows() const;
    bool fillsColor() const;
    bool getIsVisible() const;
    bool hasBlur() const;
    bool hasBufferOrSidebandStream() const;
    bool hasEffect() const;
    bool hasSomethingToDraw() const;
    bool isContentOpaque() const;
    bool isHiddenByPolicy() const;
    std::string getDebugString() const;
    std::string getIsVisibleReason() const;
    bool hasInputInfo() const;
    FloatRect sourceBounds() const;
};

} // namespace android::surfaceflinger::frontend
