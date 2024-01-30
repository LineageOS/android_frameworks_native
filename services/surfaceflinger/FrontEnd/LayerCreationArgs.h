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

#include <binder/Binder.h>
#include <gui/LayerMetadata.h>
#include <ui/LayerStack.h>
#include <utils/StrongPointer.h>
#include <cstdint>
#include <limits>
#include <optional>

constexpr uint32_t UNASSIGNED_LAYER_ID = std::numeric_limits<uint32_t>::max();
constexpr uint32_t INTERNAL_LAYER_PREFIX = 1u << 31;

namespace android {
class SurfaceFlinger;
class Client;
} // namespace android

namespace android::surfaceflinger {

struct LayerCreationArgs {
    static std::atomic<uint32_t> sSequence;
    static std::atomic<uint32_t> sInternalSequence;
    static uint32_t getInternalLayerId(uint32_t id);
    static LayerCreationArgs fromOtherArgs(const LayerCreationArgs& other);

    LayerCreationArgs(android::SurfaceFlinger*, sp<android::Client>, std::string name,
                      uint32_t flags, gui::LayerMetadata, std::optional<uint32_t> id = std::nullopt,
                      bool internalLayer = false);
    LayerCreationArgs(std::optional<uint32_t> id, bool internalLayer = false);
    LayerCreationArgs() = default; // for tracing
    std::string getDebugString() const;

    android::SurfaceFlinger* flinger;
    sp<android::Client> client;
    std::string name;
    uint32_t flags; // ISurfaceComposerClient flags
    gui::LayerMetadata metadata;
    pid_t ownerPid;
    uid_t ownerUid;
    uint32_t sequence;
    bool addToRoot = true;
    wp<IBinder> parentHandle = nullptr;
    wp<IBinder> mirrorLayerHandle = nullptr;
    ui::LayerStack layerStackToMirror = ui::INVALID_LAYER_STACK;
    uint32_t parentId = UNASSIGNED_LAYER_ID;
    uint32_t layerIdToMirror = UNASSIGNED_LAYER_ID;
};

} // namespace android::surfaceflinger
