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

#include "LayerCreationArgs.h"
#include <binder/IPCThreadState.h>
#include <private/android_filesystem_config.h>
#include "Client.h"
#include "gui/LayerMetadata.h"

namespace android::surfaceflinger {

std::atomic<uint32_t> LayerCreationArgs::sSequence{1};
std::atomic<uint32_t> LayerCreationArgs::sInternalSequence{1};

uint32_t LayerCreationArgs::getInternalLayerId(uint32_t id) {
    return id | INTERNAL_LAYER_PREFIX;
}

LayerCreationArgs::LayerCreationArgs(SurfaceFlinger* flinger, sp<Client> client, std::string name,
                                     uint32_t flags, gui::LayerMetadata metadataArg,
                                     std::optional<uint32_t> id, bool internalLayer)
      : flinger(flinger),
        client(std::move(client)),
        name(std::move(name)),
        flags(flags),
        metadata(std::move(metadataArg)) {
    IPCThreadState* ipc = IPCThreadState::self();
    ownerPid = ipc->getCallingPid();
    uid_t callingUid = ipc->getCallingUid();
    metadata.setInt32(gui::METADATA_CALLING_UID, static_cast<int32_t>(callingUid));
    ownerUid = callingUid;
    if (ownerUid == AID_GRAPHICS || ownerUid == AID_SYSTEM) {
        // System can override the calling UID/PID since it can create layers on behalf of apps.
        ownerPid = metadata.getInt32(gui::METADATA_OWNER_PID, ownerPid);
        ownerUid = static_cast<uid_t>(
                metadata.getInt32(gui::METADATA_OWNER_UID, static_cast<int32_t>(ownerUid)));
    }

    if (internalLayer) {
        sequence = id.value_or(getInternalLayerId(sInternalSequence++));
    } else if (id) {
        sequence = *id;
        sSequence = *id + 1;
    } else {
        sequence = sSequence++;
        if (sequence >= INTERNAL_LAYER_PREFIX) {
            sSequence = 1;
            ALOGW("Layer sequence id rolled over.");
            sequence = sSequence++;
        }
    }
}

LayerCreationArgs::LayerCreationArgs(std::optional<uint32_t> id, bool internalLayer)
      : LayerCreationArgs(nullptr, nullptr, /*name=*/"", /*flags=*/0, /*metadata=*/{}, id,
                          internalLayer) {}

LayerCreationArgs LayerCreationArgs::fromOtherArgs(const LayerCreationArgs& other) {
    // returns a new instance of LayerCreationArgs with a unique id.
    return LayerCreationArgs(other.flinger, other.client, other.name, other.flags, other.metadata);
}

std::string LayerCreationArgs::getDebugString() const {
    std::stringstream stream;
    stream << "LayerCreationArgs{" << name << "[" << sequence << "] flags=" << flags
           << " pid=" << ownerPid << " uid=" << ownerUid;
    if (addToRoot) {
        stream << " addToRoot=" << addToRoot;
    }
    if (parentId != UNASSIGNED_LAYER_ID) {
        stream << " parentId=" << parentId;
    }
    if (layerIdToMirror != UNASSIGNED_LAYER_ID) {
        stream << " layerIdToMirror=" << layerIdToMirror;
    }
    if (layerStackToMirror != ui::INVALID_LAYER_STACK) {
        stream << " layerStackToMirror=" << layerStackToMirror.id;
    }
    return stream.str();
}

} // namespace android::surfaceflinger
