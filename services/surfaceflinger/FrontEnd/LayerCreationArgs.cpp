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

LayerCreationArgs::LayerCreationArgs(SurfaceFlinger* flinger, sp<Client> client, std::string name,
                                     uint32_t flags, gui::LayerMetadata metadataArg,
                                     std::optional<uint32_t> id)
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

    if (id) {
        sequence = *id;
        sSequence = *id + 1;
    } else {
        sequence = sSequence++;
        if (sequence == UNASSIGNED_LAYER_ID) {
            ALOGW("Layer sequence id rolled over.");
            sequence = sSequence++;
        }
    }
}

LayerCreationArgs::LayerCreationArgs(const LayerCreationArgs& args)
      : LayerCreationArgs(args.flinger, args.client, args.name, args.flags, args.metadata) {}

} // namespace android::surfaceflinger
