/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>

#include <binder/IPCThreadState.h>

#include <private/android_filesystem_config.h>

#include <gui/AidlStatusUtil.h>

#include "Client.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/LayerHandle.h"
#include "Layer.h"
#include "SurfaceFlinger.h"

namespace android {

using gui::aidl_utils::binderStatusFromStatusT;

// ---------------------------------------------------------------------------

const String16 sAccessSurfaceFlinger("android.permission.ACCESS_SURFACE_FLINGER");

// ---------------------------------------------------------------------------

Client::Client(const sp<SurfaceFlinger>& flinger)
    : mFlinger(flinger)
{
}

status_t Client::initCheck() const {
    return NO_ERROR;
}

binder::Status Client::createSurface(const std::string& name, int32_t flags,
                                     const sp<IBinder>& parent, const gui::LayerMetadata& metadata,
                                     gui::CreateSurfaceResult* outResult) {
    // We rely on createLayer to check permissions.
    sp<IBinder> handle;
    LayerCreationArgs args(mFlinger.get(), sp<Client>::fromExisting(this), name.c_str(),
                           static_cast<uint32_t>(flags), std::move(metadata));
    args.parentHandle = parent;
    const status_t status = mFlinger->createLayer(args, *outResult);
    return binderStatusFromStatusT(status);
}

binder::Status Client::clearLayerFrameStats(const sp<IBinder>& handle) {
    status_t status;
    sp<Layer> layer = LayerHandle::getLayer(handle);
    if (layer == nullptr) {
        status = NAME_NOT_FOUND;
    } else {
        layer->clearFrameStats();
        status = NO_ERROR;
    }
    return binderStatusFromStatusT(status);
}

binder::Status Client::getLayerFrameStats(const sp<IBinder>& handle, gui::FrameStats* outStats) {
    status_t status;
    sp<Layer> layer = LayerHandle::getLayer(handle);
    if (layer == nullptr) {
        status = NAME_NOT_FOUND;
    } else {
        FrameStats stats;
        layer->getFrameStats(&stats);
        outStats->refreshPeriodNano = stats.refreshPeriodNano;
        outStats->desiredPresentTimesNano.reserve(stats.desiredPresentTimesNano.size());
        for (const auto& t : stats.desiredPresentTimesNano) {
            outStats->desiredPresentTimesNano.push_back(t);
        }
        outStats->actualPresentTimesNano.reserve(stats.actualPresentTimesNano.size());
        for (const auto& t : stats.actualPresentTimesNano) {
            outStats->actualPresentTimesNano.push_back(t);
        }
        outStats->frameReadyTimesNano.reserve(stats.frameReadyTimesNano.size());
        for (const auto& t : stats.frameReadyTimesNano) {
            outStats->frameReadyTimesNano.push_back(t);
        }
        status = NO_ERROR;
    }
    return binderStatusFromStatusT(status);
}

binder::Status Client::mirrorSurface(const sp<IBinder>& mirrorFromHandle,
                                     gui::CreateSurfaceResult* outResult) {
    sp<IBinder> handle;
    LayerCreationArgs args(mFlinger.get(), sp<Client>::fromExisting(this), "MirrorRoot",
                           0 /* flags */, gui::LayerMetadata());
    status_t status = mFlinger->mirrorLayer(args, mirrorFromHandle, *outResult);
    return binderStatusFromStatusT(status);
}

binder::Status Client::mirrorDisplay(int64_t displayId, gui::CreateSurfaceResult* outResult) {
    sp<IBinder> handle;
    LayerCreationArgs args(mFlinger.get(), sp<Client>::fromExisting(this),
                           "MirrorRoot-" + std::to_string(displayId), 0 /* flags */,
                           gui::LayerMetadata());
    std::optional<DisplayId> id = DisplayId::fromValue(static_cast<uint64_t>(displayId));
    status_t status = mFlinger->mirrorDisplay(*id, args, *outResult);
    return binderStatusFromStatusT(status);
}

// ---------------------------------------------------------------------------
}; // namespace android
