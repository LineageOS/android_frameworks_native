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

void Client::attachLayer(const sp<IBinder>& handle, const sp<Layer>& layer)
{
    Mutex::Autolock _l(mLock);
    mLayers.add(handle, layer);
}

void Client::detachLayer(const Layer* layer)
{
    Mutex::Autolock _l(mLock);
    // we do a linear search here, because this doesn't happen often
    const size_t count = mLayers.size();
    for (size_t i=0 ; i<count ; i++) {
        if (mLayers.valueAt(i) == layer) {
            mLayers.removeItemsAt(i, 1);
            break;
        }
    }
}
sp<Layer> Client::getLayerUser(const sp<IBinder>& handle) const
{
    Mutex::Autolock _l(mLock);
    sp<Layer> lbc;
    wp<Layer> layer(mLayers.valueFor(handle));
    if (layer != 0) {
        lbc = layer.promote();
        ALOGE_IF(lbc==0, "getLayerUser(name=%p) is dead", handle.get());
    }
    return lbc;
}

binder::Status Client::createSurface(const std::string& name, int32_t flags,
                                     const sp<IBinder>& parent, const gui::LayerMetadata& metadata,
                                     gui::CreateSurfaceResult* outResult) {
    // We rely on createLayer to check permissions.
    sp<IBinder> handle;
    int32_t layerId;
    uint32_t transformHint;
    LayerCreationArgs args(mFlinger.get(), this, name.c_str(), static_cast<uint32_t>(flags),
                           std::move(metadata));
    const status_t status =
            mFlinger->createLayer(args, &handle, parent, &layerId, nullptr, &transformHint);
    if (status == NO_ERROR) {
        outResult->handle = handle;
        outResult->layerId = layerId;
        outResult->transformHint = static_cast<int32_t>(transformHint);
    }
    return binderStatusFromStatusT(status);
}

binder::Status Client::clearLayerFrameStats(const sp<IBinder>& handle) {
    status_t status;
    sp<Layer> layer = getLayerUser(handle);
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
    sp<Layer> layer = getLayerUser(handle);
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
                                     gui::MirrorSurfaceResult* outResult) {
    sp<IBinder> handle;
    int32_t layerId;
    LayerCreationArgs args(mFlinger.get(), this, "MirrorRoot", 0 /* flags */, gui::LayerMetadata());
    status_t status = mFlinger->mirrorLayer(args, mirrorFromHandle, &handle, &layerId);
    if (status == NO_ERROR) {
        outResult->handle = handle;
        outResult->layerId = layerId;
    }
    return binderStatusFromStatusT(status);
}

// ---------------------------------------------------------------------------
}; // namespace android
