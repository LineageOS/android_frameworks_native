/*
 * Copyright (C) 2007 The Android Open Source Project
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

// tag as surfaceflinger
#define LOG_TAG "SurfaceFlinger"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/SafeInterface.h>

#include <ui/FrameStats.h>
#include <ui/Point.h>
#include <ui/Rect.h>

#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposerClient.h>

namespace android {

class BpSurfaceComposerClient : public SafeBpInterface<ISurfaceComposerClient> {
public:
    explicit BpSurfaceComposerClient(const sp<IBinder>& impl)
          : SafeBpInterface<ISurfaceComposerClient>(impl, "BpSurfaceComposerClient") {}

    ~BpSurfaceComposerClient() override;

    status_t createSurface(const String8& name, uint32_t width, uint32_t height, PixelFormat format,
                           uint32_t flags, const sp<IBinder>& parent, uint32_t windowType,
                           uint32_t ownerUid, sp<IBinder>* handle,
                           sp<IGraphicBufferProducer>* gbp) override {
        return callRemote<decltype(&ISurfaceComposerClient::createSurface)>(Tag::CreateSurface,
                                                                            name, width, height,
                                                                            format, flags, parent,
                                                                            windowType, ownerUid,
                                                                            handle, gbp);
    }

    status_t destroySurface(const sp<IBinder>& handle) override {
        return callRemote<decltype(&ISurfaceComposerClient::destroySurface)>(Tag::DestroySurface,
                                                                             handle);
    }

    status_t clearLayerFrameStats(const sp<IBinder>& handle) const override {
        return callRemote<decltype(
                &ISurfaceComposerClient::clearLayerFrameStats)>(Tag::ClearLayerFrameStats, handle);
    }

    status_t getLayerFrameStats(const sp<IBinder>& handle, FrameStats* outStats) const override {
        return callRemote<decltype(
                &ISurfaceComposerClient::getLayerFrameStats)>(Tag::GetLayerFrameStats, handle,
                                                              outStats);
    }
};

// Out-of-line virtual method definition to trigger vtable emission in this
// translation unit (see clang warning -Wweak-vtables)
BpSurfaceComposerClient::~BpSurfaceComposerClient() {}

IMPLEMENT_META_INTERFACE(SurfaceComposerClient, "android.ui.ISurfaceComposerClient");

// ----------------------------------------------------------------------

status_t BnSurfaceComposerClient::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                             uint32_t flags) {
    if (code < IBinder::FIRST_CALL_TRANSACTION || code >= static_cast<uint32_t>(Tag::Last)) {
        return BBinder::onTransact(code, data, reply, flags);
    }
    auto tag = static_cast<Tag>(code);
    switch (tag) {
        case Tag::CreateSurface: {
            return callLocal(data, reply, &ISurfaceComposerClient::createSurface);
        }
        case Tag::DestroySurface: {
            return callLocal(data, reply, &ISurfaceComposerClient::destroySurface);
        }
        case Tag::ClearLayerFrameStats: {
            return callLocal(data, reply, &ISurfaceComposerClient::clearLayerFrameStats);
        }
        case Tag::GetLayerFrameStats: {
            return callLocal(data, reply, &ISurfaceComposerClient::getLayerFrameStats);
        }
        case Tag::Last:
            // Should not be possible because of the check at the beginning of the method
            return BBinder::onTransact(code, data, reply, flags);
    }
}

} // namespace android
