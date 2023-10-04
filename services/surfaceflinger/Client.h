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

#ifndef ANDROID_SF_CLIENT_H
#define ANDROID_SF_CLIENT_H

#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/Mutex.h>

#include <android/gui/BnSurfaceComposerClient.h>

namespace android {

class Layer;
class SurfaceFlinger;

class Client : public gui::BnSurfaceComposerClient {
public:
    explicit Client(const sp<SurfaceFlinger>& flinger);
    ~Client() = default;

    status_t initCheck() const;

private:
    // ISurfaceComposerClient interface

    binder::Status createSurface(const std::string& name, int32_t flags, const sp<IBinder>& parent,
                                 const gui::LayerMetadata& metadata,
                                 gui::CreateSurfaceResult* outResult) override;

    binder::Status clearLayerFrameStats(const sp<IBinder>& handle) override;

    binder::Status getLayerFrameStats(const sp<IBinder>& handle,
                                      gui::FrameStats* outStats) override;

    binder::Status mirrorSurface(const sp<IBinder>& mirrorFromHandle,
                                 gui::CreateSurfaceResult* outResult) override;

    binder::Status mirrorDisplay(int64_t displayId, gui::CreateSurfaceResult* outResult) override;

    binder::Status getSchedulingPolicy(gui::SchedulingPolicy* outPolicy) override;

    // constant
    sp<SurfaceFlinger> mFlinger;

    // thread-safe
    mutable Mutex mLock;
};

}; // namespace android

#endif // ANDROID_SF_CLIENT_H
