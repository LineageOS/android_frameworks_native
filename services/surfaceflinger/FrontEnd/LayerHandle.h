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
#include <utils/StrongPointer.h>

namespace android {
class SurfaceFlinger;
class Layer;
} // namespace android

namespace android::surfaceflinger {

/*
 * The layer handle is just a BBinder object passed to the client
 * (remote process) -- we don't keep any reference on our side such that
 * the dtor is called when the remote side let go of its reference.
 *
 * ~LayerHandle ensures that mFlinger->onLayerDestroyed() is called for
 * this layer when the handle is destroyed.
 */
class LayerHandle : public BBinder {
public:
    LayerHandle(const sp<android::SurfaceFlinger>& flinger, const sp<android::Layer>& layer);
    // for testing
    LayerHandle(uint32_t layerId) : mFlinger(nullptr), mLayer(nullptr), mLayerId(layerId) {}
    ~LayerHandle();

    // Static functions to access the layer and layer id safely from an incoming binder.
    static sp<LayerHandle> fromIBinder(const sp<IBinder>& handle);
    static sp<android::Layer> getLayer(const sp<IBinder>& handle);
    static uint32_t getLayerId(const sp<IBinder>& handle);
    static const String16 kDescriptor;

    const String16& getInterfaceDescriptor() const override { return kDescriptor; }

private:
    sp<android::SurfaceFlinger> mFlinger;
    sp<android::Layer> mLayer;
    const uint32_t mLayerId;
};

} // namespace android::surfaceflinger
