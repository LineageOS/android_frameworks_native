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

#include "LayerHandle.h"
#include <cstdint>
#include "Layer.h"
#include "LayerCreationArgs.h"
#include "SurfaceFlinger.h"

namespace android::surfaceflinger {

LayerHandle::LayerHandle(const sp<android::SurfaceFlinger>& flinger,
                         const sp<android::Layer>& layer)
      : mFlinger(flinger), mLayer(layer), mLayerId(static_cast<uint32_t>(layer->getSequence())) {}

LayerHandle::~LayerHandle() {
    if (mFlinger) {
        mFlinger->onHandleDestroyed(this, mLayer, mLayerId);
    }
}

const String16 LayerHandle::kDescriptor = String16("android.Layer.LayerHandle");

sp<LayerHandle> LayerHandle::fromIBinder(const sp<IBinder>& binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    BBinder* b = binder->localBinder();
    if (b == nullptr || b->getInterfaceDescriptor() != LayerHandle::kDescriptor) {
        ALOGD("handle does not have a valid descriptor");
        return nullptr;
    }

    // We can safely cast this binder since its local and we verified its interface descriptor.
    return sp<LayerHandle>::cast(binder);
}

sp<android::Layer> LayerHandle::getLayer(const sp<IBinder>& binder) {
    sp<LayerHandle> handle = LayerHandle::fromIBinder(binder);
    return handle ? handle->mLayer : nullptr;
}

uint32_t LayerHandle::getLayerId(const sp<IBinder>& binder) {
    sp<LayerHandle> handle = LayerHandle::fromIBinder(binder);
    return handle ? handle->mLayerId : UNASSIGNED_LAYER_ID;
}

} // namespace android::surfaceflinger
