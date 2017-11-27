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

#ifndef ANDROID_SURFACEFLINGERCONSUMER_H
#define ANDROID_SURFACEFLINGERCONSUMER_H

#include "BufferLayerConsumer.h"
#include "DispSync.h"

#include <ui/Region.h>

namespace android {
// ----------------------------------------------------------------------------

class Layer;

/*
 * This is a thin wrapper around BufferLayerConsumer.
 */
class SurfaceFlingerConsumer : public BufferLayerConsumer {
public:
    SurfaceFlingerConsumer(const sp<IGraphicBufferConsumer>& consumer,
            uint32_t tex, Layer* layer)
        : BufferLayerConsumer(consumer, tex, layer)
    {}

    // See BufferLayerConsumer::bindTextureImageLocked().
    status_t bindTextureImage();

    sp<Fence> getPrevFinalReleaseFence() const;
};

// ----------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_SURFACEFLINGERCONSUMER_H
