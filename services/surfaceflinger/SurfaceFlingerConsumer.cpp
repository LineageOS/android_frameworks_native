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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include "SurfaceFlingerConsumer.h"
#include "Layer.h"

#include <private/gui/SyncFeatures.h>

#include <gui/BufferItem.h>
#include <gui/BufferQueue.h>

#include <utils/Errors.h>
#include <utils/NativeHandle.h>
#include <utils/Trace.h>

namespace android {

// ---------------------------------------------------------------------------

status_t SurfaceFlingerConsumer::bindTextureImage()
{
    Mutex::Autolock lock(mMutex);

    return bindTextureImageLocked();
}

sp<Fence> SurfaceFlingerConsumer::getPrevFinalReleaseFence() const {
    Mutex::Autolock lock(mMutex);
    return ConsumerBase::mPrevFinalReleaseFence;
}

// ---------------------------------------------------------------------------
}; // namespace android

