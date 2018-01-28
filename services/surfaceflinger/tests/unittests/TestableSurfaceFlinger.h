/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "DisplayDevice.h"
#include "SurfaceFlinger.h"

namespace android {

class TestableSurfaceFlinger {
public:
    // Extend this as needed for accessing SurfaceFlinger private (and public)
    // functions.

    /* ------------------------------------------------------------------------
     * Forwarding for functions being tested
     */
    auto getDefaultDisplayDeviceLocked() const { return mFlinger->getDefaultDisplayDeviceLocked(); }

    auto processDisplayChangesLocked() { return mFlinger->processDisplayChangesLocked(); }

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */
    auto& mutableBuiltinDisplays() { return mFlinger->mBuiltinDisplays; }

    sp<SurfaceFlinger> mFlinger = new SurfaceFlinger();
};

} // namespace android
