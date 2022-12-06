/*
 * Copyright 2019 The Android Open Source Project
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

#include <cstdint>
#include <optional>

#include <ui/DisplayIdentification.h>

#include <compositionengine/Output.h>

namespace android::compositionengine {

struct RenderSurfaceCreationArgs;
struct DisplayColorProfileCreationArgs;

/**
 * A display is a composition target which may be backed by a hardware composer
 * display device
 */
class Display : public virtual Output {
public:
    // Gets the DisplayId for the display
    virtual DisplayId getId() const = 0;

    // True if the display is secure
    virtual bool isSecure() const = 0;

    // True if the display is virtual
    virtual bool isVirtual() const = 0;

    // Releases the use of the HWC display, if any
    virtual void disconnect() = 0;

    // Creates a render color mode for the display
    virtual void createDisplayColorProfile(const DisplayColorProfileCreationArgs&) = 0;

    // Creates a render surface for the display
    virtual void createRenderSurface(const RenderSurfaceCreationArgs&) = 0;

    // Creates a cache to cache duplicate client composition requests and skip
    // similar requests if needed.
    virtual void createClientCompositionCache(uint32_t cacheSize) = 0;

    // Sends the brightness setting to HWC
    virtual void applyDisplayBrightness(const bool applyImmediately) = 0;

protected:
    ~Display() = default;
};

} // namespace android::compositionengine
