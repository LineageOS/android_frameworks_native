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

#include <sstream>

#include <gui/DisplayInfo.h>
#include <ui/DisplayMap.h>
#include <ui/LayerStack.h>
#include <ui/LogicalDisplayId.h>
#include <ui/Transform.h>

namespace android::surfaceflinger::frontend {

// Display information needed to populate input and calculate layer geometry.
struct DisplayInfo {
    gui::DisplayInfo info;
    ui::Transform transform;
    bool receivesInput;
    bool isSecure;
    // TODO(b/259407931): can eliminate once SurfaceFlinger::sActiveDisplayRotationFlags is removed.
    bool isPrimary;
    bool isVirtual;
    ui::Transform::RotationFlags rotationFlags;
    ui::Transform::RotationFlags transformHint;
    std::string getDebugString() const {
        std::stringstream debug;
        debug << "DisplayInfo {displayId=" << info.displayId << " lw=" << info.logicalWidth
              << " lh=" << info.logicalHeight << " transform={" << transform.dsdx() << " ,"
              << transform.dsdy() << " ," << transform.dtdx() << " ," << transform.dtdy()
              << "} isSecure=" << isSecure << " isPrimary=" << isPrimary
              << " rotationFlags=" << rotationFlags << " transformHint=" << transformHint << "}";
        return debug.str();
    }
};

using DisplayInfos = ui::DisplayMap<ui::LayerStack, DisplayInfo>;

} // namespace android::surfaceflinger::frontend
