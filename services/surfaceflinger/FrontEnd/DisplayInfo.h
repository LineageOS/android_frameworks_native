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

#include <gui/DisplayInfo.h>

namespace android::surfaceflinger::frontend {

// Display information needed to populate input and calculate layer geometry.
struct DisplayInfo {
    gui::DisplayInfo info;
    ui::Transform transform;
    bool receivesInput;
    bool isSecure;
    // TODO(b/238781169) can eliminate once sPrimaryDisplayRotationFlags is removed.
    bool isPrimary;
    ui::Transform::RotationFlags rotationFlags;
};

} // namespace android::surfaceflinger::frontend
