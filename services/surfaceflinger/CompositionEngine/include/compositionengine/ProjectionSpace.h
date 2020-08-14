/*
 * Copyright 2020 The Android Open Source Project
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

#include <ostream>

#include <android-base/stringprintf.h>
#include <ui/Rect.h>
#include <ui/Rotation.h>
#include <ui/Transform.h>

namespace android {
namespace compositionengine {

// Geometrical space to which content is projected.
// For example, this can be the layer space or the physical display space.
struct ProjectionSpace {
    ProjectionSpace() = default;
    ProjectionSpace(ui::Size size, Rect content)
          : bounds(std::move(size)), content(std::move(content)) {}

    // Bounds of this space. Always starts at (0,0).
    Rect bounds;

    // Rect onto which content is projected.
    Rect content;
};

} // namespace compositionengine

inline std::string to_string(const android::compositionengine::ProjectionSpace& space) {
    return android::base::StringPrintf("ProjectionSpace(bounds = %s, content = %s)",
                                       to_string(space.bounds).c_str(),
                                       to_string(space.content).c_str());
}

// Defining PrintTo helps with Google Tests.
inline void PrintTo(const android::compositionengine::ProjectionSpace& space, ::std::ostream* os) {
    *os << to_string(space);
}

} // namespace android