/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "InputTarget.h"

#include <android-base/stringprintf.h>
#include <inttypes.h>
#include <string>

using android::base::StringPrintf;

namespace android::inputdispatcher {

void InputTarget::addPointers(std::bitset<MAX_POINTER_ID + 1> newPointerIds,
                              const ui::Transform& transform) {
    // The pointerIds can be empty, but still a valid InputTarget. This can happen when there is no
    // valid pointer property from the input event.
    if (newPointerIds.none()) {
        setDefaultPointerTransform(transform);
        return;
    }

    // Ensure that the new set of pointers doesn't overlap with the current set of pointers.
    LOG_ALWAYS_FATAL_IF((pointerIds & newPointerIds).any());

    pointerIds |= newPointerIds;
    for (size_t i = 0; i < newPointerIds.size(); i++) {
        if (!newPointerIds.test(i)) {
            continue;
        }
        pointerTransforms[i] = transform;
    }
}

void InputTarget::setDefaultPointerTransform(const ui::Transform& transform) {
    pointerIds.reset();
    pointerTransforms[0] = transform;
}

bool InputTarget::useDefaultPointerTransform() const {
    return pointerIds.none();
}

const ui::Transform& InputTarget::getDefaultPointerTransform() const {
    return pointerTransforms[0];
}

std::string InputTarget::getPointerInfoString() const {
    std::string out = "\n";
    if (useDefaultPointerTransform()) {
        const ui::Transform& transform = getDefaultPointerTransform();
        transform.dump(out, "default", "        ");
        return out;
    }

    for (uint32_t i = 0; i < pointerIds.size(); i++) {
        if (!pointerIds.test(i)) {
            continue;
        }

        const std::string name = "pointerId " + std::to_string(i) + ":";
        pointerTransforms[i].dump(out, name.c_str(), "        ");
    }
    return out;
}
} // namespace android::inputdispatcher
