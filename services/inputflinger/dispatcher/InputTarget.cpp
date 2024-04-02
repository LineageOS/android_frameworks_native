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

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <input/PrintTools.h>
#include <inttypes.h>
#include <string>

using android::base::Error;
using android::base::Result;
using android::base::StringPrintf;

namespace android::inputdispatcher {

namespace {

const static ui::Transform kIdentityTransform{};

}

InputTarget::InputTarget(const std::shared_ptr<Connection>& connection, ftl::Flags<Flags> flags)
      : connection(connection), flags(flags) {}

Result<void> InputTarget::addPointers(std::bitset<MAX_POINTER_ID + 1> newPointerIds,
                                      const ui::Transform& transform) {
    // The pointerIds can be empty, but still a valid InputTarget. This can happen when there is no
    // valid pointer property from the input event.
    if (newPointerIds.none()) {
        setDefaultPointerTransform(transform);
        return {};
    }

    // Ensure that the new set of pointers doesn't overlap with the current set of pointers.
    if ((getPointerIds() & newPointerIds).any()) {
        return Error() << __func__ << " - overlap with incoming pointers "
                       << bitsetToString(newPointerIds) << " in " << *this;
    }

    for (auto& [existingTransform, existingPointers] : mPointerTransforms) {
        if (transform == existingTransform) {
            existingPointers |= newPointerIds;
            return {};
        }
    }
    mPointerTransforms.emplace_back(transform, newPointerIds);
    return {};
}

void InputTarget::setDefaultPointerTransform(const ui::Transform& transform) {
    mPointerTransforms = {{transform, {}}};
}

bool InputTarget::useDefaultPointerTransform() const {
    return mPointerTransforms.size() <= 1;
}

const ui::Transform& InputTarget::getDefaultPointerTransform() const {
    if (!useDefaultPointerTransform()) {
        LOG(FATAL) << __func__ << ": Not using default pointer transform";
    }
    return mPointerTransforms.size() == 1 ? mPointerTransforms[0].first : kIdentityTransform;
}

const ui::Transform& InputTarget::getTransformForPointer(int32_t pointerId) const {
    for (const auto& [transform, ids] : mPointerTransforms) {
        if (ids.test(pointerId)) {
            return transform;
        }
    }

    LOG(FATAL) << __func__
               << ": Cannot get transform: The following Pointer ID does not exist in target: "
               << pointerId;
    return kIdentityTransform;
}

std::string InputTarget::getPointerInfoString() const {
    std::string out = "\n";
    if (useDefaultPointerTransform()) {
        const ui::Transform& transform = getDefaultPointerTransform();
        transform.dump(out, "default", "        ");
        return out;
    }

    for (const auto& [transform, ids] : mPointerTransforms) {
        const std::string name = "pointerIds " + bitsetToString(ids) + ":";
        transform.dump(out, name.c_str(), "        ");
    }
    return out;
}

std::bitset<MAX_POINTER_ID + 1> InputTarget::getPointerIds() const {
    PointerIds allIds;
    for (const auto& [_, ids] : mPointerTransforms) {
        allIds |= ids;
    }
    return allIds;
}

std::ostream& operator<<(std::ostream& out, const InputTarget& target) {
    out << "{connection=";
    if (target.connection != nullptr) {
        out << target.connection->getInputChannelName();
    } else {
        out << "<null>";
    }
    out << ", windowHandle=";
    if (target.windowHandle != nullptr) {
        out << target.windowHandle->getName();
    } else {
        out << "<null>";
    }
    out << ", dispatchMode=" << ftl::enum_string(target.dispatchMode).c_str();
    out << ", targetFlags=" << target.flags.string();
    out << ", pointers=" << target.getPointerInfoString();
    out << "}";
    return out;
}

} // namespace android::inputdispatcher
