/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "InputVerifier"

#include <android-base/logging.h>
#include <input/InputVerifier.h>
#include "input_cxx_bridge.rs.h"

using android::base::Error;
using android::base::Result;
using android::input::RustPointerProperties;

using DeviceId = int32_t;

namespace android {

// --- InputVerifier ---

InputVerifier::InputVerifier(const std::string& name)
      : mVerifier(android::input::verifier::create(rust::String::lossy(name))){};

Result<void> InputVerifier::processMovement(DeviceId deviceId, int32_t source, int32_t action,
                                            uint32_t pointerCount,
                                            const PointerProperties* pointerProperties,
                                            const PointerCoords* pointerCoords, int32_t flags) {
    std::vector<RustPointerProperties> rpp;
    for (size_t i = 0; i < pointerCount; i++) {
        rpp.emplace_back(RustPointerProperties{.id = pointerProperties[i].id});
    }
    rust::Slice<const RustPointerProperties> properties{rpp.data(), rpp.size()};
    rust::String errorMessage =
            android::input::verifier::process_movement(*mVerifier, deviceId, source, action,
                                                       properties, static_cast<uint32_t>(flags));
    if (errorMessage.empty()) {
        return {};
    } else {
        return Error() << errorMessage;
    }
}

void InputVerifier::resetDevice(DeviceId deviceId) {
    android::input::verifier::reset_device(*mVerifier, deviceId);
}

} // namespace android
