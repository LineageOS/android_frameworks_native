/*
 * Copyright 2023 The Android Open Source Project
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

#include <android-base/result.h>
#include <input/Input.h>
#include "rust/cxx.h"

namespace android {

namespace input {
namespace verifier {
struct InputVerifier;
}
} // namespace input

/*
 * Crash if the provided touch stream is inconsistent.
 * This class is a pass-through to the rust implementation of InputVerifier.
 * The rust class could also be used directly, but it would be less convenient.
 * We can't directly invoke the rust methods on a rust object. So, there's no way to do:
 * mVerifier.process_movement(...).
 * This C++ class makes it a bit easier to use.
 *
 * TODO(b/211379801): Add support for hover events:
 * - No hover move without enter
 * - No touching pointers when hover enter
 * - No hovering pointers when touching
 * - Only 1 hovering pointer max
 */
class InputVerifier {
public:
    InputVerifier(const std::string& name);

    android::base::Result<void> processMovement(int32_t deviceId, int32_t source, int32_t action,
                                                uint32_t pointerCount,
                                                const PointerProperties* pointerProperties,
                                                const PointerCoords* pointerCoords, int32_t flags);

    void resetDevice(int32_t deviceId);

private:
    rust::Box<android::input::verifier::InputVerifier> mVerifier;
};

} // namespace android
