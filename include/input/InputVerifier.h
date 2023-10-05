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

#pragma once

#include <input/Input.h>
#include <map>

namespace android {

/*
 * Crash if the provided touch stream is inconsistent.
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

    void processMovement(int32_t deviceId, int32_t action, uint32_t pointerCount,
                         const PointerProperties* pointerProperties,
                         const PointerCoords* pointerCoords, int32_t flags);

private:
    const std::string mName;
    std::map<int32_t /*deviceId*/, std::bitset<MAX_POINTER_ID + 1>> mTouchingPointerIdsByDevice;
    void ensureTouchingPointersMatch(int32_t deviceId, uint32_t pointerCount,
                                     const PointerProperties* pointerProperties,
                                     const char* action) const;
};

} // namespace android
