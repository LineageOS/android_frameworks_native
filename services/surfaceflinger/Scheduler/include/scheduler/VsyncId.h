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

#include <cstdint>

namespace android {

// TODO(b/185536303): Import StrongTyping.h into FTL so it can be used here.

// Sequential frame identifier, also known as FrameTimeline token.
struct VsyncId {
    int64_t value = -1;
};

inline bool operator==(VsyncId lhs, VsyncId rhs) {
    return lhs.value == rhs.value;
}

} // namespace android
