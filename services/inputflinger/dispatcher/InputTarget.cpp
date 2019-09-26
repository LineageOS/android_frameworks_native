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

std::string dispatchModeToString(int32_t dispatchMode) {
    switch (dispatchMode) {
        case InputTarget::FLAG_DISPATCH_AS_IS:
            return "DISPATCH_AS_IS";
        case InputTarget::FLAG_DISPATCH_AS_OUTSIDE:
            return "DISPATCH_AS_OUTSIDE";
        case InputTarget::FLAG_DISPATCH_AS_HOVER_ENTER:
            return "DISPATCH_AS_HOVER_ENTER";
        case InputTarget::FLAG_DISPATCH_AS_HOVER_EXIT:
            return "DISPATCH_AS_HOVER_EXIT";
        case InputTarget::FLAG_DISPATCH_AS_SLIPPERY_EXIT:
            return "DISPATCH_AS_SLIPPERY_EXIT";
        case InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER:
            return "DISPATCH_AS_SLIPPERY_ENTER";
    }
    return StringPrintf("%" PRId32, dispatchMode);
}

} // namespace android::inputdispatcher
