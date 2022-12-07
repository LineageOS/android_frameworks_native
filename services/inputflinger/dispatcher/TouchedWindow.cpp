/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "TouchedWindow.h"

#include <android-base/stringprintf.h>
#include <input/PrintTools.h>

using android::base::StringPrintf;

namespace android {

namespace inputdispatcher {

std::string TouchedWindow::dump() const {
    return StringPrintf("name='%s', pointerIds=0x%0x, "
                        "targetFlags=%s, firstDownTimeInTarget=%s\n",
                        windowHandle->getName().c_str(), pointerIds.value,
                        targetFlags.string().c_str(), toString(firstDownTimeInTarget).c_str());
}

} // namespace inputdispatcher
} // namespace android
