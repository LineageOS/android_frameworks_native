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

#include "HidUsageAccumulator.h"

namespace android {

void HidUsageAccumulator::process(const RawEvent& rawEvent) {
    if (rawEvent.type == EV_MSC && rawEvent.code == MSC_SCAN) {
        mCurrentHidUsage = rawEvent.value;
        return;
    }

    if (rawEvent.type == EV_SYN && rawEvent.code == SYN_REPORT) {
        reset();
        return;
    }
}

int32_t HidUsageAccumulator::consumeCurrentHidUsage() {
    const int32_t currentHidUsage = mCurrentHidUsage;
    reset();
    return currentHidUsage;
}

} // namespace android
