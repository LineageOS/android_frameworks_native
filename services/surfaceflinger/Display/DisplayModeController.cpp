/*
 * Copyright 2024 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "DisplayModeController"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "Display/DisplayModeController.h"
#include "Display/DisplaySnapshot.h"

#include <log/log.h>

namespace android::display {

void DisplayModeController::registerDisplay(DisplaySnapshotRef snapshotRef,
                                            DisplayModeId activeModeId,
                                            scheduler::RefreshRateSelector::Config config) {
    const auto& snapshot = snapshotRef.get();
    const auto displayId = snapshot.displayId();

    mDisplays.emplace_or_replace(displayId, snapshotRef, snapshot.displayModes(), activeModeId,
                                 config);
}

void DisplayModeController::unregisterDisplay(PhysicalDisplayId displayId) {
    const bool ok = mDisplays.erase(displayId);
    ALOGE_IF(!ok, "%s: Unknown display %s", __func__, to_string(displayId).c_str());
}

auto DisplayModeController::selectorPtrFor(PhysicalDisplayId displayId) -> RefreshRateSelectorPtr {
    return mDisplays.get(displayId)
            .transform([](const Display& display) { return display.selectorPtr; })
            .value_or(nullptr);
}

} // namespace android::display
