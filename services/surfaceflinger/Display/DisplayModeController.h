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

#pragma once

#include <memory>
#include <utility>

#include <android-base/thread_annotations.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMap.h>

#include "Display/DisplaySnapshotRef.h"
#include "DisplayHardware/DisplayMode.h"
#include "Scheduler/RefreshRateSelector.h"
#include "ThreadContext.h"

namespace android::display {

// Selects the DisplayMode of each physical display, in accordance with DisplayManager policy and
// certain heuristic signals.
class DisplayModeController {
public:
    // The referenced DisplaySnapshot must outlive the registration.
    void registerDisplay(DisplaySnapshotRef, DisplayModeId, scheduler::RefreshRateSelector::Config)
            REQUIRES(kMainThreadContext);
    void unregisterDisplay(PhysicalDisplayId) REQUIRES(kMainThreadContext);

    // TODO(b/241285876): Remove once ownership is no longer shared with DisplayDevice.
    using RefreshRateSelectorPtr = std::shared_ptr<scheduler::RefreshRateSelector>;

    // Returns `nullptr` if the display is no longer registered (or never was).
    RefreshRateSelectorPtr selectorPtrFor(PhysicalDisplayId) REQUIRES(kMainThreadContext);

    // Used by tests to inject an existing RefreshRateSelector.
    // TODO(b/241285876): Remove this.
    void registerDisplay(PhysicalDisplayId displayId, DisplaySnapshotRef snapshotRef,
                         RefreshRateSelectorPtr selectorPtr) {
        mDisplays.emplace_or_replace(displayId, snapshotRef, selectorPtr);
    }

private:
    struct Display {
        Display(DisplaySnapshotRef snapshot, RefreshRateSelectorPtr selectorPtr)
              : snapshot(snapshot), selectorPtr(std::move(selectorPtr)) {}

        Display(DisplaySnapshotRef snapshot, DisplayModes modes, DisplayModeId activeModeId,
                scheduler::RefreshRateSelector::Config config)
              : Display(snapshot,
                        std::make_shared<scheduler::RefreshRateSelector>(std::move(modes),
                                                                         activeModeId, config)) {}

        const DisplaySnapshotRef snapshot;
        const RefreshRateSelectorPtr selectorPtr;
    };

    ui::PhysicalDisplayMap<PhysicalDisplayId, Display> mDisplays;
};

} // namespace android::display
