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
#include <mutex>
#include <string>
#include <utility>

#include <android-base/thread_annotations.h>
#include <ftl/function.h>
#include <ftl/optional.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMap.h>

#include "Display/DisplayModeRequest.h"
#include "Display/DisplaySnapshotRef.h"
#include "DisplayHardware/DisplayMode.h"
#include "Scheduler/RefreshRateSelector.h"
#include "ThreadContext.h"
#include "TracedOrdinal.h"

namespace android {
class HWComposer;
} // namespace android

namespace android::display {

// Selects the DisplayMode of each physical display, in accordance with DisplayManager policy and
// certain heuristic signals.
class DisplayModeController {
public:
    using ActiveModeListener = ftl::Function<void(PhysicalDisplayId, Fps vsyncRate, Fps renderFps)>;

    DisplayModeController() = default;

    void setHwComposer(HWComposer* composerPtr) { mComposerPtr = composerPtr; }
    void setActiveModeListener(const ActiveModeListener& listener) {
        mActiveModeListener = listener;
    }

    // TODO: b/241285876 - Remove once ownership is no longer shared with DisplayDevice.
    using RefreshRateSelectorPtr = std::shared_ptr<scheduler::RefreshRateSelector>;

    // Used by tests to inject an existing RefreshRateSelector.
    // TODO: b/241285876 - Remove this.
    void registerDisplay(PhysicalDisplayId, DisplaySnapshotRef, RefreshRateSelectorPtr)
            EXCLUDES(mDisplayLock);

    // The referenced DisplaySnapshot must outlive the registration.
    void registerDisplay(DisplaySnapshotRef, DisplayModeId, scheduler::RefreshRateSelector::Config)
            REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);
    void unregisterDisplay(PhysicalDisplayId) REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);

    // Returns `nullptr` if the display is no longer registered (or never was).
    RefreshRateSelectorPtr selectorPtrFor(PhysicalDisplayId) const EXCLUDES(mDisplayLock);

    enum class DesiredModeAction { None, InitiateDisplayModeSwitch, InitiateRenderRateSwitch };

    DesiredModeAction setDesiredMode(PhysicalDisplayId, DisplayModeRequest&&)
            EXCLUDES(mDisplayLock);

    using DisplayModeRequestOpt = ftl::Optional<DisplayModeRequest>;

    DisplayModeRequestOpt getDesiredMode(PhysicalDisplayId) const EXCLUDES(mDisplayLock);
    void clearDesiredMode(PhysicalDisplayId) EXCLUDES(mDisplayLock);

    DisplayModeRequestOpt getPendingMode(PhysicalDisplayId) const REQUIRES(kMainThreadContext)
            EXCLUDES(mDisplayLock);
    bool isModeSetPending(PhysicalDisplayId) const REQUIRES(kMainThreadContext)
            EXCLUDES(mDisplayLock);

    scheduler::FrameRateMode getActiveMode(PhysicalDisplayId) const EXCLUDES(mDisplayLock);

    bool initiateModeChange(PhysicalDisplayId, DisplayModeRequest&&,
                            const hal::VsyncPeriodChangeConstraints&,
                            hal::VsyncPeriodChangeTimeline& outTimeline)
            REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);

    void finalizeModeChange(PhysicalDisplayId, DisplayModeId, Fps vsyncRate, Fps renderFps)
            REQUIRES(kMainThreadContext) EXCLUDES(mDisplayLock);

    void setActiveMode(PhysicalDisplayId, DisplayModeId, Fps vsyncRate, Fps renderFps)
            EXCLUDES(mDisplayLock);

private:
    struct Display {
        template <size_t N>
        std::string concatId(const char (&)[N]) const;

        Display(DisplaySnapshotRef, RefreshRateSelectorPtr);
        Display(DisplaySnapshotRef snapshot, DisplayModes modes, DisplayModeId activeModeId,
                scheduler::RefreshRateSelector::Config config)
              : Display(snapshot,
                        std::make_shared<scheduler::RefreshRateSelector>(std::move(modes),
                                                                         activeModeId, config)) {}
        const DisplaySnapshotRef snapshot;
        const RefreshRateSelectorPtr selectorPtr;

        const std::string pendingModeFpsTrace;
        const std::string activeModeFpsTrace;
        const std::string renderRateFpsTrace;

        std::mutex desiredModeLock;
        DisplayModeRequestOpt desiredModeOpt GUARDED_BY(desiredModeLock);
        TracedOrdinal<bool> hasDesiredModeTrace GUARDED_BY(desiredModeLock);

        DisplayModeRequestOpt pendingModeOpt GUARDED_BY(kMainThreadContext);
        bool isModeSetPending GUARDED_BY(kMainThreadContext) = false;
    };

    using DisplayPtr = std::unique_ptr<Display>;

    void setActiveModeLocked(PhysicalDisplayId, DisplayModeId, Fps vsyncRate, Fps renderFps)
            REQUIRES(mDisplayLock);

    // Set once when initializing the DisplayModeController, which the HWComposer must outlive.
    HWComposer* mComposerPtr = nullptr;

    ActiveModeListener mActiveModeListener;

    mutable std::mutex mDisplayLock;
    ui::PhysicalDisplayMap<PhysicalDisplayId, DisplayPtr> mDisplays GUARDED_BY(mDisplayLock);
};

} // namespace android::display
