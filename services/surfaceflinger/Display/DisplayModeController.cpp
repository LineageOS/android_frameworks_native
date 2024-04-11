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
#include "DisplayHardware/HWComposer.h"

#include <common/FlagManager.h>
#include <ftl/concat.h>
#include <ftl/expected.h>
#include <log/log.h>

namespace android::display {

template <size_t N>
inline std::string DisplayModeController::Display::concatId(const char (&str)[N]) const {
    return std::string(ftl::Concat(str, ' ', snapshot.get().displayId().value).str());
}

DisplayModeController::Display::Display(DisplaySnapshotRef snapshot,
                                        RefreshRateSelectorPtr selectorPtr)
      : snapshot(snapshot),
        selectorPtr(std::move(selectorPtr)),
        pendingModeFpsTrace(concatId("PendingModeFps")),
        activeModeFpsTrace(concatId("ActiveModeFps")),
        renderRateFpsTrace(concatId("RenderRateFps")),
        hasDesiredModeTrace(concatId("HasDesiredMode"), false) {}

void DisplayModeController::registerDisplay(PhysicalDisplayId displayId,
                                            DisplaySnapshotRef snapshotRef,
                                            RefreshRateSelectorPtr selectorPtr) {
    std::lock_guard lock(mDisplayLock);
    mDisplays.emplace_or_replace(displayId, std::make_unique<Display>(snapshotRef, selectorPtr));
}

void DisplayModeController::registerDisplay(DisplaySnapshotRef snapshotRef,
                                            DisplayModeId activeModeId,
                                            scheduler::RefreshRateSelector::Config config) {
    const auto& snapshot = snapshotRef.get();
    const auto displayId = snapshot.displayId();

    std::lock_guard lock(mDisplayLock);
    mDisplays.emplace_or_replace(displayId,
                                 std::make_unique<Display>(snapshotRef, snapshot.displayModes(),
                                                           activeModeId, config));
}

void DisplayModeController::unregisterDisplay(PhysicalDisplayId displayId) {
    std::lock_guard lock(mDisplayLock);
    const bool ok = mDisplays.erase(displayId);
    ALOGE_IF(!ok, "%s: Unknown display %s", __func__, to_string(displayId).c_str());
}

auto DisplayModeController::selectorPtrFor(PhysicalDisplayId displayId) const
        -> RefreshRateSelectorPtr {
    std::lock_guard lock(mDisplayLock);
    return mDisplays.get(displayId)
            .transform([](const DisplayPtr& displayPtr) { return displayPtr->selectorPtr; })
            .value_or(nullptr);
}

auto DisplayModeController::setDesiredMode(PhysicalDisplayId displayId,
                                           DisplayModeRequest&& desiredMode) -> DesiredModeAction {
    std::lock_guard lock(mDisplayLock);
    const auto& displayPtr =
            FTL_EXPECT(mDisplays.get(displayId).ok_or(DesiredModeAction::None)).get();

    {
        ATRACE_NAME(displayPtr->concatId(__func__).c_str());
        ALOGD("%s %s", displayPtr->concatId(__func__).c_str(), to_string(desiredMode).c_str());

        std::scoped_lock lock(displayPtr->desiredModeLock);

        if (auto& desiredModeOpt = displayPtr->desiredModeOpt) {
            // A mode transition was already scheduled, so just override the desired mode.
            const bool emitEvent = desiredModeOpt->emitEvent;
            const bool force = desiredModeOpt->force;
            desiredModeOpt = std::move(desiredMode);
            desiredModeOpt->emitEvent |= emitEvent;
            if (FlagManager::getInstance().connected_display()) {
                desiredModeOpt->force |= force;
            }
            return DesiredModeAction::None;
        }

        // If the desired mode is already active...
        const auto activeMode = displayPtr->selectorPtr->getActiveMode();
        if (const auto& desiredModePtr = desiredMode.mode.modePtr;
            !desiredMode.force && activeMode.modePtr->getId() == desiredModePtr->getId()) {
            if (activeMode == desiredMode.mode) {
                return DesiredModeAction::None;
            }

            // ...but the render rate changed:
            setActiveModeLocked(displayId, desiredModePtr->getId(), desiredModePtr->getVsyncRate(),
                                desiredMode.mode.fps);
            return DesiredModeAction::InitiateRenderRateSwitch;
        }

        // Restore peak render rate to schedule the next frame as soon as possible.
        setActiveModeLocked(displayId, activeMode.modePtr->getId(),
                            activeMode.modePtr->getVsyncRate(), activeMode.modePtr->getPeakFps());

        // Initiate a mode change.
        displayPtr->desiredModeOpt = std::move(desiredMode);
        displayPtr->hasDesiredModeTrace = true;
    }

    return DesiredModeAction::InitiateDisplayModeSwitch;
}

auto DisplayModeController::getDesiredMode(PhysicalDisplayId displayId) const
        -> DisplayModeRequestOpt {
    std::lock_guard lock(mDisplayLock);
    const auto& displayPtr =
            FTL_EXPECT(mDisplays.get(displayId).ok_or(DisplayModeRequestOpt())).get();

    {
        std::scoped_lock lock(displayPtr->desiredModeLock);
        return displayPtr->desiredModeOpt;
    }
}

auto DisplayModeController::getPendingMode(PhysicalDisplayId displayId) const
        -> DisplayModeRequestOpt {
    std::lock_guard lock(mDisplayLock);
    const auto& displayPtr =
            FTL_EXPECT(mDisplays.get(displayId).ok_or(DisplayModeRequestOpt())).get();

    {
        std::scoped_lock lock(displayPtr->desiredModeLock);
        return displayPtr->pendingModeOpt;
    }
}

bool DisplayModeController::isModeSetPending(PhysicalDisplayId displayId) const {
    std::lock_guard lock(mDisplayLock);
    const auto& displayPtr = FTL_EXPECT(mDisplays.get(displayId).ok_or(false)).get();

    {
        std::scoped_lock lock(displayPtr->desiredModeLock);
        return displayPtr->isModeSetPending;
    }
}

scheduler::FrameRateMode DisplayModeController::getActiveMode(PhysicalDisplayId displayId) const {
    return selectorPtrFor(displayId)->getActiveMode();
}

void DisplayModeController::clearDesiredMode(PhysicalDisplayId displayId) {
    std::lock_guard lock(mDisplayLock);
    const auto& displayPtr = FTL_TRY(mDisplays.get(displayId).ok_or(ftl::Unit())).get();

    {
        std::scoped_lock lock(displayPtr->desiredModeLock);
        displayPtr->desiredModeOpt.reset();
        displayPtr->hasDesiredModeTrace = false;
    }
}

bool DisplayModeController::initiateModeChange(PhysicalDisplayId displayId,
                                               DisplayModeRequest&& desiredMode,
                                               const hal::VsyncPeriodChangeConstraints& constraints,
                                               hal::VsyncPeriodChangeTimeline& outTimeline) {
    std::lock_guard lock(mDisplayLock);
    const auto& displayPtr = FTL_EXPECT(mDisplays.get(displayId).ok_or(false)).get();

    // TODO: b/255635711 - Flow the DisplayModeRequest through the desired/pending/active states.
    // For now, `desiredMode` and `desiredModeOpt` are one and the same, but the latter is not
    // cleared until the next `SF::initiateDisplayModeChanges`. However, the desired mode has been
    // consumed at this point, so clear the `force` flag to prevent an endless loop of
    // `initiateModeChange`.
    if (FlagManager::getInstance().connected_display()) {
        std::scoped_lock lock(displayPtr->desiredModeLock);
        if (displayPtr->desiredModeOpt) {
            displayPtr->desiredModeOpt->force = false;
        }
    }

    displayPtr->pendingModeOpt = std::move(desiredMode);
    displayPtr->isModeSetPending = true;

    const auto& mode = *displayPtr->pendingModeOpt->mode.modePtr;

    if (mComposerPtr->setActiveModeWithConstraints(displayId, mode.getHwcId(), constraints,
                                                   &outTimeline) != OK) {
        return false;
    }

    ATRACE_INT(displayPtr->pendingModeFpsTrace.c_str(), mode.getVsyncRate().getIntValue());
    return true;
}

void DisplayModeController::finalizeModeChange(PhysicalDisplayId displayId, DisplayModeId modeId,
                                               Fps vsyncRate, Fps renderFps) {
    std::lock_guard lock(mDisplayLock);
    setActiveModeLocked(displayId, modeId, vsyncRate, renderFps);

    const auto& displayPtr = FTL_TRY(mDisplays.get(displayId).ok_or(ftl::Unit())).get();
    displayPtr->isModeSetPending = false;
}

void DisplayModeController::setActiveMode(PhysicalDisplayId displayId, DisplayModeId modeId,
                                          Fps vsyncRate, Fps renderFps) {
    std::lock_guard lock(mDisplayLock);
    setActiveModeLocked(displayId, modeId, vsyncRate, renderFps);
}

void DisplayModeController::setActiveModeLocked(PhysicalDisplayId displayId, DisplayModeId modeId,
                                                Fps vsyncRate, Fps renderFps) {
    const auto& displayPtr = FTL_TRY(mDisplays.get(displayId).ok_or(ftl::Unit())).get();

    ATRACE_INT(displayPtr->activeModeFpsTrace.c_str(), vsyncRate.getIntValue());
    ATRACE_INT(displayPtr->renderRateFpsTrace.c_str(), renderFps.getIntValue());

    displayPtr->selectorPtr->setActiveMode(modeId, renderFps);

    if (mActiveModeListener) {
        mActiveModeListener(displayId, vsyncRate, renderFps);
    }
}

} // namespace android::display
