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

#define LOG_TAG "PointerChoreographer"

#include <android-base/logging.h>
#include <input/PrintTools.h>

#include "PointerChoreographer.h"

#define INDENT "  "

namespace android {

namespace {
bool isFromMouse(const NotifyMotionArgs& args) {
    return isFromSource(args.source, AINPUT_SOURCE_MOUSE) &&
            args.pointerProperties[0].toolType == ToolType::MOUSE;
}

} // namespace

// --- PointerChoreographer ---

PointerChoreographer::PointerChoreographer(InputListenerInterface& listener,
                                           PointerChoreographerPolicyInterface& policy)
      : mNextListener(listener),
        mPolicy(policy),
        mDefaultMouseDisplayId(ADISPLAY_ID_DEFAULT),
        mNotifiedPointerDisplayId(ADISPLAY_ID_NONE) {}

void PointerChoreographer::notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) {
    std::scoped_lock _l(mLock);

    mInputDeviceInfos = args.inputDeviceInfos;
    updatePointerControllersLocked();
    mNextListener.notify(args);
}

void PointerChoreographer::notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) {
    mNextListener.notify(args);
}

void PointerChoreographer::notifyKey(const NotifyKeyArgs& args) {
    mNextListener.notify(args);
}

void PointerChoreographer::notifyMotion(const NotifyMotionArgs& args) {
    NotifyMotionArgs newArgs = processMotion(args);

    mNextListener.notify(newArgs);
}

NotifyMotionArgs PointerChoreographer::processMotion(const NotifyMotionArgs& args) {
    std::scoped_lock _l(mLock);

    if (isFromMouse(args)) {
        return processMouseEventLocked(args);
    } else if (isFromSource(args.source, AINPUT_SOURCE_TOUCHSCREEN)) {
        return processTouchscreenEventLocked(args);
    }
    return args;
}

NotifyMotionArgs PointerChoreographer::processMouseEventLocked(const NotifyMotionArgs& args) {
    if (args.getPointerCount() != 1) {
        LOG(FATAL) << "Only mouse events with a single pointer are currently supported: "
                   << args.dump();
    }

    const int32_t displayId = getTargetMouseDisplayLocked(args.displayId);

    // Get the mouse pointer controller for the display, or create one if it doesn't exist.
    auto [it, emplaced] =
            mMousePointersByDisplay.try_emplace(displayId,
                                                getMouseControllerConstructor(displayId));
    if (emplaced) {
        notifyPointerDisplayIdChangedLocked();
    }

    PointerControllerInterface& pc = *it->second;

    const float deltaX = args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X);
    const float deltaY = args.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y);
    pc.move(deltaX, deltaY);
    pc.unfade(PointerControllerInterface::Transition::IMMEDIATE);

    const auto [x, y] = pc.getPosition();
    NotifyMotionArgs newArgs(args);
    newArgs.pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, x);
    newArgs.pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, y);
    newArgs.xCursorPosition = x;
    newArgs.yCursorPosition = y;
    newArgs.displayId = displayId;
    return newArgs;
}

/**
 * When screen is touched, fade the mouse pointer on that display. We only call fade for
 * ACTION_DOWN events.This would allow both mouse and touch to be used at the same time if the
 * mouse device keeps moving and unfades the cursor.
 * For touch events, we do not need to populate the cursor position.
 */
NotifyMotionArgs PointerChoreographer::processTouchscreenEventLocked(const NotifyMotionArgs& args) {
    if (const auto it = mMousePointersByDisplay.find(args.displayId);
        it != mMousePointersByDisplay.end() && args.action == AMOTION_EVENT_ACTION_DOWN) {
        it->second->fade(PointerControllerInterface::Transition::GRADUAL);
    }
    return args;
}

void PointerChoreographer::notifySwitch(const NotifySwitchArgs& args) {
    mNextListener.notify(args);
}

void PointerChoreographer::notifySensor(const NotifySensorArgs& args) {
    mNextListener.notify(args);
}

void PointerChoreographer::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    mNextListener.notify(args);
}

void PointerChoreographer::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    mNextListener.notify(args);
}

void PointerChoreographer::notifyPointerCaptureChanged(
        const NotifyPointerCaptureChangedArgs& args) {
    if (args.request.enable) {
        std::scoped_lock _l(mLock);
        for (const auto& [_, mousePointerController] : mMousePointersByDisplay) {
            mousePointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
        }
    }
    mNextListener.notify(args);
}

void PointerChoreographer::dump(std::string& dump) {
    std::scoped_lock _l(mLock);

    dump += "PointerChoreographer:\n";

    dump += INDENT "MousePointerControllers:\n";
    for (const auto& [displayId, mousePointerController] : mMousePointersByDisplay) {
        std::string pointerControllerDump = addLinePrefix(mousePointerController->dump(), INDENT);
        dump += INDENT + std::to_string(displayId) + " : " + pointerControllerDump;
    }
    dump += "\n";
}

const DisplayViewport* PointerChoreographer::findViewportByIdLocked(int32_t displayId) const {
    for (auto& viewport : mViewports) {
        if (viewport.displayId == displayId) {
            return &viewport;
        }
    }
    return nullptr;
}

int32_t PointerChoreographer::getTargetMouseDisplayLocked(int32_t associatedDisplayId) const {
    return associatedDisplayId == ADISPLAY_ID_NONE ? mDefaultMouseDisplayId : associatedDisplayId;
}

void PointerChoreographer::updatePointerControllersLocked() {
    std::set<int32_t /*displayId*/> mouseDisplaysToKeep;

    // Mark the displayIds or deviceIds of PointerControllers currently needed.
    for (const auto& info : mInputDeviceInfos) {
        const uint32_t sources = info.getSources();
        if (isFromSource(sources, AINPUT_SOURCE_MOUSE) ||
            isFromSource(sources, AINPUT_SOURCE_MOUSE_RELATIVE)) {
            const int32_t resolvedDisplayId =
                    getTargetMouseDisplayLocked(info.getAssociatedDisplayId());
            mouseDisplaysToKeep.insert(resolvedDisplayId);
        }
    }

    // Remove PointerControllers no longer needed.
    // This has the side-effect of fading pointers or clearing spots before removal.
    std::erase_if(mMousePointersByDisplay, [&mouseDisplaysToKeep](const auto& pair) {
        auto& [displayId, controller] = pair;
        if (mouseDisplaysToKeep.find(displayId) == mouseDisplaysToKeep.end()) {
            controller->fade(PointerControllerInterface::Transition::IMMEDIATE);
            return true;
        }
        return false;
    });

    // Notify the policy if there's a change on the pointer display ID.
    notifyPointerDisplayIdChangedLocked();
}

void PointerChoreographer::notifyPointerDisplayIdChangedLocked() {
    int32_t displayIdToNotify = ADISPLAY_ID_NONE;
    FloatPoint cursorPosition = {0, 0};
    if (const auto it = mMousePointersByDisplay.find(mDefaultMouseDisplayId);
        it != mMousePointersByDisplay.end()) {
        const auto& pointerController = it->second;
        // Use the displayId from the pointerController, because it accurately reflects whether
        // the viewport has been added for that display. Otherwise, we would have to check if
        // the viewport exists separately.
        displayIdToNotify = pointerController->getDisplayId();
        cursorPosition = pointerController->getPosition();
    }

    if (mNotifiedPointerDisplayId == displayIdToNotify) {
        return;
    }
    mPolicy.notifyPointerDisplayIdChanged(displayIdToNotify, cursorPosition);
    mNotifiedPointerDisplayId = displayIdToNotify;
}

void PointerChoreographer::setDefaultMouseDisplayId(int32_t displayId) {
    std::scoped_lock _l(mLock);

    mDefaultMouseDisplayId = displayId;
    updatePointerControllersLocked();
}

void PointerChoreographer::setDisplayViewports(const std::vector<DisplayViewport>& viewports) {
    std::scoped_lock _l(mLock);
    for (const auto& viewport : viewports) {
        if (const auto it = mMousePointersByDisplay.find(viewport.displayId);
            it != mMousePointersByDisplay.end()) {
            it->second->setDisplayViewport(viewport);
        }
    }
    mViewports = viewports;
    notifyPointerDisplayIdChangedLocked();
}

std::optional<DisplayViewport> PointerChoreographer::getViewportForPointerDevice(
        int32_t associatedDisplayId) {
    std::scoped_lock _l(mLock);
    const int32_t resolvedDisplayId = getTargetMouseDisplayLocked(associatedDisplayId);
    if (const auto viewport = findViewportByIdLocked(resolvedDisplayId); viewport) {
        return *viewport;
    }
    return std::nullopt;
}

FloatPoint PointerChoreographer::getMouseCursorPosition(int32_t displayId) {
    std::scoped_lock _l(mLock);
    const int32_t resolvedDisplayId = getTargetMouseDisplayLocked(displayId);
    if (auto it = mMousePointersByDisplay.find(resolvedDisplayId);
        it != mMousePointersByDisplay.end()) {
        return it->second->getPosition();
    }
    return {AMOTION_EVENT_INVALID_CURSOR_POSITION, AMOTION_EVENT_INVALID_CURSOR_POSITION};
}

PointerChoreographer::ControllerConstructor PointerChoreographer::getMouseControllerConstructor(
        int32_t displayId) {
    std::function<std::shared_ptr<PointerControllerInterface>()> ctor =
            [this, displayId]() REQUIRES(mLock) {
                auto pc = mPolicy.createPointerController(
                        PointerControllerInterface::ControllerType::MOUSE);
                if (const auto viewport = findViewportByIdLocked(displayId); viewport) {
                    pc->setDisplayViewport(*viewport);
                }
                return pc;
            };
    return ConstructorDelegate(std::move(ctor));
}

} // namespace android
