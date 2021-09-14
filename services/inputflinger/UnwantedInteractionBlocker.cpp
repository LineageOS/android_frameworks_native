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

#define LOG_TAG "UnwantedInteractionBlocker"
#include "UnwantedInteractionBlocker.h"

#include <android-base/stringprintf.h>
#include <inttypes.h>
#include <linux/input-event-codes.h>
#include <linux/input.h>
#include <server_configurable_flags/get_flags.h>

#include "ui/events/ozone/evdev/touch_filter/neural_stylus_palm_detection_filter.h"
#include "ui/events/ozone/evdev/touch_filter/palm_model/onedevice_train_palm_detection_filter_model.h"

using android::base::StringPrintf;

namespace android {

// Category (=namespace) name for the input settings that are applied at boot time
static const char* INPUT_NATIVE_BOOT = "input_native_boot";
/**
 * Feature flag name. This flag determines whether palm rejection is enabled. To enable, specify
 * 'true' (not case sensitive) or '1'. To disable, specify any other value.
 */
static const char* PALM_REJECTION_ENABLED = "palm_rejection_enabled";

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static bool isFromTouchscreen(int32_t source) {
    return isFromSource(source, AINPUT_SOURCE_TOUCHSCREEN);
}

static ::base::TimeTicks toChromeTimestamp(nsecs_t eventTime) {
    return ::base::TimeTicks::UnixEpoch() +
            ::base::Milliseconds(static_cast<float>(ns2ms(eventTime)));
}

/**
 * Return true if palm rejection is enabled via the server configurable flags. Return false
 * otherwise.
 */
static bool isPalmRejectionEnabled() {
    std::string value = toLower(
            server_configurable_flags::GetServerConfigurableFlag(INPUT_NATIVE_BOOT,
                                                                 PALM_REJECTION_ENABLED, "false"));
    if (value == "true" || value == "1") {
        return true;
    }
    return false;
}

static int getLinuxToolType(int32_t toolType) {
    switch (toolType) {
        case AMOTION_EVENT_TOOL_TYPE_FINGER:
            return MT_TOOL_FINGER;
        case AMOTION_EVENT_TOOL_TYPE_STYLUS:
            return MT_TOOL_PEN;
        case AMOTION_EVENT_TOOL_TYPE_PALM:
            return MT_TOOL_PALM;
    }
    ALOGW("Got tool type %" PRId32 ", converting to MT_TOOL_FINGER", toolType);
    return MT_TOOL_FINGER;
}

static std::string addPrefix(std::string str, const std::string& prefix) {
    std::stringstream ss;
    bool newLineStarted = true;
    for (const auto& ch : str) {
        if (newLineStarted) {
            ss << prefix;
            newLineStarted = false;
        }
        if (ch == '\n') {
            newLineStarted = true;
        }
        ss << ch;
    }
    return ss.str();
}

template <typename T>
static std::string dumpSet(const std::set<T>& v) {
    static_assert(std::is_integral<T>::value, "Only integral types can be printed.");
    std::string out;
    for (const T& entry : v) {
        out += out.empty() ? "{" : ", ";
        out += android::base::StringPrintf("%i", entry);
    }
    return out.empty() ? "{}" : (out + "}");
}

template <typename K, typename V>
static std::string dumpMap(const std::map<K, V>& map) {
    static_assert(std::is_integral<K>::value, "Keys should have integral type to be printed.");
    static_assert(std::is_integral<V>::value, "Values should have integral type to be printed.");
    std::string out;
    for (const auto& [k, v] : map) {
        if (!out.empty()) {
            out += "\n";
        }
        out += android::base::StringPrintf("%i : %i", static_cast<int>(k), static_cast<int>(v));
    }
    return out;
}

static std::string dumpDeviceInfo(const AndroidPalmFilterDeviceInfo& info) {
    std::string out;
    out += StringPrintf("max_x = %.2f\n", info.max_x);
    out += StringPrintf("max_y = %.2f\n", info.max_y);
    out += StringPrintf("x_res = %.2f\n", info.x_res);
    out += StringPrintf("y_res = %.2f\n", info.y_res);
    out += StringPrintf("major_radius_res = %.2f\n", info.major_radius_res);
    out += StringPrintf("minor_radius_res = %.2f\n", info.minor_radius_res);
    out += StringPrintf("minor_radius_supported = %s\n",
                        info.minor_radius_supported ? "true" : "false");
    out += StringPrintf("touch_major_res = %" PRId32 "\n", info.touch_major_res);
    out += StringPrintf("touch_minor_res = %" PRId32 "\n", info.touch_minor_res);
    return out;
}

static int32_t getActionUpForPointerId(const NotifyMotionArgs& args, int32_t pointerId) {
    for (size_t i = 0; i < args.pointerCount; i++) {
        if (pointerId == args.pointerProperties[i].id) {
            return AMOTION_EVENT_ACTION_POINTER_UP |
                    (i << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        }
    }
    LOG_ALWAYS_FATAL("Can't find pointerId %" PRId32 " in %s", pointerId, args.dump().c_str());
}

/**
 * Find the action for individual pointer at the given pointer index.
 * This is always equal to MotionEvent::getActionMasked, except for
 * POINTER_UP or POINTER_DOWN events. For example, in a POINTER_UP event, the action for
 * the active pointer is ACTION_POINTER_UP, while the action for the other pointers is ACTION_MOVE.
 */
static int32_t resolveActionForPointer(uint8_t pointerIndex, int32_t action) {
    const int32_t actionMasked = MotionEvent::getActionMasked(action);
    if (actionMasked != AMOTION_EVENT_ACTION_POINTER_DOWN &&
        actionMasked != AMOTION_EVENT_ACTION_POINTER_UP) {
        return actionMasked;
    }
    // This is a POINTER_DOWN or POINTER_UP event
    const uint8_t actionIndex = MotionEvent::getActionIndex(action);
    if (pointerIndex == actionIndex) {
        return actionMasked;
    }
    // When POINTER_DOWN or POINTER_UP happens, it's actually a MOVE for all of the other
    // pointers
    return AMOTION_EVENT_ACTION_MOVE;
}

static const char* toString(bool value) {
    return value ? "true" : "false";
}

std::string toString(const ::ui::InProgressTouchEvdev& touch) {
    return StringPrintf("x=%.1f, y=%.1f, tracking_id=%i, slot=%zu,"
                        " pressure=%.1f, major=%i, minor=%i, "
                        "tool_type=%i, altered=%s, was_touching=%s, touching=%s",
                        touch.x, touch.y, touch.tracking_id, touch.slot, touch.pressure,
                        touch.major, touch.minor, touch.tool_type, toString(touch.altered),
                        toString(touch.was_touching), toString(touch.touching));
}

/**
 * Remove the data for the provided pointers from the args. The pointers are identified by their
 * pointerId, not by the index inside the array.
 * Return the new NotifyMotionArgs struct that has the remaining pointers.
 * The only fields that may be different in the returned args from the provided args are:
 *     - action
 *     - pointerCount
 *     - pointerProperties
 *     - pointerCoords
 * Action might change because it contains a pointer index. If another pointer is removed, the
 * active pointer index would be shifted.
 * Do not call this function for events with POINTER_UP or POINTER_DOWN events when removed pointer
 * id is the acting pointer id.
 *
 * @param args the args from which the pointers should be removed
 * @param pointerIds the pointer ids of the pointers that should be removed
 */
NotifyMotionArgs removePointerIds(const NotifyMotionArgs& args,
                                  const std::set<int32_t>& pointerIds) {
    const uint8_t actionIndex = MotionEvent::getActionIndex(args.action);
    const int32_t actionMasked = MotionEvent::getActionMasked(args.action);
    const bool isPointerUpOrDownAction = actionMasked == AMOTION_EVENT_ACTION_POINTER_DOWN ||
            actionMasked == AMOTION_EVENT_ACTION_POINTER_UP;

    NotifyMotionArgs newArgs{args};
    newArgs.pointerCount = 0;
    int32_t newActionIndex = 0;
    for (uint32_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        if (pointerIds.find(pointerId) != pointerIds.end()) {
            // skip this pointer
            if (isPointerUpOrDownAction && i == actionIndex) {
                // The active pointer is being removed, so the action is no longer valid.
                // Set the action to 'UNKNOWN' here. The caller is responsible for updating this
                // action later to a proper value.
                newArgs.action = ACTION_UNKNOWN;
            }
            continue;
        }
        newArgs.pointerProperties[newArgs.pointerCount].copyFrom(args.pointerProperties[i]);
        newArgs.pointerCoords[newArgs.pointerCount].copyFrom(args.pointerCoords[i]);
        if (i == actionIndex) {
            newActionIndex = newArgs.pointerCount;
        }
        newArgs.pointerCount++;
    }
    // Update POINTER_DOWN or POINTER_UP actions
    if (isPointerUpOrDownAction && newArgs.action != ACTION_UNKNOWN) {
        newArgs.action =
                actionMasked | (newActionIndex << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        // Convert POINTER_DOWN and POINTER_UP to DOWN and UP if there's only 1 pointer remaining
        if (newArgs.pointerCount == 1) {
            if (actionMasked == AMOTION_EVENT_ACTION_POINTER_DOWN) {
                newArgs.action = AMOTION_EVENT_ACTION_DOWN;
            } else if (actionMasked == AMOTION_EVENT_ACTION_POINTER_UP) {
                newArgs.action = AMOTION_EVENT_ACTION_UP;
            }
        }
    }
    return newArgs;
}

std::optional<AndroidPalmFilterDeviceInfo> createPalmFilterDeviceInfo(
        const InputDeviceInfo& deviceInfo) {
    if (!isFromTouchscreen(deviceInfo.getSources())) {
        return std::nullopt;
    }
    AndroidPalmFilterDeviceInfo out;
    const InputDeviceInfo::MotionRange* axisX =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_X, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisX != nullptr) {
        out.max_x = axisX->max;
        out.x_res = axisX->resolution;
    } else {
        ALOGW("Palm rejection is disabled for %s because AXIS_X is not supported",
              deviceInfo.getDisplayName().c_str());
        return std::nullopt;
    }
    const InputDeviceInfo::MotionRange* axisY =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_Y, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisY != nullptr) {
        out.max_y = axisY->max;
        out.y_res = axisY->resolution;
    } else {
        ALOGW("Palm rejection is disabled for %s because AXIS_Y is not supported",
              deviceInfo.getDisplayName().c_str());
        return std::nullopt;
    }
    const InputDeviceInfo::MotionRange* axisMajor =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_TOUCH_MAJOR, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisMajor != nullptr) {
        out.major_radius_res = axisMajor->resolution;
        out.touch_major_res = axisMajor->resolution;
    } else {
        return std::nullopt;
    }
    const InputDeviceInfo::MotionRange* axisMinor =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_TOUCH_MINOR, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisMinor != nullptr) {
        out.minor_radius_res = axisMinor->resolution;
        out.touch_minor_res = axisMinor->resolution;
        out.minor_radius_supported = true;
    } else {
        out.minor_radius_supported = false;
    }

    return out;
}

/**
 * Synthesize CANCEL events for any new pointers that should be canceled, while removing pointers
 * that have already been canceled.
 * The flow of the function is as follows:
 * 1. Remove all already canceled pointers
 * 2. Cancel all newly suppressed pointers
 * 3. Decide what to do with the current event : keep it, or drop it
 * The pointers can never be "unsuppressed": once a pointer is canceled, it will never become valid.
 */
std::vector<NotifyMotionArgs> cancelSuppressedPointers(
        const NotifyMotionArgs& args, const std::set<int32_t>& oldSuppressedPointerIds,
        const std::set<int32_t>& newSuppressedPointerIds) {
    LOG_ALWAYS_FATAL_IF(args.pointerCount == 0, "0 pointers in %s", args.dump().c_str());

    // First, let's remove the old suppressed pointers. They've already been canceled previously.
    NotifyMotionArgs oldArgs = removePointerIds(args, oldSuppressedPointerIds);

    // Cancel any newly suppressed pointers.
    std::vector<NotifyMotionArgs> out;
    const int32_t activePointerId =
            args.pointerProperties[MotionEvent::getActionIndex(args.action)].id;
    const int32_t actionMasked = MotionEvent::getActionMasked(args.action);
    // We will iteratively remove pointers from 'removedArgs'.
    NotifyMotionArgs removedArgs{oldArgs};
    for (uint32_t i = 0; i < oldArgs.pointerCount; i++) {
        const int32_t pointerId = oldArgs.pointerProperties[i].id;
        if (newSuppressedPointerIds.find(pointerId) == newSuppressedPointerIds.end()) {
            // This is a pointer that should not be canceled. Move on.
            continue;
        }
        if (pointerId == activePointerId && actionMasked == AMOTION_EVENT_ACTION_POINTER_DOWN) {
            // Remove this pointer, but don't cancel it. We'll just not send the POINTER_DOWN event
            removedArgs = removePointerIds(removedArgs, {pointerId});
            continue;
        }

        if (removedArgs.pointerCount == 1) {
            // We are about to remove the last pointer, which means there will be no more gesture
            // remaining. This is identical to canceling all pointers, so just send a single CANCEL
            // event, without any of the preceding POINTER_UP with FLAG_CANCELED events.
            oldArgs.flags |= AMOTION_EVENT_FLAG_CANCELED;
            oldArgs.action = AMOTION_EVENT_ACTION_CANCEL;
            return {oldArgs};
        }
        // Cancel the current pointer
        out.push_back(removedArgs);
        out.back().flags |= AMOTION_EVENT_FLAG_CANCELED;
        out.back().action = getActionUpForPointerId(out.back(), pointerId);

        // Remove the newly canceled pointer from the args
        removedArgs = removePointerIds(removedArgs, {pointerId});
    }

    // Now 'removedArgs' contains only pointers that are valid.
    if (removedArgs.pointerCount <= 0 || removedArgs.action == ACTION_UNKNOWN) {
        return out;
    }
    out.push_back(removedArgs);
    return out;
}

UnwantedInteractionBlocker::UnwantedInteractionBlocker(InputListenerInterface& listener)
      : UnwantedInteractionBlocker(listener, isPalmRejectionEnabled()){};

UnwantedInteractionBlocker::UnwantedInteractionBlocker(InputListenerInterface& listener,
                                                       bool enablePalmRejection)
      : mListener(listener), mEnablePalmRejection(enablePalmRejection) {}

void UnwantedInteractionBlocker::notifyConfigurationChanged(
        const NotifyConfigurationChangedArgs* args) {
    mListener.notifyConfigurationChanged(args);
}

void UnwantedInteractionBlocker::notifyKey(const NotifyKeyArgs* args) {
    mListener.notifyKey(args);
}

void UnwantedInteractionBlocker::notifyMotion(const NotifyMotionArgs* args) {
    auto it = mPalmRejectors.find(args->deviceId);
    const bool sendToPalmRejector = it != mPalmRejectors.end() && isFromTouchscreen(args->source);
    if (!sendToPalmRejector) {
        mListener.notifyMotion(args);
        return;
    }

    const std::vector<NotifyMotionArgs> newMotions = it->second.processMotion(*args);
    for (const NotifyMotionArgs& newArgs : newMotions) {
        mListener.notifyMotion(&newArgs);
    }
}

void UnwantedInteractionBlocker::notifySwitch(const NotifySwitchArgs* args) {
    mListener.notifySwitch(args);
}

void UnwantedInteractionBlocker::notifySensor(const NotifySensorArgs* args) {
    mListener.notifySensor(args);
}

void UnwantedInteractionBlocker::notifyVibratorState(const NotifyVibratorStateArgs* args) {
    mListener.notifyVibratorState(args);
}
void UnwantedInteractionBlocker::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
    auto it = mPalmRejectors.find(args->deviceId);
    if (it != mPalmRejectors.end()) {
        AndroidPalmFilterDeviceInfo info = it->second.getPalmFilterDeviceInfo();
        // Re-create the object instead of resetting it
        mPalmRejectors.erase(it);
        mPalmRejectors.emplace(args->deviceId, info);
    }
    mListener.notifyDeviceReset(args);
}

void UnwantedInteractionBlocker::notifyPointerCaptureChanged(
        const NotifyPointerCaptureChangedArgs* args) {
    mListener.notifyPointerCaptureChanged(args);
}

void UnwantedInteractionBlocker::notifyInputDevicesChanged(
        const std::vector<InputDeviceInfo>& inputDevices) {
    if (!mEnablePalmRejection) {
        // Palm rejection is disabled. Don't create any palm rejector objects.
        return;
    }

    // Let's see which of the existing devices didn't change, so that we can keep them
    // and prevent event stream disruption
    std::set<int32_t /*deviceId*/> devicesToKeep;
    for (const InputDeviceInfo& device : inputDevices) {
        std::optional<AndroidPalmFilterDeviceInfo> info = createPalmFilterDeviceInfo(device);
        if (!info) {
            continue;
        }

        auto [it, emplaced] = mPalmRejectors.try_emplace(device.getId(), *info);
        if (!emplaced && *info != it->second.getPalmFilterDeviceInfo()) {
            // Re-create the PalmRejector because the device info has changed.
            mPalmRejectors.erase(it);
            mPalmRejectors.emplace(device.getId(), *info);
        }
        devicesToKeep.insert(device.getId());
    }
    // Delete all devices that we don't need to keep
    std::erase_if(mPalmRejectors, [&devicesToKeep](const auto& item) {
        auto const& [deviceId, _] = item;
        return devicesToKeep.find(deviceId) == devicesToKeep.end();
    });
}

void UnwantedInteractionBlocker::dump(std::string& dump) {
    dump += "UnwantedInteractionBlocker:\n";
    dump += StringPrintf("  mEnablePalmRejection: %s\n", toString(mEnablePalmRejection));
    dump += StringPrintf("  isPalmRejectionEnabled (flag value): %s\n",
                         toString(isPalmRejectionEnabled()));
    dump += mPalmRejectors.empty() ? "  mPalmRejectors: None\n" : "  mPalmRejectors:\n";
    for (const auto& [deviceId, palmRejector] : mPalmRejectors) {
        dump += StringPrintf("    deviceId = %" PRId32 ":\n", deviceId);
        dump += addPrefix(palmRejector.dump(), "      ");
    }
}

void UnwantedInteractionBlocker::monitor() {}

UnwantedInteractionBlocker::~UnwantedInteractionBlocker() {}

void SlotState::update(const NotifyMotionArgs& args) {
    for (size_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        const int32_t resolvedAction = resolveActionForPointer(i, args.action);
        processPointerId(pointerId, resolvedAction);
    }
}

size_t SlotState::findUnusedSlot() const {
    size_t unusedSlot = 0;
    // Since the collection is ordered, we can rely on the in-order traversal
    for (const auto& [slot, trackingId] : mPointerIdsBySlot) {
        if (unusedSlot != slot) {
            break;
        }
        unusedSlot++;
    }
    return unusedSlot;
}

void SlotState::processPointerId(int pointerId, int32_t actionMasked) {
    switch (MotionEvent::getActionMasked(actionMasked)) {
        case AMOTION_EVENT_ACTION_DOWN:
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
        case AMOTION_EVENT_ACTION_HOVER_ENTER: {
            // New pointer going down
            size_t newSlot = findUnusedSlot();
            mPointerIdsBySlot[newSlot] = pointerId;
            mSlotsByPointerId[pointerId] = newSlot;
            return;
        }
        case AMOTION_EVENT_ACTION_MOVE:
        case AMOTION_EVENT_ACTION_HOVER_MOVE: {
            return;
        }
        case AMOTION_EVENT_ACTION_CANCEL:
        case AMOTION_EVENT_ACTION_POINTER_UP:
        case AMOTION_EVENT_ACTION_UP:
        case AMOTION_EVENT_ACTION_HOVER_EXIT: {
            auto it = mSlotsByPointerId.find(pointerId);
            LOG_ALWAYS_FATAL_IF(it == mSlotsByPointerId.end());
            size_t slot = it->second;
            // Erase this pointer from both collections
            mPointerIdsBySlot.erase(slot);
            mSlotsByPointerId.erase(pointerId);
            return;
        }
    }
    LOG_ALWAYS_FATAL("Unhandled action : %s", MotionEvent::actionToString(actionMasked).c_str());
    return;
}

std::optional<size_t> SlotState::getSlotForPointerId(int32_t pointerId) const {
    auto it = mSlotsByPointerId.find(pointerId);
    if (it == mSlotsByPointerId.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::string SlotState::dump() const {
    std::string out = "mSlotsByPointerId:\n";
    out += addPrefix(dumpMap(mSlotsByPointerId), "  ") + "\n";
    out += "mPointerIdsBySlot:\n";
    out += addPrefix(dumpMap(mPointerIdsBySlot), "  ") + "\n";
    return out;
}

PalmRejector::PalmRejector(const AndroidPalmFilterDeviceInfo& info,
                           std::unique_ptr<::ui::PalmDetectionFilter> filter)
      : mSharedPalmState(std::make_unique<::ui::SharedPalmDetectionFilterState>()),
        mDeviceInfo(info),
        mPalmDetectionFilter(std::move(filter)) {
    if (mPalmDetectionFilter != nullptr) {
        // This path is used for testing. Non-testing invocations should let this constructor
        // create a real PalmDetectionFilter
        return;
    }
    std::unique_ptr<::ui::NeuralStylusPalmDetectionFilterModel> model =
            std::make_unique<::ui::OneDeviceTrainNeuralStylusPalmDetectionFilterModel>(
                    std::vector<float>());
    mPalmDetectionFilter =
            std::make_unique<::ui::NeuralStylusPalmDetectionFilter>(mDeviceInfo, std::move(model),
                                                                    mSharedPalmState.get());
}

std::vector<::ui::InProgressTouchEvdev> getTouches(const NotifyMotionArgs& args,
                                                   const AndroidPalmFilterDeviceInfo& deviceInfo,
                                                   const SlotState& oldSlotState,
                                                   const SlotState& newSlotState) {
    std::vector<::ui::InProgressTouchEvdev> touches;

    for (size_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        touches.emplace_back(::ui::InProgressTouchEvdev());
        touches.back().major = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR);
        touches.back().minor = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR);
        touches.back().tool_type = getLinuxToolType(args.pointerProperties[i].toolType);

        // Whether there is new information for the touch.
        touches.back().altered = true;

        // Whether the touch was cancelled. Touch events should be ignored till a
        // new touch is initiated.
        touches.back().was_cancelled = false;

        // Whether the touch is going to be canceled.
        touches.back().cancelled = false;

        // Whether the touch is delayed at first appearance. Will not be reported yet.
        touches.back().delayed = false;

        // Whether the touch was delayed before.
        touches.back().was_delayed = false;

        // Whether the touch is held until end or no longer held.
        touches.back().held = false;

        // Whether this touch was held before being sent.
        touches.back().was_held = false;

        const int32_t resolvedAction = resolveActionForPointer(i, args.action);
        const bool isDown = resolvedAction == AMOTION_EVENT_ACTION_POINTER_DOWN ||
                resolvedAction == AMOTION_EVENT_ACTION_DOWN;
        touches.back().was_touching = !isDown;

        const bool isUpOrCancel = resolvedAction == AMOTION_EVENT_ACTION_CANCEL ||
                resolvedAction == AMOTION_EVENT_ACTION_UP ||
                resolvedAction == AMOTION_EVENT_ACTION_POINTER_UP;

        touches.back().x = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_X);
        touches.back().y = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_Y);

        std::optional<size_t> slot = newSlotState.getSlotForPointerId(pointerId);
        if (!slot) {
            slot = oldSlotState.getSlotForPointerId(pointerId);
        }
        LOG_ALWAYS_FATAL_IF(!slot, "Could not find slot for pointer %d", pointerId);
        touches.back().slot = *slot;
        touches.back().tracking_id = (!isUpOrCancel) ? pointerId : -1;
        touches.back().touching = !isUpOrCancel;

        // The fields 'radius_x' and 'radius_x' are not used for palm rejection
        touches.back().pressure = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE);
        touches.back().tool_code = BTN_TOOL_FINGER;
        // The field 'orientation' is not used for palm rejection
        // The fields 'tilt_x' and 'tilt_y' are not used for palm rejection
        touches.back().reported_tool_type = ::ui::EventPointerType::kTouch;
        touches.back().stylus_button = false;
    }
    return touches;
}

std::vector<NotifyMotionArgs> PalmRejector::processMotion(const NotifyMotionArgs& args) {
    if (mPalmDetectionFilter == nullptr) {
        return {args};
    }
    const bool skipThisEvent = args.action == AMOTION_EVENT_ACTION_HOVER_ENTER ||
            args.action == AMOTION_EVENT_ACTION_HOVER_MOVE ||
            args.action == AMOTION_EVENT_ACTION_HOVER_EXIT ||
            args.action == AMOTION_EVENT_ACTION_BUTTON_PRESS ||
            args.action == AMOTION_EVENT_ACTION_BUTTON_RELEASE ||
            args.action == AMOTION_EVENT_ACTION_SCROLL;
    if (skipThisEvent) {
        // Lets not process hover events, button events, or scroll for now.
        return {args};
    }
    if (args.action == AMOTION_EVENT_ACTION_DOWN) {
        mSuppressedPointerIds.clear();
    }
    std::bitset<::ui::kNumTouchEvdevSlots> slotsToHold;
    std::bitset<::ui::kNumTouchEvdevSlots> slotsToSuppress;

    // Store the slot state before we call getTouches and update it. This way, we can find
    // the slots that have been removed due to the incoming event.
    SlotState oldSlotState = mSlotState;
    mSlotState.update(args);
    std::vector<::ui::InProgressTouchEvdev> touches =
            getTouches(args, mDeviceInfo, oldSlotState, mSlotState);
    ::base::TimeTicks chromeTimestamp = toChromeTimestamp(args.eventTime);

    mPalmDetectionFilter->Filter(touches, chromeTimestamp, &slotsToHold, &slotsToSuppress);

    // Now that we know which slots should be suppressed, let's convert those to pointer id's.
    std::set<int32_t> oldSuppressedIds;
    std::swap(oldSuppressedIds, mSuppressedPointerIds);
    for (size_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        std::optional<size_t> slot = oldSlotState.getSlotForPointerId(pointerId);
        if (!slot) {
            slot = mSlotState.getSlotForPointerId(pointerId);
            LOG_ALWAYS_FATAL_IF(!slot, "Could not find slot for pointer id %" PRId32, pointerId);
        }
        if (slotsToSuppress.test(*slot)) {
            mSuppressedPointerIds.insert(pointerId);
        }
    }

    std::vector<NotifyMotionArgs> argsWithoutUnwantedPointers =
            cancelSuppressedPointers(args, oldSuppressedIds, mSuppressedPointerIds);
    for (const NotifyMotionArgs& checkArgs : argsWithoutUnwantedPointers) {
        LOG_ALWAYS_FATAL_IF(checkArgs.action == ACTION_UNKNOWN, "%s", checkArgs.dump().c_str());
    }

    if (mSuppressedPointerIds != oldSuppressedIds) {
        if (argsWithoutUnwantedPointers.size() != 1 ||
            argsWithoutUnwantedPointers[0].pointerCount != args.pointerCount) {
            ALOGI("Palm detected, removing pointer ids %s from %s",
                  dumpSet(mSuppressedPointerIds).c_str(), args.dump().c_str());
        }
    }

    return argsWithoutUnwantedPointers;
}

const AndroidPalmFilterDeviceInfo& PalmRejector::getPalmFilterDeviceInfo() {
    return mDeviceInfo;
}

std::string PalmRejector::dump() const {
    std::string out;
    out += "mDeviceInfo:\n";
    out += addPrefix(dumpDeviceInfo(mDeviceInfo), "  ");
    out += "mSlotState:\n";
    out += addPrefix(mSlotState.dump(), "  ");
    out += "mSuppressedPointerIds: ";
    out += dumpSet(mSuppressedPointerIds) + "\n";
    return out;
}

} // namespace android
