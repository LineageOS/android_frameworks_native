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

#define LOG_TAG "InputDeviceMetricsCollector"
#include "InputDeviceMetricsCollector.h"

#include "KeyCodeClassifications.h"

#include <android-base/stringprintf.h>
#include <input/PrintTools.h>
#include <linux/input.h>

namespace android {

using android::base::StringPrintf;
using std::chrono::nanoseconds;

namespace {

constexpr nanoseconds DEFAULT_USAGE_SESSION_TIMEOUT = std::chrono::seconds(5);

/**
 * Log debug messages about metrics events logged to statsd.
 * Enable this via "adb shell setprop log.tag.InputDeviceMetricsCollector DEBUG" (requires restart)
 */
const bool DEBUG = __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG, ANDROID_LOG_INFO);

int32_t linuxBusToInputDeviceBusEnum(int32_t linuxBus) {
    switch (linuxBus) {
        case BUS_USB:
            return util::INPUT_DEVICE_USAGE_REPORTED__DEVICE_BUS__USB;
        case BUS_BLUETOOTH:
            return util::INPUT_DEVICE_USAGE_REPORTED__DEVICE_BUS__BLUETOOTH;
        default:
            return util::INPUT_DEVICE_USAGE_REPORTED__DEVICE_BUS__OTHER;
    }
}

class : public InputDeviceMetricsLogger {
    nanoseconds getCurrentTime() override { return nanoseconds(systemTime(SYSTEM_TIME_MONOTONIC)); }

    void logInputDeviceUsageReported(const InputDeviceIdentifier& identifier,
                                     nanoseconds sessionDuration) override {
        const int32_t durationMillis =
                std::chrono::duration_cast<std::chrono::milliseconds>(sessionDuration).count();
        const static std::vector<int32_t> empty;

        ALOGD_IF(DEBUG, "Usage session reported for device: %s", identifier.name.c_str());
        ALOGD_IF(DEBUG, "    Total duration: %dms", durationMillis);

        util::stats_write(util::INPUTDEVICE_USAGE_REPORTED, identifier.vendor, identifier.product,
                          identifier.version, linuxBusToInputDeviceBusEnum(identifier.bus),
                          durationMillis, /*usage_sources=*/empty,
                          /*usage_durations_per_source=*/empty, /*uids=*/empty,
                          /*usage_durations_per_uid=*/empty);
    }
} sStatsdLogger;

bool isIgnoredInputDeviceId(int32_t deviceId) {
    switch (deviceId) {
        case INVALID_INPUT_DEVICE_ID:
        case VIRTUAL_KEYBOARD_ID:
            return true;
        default:
            return false;
    }
}

} // namespace

InputDeviceUsageSource getUsageSourceForKeyArgs(const InputDeviceInfo& info,
                                                const NotifyKeyArgs& keyArgs) {
    if (!isFromSource(keyArgs.source, AINPUT_SOURCE_KEYBOARD)) {
        return InputDeviceUsageSource::UNKNOWN;
    }

    if (isFromSource(keyArgs.source, AINPUT_SOURCE_DPAD) &&
        DPAD_ALL_KEYCODES.count(keyArgs.keyCode) != 0) {
        return InputDeviceUsageSource::DPAD;
    }

    if (isFromSource(keyArgs.source, AINPUT_SOURCE_GAMEPAD) &&
        GAMEPAD_KEYCODES.count(keyArgs.keyCode) != 0) {
        return InputDeviceUsageSource::GAMEPAD;
    }

    if (info.getKeyboardType() == AINPUT_KEYBOARD_TYPE_ALPHABETIC) {
        return InputDeviceUsageSource::KEYBOARD;
    }

    return InputDeviceUsageSource::BUTTONS;
}

std::set<InputDeviceUsageSource> getUsageSourcesForMotionArgs(const NotifyMotionArgs& motionArgs) {
    LOG_ALWAYS_FATAL_IF(motionArgs.pointerCount < 1, "Received motion args without pointers");
    std::set<InputDeviceUsageSource> sources;

    for (uint32_t i = 0; i < motionArgs.pointerCount; i++) {
        const auto toolType = motionArgs.pointerProperties[i].toolType;
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_MOUSE)) {
            if (toolType == ToolType::MOUSE) {
                sources.emplace(InputDeviceUsageSource::MOUSE);
                continue;
            }
            if (toolType == ToolType::FINGER) {
                sources.emplace(InputDeviceUsageSource::TOUCHPAD);
                continue;
            }
            if (isStylusToolType(toolType)) {
                sources.emplace(InputDeviceUsageSource::STYLUS_INDIRECT);
                continue;
            }
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_MOUSE_RELATIVE) &&
            toolType == ToolType::MOUSE) {
            sources.emplace(InputDeviceUsageSource::MOUSE_CAPTURED);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TOUCHPAD) &&
            toolType == ToolType::FINGER) {
            sources.emplace(InputDeviceUsageSource::TOUCHPAD_CAPTURED);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_BLUETOOTH_STYLUS) &&
            isStylusToolType(toolType)) {
            sources.emplace(InputDeviceUsageSource::STYLUS_FUSED);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_STYLUS) && isStylusToolType(toolType)) {
            sources.emplace(InputDeviceUsageSource::STYLUS_DIRECT);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TOUCH_NAVIGATION)) {
            sources.emplace(InputDeviceUsageSource::TOUCH_NAVIGATION);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_JOYSTICK)) {
            sources.emplace(InputDeviceUsageSource::JOYSTICK);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_ROTARY_ENCODER)) {
            sources.emplace(InputDeviceUsageSource::ROTARY_ENCODER);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TRACKBALL)) {
            sources.emplace(InputDeviceUsageSource::TRACKBALL);
            continue;
        }
        if (isFromSource(motionArgs.source, AINPUT_SOURCE_TOUCHSCREEN)) {
            sources.emplace(InputDeviceUsageSource::TOUCHSCREEN);
            continue;
        }
        sources.emplace(InputDeviceUsageSource::UNKNOWN);
    }

    return sources;
}

// --- InputDeviceMetricsCollector ---

InputDeviceMetricsCollector::InputDeviceMetricsCollector(InputListenerInterface& listener)
      : InputDeviceMetricsCollector(listener, sStatsdLogger, DEFAULT_USAGE_SESSION_TIMEOUT) {}

InputDeviceMetricsCollector::InputDeviceMetricsCollector(InputListenerInterface& listener,
                                                         InputDeviceMetricsLogger& logger,
                                                         nanoseconds usageSessionTimeout)
      : mNextListener(listener), mLogger(logger), mUsageSessionTimeout(usageSessionTimeout) {}

void InputDeviceMetricsCollector::notifyInputDevicesChanged(
        const NotifyInputDevicesChangedArgs& args) {
    processUsages();
    onInputDevicesChanged(args.inputDeviceInfos);
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyConfigurationChanged(
        const NotifyConfigurationChangedArgs& args) {
    processUsages();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyKey(const NotifyKeyArgs& args) {
    processUsages();
    onInputDeviceUsage(DeviceId{args.deviceId}, nanoseconds(args.eventTime));

    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyMotion(const NotifyMotionArgs& args) {
    processUsages();
    onInputDeviceUsage(DeviceId{args.deviceId}, nanoseconds(args.eventTime));

    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifySwitch(const NotifySwitchArgs& args) {
    processUsages();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifySensor(const NotifySensorArgs& args) {
    processUsages();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    processUsages();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    processUsages();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyPointerCaptureChanged(
        const NotifyPointerCaptureChangedArgs& args) {
    processUsages();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::dump(std::string& dump) {
    dump += "InputDeviceMetricsCollector:\n";

    dump += "  Logged device IDs: " + dumpMapKeys(mLoggedDeviceInfos, &toString) + "\n";
    dump += "  Devices with active usage sessions: " +
            dumpMapKeys(mActiveUsageSessions, &toString) + "\n";
}

void InputDeviceMetricsCollector::onInputDevicesChanged(const std::vector<InputDeviceInfo>& infos) {
    std::map<DeviceId, InputDeviceIdentifier> newDeviceIds;

    for (const InputDeviceInfo& info : infos) {
        if (isIgnoredInputDeviceId(info.getId())) {
            continue;
        }
        newDeviceIds.emplace(info.getId(), info.getIdentifier());
    }

    for (auto [deviceId, identifier] : mLoggedDeviceInfos) {
        if (newDeviceIds.count(deviceId) != 0) {
            continue;
        }
        onInputDeviceRemoved(deviceId, identifier);
    }

    std::swap(newDeviceIds, mLoggedDeviceInfos);
}

void InputDeviceMetricsCollector::onInputDeviceRemoved(DeviceId deviceId,
                                                       const InputDeviceIdentifier& identifier) {
    // Report usage for that device if there is an active session.
    auto it = mActiveUsageSessions.find(deviceId);
    if (it != mActiveUsageSessions.end()) {
        mLogger.logInputDeviceUsageReported(identifier, it->second.end - it->second.start);
        mActiveUsageSessions.erase(it);
    }
    // We don't remove this from mLoggedDeviceInfos because it will be updated in
    // onInputDevicesChanged().
}

void InputDeviceMetricsCollector::onInputDeviceUsage(DeviceId deviceId, nanoseconds eventTime) {
    if (mLoggedDeviceInfos.count(deviceId) == 0) {
        // Do not track usage for devices that are not logged.
        return;
    }

    auto [it, inserted] = mActiveUsageSessions.try_emplace(deviceId, eventTime, eventTime);
    if (!inserted) {
        it->second.end = eventTime;
    }
}

void InputDeviceMetricsCollector::processUsages() {
    const auto usageSessionExpiryTime = mLogger.getCurrentTime() - mUsageSessionTimeout;

    std::vector<DeviceId> completedUsageSessions;

    for (const auto& [deviceId, usageSession] : mActiveUsageSessions) {
        if (usageSession.end <= usageSessionExpiryTime) {
            completedUsageSessions.emplace_back(deviceId);
        }
    }

    for (DeviceId deviceId : completedUsageSessions) {
        const auto it = mLoggedDeviceInfos.find(deviceId);
        LOG_ALWAYS_FATAL_IF(it == mLoggedDeviceInfos.end());

        const auto& session = mActiveUsageSessions[deviceId];
        mLogger.logInputDeviceUsageReported(it->second, session.end - session.start);

        mActiveUsageSessions.erase(deviceId);
    }
}

} // namespace android
