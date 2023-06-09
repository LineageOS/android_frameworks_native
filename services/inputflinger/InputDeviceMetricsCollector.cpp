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
using std::chrono_literals::operator""ns;

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
                                     const DeviceUsageReport& report) override {
        const int32_t durationMillis =
                std::chrono::duration_cast<std::chrono::milliseconds>(report.usageDuration).count();
        const static std::vector<int32_t> empty;

        ALOGD_IF(DEBUG, "Usage session reported for device: %s", identifier.name.c_str());
        ALOGD_IF(DEBUG, "    Total duration: %dms", durationMillis);
        ALOGD_IF(DEBUG, "    Source breakdown:");

        std::vector<int32_t> sources;
        std::vector<int32_t> durationsPerSource;
        for (auto& [src, dur] : report.sourceBreakdown) {
            sources.push_back(ftl::to_underlying(src));
            int32_t durMillis = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
            durationsPerSource.emplace_back(durMillis);
            ALOGD_IF(DEBUG, "        - usageSource: %s\t duration: %dms",
                     ftl::enum_string(src).c_str(), durMillis);
        }

        ALOGD_IF(DEBUG, "    Uid breakdown:");

        std::vector<int32_t> uids;
        std::vector<int32_t> durationsPerUid;
        for (auto& [uid, dur] : report.uidBreakdown) {
            uids.push_back(uid);
            int32_t durMillis = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
            durationsPerUid.push_back(durMillis);
            ALOGD_IF(DEBUG, "        - uid: %d\t duration: %dms", uid, durMillis);
        }
        util::stats_write(util::INPUTDEVICE_USAGE_REPORTED, identifier.vendor, identifier.product,
                          identifier.version, linuxBusToInputDeviceBusEnum(identifier.bus),
                          durationMillis, sources, durationsPerSource, uids, durationsPerUid);
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
    reportCompletedSessions();
    onInputDevicesChanged(args.inputDeviceInfos);
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyConfigurationChanged(
        const NotifyConfigurationChangedArgs& args) {
    reportCompletedSessions();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyKey(const NotifyKeyArgs& args) {
    reportCompletedSessions();
    const SourceProvider getSources = [&args](const InputDeviceInfo& info) {
        return std::set{getUsageSourceForKeyArgs(info, args)};
    };
    onInputDeviceUsage(DeviceId{args.deviceId}, nanoseconds(args.eventTime), getSources);

    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyMotion(const NotifyMotionArgs& args) {
    reportCompletedSessions();
    onInputDeviceUsage(DeviceId{args.deviceId}, nanoseconds(args.eventTime),
                       [&args](const auto&) { return getUsageSourcesForMotionArgs(args); });

    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifySwitch(const NotifySwitchArgs& args) {
    reportCompletedSessions();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifySensor(const NotifySensorArgs& args) {
    reportCompletedSessions();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    reportCompletedSessions();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    reportCompletedSessions();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyPointerCaptureChanged(
        const NotifyPointerCaptureChangedArgs& args) {
    reportCompletedSessions();
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyDeviceInteraction(int32_t deviceId, nsecs_t timestamp,
                                                          const std::set<int32_t>& uids) {
    std::set<Uid> typeSafeUids;
    for (auto uid : uids) {
        typeSafeUids.emplace(uid);
    }
    mInteractionsQueue.push(DeviceId{deviceId}, timestamp, typeSafeUids);
}

void InputDeviceMetricsCollector::dump(std::string& dump) {
    dump += "InputDeviceMetricsCollector:\n";

    dump += "  Logged device IDs: " + dumpMapKeys(mLoggedDeviceInfos, &toString) + "\n";
    dump += "  Devices with active usage sessions: " +
            dumpMapKeys(mActiveUsageSessions, &toString) + "\n";
}

void InputDeviceMetricsCollector::onInputDevicesChanged(const std::vector<InputDeviceInfo>& infos) {
    std::map<DeviceId, InputDeviceInfo> newDeviceInfos;

    for (const InputDeviceInfo& info : infos) {
        if (isIgnoredInputDeviceId(info.getId())) {
            continue;
        }
        newDeviceInfos.emplace(info.getId(), info);
    }

    for (auto [deviceId, info] : mLoggedDeviceInfos) {
        if (newDeviceInfos.count(deviceId) != 0) {
            continue;
        }
        onInputDeviceRemoved(deviceId, info.getIdentifier());
    }

    std::swap(newDeviceInfos, mLoggedDeviceInfos);
}

void InputDeviceMetricsCollector::onInputDeviceRemoved(DeviceId deviceId,
                                                       const InputDeviceIdentifier& identifier) {
    auto it = mActiveUsageSessions.find(deviceId);
    if (it == mActiveUsageSessions.end()) {
        return;
    }
    // Report usage for that device if there is an active session.
    auto& [_, activeSession] = *it;
    mLogger.logInputDeviceUsageReported(identifier, activeSession.finishSession());
    mActiveUsageSessions.erase(it);

    // We don't remove this from mLoggedDeviceInfos because it will be updated in
    // onInputDevicesChanged().
}

void InputDeviceMetricsCollector::onInputDeviceUsage(DeviceId deviceId, nanoseconds eventTime,
                                                     const SourceProvider& getSources) {
    auto infoIt = mLoggedDeviceInfos.find(deviceId);
    if (infoIt == mLoggedDeviceInfos.end()) {
        // Do not track usage for devices that are not logged.
        return;
    }

    auto [sessionIt, _] =
            mActiveUsageSessions.try_emplace(deviceId, mUsageSessionTimeout, eventTime);
    for (InputDeviceUsageSource source : getSources(infoIt->second)) {
        sessionIt->second.recordUsage(eventTime, source);
    }
}

void InputDeviceMetricsCollector::onInputDeviceInteraction(const Interaction& interaction) {
    auto activeSessionIt = mActiveUsageSessions.find(std::get<DeviceId>(interaction));
    if (activeSessionIt == mActiveUsageSessions.end()) {
        return;
    }

    activeSessionIt->second.recordInteraction(interaction);
}

void InputDeviceMetricsCollector::reportCompletedSessions() {
    // Process all pending interactions.
    for (auto interaction = mInteractionsQueue.pop(); interaction;
         interaction = mInteractionsQueue.pop()) {
        onInputDeviceInteraction(*interaction);
    }

    const auto currentTime = mLogger.getCurrentTime();
    std::vector<DeviceId> completedUsageSessions;

    // Process usages for all active session to determine if any sessions have expired.
    for (auto& [deviceId, activeSession] : mActiveUsageSessions) {
        if (activeSession.checkIfCompletedAt(currentTime)) {
            completedUsageSessions.emplace_back(deviceId);
        }
    }

    // Close out and log all expired usage sessions.
    for (DeviceId deviceId : completedUsageSessions) {
        const auto infoIt = mLoggedDeviceInfos.find(deviceId);
        LOG_ALWAYS_FATAL_IF(infoIt == mLoggedDeviceInfos.end());

        auto activeSessionIt = mActiveUsageSessions.find(deviceId);
        LOG_ALWAYS_FATAL_IF(activeSessionIt == mActiveUsageSessions.end());
        auto& [_, activeSession] = *activeSessionIt;
        mLogger.logInputDeviceUsageReported(infoIt->second.getIdentifier(),
                                            activeSession.finishSession());
        mActiveUsageSessions.erase(activeSessionIt);
    }
}

// --- InputDeviceMetricsCollector::ActiveSession ---

InputDeviceMetricsCollector::ActiveSession::ActiveSession(nanoseconds usageSessionTimeout,
                                                          nanoseconds startTime)
      : mUsageSessionTimeout(usageSessionTimeout), mDeviceSession({startTime, startTime}) {}

void InputDeviceMetricsCollector::ActiveSession::recordUsage(nanoseconds eventTime,
                                                             InputDeviceUsageSource source) {
    // We assume that event times for subsequent events are always monotonically increasing for each
    // input device.
    auto [activeSourceIt, inserted] =
            mActiveSessionsBySource.try_emplace(source, eventTime, eventTime);
    if (!inserted) {
        activeSourceIt->second.end = eventTime;
    }
    mDeviceSession.end = eventTime;
}

void InputDeviceMetricsCollector::ActiveSession::recordInteraction(const Interaction& interaction) {
    const auto sessionExpiryTime = mDeviceSession.end + mUsageSessionTimeout;
    const auto timestamp = std::get<nanoseconds>(interaction);
    if (timestamp >= sessionExpiryTime) {
        // This interaction occurred after the device's current active session is set to expire.
        // Ignore it.
        return;
    }

    for (Uid uid : std::get<std::set<Uid>>(interaction)) {
        auto [activeUidIt, inserted] = mActiveSessionsByUid.try_emplace(uid, timestamp, timestamp);
        if (!inserted) {
            activeUidIt->second.end = timestamp;
        }
    }
}

bool InputDeviceMetricsCollector::ActiveSession::checkIfCompletedAt(nanoseconds timestamp) {
    const auto sessionExpiryTime = timestamp - mUsageSessionTimeout;
    std::vector<InputDeviceUsageSource> completedSourceSessionsForDevice;
    for (auto& [source, session] : mActiveSessionsBySource) {
        if (session.end <= sessionExpiryTime) {
            completedSourceSessionsForDevice.emplace_back(source);
        }
    }
    for (InputDeviceUsageSource source : completedSourceSessionsForDevice) {
        auto it = mActiveSessionsBySource.find(source);
        const auto& [_, session] = *it;
        mSourceUsageBreakdown.emplace_back(source, session.end - session.start);
        mActiveSessionsBySource.erase(it);
    }

    std::vector<Uid> completedUidSessionsForDevice;
    for (auto& [uid, session] : mActiveSessionsByUid) {
        if (session.end <= sessionExpiryTime) {
            completedUidSessionsForDevice.emplace_back(uid);
        }
    }
    for (Uid uid : completedUidSessionsForDevice) {
        auto it = mActiveSessionsByUid.find(uid);
        const auto& [_, session] = *it;
        mUidUsageBreakdown.emplace_back(uid, session.end - session.start);
        mActiveSessionsByUid.erase(it);
    }

    // This active session has expired if there are no more active source sessions tracked.
    return mActiveSessionsBySource.empty();
}

InputDeviceMetricsLogger::DeviceUsageReport
InputDeviceMetricsCollector::ActiveSession::finishSession() {
    const auto deviceUsageDuration = mDeviceSession.end - mDeviceSession.start;

    for (const auto& [source, sourceSession] : mActiveSessionsBySource) {
        mSourceUsageBreakdown.emplace_back(source, sourceSession.end - sourceSession.start);
    }
    mActiveSessionsBySource.clear();

    for (const auto& [uid, uidSession] : mActiveSessionsByUid) {
        mUidUsageBreakdown.emplace_back(uid, uidSession.end - uidSession.start);
    }
    mActiveSessionsByUid.clear();

    return {deviceUsageDuration, mSourceUsageBreakdown, mUidUsageBreakdown};
}

} // namespace android
