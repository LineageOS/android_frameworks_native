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

#pragma once

#include "InputListener.h"

#include <ftl/mixins.h>
#include <input/InputDevice.h>
#include <chrono>
#include <map>
#include <vector>

namespace android {

/**
 * Logs metrics about registered input devices and their usages.
 *
 * Not thread safe. Must be called from a single thread.
 */
class InputDeviceMetricsCollectorInterface : public InputListenerInterface {
public:
    /**
     * Dump the state of the interaction blocker.
     * This method may be called on any thread (usually by the input manager on a binder thread).
     */
    virtual void dump(std::string& dump) = 0;
};

/** The logging interface for the metrics collector, injected for testing. */
class InputDeviceMetricsLogger {
public:
    virtual std::chrono::nanoseconds getCurrentTime() = 0;
    virtual void logInputDeviceUsageReported(const InputDeviceIdentifier&,
                                             std::chrono::nanoseconds duration) = 0;
    virtual ~InputDeviceMetricsLogger() = default;
};

class InputDeviceMetricsCollector : public InputDeviceMetricsCollectorInterface {
public:
    explicit InputDeviceMetricsCollector(InputListenerInterface& listener);
    ~InputDeviceMetricsCollector() override = default;

    // Test constructor
    InputDeviceMetricsCollector(InputListenerInterface& listener, InputDeviceMetricsLogger& logger,
                                std::chrono::nanoseconds usageSessionTimeout);

    void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) override;
    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) override;
    void notifyKey(const NotifyKeyArgs& args) override;
    void notifyMotion(const NotifyMotionArgs& args) override;
    void notifySwitch(const NotifySwitchArgs& args) override;
    void notifySensor(const NotifySensorArgs& args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs& args) override;
    void notifyDeviceReset(const NotifyDeviceResetArgs& args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) override;

    void dump(std::string& dump) override;

private:
    InputListenerInterface& mNextListener;
    InputDeviceMetricsLogger& mLogger;
    const std::chrono::nanoseconds mUsageSessionTimeout;

    // Type-safe wrapper for input device id.
    struct DeviceId : ftl::Constructible<DeviceId, std::int32_t>,
                      ftl::Equatable<DeviceId>,
                      ftl::Orderable<DeviceId> {
        using Constructible::Constructible;
    };
    static std::string toString(const DeviceId& id) {
        return std::to_string(ftl::to_underlying(id));
    }

    std::map<DeviceId, InputDeviceIdentifier> mLoggedDeviceInfos;

    struct UsageSession {
        std::chrono::nanoseconds start;
        std::chrono::nanoseconds end;
    };
    // The input devices that currently have active usage sessions.
    std::map<DeviceId, UsageSession> mActiveUsageSessions;

    void onInputDevicesChanged(const std::vector<InputDeviceInfo>& infos);
    void onInputDeviceRemoved(DeviceId deviceId, const InputDeviceIdentifier& identifier);
    void onInputDeviceUsage(DeviceId deviceId, std::chrono::nanoseconds eventTime);
    void processUsages();
};

} // namespace android
