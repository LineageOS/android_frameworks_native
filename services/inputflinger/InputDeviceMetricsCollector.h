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

#include "InputDeviceMetricsSource.h"
#include "InputListener.h"
#include "NotifyArgs.h"
#include "SyncQueue.h"

#include <android-base/thread_annotations.h>
#include <ftl/mixins.h>
#include <gui/WindowInfo.h>
#include <input/InputDevice.h>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <vector>

namespace android {

/**
 * Logs metrics about registered input devices and their usages.
 */
class InputDeviceMetricsCollectorInterface : public InputListenerInterface {
public:
    /**
     * Notify the metrics collector that there was an input device interaction with apps.
     * Called from the InputDispatcher thread.
     */
    virtual void notifyDeviceInteraction(int32_t deviceId, nsecs_t timestamp,
                                         const std::set<gui::Uid>& uids) = 0;
    /**
     * Dump the state of the interaction blocker.
     * This method may be called on any thread (usually by the input manager on a binder thread).
     */
    virtual void dump(std::string& dump) = 0;

    /** Called by the heartbeat to ensure that this component has not deadlocked. */
    virtual void monitor() = 0;
};

/** The logging interface for the metrics collector, injected for testing. */
class InputDeviceMetricsLogger {
public:
    virtual std::chrono::nanoseconds getCurrentTime() = 0;

    // Describes the breakdown of an input device usage session by its usage sources.
    // An input device can have more than one usage source. For example, some game controllers have
    // buttons, joysticks, and touchpads. We track usage by these sources to get a better picture of
    // the device usage. The source breakdown of a 10 minute usage session could look like this:
    //   { {GAMEPAD, <9 mins>}, {TOUCHPAD, <2 mins>}, {TOUCHPAD, <3 mins>} }
    // This would indicate that the GAMEPAD source was used first, and that source usage session
    // lasted for 9 mins. During that time, the TOUCHPAD was used for 2 mins, until its source
    // usage session expired. The TOUCHPAD was then used again later for another 3 mins.
    using SourceUsageBreakdown =
            std::vector<std::pair<InputDeviceUsageSource, std::chrono::nanoseconds /*duration*/>>;

    // Describes the breakdown of an input device usage session by the UIDs that it interacted with.
    using UidUsageBreakdown =
            std::vector<std::pair<gui::Uid, std::chrono::nanoseconds /*duration*/>>;

    struct DeviceUsageReport {
        std::chrono::nanoseconds usageDuration;
        SourceUsageBreakdown sourceBreakdown;
        UidUsageBreakdown uidBreakdown;
    };

    // A subset of information from the InputDeviceInfo class that is used for metrics collection,
    // used to avoid copying and storing all of the fields and strings in InputDeviceInfo.
    struct MetricsDeviceInfo {
        int32_t deviceId;
        int32_t vendor;
        int32_t product;
        int32_t version;
        int32_t bus;
        bool isUsiStylus;
        int32_t keyboardType;
    };
    virtual void logInputDeviceUsageReported(const MetricsDeviceInfo&,
                                             const DeviceUsageReport&) = 0;
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

    void notifyDeviceInteraction(int32_t deviceId, nsecs_t timestamp,
                                 const std::set<gui::Uid>& uids) override;
    void dump(std::string& dump) override;
    void monitor() override;

private:
    std::mutex mLock;
    InputListenerInterface& mNextListener;
    InputDeviceMetricsLogger& mLogger GUARDED_BY(mLock);
    const std::chrono::nanoseconds mUsageSessionTimeout;

    // Type-safe wrapper for input device id.
    struct DeviceId : ftl::Constructible<DeviceId, std::int32_t>,
                      ftl::Equatable<DeviceId>,
                      ftl::Orderable<DeviceId> {
        using Constructible::Constructible;
    };
    static inline std::string toString(const DeviceId& id) {
        return std::to_string(ftl::to_underlying(id));
    }

    using Uid = gui::Uid;
    using MetricsDeviceInfo = InputDeviceMetricsLogger::MetricsDeviceInfo;

    std::map<DeviceId, MetricsDeviceInfo> mLoggedDeviceInfos GUARDED_BY(mLock);

    using Interaction = std::tuple<DeviceId, std::chrono::nanoseconds, std::set<Uid>>;
    SyncQueue<Interaction> mInteractionsQueue GUARDED_BY(mLock);

    class ActiveSession {
    public:
        explicit ActiveSession(std::chrono::nanoseconds usageSessionTimeout,
                               std::chrono::nanoseconds startTime);
        void recordUsage(std::chrono::nanoseconds eventTime, InputDeviceUsageSource source);
        void recordInteraction(const Interaction&);
        bool checkIfCompletedAt(std::chrono::nanoseconds timestamp);
        InputDeviceMetricsLogger::DeviceUsageReport finishSession();

    private:
        struct UsageSession {
            std::chrono::nanoseconds start{};
            std::chrono::nanoseconds end{};
        };

        const std::chrono::nanoseconds mUsageSessionTimeout;
        UsageSession mDeviceSession{};

        std::map<InputDeviceUsageSource, UsageSession> mActiveSessionsBySource{};
        InputDeviceMetricsLogger::SourceUsageBreakdown mSourceUsageBreakdown{};

        std::map<Uid, UsageSession> mActiveSessionsByUid{};
        InputDeviceMetricsLogger::UidUsageBreakdown mUidUsageBreakdown{};
    };

    // The input devices that currently have active usage sessions.
    std::map<DeviceId, ActiveSession> mActiveUsageSessions GUARDED_BY(mLock);

    void onInputDevicesChanged(const std::vector<InputDeviceInfo>& infos) REQUIRES(mLock);
    void onInputDeviceRemoved(DeviceId deviceId, const MetricsDeviceInfo& info) REQUIRES(mLock);
    using SourceProvider =
            std::function<std::set<InputDeviceUsageSource>(const MetricsDeviceInfo&)>;
    void onInputDeviceUsage(DeviceId deviceId, std::chrono::nanoseconds eventTime,
                            const SourceProvider& getSources) REQUIRES(mLock);
    void onInputDeviceInteraction(const Interaction&) REQUIRES(mLock);
    void reportCompletedSessions() REQUIRES(mLock);
};

} // namespace android
