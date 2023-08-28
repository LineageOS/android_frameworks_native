/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>

#include <batterystats/IBatteryStats.h>
#include <utils/Singleton.h>
#include <utils/SortedVector.h>
#include <utils/SystemClock.h>

namespace android {
// ---------------------------------------------------------------------------

class BatteryService : public Singleton<BatteryService> {
    static constexpr int64_t WAKEUP_SENSOR_EVENT_DEBOUNCE_MS = 1000;

    friend class Singleton<BatteryService>;
    sp<IBatteryStats> mBatteryStatService;

    BatteryService();

    void enableSensorImpl(uid_t uid, int handle);
    void disableSensorImpl(uid_t uid, int handle);
    void noteWakeupSensorEventImpl(int64_t elapsedNanos, uid_t uid, int handle);

    struct Info {
        uid_t uid;
        int handle;
        int32_t count;
        Info()  : uid(0), handle(0), count(0) { }
        Info(uid_t uid, int handle) : uid(uid), handle(handle), count(0) { }
        bool operator < (const Info& rhs) const {
            return (uid == rhs.uid) ? (handle < rhs.handle) :  (uid < rhs.uid);
        }
    };

    int64_t mLastWakeupSensorEventReportedMs;
    Mutex mActivationsLock;
    SortedVector<Info> mActivations;
    bool addSensor(uid_t uid, int handle);
    bool removeSensor(uid_t uid, int handle);
    bool checkService();

public:
    static void enableSensor(uid_t uid, int handle) {
        BatteryService::getInstance().enableSensorImpl(uid, handle);
    }
    static void disableSensor(uid_t uid, int handle) {
        BatteryService::getInstance().disableSensorImpl(uid, handle);
    }
    static void noteWakeupSensorEvent(int64_t elapsed, uid_t uid, int handle) {
        BatteryService& instance = BatteryService::getInstance();
        const int64_t nowElapsedMs = elapsedRealtime();
        if (nowElapsedMs >= (instance.mLastWakeupSensorEventReportedMs
                              + WAKEUP_SENSOR_EVENT_DEBOUNCE_MS)) {
            instance.noteWakeupSensorEventImpl(elapsed, uid, handle);
            instance.mLastWakeupSensorEventReportedMs = nowElapsedMs;
        }
    }
};

// ---------------------------------------------------------------------------
}; // namespace android

