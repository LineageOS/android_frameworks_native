/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_ISENSOR_HAL_WRAPPER_H
#define ANDROID_ISENSOR_HAL_WRAPPER_H

#include <hardware/sensors.h>
#include <stdint.h>
#include <sys/types.h>

#include "SensorService.h"

namespace android {

/**
 * A wrapper for various types of HAL implementation, e.g. to distinguish HIDL and AIDL versions.
 */
class ISensorHalWrapper {
public:
    class ICallback : public ISensorsCallback {

        void onDynamicSensorsConnected(
                const std::vector<sensor_t> &dynamicSensorsAdded) = 0;

        void onDynamicSensorsDisconnected(
                const std::vector<int32_t> &dynamicSensorHandlesRemoved) = 0;
    };

    /**
     * Connects to the underlying sensors HAL. This should also be used for any reconnections
     * due to HAL resets.
     */
    virtual bool connect(ICallback *callback) = 0;

    /**
     * Polls for available sensor events. This could be using the traditional sensors
     * polling or from a FMQ.
     */
    virtual ssize_t poll(sensors_event_t* buffer, size_t count) = 0;

    /**
     * The below functions directly mirrors the sensors HAL definitions.
     */
    virtual std::vector<sensor_t> getSensorsList() = 0;

    virtual status_t setOperationMode(SensorService::Mode mode) = 0;

    virtual status_t activate(int32_t sensorHandle, bool enabled) = 0;

    virtual status_t batch(int32_t sensorHandle, int64_t samplingPeriodNs,
                           int64_t maxReportLatencyNs) = 0;

    virtual status_t flush(int32_t sensorHandle) = 0;

    virtual status_t injectSensorData(const sensors_event_t *event) = 0;

    virtual status_t registerDirectChannel(const sensors_direct_mem_t *memory,
                                           int32_t *channelHandle) = 0;

    virtual void unregisterDirectChannel(int32_t channelHandle) = 0;

    virtual status_t configureDirectChannel(int32_t sensorHandle, int32_t channelHandle,
                                            const struct sensors_direct_cfg_t *config) = 0;
}

} // namespace android

#endif // ANDROID_ISENSOR_HAL_WRAPPER_H
