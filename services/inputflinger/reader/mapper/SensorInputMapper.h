/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <optional>
#include <string>

#include "InputMapper.h"

namespace android {
// sensor data vector length
static constexpr ssize_t SENSOR_VEC_LEN = 3;

class SensorInputMapper : public InputMapper {
public:
    template <class T, class... Args>
    friend std::unique_ptr<T> createInputMapper(InputDeviceContext& deviceContext,
                                                const InputReaderConfiguration& readerConfig,
                                                Args... args);
    ~SensorInputMapper() override;

    uint32_t getSources() const override;
    void populateDeviceInfo(InputDeviceInfo& deviceInfo) override;
    void dump(std::string& dump) override;
    [[nodiscard]] std::list<NotifyArgs> reconfigure(nsecs_t when,
                                                    const InputReaderConfiguration& config,
                                                    ConfigurationChanges changes) override;
    [[nodiscard]] std::list<NotifyArgs> reset(nsecs_t when) override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent& rawEvent) override;
    bool enableSensor(InputDeviceSensorType sensorType, std::chrono::microseconds samplingPeriod,
                      std::chrono::microseconds maxBatchReportLatency) override;
    void disableSensor(InputDeviceSensorType sensorType) override;
    void flushSensor(InputDeviceSensorType sensorType) override;

private:
    struct Axis {
        explicit Axis(const RawAbsoluteAxisInfo& rawAxisInfo, const AxisInfo& axisInfo, float scale,
                      float offset, float min, float max, float flat, float fuzz, float resolution,
                      float filter)
              : rawAxisInfo(rawAxisInfo),
                axisInfo(axisInfo),
                scale(scale),
                offset(offset),
                min(min),
                max(max),
                flat(flat),
                fuzz(fuzz),
                resolution(resolution),
                filter(filter) {
            resetValue();
        }

        RawAbsoluteAxisInfo rawAxisInfo;
        AxisInfo axisInfo;

        float scale;  // scale factor from raw to normalized values
        float offset; // offset to add after scaling for normalization

        float min;        // normalized inclusive minimum
        float max;        // normalized inclusive maximum
        float flat;       // normalized flat region size
        float fuzz;       // normalized error tolerance
        float resolution; // normalized resolution in units

        float filter;       // filter out small variations of this size
        float currentValue; // current value
        float newValue;     // most recent value

        void resetValue() {
            this->currentValue = 0;
            this->newValue = 0;
        }
    };

    struct Sensor {
        explicit Sensor(const InputDeviceSensorInfo& sensorInfo) : sensorInfo(sensorInfo) {
            resetValue();
        }
        bool enabled;
        InputDeviceSensorAccuracy accuracy;
        std::chrono::nanoseconds samplingPeriod;
        std::chrono::nanoseconds maxBatchReportLatency;
        // last sample time in nano seconds
        std::optional<nsecs_t> lastSampleTimeNs;
        InputDeviceSensorInfo sensorInfo;
        // Sensor X, Y, Z data mapping to abs
        std::array<int32_t, SENSOR_VEC_LEN> dataVec;
        void resetValue() {
            this->enabled = false;
            this->accuracy = InputDeviceSensorAccuracy::ACCURACY_NONE;
            this->samplingPeriod = std::chrono::nanoseconds(0);
            this->maxBatchReportLatency = std::chrono::nanoseconds(0);
            this->lastSampleTimeNs = std::nullopt;
        }
    };

    explicit SensorInputMapper(InputDeviceContext& deviceContext,
                               const InputReaderConfiguration& readerConfig);

    static Axis createAxis(const AxisInfo& AxisInfo, const RawAbsoluteAxisInfo& rawAxisInfo);

    // Axes indexed by raw ABS_* axis index.
    std::unordered_map<int32_t, Axis> mAxes;

    // hardware timestamp from MSC_TIMESTAMP
    nsecs_t mHardwareTimestamp;
    uint32_t mPrevMscTime;

    bool mDeviceEnabled;
    // Does device support MSC_TIMESTAMP
    bool mHasHardwareTimestamp;

    // Sensor list
    std::unordered_map<InputDeviceSensorType, Sensor> mSensors;

    [[nodiscard]] std::list<NotifyArgs> sync(nsecs_t when, bool force);

    void parseSensorConfiguration(InputDeviceSensorType sensorType, int32_t absCode,
                                  int32_t sensorDataIndex, const Axis& axis);

    void processHardWareTimestamp(nsecs_t evTime, int32_t evValue);

    Sensor createSensor(InputDeviceSensorType sensorType, const Axis& axis);

    bool setSensorEnabled(InputDeviceSensorType sensorType, bool enabled);
};

} // namespace android
