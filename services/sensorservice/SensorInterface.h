/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_SENSOR_INTERFACE_H
#define ANDROID_SENSOR_INTERFACE_H

#include <sensor/Sensor.h>
#include <utils/RefBase.h>

// ---------------------------------------------------------------------------

namespace android {
// ---------------------------------------------------------------------------
class SensorDevice;
class SensorFusion;
class SensorService;

class SensorInterface : public VirtualLightRefBase {
public:
    virtual ~SensorInterface() {}

    virtual bool process(sensors_event_t* outEvent, const sensors_event_t& event) = 0;

    virtual status_t activate(void* ident, bool enabled) = 0;
    virtual status_t setDelay(void* ident, int handle, int64_t ns) = 0;
    virtual status_t batch(void* ident, int handle, int /*flags*/, int64_t samplingPeriodNs,
                           int64_t maxBatchReportLatencyNs) = 0;

    virtual status_t flush(void* /*ident*/, int /*handle*/) = 0;

    virtual const Sensor& getSensor() const = 0;
    virtual bool isVirtual() const = 0;
    virtual void autoDisable(void* /*ident*/, int /*handle*/) = 0;
};

class BaseSensor : public SensorInterface {
public:
    explicit BaseSensor(const sensor_t& sensor);
    BaseSensor(const sensor_t& sensor, const uint8_t (&uuid)[16]);

    // Not all sensors need to support batching.
    virtual status_t batch(void* ident, int handle, int, int64_t samplingPeriodNs,
                           int64_t maxBatchReportLatencyNs) override {
        if (maxBatchReportLatencyNs == 0) {
            return setDelay(ident, handle, samplingPeriodNs);
        }
        return -EINVAL;
    }

    virtual status_t flush(void* /*ident*/, int /*handle*/) override {
        return -EINVAL;
    }

    virtual const Sensor& getSensor() const override { return mSensor; }
    virtual void autoDisable(void* /*ident*/, int /*handle*/) override { }

protected:
    SensorDevice& mSensorDevice;
    Sensor mSensor;
};

// ---------------------------------------------------------------------------

class HardwareSensor : public BaseSensor {
public:
    explicit HardwareSensor(const sensor_t& sensor);
    HardwareSensor(const sensor_t& sensor, const uint8_t (&uuid)[16]);

    virtual ~HardwareSensor();

    virtual bool process(sensors_event_t* outEvent,
            const sensors_event_t& event);

    virtual status_t activate(void* ident, bool enabled) override;
    virtual status_t batch(void* ident, int handle, int flags, int64_t samplingPeriodNs,
                           int64_t maxBatchReportLatencyNs) override;
    virtual status_t setDelay(void* ident, int handle, int64_t ns) override;
    virtual status_t flush(void* ident, int handle) override;
    virtual bool isVirtual() const override { return false; }
    virtual void autoDisable(void *ident, int handle) override;
};

class VirtualSensor : public BaseSensor
{
public:
    VirtualSensor();
    virtual bool isVirtual() const override { return true; }
protected:
    SensorFusion& mSensorFusion;
};

// ---------------------------------------------------------------------------

class RuntimeSensor : public BaseSensor {
public:
    static constexpr int DEFAULT_DEVICE_ID = 0;

    class SensorCallback : public virtual RefBase {
      public:
        virtual status_t onConfigurationChanged(int handle, bool enabled, int64_t samplingPeriodNs,
                                                int64_t batchReportLatencyNs) = 0;
    };
    RuntimeSensor(const sensor_t& sensor, sp<SensorCallback> callback);
    virtual status_t activate(void* ident, bool enabled) override;
    virtual status_t batch(void* ident, int handle, int flags, int64_t samplingPeriodNs,
                           int64_t maxBatchReportLatencyNs) override;
    virtual status_t setDelay(void* ident, int handle, int64_t ns) override;
    virtual bool process(sensors_event_t*, const sensors_event_t&) { return false; }
    virtual bool isVirtual() const override { return false; }

private:
    bool mEnabled = false;
    int64_t mSamplingPeriodNs = 0;
    int64_t mBatchReportLatencyNs = 0;
    sp<SensorCallback> mCallback;
};

// ---------------------------------------------------------------------------

class ProximitySensor : public HardwareSensor {
public:
    explicit ProximitySensor(const sensor_t& sensor, SensorService& service);

    status_t activate(void* ident, bool enabled) override;

private:
    SensorService& mSensorService;
};

// ---------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_SENSOR_INTERFACE_H
