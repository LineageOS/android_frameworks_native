/*
 * Copyright (C) 2011 The Android Open Source Project
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
#include <math.h>
#include <sys/types.h>

#include <utils/Errors.h>

#include <hardware/sensors.h>

#include "LegacyOrientationSensor.h"

namespace android {
// ---------------------------------------------------------------------------

LegacyOrientationSensor::LegacyOrientationSensor()
    : mSensorDevice(SensorDevice::getInstance()),
      mSensorFusion(SensorFusion::getInstance()),
      mALowPass(M_SQRT1_2, 1.5f),
      mAX(mALowPass), mAY(mALowPass), mAZ(mALowPass),
      mMLowPass(M_SQRT1_2, 1.5f),
      mMX(mMLowPass), mMY(mMLowPass), mMZ(mMLowPass)
{
}

bool LegacyOrientationSensor::process(sensors_event_t* outEvent,
        const sensors_event_t& event)
{
    const static double NS2S = 1.0 / 1000000000.0;
    if (event.type == SENSOR_TYPE_MAGNETIC_FIELD) {
        const double now = event.timestamp * NS2S;
        if (mMagTime == 0) {
            mMagData[0] = mMX.init(event.magnetic.x);
            mMagData[1] = mMY.init(event.magnetic.y);
            mMagData[2] = mMZ.init(event.magnetic.z);
        } else {
            double dT = now - mMagTime;
            mMLowPass.setSamplingPeriod(dT);
            mMagData[0] = mMX(event.magnetic.x);
            mMagData[1] = mMY(event.magnetic.y);
            mMagData[2] = mMZ(event.magnetic.z);
        }
        mMagTime = now;
    }
    if (event.type == SENSOR_TYPE_ACCELEROMETER) {
        const double now = event.timestamp * NS2S;
        float Ax, Ay, Az;
        if (mAccTime == 0) {
            Ax = mAX.init(event.acceleration.x);
            Ay = mAY.init(event.acceleration.y);
            Az = mAZ.init(event.acceleration.z);
        } else {
            double dT = now - mAccTime;
            mALowPass.setSamplingPeriod(dT);
            Ax = mAX(event.acceleration.x);
            Ay = mAY(event.acceleration.y);
            Az = mAZ(event.acceleration.z);
        }
        mAccTime = now;

        const float rad2deg = 180 / M_PI;
        vec3_t g;

        float pitch = atan2(Ay, Az);
        float sinPhi = sin(pitch);
        float cosPhi = cos(pitch);
        float Yh = mMagData[1] * cosPhi - mMagData[2] * sinPhi;
        mMagData[2] = mMagData[1] * sinPhi + mMagData[2] * cosPhi;
        Az = Ay * sinPhi + Az * cosPhi;

        float roll = atan2(-Ax, Az);
        float sinTheta = sin(roll);
        float cosTheta = cos(roll);
        float Xh = mMagData[0] * cosTheta + mMagData[2] * sinTheta;
        float yaw = atan2(Yh, Xh);

        g[0] = round(-90 + (yaw * rad2deg));
        g[1] = round(pitch * rad2deg);
        g[2] = round(roll * rad2deg);

        if (g[0] < 0)
            g[0] += 360;

        *outEvent = event;
        outEvent->orientation.azimuth = g.x;
        outEvent->orientation.pitch   = g.y;
        outEvent->orientation.roll    = g.z;
        outEvent->orientation.status  = SENSOR_STATUS_ACCURACY_HIGH;
        outEvent->sensor = '_ypr';
        outEvent->type = SENSOR_TYPE_ORIENTATION;
        return true;
    }
    return false;
}

status_t LegacyOrientationSensor::activate(void* ident, bool enabled) {
    if (enabled) {
        mMagTime = 0;
        mAccTime = 0;
    }
    return mSensorFusion.activate(this, enabled);
}

status_t LegacyOrientationSensor::setDelay(void* ident, int handle, int64_t ns) {
    return mSensorFusion.setDelay(this, ns);
}

Sensor LegacyOrientationSensor::getSensor() const {
    sensor_t hwSensor;
    hwSensor.name       = "Orientation Sensor";
    hwSensor.vendor     = "Google Inc.";
    hwSensor.version    = 1;
    hwSensor.handle     = '_ypr';
    hwSensor.type       = SENSOR_TYPE_ORIENTATION;
    hwSensor.maxRange   = 360.0f;
    hwSensor.resolution = 1.0f/256.0f; // FIXME: real value here
    hwSensor.power      = mSensorFusion.getPowerUsage();
    hwSensor.minDelay   = mSensorFusion.getMinDelay();
    Sensor sensor(&hwSensor);
    return sensor;
}

// ---------------------------------------------------------------------------
}; // namespace android

