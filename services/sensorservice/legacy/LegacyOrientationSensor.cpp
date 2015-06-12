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

#include <stdint.h>
#include <math.h>
#include <sys/types.h>

#include <utils/Errors.h>

#include <hardware/sensors.h>

#include "LegacyOrientationSensor.h"

namespace android {
// ---------------------------------------------------------------------------

template <typename T>
static inline T clamp(T v) {
    return v < 0 ? 0 : v;
}

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
        const float Ex = mMagData[0];
        const float Ey = mMagData[1];
        const float Ez = mMagData[2];
        float Hx = Ey*Az - Ez*Ay;
        float Hy = Ez*Ax - Ex*Az;
        float Hz = Ex*Ay - Ey*Ax;
        const float normH = sqrtf(Hx*Hx + Hy*Hy + Hz*Hz);
        if (normH < 0.1f) {
            // device is close to free fall (or in space?), or close to
            // magnetic north pole. Typical values are  > 100.
            return false;
        }
        const float invH = 1.0f / normH;
        const float invA = 1.0f / sqrtf(Ax*Ax + Ay*Ay + Az*Az);
        Hx *= invH;
        Hy *= invH;
        Hz *= invH;
        Ax *= invA;
        Ay *= invA;
        Az *= invA;
        const float Mx = Ay*Hz - Az*Hy;
        const float My = Az*Hx - Ax*Hz;
        const float Mz = Ax*Hy - Ay*Hx;

        // construct real rotation matrix
        mat33_t R;
        R[0].x = Hx;
        R[0].y = Hy;
        R[0].z = Hz;
        R[1].x = Mx;
        R[1].y = My;
        R[2].x = Ax;
        R[2].y = Ay;
        R[2].z = Az;

        vec3_t g;
        const float rad2deg = 180 / M_PI;
        g[0] = atan2f(-R[1][0], R[0][0])    * rad2deg;
        g[1] = atan2f(-R[2][1], R[2][2])    * rad2deg;
        g[2] = asinf ( R[2][0])             * rad2deg;
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
    return mSensorFusion.activate(ident, enabled);
}

status_t LegacyOrientationSensor::setDelay(void* ident, int handle, int64_t ns) {
    return mSensorFusion.setDelay(ident, ns);
}

Sensor LegacyOrientationSensor::getSensor() const {
    sensor_t hwSensor;
    hwSensor.name       = "Orientation Sensor";
    hwSensor.vendor     = "AOSP";
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

