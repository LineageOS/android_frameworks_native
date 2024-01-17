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

#define LOG_TAG "VelocityControl"

// Log debug messages about acceleration.
static constexpr bool DEBUG_ACCELERATION = false;

#include <math.h>
#include <limits.h>

#include <android-base/logging.h>
#include <input/VelocityControl.h>
#include <utils/BitSet.h>
#include <utils/Timers.h>

namespace android {

// --- VelocityControl ---

const nsecs_t VelocityControl::STOP_TIME;

VelocityControl::VelocityControl() {
    reset();
}

void VelocityControl::reset() {
    mLastMovementTime = LLONG_MIN;
    mRawPositionX = 0;
    mRawPositionY = 0;
    mVelocityTracker.clear();
}

void VelocityControl::move(nsecs_t eventTime, float* deltaX, float* deltaY) {
    if ((deltaX == nullptr || *deltaX == 0) && (deltaY == nullptr || *deltaY == 0)) {
        return;
    }
    if (eventTime >= mLastMovementTime + STOP_TIME) {
        ALOGD_IF(DEBUG_ACCELERATION && mLastMovementTime != LLONG_MIN,
                 "VelocityControl: stopped, last movement was %0.3fms ago",
                 (eventTime - mLastMovementTime) * 0.000001f);
        reset();
    }

    mLastMovementTime = eventTime;
    if (deltaX) {
        mRawPositionX += *deltaX;
    }
    if (deltaY) {
        mRawPositionY += *deltaY;
    }
    mVelocityTracker.addMovement(eventTime, /*pointerId=*/0, AMOTION_EVENT_AXIS_X, mRawPositionX);
    mVelocityTracker.addMovement(eventTime, /*pointerId=*/0, AMOTION_EVENT_AXIS_Y, mRawPositionY);
    scaleDeltas(deltaX, deltaY);
}

// --- SimpleVelocityControl ---

const VelocityControlParameters& SimpleVelocityControl::getParameters() const {
    return mParameters;
}

void SimpleVelocityControl::setParameters(const VelocityControlParameters& parameters) {
    mParameters = parameters;
    reset();
}

void SimpleVelocityControl::scaleDeltas(float* deltaX, float* deltaY) {
    std::optional<float> vx = mVelocityTracker.getVelocity(AMOTION_EVENT_AXIS_X, 0);
    std::optional<float> vy = mVelocityTracker.getVelocity(AMOTION_EVENT_AXIS_Y, 0);
    float scale = mParameters.scale;
    if (vx.has_value() && vy.has_value()) {
        float speed = hypotf(*vx, *vy) * scale;
        if (speed >= mParameters.highThreshold) {
            // Apply full acceleration above the high speed threshold.
            scale *= mParameters.acceleration;
        } else if (speed > mParameters.lowThreshold) {
            // Linearly interpolate the acceleration to apply between the low and high
            // speed thresholds.
            scale *= 1 +
                    (speed - mParameters.lowThreshold) /
                            (mParameters.highThreshold - mParameters.lowThreshold) *
                            (mParameters.acceleration - 1);
        }

        ALOGD_IF(DEBUG_ACCELERATION,
                 "SimpleVelocityControl(%0.3f, %0.3f, %0.3f, %0.3f): "
                 "vx=%0.3f, vy=%0.3f, speed=%0.3f, accel=%0.3f",
                 mParameters.scale, mParameters.lowThreshold, mParameters.highThreshold,
                 mParameters.acceleration, *vx, *vy, speed, scale / mParameters.scale);

    } else {
        ALOGD_IF(DEBUG_ACCELERATION,
                 "SimpleVelocityControl(%0.3f, %0.3f, %0.3f, %0.3f): unknown velocity",
                 mParameters.scale, mParameters.lowThreshold, mParameters.highThreshold,
                 mParameters.acceleration);
    }

    if (deltaX != nullptr) {
        *deltaX *= scale;
    }
    if (deltaY != nullptr) {
        *deltaY *= scale;
    }
}

// --- CurvedVelocityControl ---

namespace {

/**
 * The resolution that we assume a mouse to have, in counts per inch.
 *
 * Mouse resolutions vary wildly, but 800 CPI is probably the most common. There should be enough
 * range in the available sensitivity settings to accommodate users of mice with other resolutions.
 */
constexpr int32_t MOUSE_CPI = 800;

float countsToMm(float counts) {
    return counts / MOUSE_CPI * 25.4;
}

} // namespace

CurvedVelocityControl::CurvedVelocityControl()
      : mCurveSegments(createAccelerationCurveForPointerSensitivity(0)) {}

void CurvedVelocityControl::setCurve(const std::vector<AccelerationCurveSegment>& curve) {
    mCurveSegments = curve;
}

void CurvedVelocityControl::setAccelerationEnabled(bool enabled) {
    mAccelerationEnabled = enabled;
}

void CurvedVelocityControl::scaleDeltas(float* deltaX, float* deltaY) {
    if (!mAccelerationEnabled) {
        ALOGD_IF(DEBUG_ACCELERATION, "CurvedVelocityControl: acceleration disabled");
        return;
    }

    std::optional<float> vx = mVelocityTracker.getVelocity(AMOTION_EVENT_AXIS_X, 0);
    std::optional<float> vy = mVelocityTracker.getVelocity(AMOTION_EVENT_AXIS_Y, 0);

    float ratio;
    if (vx.has_value() && vy.has_value()) {
        float vxMmPerS = countsToMm(*vx);
        float vyMmPerS = countsToMm(*vy);
        float speedMmPerS = sqrtf(vxMmPerS * vxMmPerS + vyMmPerS * vyMmPerS);

        const AccelerationCurveSegment& seg = segmentForSpeed(speedMmPerS);
        ratio = seg.baseGain + seg.reciprocal / speedMmPerS;
        ALOGD_IF(DEBUG_ACCELERATION,
                 "CurvedVelocityControl: velocities (%0.3f, %0.3f) → speed %0.3f → ratio %0.3f",
                 vxMmPerS, vyMmPerS, speedMmPerS, ratio);
    } else {
        // We don't have enough data to compute a velocity yet. This happens early in the movement,
        // when the speed is presumably low, so use the base gain of the first segment of the curve.
        // (This would behave oddly for curves with a reciprocal term on the first segment, but we
        // don't have any of those, and they'd be very strange at velocities close to zero anyway.)
        ratio = mCurveSegments[0].baseGain;
        ALOGD_IF(DEBUG_ACCELERATION,
                 "CurvedVelocityControl: unknown velocity, using base gain of first segment (%.3f)",
                 ratio);
    }

    if (deltaX != nullptr) {
        *deltaX *= ratio;
    }
    if (deltaY != nullptr) {
        *deltaY *= ratio;
    }
}

const AccelerationCurveSegment& CurvedVelocityControl::segmentForSpeed(float speedMmPerS) {
    for (const AccelerationCurveSegment& seg : mCurveSegments) {
        if (speedMmPerS <= seg.maxPointerSpeedMmPerS) {
            return seg;
        }
    }
    ALOGE("CurvedVelocityControl: No segment found for speed %.3f; last segment should always have "
          "a max speed of infinity.",
          speedMmPerS);
    return mCurveSegments.back();
}

} // namespace android
