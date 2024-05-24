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

#pragma once

#include <vector>

#include <android-base/stringprintf.h>
#include <input/AccelerationCurve.h>
#include <input/Input.h>
#include <input/VelocityTracker.h>
#include <utils/Timers.h>

using android::base::StringPrintf;

namespace android {

/*
 * Specifies parameters that govern pointer or wheel acceleration.
 */
struct VelocityControlParameters {
    // A scale factor that is multiplied with the raw velocity deltas
    // prior to applying any other velocity control factors.  The scale
    // factor should be used to adapt the input device resolution
    // (eg. counts per inch) to the output device resolution (eg. pixels per inch).
    //
    // Must be a positive value.
    // Default is 1.0 (no scaling).
    float scale;

    // The scaled speed at which acceleration begins to be applied.
    // This value establishes the upper bound of a low speed regime for
    // small precise motions that are performed without any acceleration.
    //
    // Must be a non-negative value.
    // Default is 0.0 (no low threshold).
    float lowThreshold;

    // The scaled speed at which maximum acceleration is applied.
    // The difference between highThreshold and lowThreshold controls
    // the range of speeds over which the acceleration factor is interpolated.
    // The wider the range, the smoother the acceleration.
    //
    // Must be a non-negative value greater than or equal to lowThreshold.
    // Default is 0.0 (no high threshold).
    float highThreshold;

    // The acceleration factor.
    // When the speed is above the low speed threshold, the velocity will scaled
    // by an interpolated value between 1.0 and this amount.
    //
    // Must be a positive greater than or equal to 1.0.
    // Default is 1.0 (no acceleration).
    float acceleration;

    VelocityControlParameters() :
            scale(1.0f), lowThreshold(0.0f), highThreshold(0.0f), acceleration(1.0f) {
    }

    VelocityControlParameters(float scale, float lowThreshold,
            float highThreshold, float acceleration) :
            scale(scale), lowThreshold(lowThreshold),
            highThreshold(highThreshold), acceleration(acceleration) {
    }

    std::string dump() const {
        return StringPrintf("scale=%0.3f, lowThreshold=%0.3f, highThreshold=%0.3f, "
                            "acceleration=%0.3f\n",
                            scale, lowThreshold, highThreshold, acceleration);
    }
};

/*
 * Implements mouse pointer and wheel speed control and acceleration.
 */
class VelocityControl {
public:
    VelocityControl();
    virtual ~VelocityControl() {}

    /* Resets the current movement counters to zero.
     * This has the effect of nullifying any acceleration. */
    void reset();

    /* Translates a raw movement delta into an appropriately
     * scaled / accelerated delta based on the current velocity. */
    void move(nsecs_t eventTime, float* deltaX, float* deltaY);

protected:
    virtual void scaleDeltas(float* deltaX, float* deltaY) = 0;

    // If no movements are received within this amount of time,
    // we assume the movement has stopped and reset the movement counters.
    static const nsecs_t STOP_TIME = 500 * 1000000; // 500 ms

    nsecs_t mLastMovementTime;
    float mRawPositionX, mRawPositionY;
    VelocityTracker mVelocityTracker;
};

/**
 * Velocity control using a simple acceleration curve where the acceleration factor increases
 * linearly with movement speed, subject to minimum and maximum values.
 */
class SimpleVelocityControl : public VelocityControl {
public:
    /** Gets the various parameters. */
    const VelocityControlParameters& getParameters() const;

    /** Sets the various parameters. */
    void setParameters(const VelocityControlParameters& parameters);

protected:
    virtual void scaleDeltas(float* deltaX, float* deltaY) override;

private:
    VelocityControlParameters mParameters;
};

/** Velocity control using a curve made up of multiple reciprocal segments. */
class CurvedVelocityControl : public VelocityControl {
public:
    CurvedVelocityControl();

    /** Sets the curve to be used for acceleration. */
    void setCurve(const std::vector<AccelerationCurveSegment>& curve);

    void setAccelerationEnabled(bool enabled);

protected:
    virtual void scaleDeltas(float* deltaX, float* deltaY) override;

private:
    const AccelerationCurveSegment& segmentForSpeed(float speedMmPerS);

    bool mAccelerationEnabled = true;
    std::vector<AccelerationCurveSegment> mCurveSegments;
};

} // namespace android
