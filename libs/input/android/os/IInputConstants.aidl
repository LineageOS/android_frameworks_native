/**
 * Copyright (c) 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.os;


/** @hide */
interface IInputConstants
{
    // This should be multiplied by the value of the system property ro.hw_timeout_multiplier before
    // use. A pre-multiplied constant is available in Java in
    // android.os.InputConstants.DEFAULT_DISPATCHING_TIMEOUT_MILLIS.
    const int UNMULTIPLIED_DEFAULT_DISPATCHING_TIMEOUT_MILLIS = 5000; // 5 seconds

    // Indicate invalid battery capacity
    const int INVALID_BATTERY_CAPACITY = -1;

    /**
     * Every input event has an id. This constant value is used when a valid input event id is not
     * available.
     */
    const int INVALID_INPUT_EVENT_ID = 0;

    /**
     * Every input device has an id. This constant value is used when a valid input device id is not
     * available.
     * The virtual keyboard uses -1 as the input device id. Therefore, we use -2 as the value for
     * an invalid input device.
     */
    const int INVALID_INPUT_DEVICE_ID = -2;

    /**
     * The input event was injected from accessibility. Used in policyFlags for input event
     * injection.
     */
    const int POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY = 0x20000;

    /**
     * The input event was generated or modified by accessibility service.
     * Shared by both KeyEvent and MotionEvent flags, so this value should not overlap with either
     * set of flags, including in input/Input.h and in android/input.h.
     */
    const int INPUT_EVENT_FLAG_IS_ACCESSIBILITY_EVENT = 0x800;

    /* The default pointer acceleration value. */
    const int DEFAULT_POINTER_ACCELERATION = 3;

    /**
     * Use the default Velocity Tracker Strategy. Different axes may use different default
     * strategies.
     */
    const int VELOCITY_TRACKER_STRATEGY_DEFAULT = -1;

    /**
     * Velocity Tracker Strategy: Impulse.
     * Physical model of pushing an object.  Quality: VERY GOOD.
     * Works with duplicate coordinates, unclean finger liftoff.
     */
    const int VELOCITY_TRACKER_STRATEGY_IMPULSE = 0;

    /**
     * Velocity Tracker Strategy: LSQ1.
     * 1st order least squares.  Quality: POOR.
     * Frequently underfits the touch data especially when the finger accelerates
     * or changes direction.  Often underestimates velocity.  The direction
     * is overly influenced by historical touch points.
     */
    const int VELOCITY_TRACKER_STRATEGY_LSQ1 = 1;

    /**
     * Velocity Tracker Strategy: LSQ2.
     * 2nd order least squares.  Quality: VERY GOOD.
     * Pretty much ideal, but can be confused by certain kinds of touch data,
     * particularly if the panel has a tendency to generate delayed,
     * duplicate or jittery touch coordinates when the finger is released.
     */
    const int VELOCITY_TRACKER_STRATEGY_LSQ2 = 2;

    /**
     * Velocity Tracker Strategy: LSQ3.
     * 3rd order least squares.  Quality: UNUSABLE.
     * Frequently overfits the touch data yielding wildly divergent estimates
     * of the velocity when the finger is released.
     */
    const int VELOCITY_TRACKER_STRATEGY_LSQ3 = 3;

    /**
     * Velocity Tracker Strategy: WLSQ2_DELTA.
     * 2nd order weighted least squares, delta weighting.  Quality: EXPERIMENTAL
     */
    const int VELOCITY_TRACKER_STRATEGY_WLSQ2_DELTA = 4;

    /**
     * Velocity Tracker Strategy: WLSQ2_CENTRAL.
     * 2nd order weighted least squares, central weighting.  Quality: EXPERIMENTALe
     */
    const int VELOCITY_TRACKER_STRATEGY_WLSQ2_CENTRAL = 5;

    /**
     * Velocity Tracker Strategy: WLSQ2_RECENT.
     * 2nd order weighted least squares, recent weighting.  Quality: EXPERIMENTAL
     */
    const int VELOCITY_TRACKER_STRATEGY_WLSQ2_RECENT = 6;

    /**
     * Velocity Tracker Strategy: INT1.
     * 1st order integrating filter.  Quality: GOOD.
     * Not as good as 'lsq2' because it cannot estimate acceleration but it is
     * more tolerant of errors.  Like 'lsq1', this strategy tends to underestimate
     * the velocity of a fling but this strategy tends to respond to changes in
     * direction more quickly and accurately.
     */
    const int VELOCITY_TRACKER_STRATEGY_INT1 = 7;

    /**
     * Velocity Tracker Strategy: INT2.
     * 2nd order integrating filter.  Quality: EXPERIMENTAL.
     * For comparison purposes only.  Unlike 'int1' this strategy can compensate
     * for acceleration but it typically overestimates the effect.
     */
    const int VELOCITY_TRACKER_STRATEGY_INT2 = 8;

    /**
     * Velocity Tracker Strategy: Legacy.
     * Legacy velocity tracker algorithm.  Quality: POOR.
     * For comparison purposes only.  This algorithm is strongly influenced by
     * old data points, consistently underestimates velocity and takes a very long
     * time to adjust to changes in direction.
     */
    const int VELOCITY_TRACKER_STRATEGY_LEGACY = 9;
}
