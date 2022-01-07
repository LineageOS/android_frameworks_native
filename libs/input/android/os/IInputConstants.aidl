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

    @Backing(type="int")
    enum InputFeature {
        /**
         * Does not construct an input channel for this window.  The channel will therefore
         * be incapable of receiving input.
         */
        NO_INPUT_CHANNEL = 0x00000002,

        /**
         * When this window has focus, does not call user activity for all input events so
         * the application will have to do it itself.  Should only be used by
         * the keyguard and phone app.
         *
         * Should only be used by the keyguard and phone app.
         */
        DISABLE_USER_ACTIVITY = 0x00000004,

        /**
         * Internal flag used to indicate that input should be dropped on this window.
         */
        DROP_INPUT = 0x00000008,

        /**
         * Internal flag used to indicate that input should be dropped on this window if this window
         * is obscured.
         */
        DROP_INPUT_IF_OBSCURED = 0x00000010,

        /**
         * An input spy window. This window will receive all pointer events within its touchable
         * area, but will will not stop events from being sent to other windows below it in z-order.
         * An input event will be dispatched to all spy windows above the top non-spy window at the
         * event's coordinates.
         */
        SPY = 0x00000020,

        /**
         * When used with the window flag {@link #FLAG_NOT_TOUCHABLE}, this window will continue
         * to receive events from a stylus device within its touchable region. All other pointer
         * events, such as from a mouse or touchscreen, will be dispatched to the windows behind it.
         *
         * This input feature has no effect when the window flag {@link #FLAG_NOT_TOUCHABLE} is
         * not set.
         *
         * The window must be a trusted overlay to use this input feature.
         */
        INTERCEPTS_STYLUS = 0x00000040,
    }
}
