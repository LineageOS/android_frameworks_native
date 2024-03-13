/*
 * Copyright 2022 The Android Open Source Project
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

package android.gui;

/** @hide */
parcelable DisplayModeSpecs {
    /**
     * Defines the refresh rates ranges that should be used by SF.
     */
    parcelable RefreshRateRanges {
        /**
         * Defines a range of refresh rates.
         */
        parcelable RefreshRateRange {
            float min;
            float max;
        }

        /**
         *  The range of refresh rates that the display should run at.
         */
        RefreshRateRange physical;

        /**
         *  The range of refresh rates that apps should render at.
         */
        RefreshRateRange render;
    }

    /**
     * Refers to the time after which the idle screen's refresh rate is to be reduced
     */
    parcelable IdleScreenRefreshRateConfig {

        /**
         *  The timeout value in milli seconds
         */
        int timeoutMillis;
    }

    /**
     * Base mode ID. This is what system defaults to for all other settings, or
     * if the refresh rate range is not available.
     */
    int defaultMode;

    /**
     * If true this will allow switching between modes in different display configuration
     * groups. This way the user may see visual interruptions when the display mode changes.
     */

    boolean allowGroupSwitching;

    /**
     * The primary physical and render refresh rate ranges represent DisplayManager's general
     * guidance on the display modes SurfaceFlinger will consider when switching refresh
     * rates and scheduling the frame rate. Unless SurfaceFlinger has a specific reason to do
     * otherwise, it will stay within this range.
     */
    RefreshRateRanges primaryRanges;

    /**
     * The app request physical and render refresh rate ranges allow SurfaceFlinger to consider
     * more display modes when switching refresh rates. Although SurfaceFlinger will
     * generally stay within the primary range, specific considerations, such as layer frame
     * rate settings specified via the setFrameRate() API, may cause SurfaceFlinger to go
     * outside the primary range. SurfaceFlinger never goes outside the app request range.
     * The app request range will be greater than or equal to the primary refresh rate range,
     * never smaller.
     */
    RefreshRateRanges appRequestRanges;

    /**
     * The config to represent the maximum time (in ms) for which the display can remain in an idle
     * state before reducing the refresh rate to conserve power.
     * Null value refers that the device is not configured to dynamically reduce the refresh rate
     * based on external conditions.
     * -1 refers to the current conditions requires no timeout
     */
    @nullable IdleScreenRefreshRateConfig idleScreenRefreshRateConfig;
}
