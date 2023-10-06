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

import android.gui.DisplayMode;
import android.gui.HdrCapabilities;

// Information about a physical display which may change on hotplug reconnect.
// Make sure to sync with libui DynamicDisplayInfo.h

/** @hide */
parcelable DynamicDisplayInfo {
    List<DisplayMode> supportedDisplayModes;

    int activeDisplayModeId;
    float renderFrameRate;

    int[] supportedColorModes;
    int activeColorMode;
    HdrCapabilities hdrCapabilities;

    // True if the display reports support for HDMI 2.1 Auto Low Latency Mode.
    // For more information, see the HDMI 2.1 specification.
    boolean autoLowLatencyModeSupported;

    // True if the display reports support for Game Content Type.
    // For more information, see the HDMI 1.4 specification.
    boolean gameContentTypeSupported;

    // The boot display mode preferred by the implementation.
    int preferredBootDisplayMode;
}
