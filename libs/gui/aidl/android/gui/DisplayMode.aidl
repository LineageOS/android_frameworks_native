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

import android.gui.Size;

// Mode supported by physical display.
// Make sure to sync with libui DisplayMode.h

/** @hide */
parcelable DisplayMode {
    int id;
    Size resolution;
    float xDpi = 0.0f;
    float yDpi = 0.0f;
    int[] supportedHdrTypes;

    // Some modes have peak refresh rate lower than the panel vsync rate.
    float peakRefreshRate = 0.0f;
    float vsyncRate = 0.0f;
    long appVsyncOffset = 0;
    long sfVsyncOffset = 0;
    long presentationDeadline = 0;
    int group = -1;
}
