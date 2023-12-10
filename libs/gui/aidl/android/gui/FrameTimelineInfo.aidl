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
parcelable FrameTimelineInfo {
    // Needs to be in sync with android.graphics.FrameInfo.INVALID_VSYNC_ID in java
    const long INVALID_VSYNC_ID = -1;

    // The vsync id that was used to start the transaction
    long vsyncId = INVALID_VSYNC_ID;

    // The id of the input event that caused this buffer
    // Default is android::os::IInputConstants::INVALID_INPUT_EVENT_ID = 0
    // We copy the value of the input event ID instead of including the header, because libgui
    // header libraries containing FrameTimelineInfo must be available to vendors, but libinput is
    // not directly vendor available.
    int inputEventId = 0;

    // The current time in nanoseconds the application started to render the frame.
    long startTimeNanos = 0;

    // Whether this vsyncId should be used to heuristically select the display refresh rate
    // TODO(b/281695725): Clean this up once TextureView use setFrameRate API
    boolean useForRefreshRateSelection = false;

    // The VsyncId of a frame that was not drawn and squashed into this frame.
    long skippedFrameVsyncId = INVALID_VSYNC_ID;

    // The start time of a frame that was not drawn and squashed into this frame.
    long skippedFrameStartTimeNanos = 0;
}
