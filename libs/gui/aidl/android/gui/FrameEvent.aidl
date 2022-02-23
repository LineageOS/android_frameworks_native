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

// Identifiers for all the events that may be recorded or reported.

/** @hide */
@Backing(type="int")
enum FrameEvent {
    POSTED = 0,
    REQUESTED_PRESENT = 1,
    LATCH = 2,
    ACQUIRE = 3,
    FIRST_REFRESH_START = 4,
    LAST_REFRESH_START = 5,
    GPU_COMPOSITION_DONE = 6,
    DISPLAY_PRESENT = 7,
    DEQUEUE_READY = 8,
    RELEASE = 9,
    EVENT_COUNT = 10 // Not an actual event.
}
