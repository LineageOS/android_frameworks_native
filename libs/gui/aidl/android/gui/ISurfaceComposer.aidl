/*
 * Copyright 2021 The Android Open Source Project
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

import android.gui.DisplayCaptureArgs;
import android.gui.LayerCaptureArgs;
import android.gui.IScreenCaptureListener;

/** @hide */
interface ISurfaceComposer {

    /* create a virtual display
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    @nullable IBinder createDisplay(@utf8InCpp String displayName, boolean secure);

    /* destroy a virtual display
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    void destroyDisplay(IBinder display);

    /* get stable IDs for connected physical displays.
     */
    long[] getPhysicalDisplayIds();

    long getPrimaryPhysicalDisplayId();

    /* get token for a physical display given its stable ID obtained via getPhysicalDisplayIds or a
     * DisplayEventReceiver hotplug event.
     */
    @nullable IBinder getPhysicalDisplayToken(long displayId);

    /**
     * Capture the specified screen. This requires READ_FRAME_BUFFER
     * permission.  This function will fail if there is a secure window on
     * screen and DisplayCaptureArgs.captureSecureLayers is false.
     *
     * This function can capture a subregion (the source crop) of the screen.
     * The subregion can be optionally rotated.  It will also be scaled to
     * match the size of the output buffer.
     */
    void captureDisplay(in DisplayCaptureArgs args, IScreenCaptureListener listener);
    void captureDisplayById(long displayId, IScreenCaptureListener listener);
    /**
     * Capture a subtree of the layer hierarchy, potentially ignoring the root node.
     * This requires READ_FRAME_BUFFER permission. This function will fail if there
     * is a secure window on screen
     */
    void captureLayers(in LayerCaptureArgs args, IScreenCaptureListener listener);
}
