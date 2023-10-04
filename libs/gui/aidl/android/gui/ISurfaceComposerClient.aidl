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

import android.gui.CreateSurfaceResult;
import android.gui.FrameStats;
import android.gui.LayerMetadata;
import android.gui.SchedulingPolicy;

/** @hide */
interface ISurfaceComposerClient {

    // flags for createSurface()
    // (keep in sync with SurfaceControl.java)
    const int eHidden = 0x00000004;
    const int eDestroyBackbuffer = 0x00000020;
    const int eSkipScreenshot = 0x00000040;
    const int eSecure = 0x00000080;
    const int eNonPremultiplied = 0x00000100;
    const int eOpaque = 0x00000400;
    const int eProtectedByApp = 0x00000800;
    const int eProtectedByDRM = 0x00001000;
    const int eCursorWindow = 0x00002000;
    const int eNoColorFill = 0x00004000;

    const int eFXSurfaceBufferQueue = 0x00000000;
    const int eFXSurfaceEffect = 0x00020000;
    const int eFXSurfaceBufferState = 0x00040000;
    const int eFXSurfaceContainer = 0x00080000;
    const int eFXSurfaceMask = 0x000F0000;

    /**
     * Requires ACCESS_SURFACE_FLINGER permission
     */
    CreateSurfaceResult createSurface(@utf8InCpp String name, int flags, @nullable IBinder parent, in LayerMetadata metadata);

    /**
     * Requires ACCESS_SURFACE_FLINGER permission
     */
    void clearLayerFrameStats(IBinder handle);

    /**
     * Requires ACCESS_SURFACE_FLINGER permission
     */
    FrameStats getLayerFrameStats(IBinder handle);

    CreateSurfaceResult mirrorSurface(IBinder mirrorFromHandle);

    CreateSurfaceResult mirrorDisplay(long displayId);

    SchedulingPolicy getSchedulingPolicy();
}
