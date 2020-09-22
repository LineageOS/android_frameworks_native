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

import android.FocusRequest;
import android.InputChannel;
import android.InputWindowInfo;
import android.os.ISetInputWindowsListener;

/** @hide */
interface IInputFlinger
{
    // SurfaceFlinger is the caller of this method, it uses the listener callback to ensure the
    // ordering when needed.
    // SurfaceFlinger calls this only every VSync, so overflow of binder's oneway buffer
    // shouldn't be a concern.
    oneway void setInputWindows(in InputWindowInfo[] inputHandles,
            in @nullable ISetInputWindowsListener setInputWindowsListener);
    InputChannel createInputChannel(in @utf8InCpp String name);
    void removeInputChannel(in IBinder connectionToken);
    /**
     * Sets focus to the window identified by the token. This must be called
     * after updating any input window handles.
     */
    oneway void setFocusedWindow(in FocusRequest request);
}
