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

import android.InputChannelInfo;
import android.InputWindowInfo;
import android.os.ISetInputWindowsListener;

/** @hide */
interface IInputFlinger
{
    void setInputWindows(in InputWindowInfo[] inputHandles,
            in @nullable ISetInputWindowsListener setInputWindowsListener);
    void registerInputChannel(in InputChannelInfo info);
    void unregisterInputChannel(in InputChannelInfo info);
}
