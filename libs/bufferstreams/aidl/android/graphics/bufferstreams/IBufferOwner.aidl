/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.graphics.bufferstreams;

import android.os.ParcelFileDescriptor;

// Interface from a client back to the owner of a buffer.
interface IBufferOwner {
    // Called when the buffer is done being processed by the stream to return its owner.
    oneway void onBufferReleased(in long bufferId, in @nullable ParcelFileDescriptor releaseFence);
}
