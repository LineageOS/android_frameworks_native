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

import android.graphics.bufferstreams.IBufferOwner;
import android.hardware.HardwareBuffer;

// Single mapping between a buffer reference and heavy-weight data (like the
// buffer itself) and data that is stable between frames.
parcelable BufferAttachment {
    // The HardwareBuffer itself.
    //
    // This field is @nullable for codegen, since HardwareBuffer doesn't implement Default in Rust.
    // In practice, it should never be null.
    @nullable HardwareBuffer buffer;
    // The buffer owner to which this buffer should be returned.
    IBufferOwner owner;
}
