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

// A Frame represents a single buffer passing through the stream.
parcelable Frame {
    // The service must have provided an associated BufferAttachment and the client is required to
    // maintain a cache between the two.
    long bufferId;
    // The expected present time of this frame, or -1 if immediate.
    long presentTimeNs;
    // The acquire fence of the buffer for this frame.
    @nullable ParcelFileDescriptor fence;
}
