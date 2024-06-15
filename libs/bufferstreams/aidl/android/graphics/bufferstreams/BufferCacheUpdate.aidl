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

import android.graphics.bufferstreams.BufferAttachment;

// A event that changes the state downstream buffer caches. Clients are responsible for forwarding
// these messages to their clients.
union BufferCacheUpdate {
    // Event requiring downstream caches to add new entries.
    CacheBuffers cacheBuffers;
    // Event requiring downstream caches to remove entries.
    ForgetBuffers forgetBuffers;

    parcelable CacheBuffers {
        // Attachments to add.
        List<BufferAttachment> attachments;
    }

    parcelable ForgetBuffers {
        // References to remove.
        long[] bufferIds;
    }
}
