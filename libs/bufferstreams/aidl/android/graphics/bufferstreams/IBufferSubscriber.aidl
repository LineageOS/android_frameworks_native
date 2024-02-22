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

import android.graphics.bufferstreams.BufferCacheUpdate;
import android.graphics.bufferstreams.IBufferSubscription;
import android.graphics.bufferstreams.Frame;

// Interface provided by clients to a service, mirroring the non-IPC interface.
//
// Clients are required to maintain a local cache of Buffer IDs to BufferAttachments.
interface IBufferSubscriber {
    // Provide a BufferSubscription object which the client can use to request frames.
    oneway void onSubscribe(in IBufferSubscription subscription);

    // Notifies the client to update its local caches.
    oneway void onBufferCacheUpdate(in BufferCacheUpdate update);

    // Notifies the client that a requested frame is available.
    oneway void onNext(in Frame frame);

    // Notifies the client that a fatal error has occurred. No subsequent on_next events will be
    // sent by the service.
    //
    // Clients must empty their caches.
    oneway void onError();

    // Notifies the client that no further on_next events will be sent by the service in response
    // to it cancelling the subscription.
    //
    // Clients must empty their caches.
    oneway void onComplete();
}
