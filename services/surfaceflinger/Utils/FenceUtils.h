/**
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

#pragma once

#include <ui/Fence.h>

namespace android {

// TODO: measure if Fence::merge is cheaper
inline void mergeFence(const char* debugName, sp<Fence>&& incomingFence, sp<Fence>& prevFence) {
    if (prevFence == nullptr && incomingFence->getStatus() != Fence::Status::Invalid) {
        prevFence = std::move(incomingFence);
    } else if (prevFence != nullptr) {
        // If both fences are signaled or both are unsignaled, we need to merge
        // them to get an accurate timestamp.
        if (prevFence->getStatus() != Fence::Status::Invalid &&
            prevFence->getStatus() == incomingFence->getStatus()) {
            char fenceName[32] = {};
            snprintf(fenceName, 32, "%.28s", debugName);
            sp<Fence> mergedFence = Fence::merge(fenceName, prevFence, incomingFence);
            if (mergedFence->isValid()) {
                prevFence = std::move(mergedFence);
            }
        } else if (incomingFence->getStatus() == Fence::Status::Unsignaled) {
            // If one fence has signaled and the other hasn't, the unsignaled
            // fence will approximately correspond with the correct timestamp.
            // There's a small race if both fences signal at about the same time
            // and their statuses are retrieved with unfortunate timing. However,
            // by this point, they will have both signaled and only the timestamp
            // will be slightly off; any dependencies after this point will
            // already have been met.
            prevFence = std::move(incomingFence);
        }
    }
}

} // namespace android
