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

#include <scheduler/PresentLatencyTracker.h>

#include <cutils/compiler.h>
#include <log/log.h>
#include <ui/FenceTime.h>

namespace android::scheduler {

Duration PresentLatencyTracker::trackPendingFrame(TimePoint compositeTime,
                                                  std::shared_ptr<FenceTime> presentFenceTime) {
    Duration presentLatency = Duration::zero();
    while (!mPendingFrames.empty()) {
        const auto& pendingFrame = mPendingFrames.front();
        const auto presentTime =
                TimePoint::fromNs(pendingFrame.presentFenceTime->getCachedSignalTime());

        if (presentTime == TimePoint::fromNs(Fence::SIGNAL_TIME_PENDING)) {
            break;
        }

        if (presentTime == TimePoint::fromNs(Fence::SIGNAL_TIME_INVALID)) {
            ALOGE("%s: Invalid present fence", __func__);
        } else {
            presentLatency = presentTime - pendingFrame.compositeTime;
        }

        mPendingFrames.pop();
    }

    mPendingFrames.emplace(compositeTime, std::move(presentFenceTime));

    if (CC_UNLIKELY(mPendingFrames.size() > kMaxPendingFrames)) {
        ALOGE("%s: Too many pending frames", __func__);
        mPendingFrames.pop();
    }

    return presentLatency;
}

} // namespace android::scheduler
