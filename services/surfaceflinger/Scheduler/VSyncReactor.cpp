/*
 * Copyright 2019 The Android Open Source Project
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

#include "VSyncReactor.h"
#include "TimeKeeper.h"
#include "VSyncDispatch.h"
#include "VSyncTracker.h"

namespace android::scheduler {

Clock::~Clock() = default;

VSyncReactor::VSyncReactor(std::unique_ptr<Clock> clock, std::unique_ptr<VSyncDispatch> dispatch,
                           std::unique_ptr<VSyncTracker> tracker, size_t pendingFenceLimit)
      : mClock(std::move(clock)),
        mDispatch(std::move(dispatch)),
        mTracker(std::move(tracker)),
        mPendingLimit(pendingFenceLimit) {}

bool VSyncReactor::addPresentFence(const std::shared_ptr<FenceTime>& fence) {
    if (!fence) {
        return false;
    }

    nsecs_t const signalTime = fence->getCachedSignalTime();
    if (signalTime == Fence::SIGNAL_TIME_INVALID) {
        return true;
    }

    std::lock_guard<std::mutex> lk(mMutex);
    if (mIgnorePresentFences) {
        return true;
    }

    for (auto it = mUnfiredFences.begin(); it != mUnfiredFences.end();) {
        auto const time = (*it)->getCachedSignalTime();
        if (time == Fence::SIGNAL_TIME_PENDING) {
            it++;
        } else if (time == Fence::SIGNAL_TIME_INVALID) {
            it = mUnfiredFences.erase(it);
        } else {
            mTracker->addVsyncTimestamp(time);
            it = mUnfiredFences.erase(it);
        }
    }

    if (signalTime == Fence::SIGNAL_TIME_PENDING) {
        if (mPendingLimit == mUnfiredFences.size()) {
            mUnfiredFences.erase(mUnfiredFences.begin());
        }
        mUnfiredFences.push_back(fence);
    } else {
        mTracker->addVsyncTimestamp(signalTime);
    }

    return false; // TODO(b/144707443): add policy for turning on HWVsync.
}

void VSyncReactor::setIgnorePresentFences(bool ignoration) {
    std::lock_guard<std::mutex> lk(mMutex);
    mIgnorePresentFences = ignoration;
    if (mIgnorePresentFences == true) {
        mUnfiredFences.clear();
    }
}

nsecs_t VSyncReactor::computeNextRefresh(int periodOffset) const {
    auto const now = mClock->now();
    auto const currentPeriod = periodOffset ? mTracker->currentPeriod() : 0;
    return mTracker->nextAnticipatedVSyncTimeFrom(now + periodOffset * currentPeriod);
}

nsecs_t VSyncReactor::expectedPresentTime() {
    return mTracker->nextAnticipatedVSyncTimeFrom(mClock->now());
}

} // namespace android::scheduler
