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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#undef LOG_TAG
#define LOG_TAG "VSyncReactor"
//#define LOG_NDEBUG 0

#include <assert.h>
#include <cutils/properties.h>
#include <ftl/concat.h>
#include <gui/TraceUtils.h>
#include <log/log.h>
#include <utils/Trace.h>

#include "../TracedOrdinal.h"
#include "VSyncDispatch.h"
#include "VSyncReactor.h"
#include "VSyncTracker.h"

namespace android::scheduler {

using base::StringAppendF;

VsyncController::~VsyncController() = default;

nsecs_t SystemClock::now() const {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

VSyncReactor::VSyncReactor(PhysicalDisplayId id, std::unique_ptr<Clock> clock,
                           VSyncTracker& tracker, size_t pendingFenceLimit,
                           bool supportKernelIdleTimer)
      : mId(id),
        mClock(std::move(clock)),
        mTracker(tracker),
        mPendingLimit(pendingFenceLimit),
        mSupportKernelIdleTimer(supportKernelIdleTimer) {}

VSyncReactor::~VSyncReactor() = default;

bool VSyncReactor::addPresentFence(std::shared_ptr<FenceTime> fence) {
    ATRACE_CALL();

    if (!fence) {
        return false;
    }

    nsecs_t const signalTime = fence->getCachedSignalTime();
    if (signalTime == Fence::SIGNAL_TIME_INVALID) {
        return true;
    }

    std::lock_guard lock(mMutex);
    if (mExternalIgnoreFences || mInternalIgnoreFences) {
        ATRACE_FORMAT_INSTANT("mExternalIgnoreFences=%d mInternalIgnoreFences=%d",
            mExternalIgnoreFences, mInternalIgnoreFences);
        return true;
    }

    bool timestampAccepted = true;
    for (auto it = mUnfiredFences.begin(); it != mUnfiredFences.end();) {
        auto const time = (*it)->getCachedSignalTime();
        if (time == Fence::SIGNAL_TIME_PENDING) {
            it++;
        } else if (time == Fence::SIGNAL_TIME_INVALID) {
            it = mUnfiredFences.erase(it);
        } else {
            timestampAccepted &= mTracker.addVsyncTimestamp(time);

            it = mUnfiredFences.erase(it);
        }
    }

    if (signalTime == Fence::SIGNAL_TIME_PENDING) {
        if (mPendingLimit == mUnfiredFences.size()) {
            mUnfiredFences.erase(mUnfiredFences.begin());
        }
        mUnfiredFences.push_back(std::move(fence));
    } else {
        timestampAccepted &= mTracker.addVsyncTimestamp(signalTime);
    }

    if (!timestampAccepted) {
        mMoreSamplesNeeded = true;
        setIgnorePresentFencesInternal(true);
        mPeriodConfirmationInProgress = true;
    }

    return mMoreSamplesNeeded;
}

void VSyncReactor::setIgnorePresentFences(bool ignore) {
    std::lock_guard lock(mMutex);
    mExternalIgnoreFences = ignore;
    updateIgnorePresentFencesInternal();
}

void VSyncReactor::setIgnorePresentFencesInternal(bool ignore) {
    mInternalIgnoreFences = ignore;
    updateIgnorePresentFencesInternal();
}

void VSyncReactor::updateIgnorePresentFencesInternal() {
    if (mExternalIgnoreFences || mInternalIgnoreFences) {
        mUnfiredFences.clear();
    }
}

void VSyncReactor::startPeriodTransitionInternal(ftl::NonNull<DisplayModePtr> modePtr) {
    ATRACE_FORMAT("%s %" PRIu64, __func__, mId.value);
    mPeriodConfirmationInProgress = true;
    mModePtrTransitioningTo = modePtr.get();
    mMoreSamplesNeeded = true;
    setIgnorePresentFencesInternal(true);
}

void VSyncReactor::endPeriodTransition() {
    ATRACE_FORMAT("%s %" PRIu64, __func__, mId.value);
    mModePtrTransitioningTo.reset();
    mPeriodConfirmationInProgress = false;
    mLastHwVsync.reset();
}

void VSyncReactor::onDisplayModeChanged(ftl::NonNull<DisplayModePtr> modePtr, bool force) {
    ATRACE_INT64(ftl::Concat("VSR-", __func__, " ", mId.value).c_str(),
                 modePtr->getVsyncRate().getPeriodNsecs());
    std::lock_guard lock(mMutex);
    mLastHwVsync.reset();

    if (!mSupportKernelIdleTimer &&
        modePtr->getVsyncRate().getPeriodNsecs() == mTracker.currentPeriod() && !force) {
        endPeriodTransition();
        setIgnorePresentFencesInternal(false);
        mMoreSamplesNeeded = false;
    } else {
        startPeriodTransitionInternal(modePtr);
    }
}

bool VSyncReactor::periodConfirmed(nsecs_t vsync_timestamp, std::optional<nsecs_t> HwcVsyncPeriod) {
    if (!mPeriodConfirmationInProgress) {
        return false;
    }

    if (mDisplayPowerMode == hal::PowerMode::DOZE ||
        mDisplayPowerMode == hal::PowerMode::DOZE_SUSPEND) {
        return true;
    }

    if (!mLastHwVsync && !HwcVsyncPeriod) {
        return false;
    }

    const std::optional<Period> newPeriod = mModePtrTransitioningTo
            ? mModePtrTransitioningTo->getVsyncRate().getPeriod()
            : std::optional<Period>{};
    const bool periodIsChanging = newPeriod && (newPeriod->ns() != mTracker.currentPeriod());
    if (mSupportKernelIdleTimer && !periodIsChanging) {
        // Clear out the Composer-provided period and use the allowance logic below
        HwcVsyncPeriod = {};
    }

    auto const period = newPeriod ? newPeriod->ns() : mTracker.currentPeriod();
    static constexpr int allowancePercent = 10;
    static constexpr std::ratio<allowancePercent, 100> allowancePercentRatio;
    auto const allowance = period * allowancePercentRatio.num / allowancePercentRatio.den;
    if (HwcVsyncPeriod) {
        return std::abs(*HwcVsyncPeriod - period) < allowance;
    }

    auto const distance = vsync_timestamp - *mLastHwVsync;
    return std::abs(distance - period) < allowance;
}

bool VSyncReactor::addHwVsyncTimestamp(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                                       bool* periodFlushed) {
    assert(periodFlushed);

    std::lock_guard lock(mMutex);
    if (periodConfirmed(timestamp, hwcVsyncPeriod)) {
        ATRACE_FORMAT("VSR %" PRIu64 ": period confirmed", mId.value);
        if (mModePtrTransitioningTo) {
            mTracker.setDisplayModePtr(ftl::as_non_null(mModePtrTransitioningTo));
            *periodFlushed = true;
        }

        if (mLastHwVsync) {
            mTracker.addVsyncTimestamp(*mLastHwVsync);
        }
        mTracker.addVsyncTimestamp(timestamp);

        endPeriodTransition();
        mMoreSamplesNeeded = mTracker.needsMoreSamples();
    } else if (mPeriodConfirmationInProgress) {
        ATRACE_FORMAT("VSR %" PRIu64 ": still confirming period", mId.value);
        mLastHwVsync = timestamp;
        mMoreSamplesNeeded = true;
        *periodFlushed = false;
    } else {
        ATRACE_FORMAT("VSR %" PRIu64 ": adding sample", mId.value);
        *periodFlushed = false;
        mTracker.addVsyncTimestamp(timestamp);
        mMoreSamplesNeeded = mTracker.needsMoreSamples();
    }

    if (!mMoreSamplesNeeded) {
        setIgnorePresentFencesInternal(false);
    }
    return mMoreSamplesNeeded;
}

void VSyncReactor::setDisplayPowerMode(hal::PowerMode powerMode) {
    std::scoped_lock lock(mMutex);
    mDisplayPowerMode = powerMode;
}

void VSyncReactor::dump(std::string& result) const {
    std::lock_guard lock(mMutex);
    StringAppendF(&result, "VsyncReactor in use\n");
    StringAppendF(&result, "Has %zu unfired fences\n", mUnfiredFences.size());
    StringAppendF(&result, "mInternalIgnoreFences=%d mExternalIgnoreFences=%d\n",
                  mInternalIgnoreFences, mExternalIgnoreFences);
    StringAppendF(&result, "mMoreSamplesNeeded=%d mPeriodConfirmationInProgress=%d\n",
                  mMoreSamplesNeeded, mPeriodConfirmationInProgress);
    if (mModePtrTransitioningTo) {
        StringAppendF(&result, "mModePtrTransitioningTo=%s\n",
                      to_string(*mModePtrTransitioningTo).c_str());
    } else {
        StringAppendF(&result, "mModePtrTransitioningTo=nullptr\n");
    }

    if (mLastHwVsync) {
        StringAppendF(&result, "Last HW vsync was %.2fms ago\n",
                      (mClock->now() - *mLastHwVsync) / 1e6f);
    } else {
        StringAppendF(&result, "No Last HW vsync\n");
    }

    StringAppendF(&result, "VSyncTracker:\n");
    mTracker.dump(result);
}

} // namespace android::scheduler
