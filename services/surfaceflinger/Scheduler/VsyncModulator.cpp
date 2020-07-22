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
#define LOG_TAG "VsyncModulator"

#include "VsyncModulator.h"

#include <android-base/properties.h>
#include <log/log.h>
#include <utils/Trace.h>

#include <chrono>
#include <cinttypes>
#include <mutex>

using namespace std::chrono_literals;

namespace android::scheduler {

const std::chrono::nanoseconds VsyncModulator::MIN_EARLY_TRANSACTION_TIME = 1ms;

VsyncModulator::VsyncModulator(const OffsetsConfig& config, Now now)
      : mOffsetsConfig(config),
        mNow(now),
        mTraceDetailedInfo(base::GetBoolProperty("debug.sf.vsync_trace_detailed_info", false)) {}

VsyncModulator::Offsets VsyncModulator::setPhaseOffsets(const OffsetsConfig& config) {
    std::lock_guard<std::mutex> lock(mMutex);
    mOffsetsConfig = config;
    return updateOffsetsLocked();
}

VsyncModulator::OffsetsOpt VsyncModulator::setTransactionSchedule(TransactionSchedule schedule) {
    switch (schedule) {
        case Schedule::EarlyStart:
            ALOGW_IF(mExplicitEarlyWakeup, "%s: Duplicate EarlyStart", __FUNCTION__);
            mExplicitEarlyWakeup = true;
            break;
        case Schedule::EarlyEnd:
            ALOGW_IF(!mExplicitEarlyWakeup, "%s: Unexpected EarlyEnd", __FUNCTION__);
            mExplicitEarlyWakeup = false;
            break;
        case Schedule::Early:
        case Schedule::Late:
            // No change to mExplicitEarlyWakeup for non-explicit states.
            break;
    }

    if (mTraceDetailedInfo) {
        ATRACE_INT("mExplicitEarlyWakeup", mExplicitEarlyWakeup);
    }

    if (!mExplicitEarlyWakeup && (schedule == Schedule::Early || schedule == Schedule::EarlyEnd)) {
        mEarlyTransactionFrames = MIN_EARLY_TRANSACTION_FRAMES;
        mEarlyTransactionStartTime = mNow();
    }

    // An early transaction stays an early transaction.
    if (schedule == mTransactionSchedule || mTransactionSchedule == Schedule::EarlyEnd) {
        return std::nullopt;
    }
    mTransactionSchedule = schedule;
    return updateOffsets();
}

VsyncModulator::OffsetsOpt VsyncModulator::onTransactionCommit() {
    mLastTransactionCommitTime = mNow();
    if (mTransactionSchedule == Schedule::Late) return std::nullopt;
    mTransactionSchedule = Schedule::Late;
    return updateOffsets();
}

VsyncModulator::OffsetsOpt VsyncModulator::onRefreshRateChangeInitiated() {
    if (mRefreshRateChangePending) return std::nullopt;
    mRefreshRateChangePending = true;
    return updateOffsets();
}

VsyncModulator::OffsetsOpt VsyncModulator::onRefreshRateChangeCompleted() {
    if (!mRefreshRateChangePending) return std::nullopt;
    mRefreshRateChangePending = false;
    return updateOffsets();
}

VsyncModulator::OffsetsOpt VsyncModulator::onDisplayRefresh(bool usedGpuComposition) {
    bool updateOffsetsNeeded = false;

    if (mEarlyTransactionStartTime.load() + MIN_EARLY_TRANSACTION_TIME <=
        mLastTransactionCommitTime.load()) {
        if (mEarlyTransactionFrames > 0) {
            mEarlyTransactionFrames--;
            updateOffsetsNeeded = true;
        }
    }
    if (usedGpuComposition) {
        mEarlyGpuFrames = MIN_EARLY_GPU_FRAMES;
        updateOffsetsNeeded = true;
    } else if (mEarlyGpuFrames > 0) {
        mEarlyGpuFrames--;
        updateOffsetsNeeded = true;
    }

    if (!updateOffsetsNeeded) return std::nullopt;
    return updateOffsets();
}

VsyncModulator::Offsets VsyncModulator::getOffsets() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mOffsets;
}

const VsyncModulator::Offsets& VsyncModulator::getNextOffsets() const {
    // Early offsets are used if we're in the middle of a refresh rate
    // change, or if we recently begin a transaction.
    if (mExplicitEarlyWakeup || mTransactionSchedule == Schedule::EarlyEnd ||
        mEarlyTransactionFrames > 0 || mRefreshRateChangePending) {
        return mOffsetsConfig.early;
    } else if (mEarlyGpuFrames > 0) {
        return mOffsetsConfig.earlyGpu;
    } else {
        return mOffsetsConfig.late;
    }
}

VsyncModulator::Offsets VsyncModulator::updateOffsets() {
    std::lock_guard<std::mutex> lock(mMutex);
    return updateOffsetsLocked();
}

VsyncModulator::Offsets VsyncModulator::updateOffsetsLocked() {
    const Offsets& offsets = getNextOffsets();
    mOffsets = offsets;

    if (mTraceDetailedInfo) {
        const bool isEarly = &offsets == &mOffsetsConfig.early;
        const bool isEarlyGpu = &offsets == &mOffsetsConfig.earlyGpu;
        const bool isLate = &offsets == &mOffsetsConfig.late;

        ATRACE_INT("Vsync-EarlyOffsetsOn", isEarly);
        ATRACE_INT("Vsync-EarlyGpuOffsetsOn", isEarlyGpu);
        ATRACE_INT("Vsync-LateOffsetsOn", isLate);
    }

    return offsets;
}

} // namespace android::scheduler
