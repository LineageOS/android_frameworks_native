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

#include "VSyncModulator.h"

#include <cutils/properties.h>
#include <utils/Trace.h>

#include <cinttypes>
#include <mutex>

namespace android::scheduler {

VSyncModulator::VSyncModulator(Scheduler& scheduler,
                               Scheduler::ConnectionHandle appConnectionHandle,
                               Scheduler::ConnectionHandle sfConnectionHandle,
                               const OffsetsConfig& config)
      : mScheduler(scheduler),
        mAppConnectionHandle(appConnectionHandle),
        mSfConnectionHandle(sfConnectionHandle),
        mOffsetsConfig(config) {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.vsync_trace_detailed_info", value, "0");
    mTraceDetailedInfo = atoi(value);
}

void VSyncModulator::setPhaseOffsets(const OffsetsConfig& config) {
    std::lock_guard<std::mutex> lock(mMutex);
    mOffsetsConfig = config;
    updateOffsetsLocked();
}

void VSyncModulator::setTransactionStart(Scheduler::TransactionStart transactionStart) {
    if (transactionStart == Scheduler::TransactionStart::EARLY) {
        mRemainingEarlyFrameCount = MIN_EARLY_FRAME_COUNT_TRANSACTION;
    }

    // An early transaction stays an early transaction.
    if (transactionStart == mTransactionStart ||
        mTransactionStart == Scheduler::TransactionStart::EARLY) {
        return;
    }
    mTransactionStart = transactionStart;
    updateOffsets();
}

void VSyncModulator::onTransactionHandled() {
    if (mTransactionStart == Scheduler::TransactionStart::NORMAL) return;
    mTransactionStart = Scheduler::TransactionStart::NORMAL;
    updateOffsets();
}

void VSyncModulator::onRefreshRateChangeInitiated() {
    if (mRefreshRateChangePending) {
        return;
    }
    mRefreshRateChangePending = true;
    updateOffsets();
}

void VSyncModulator::onRefreshRateChangeCompleted() {
    if (!mRefreshRateChangePending) {
        return;
    }
    mRefreshRateChangePending = false;
    updateOffsets();
}

void VSyncModulator::onRefreshed(bool usedRenderEngine) {
    bool updateOffsetsNeeded = false;
    if (mRemainingEarlyFrameCount > 0) {
        mRemainingEarlyFrameCount--;
        updateOffsetsNeeded = true;
    }
    if (usedRenderEngine) {
        mRemainingRenderEngineUsageCount = MIN_EARLY_GL_FRAME_COUNT_TRANSACTION;
        updateOffsetsNeeded = true;
    } else if (mRemainingRenderEngineUsageCount > 0) {
        mRemainingRenderEngineUsageCount--;
        updateOffsetsNeeded = true;
    }
    if (updateOffsetsNeeded) {
        updateOffsets();
    }
}

VSyncModulator::Offsets VSyncModulator::getOffsets() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mOffsets;
}

const VSyncModulator::Offsets& VSyncModulator::getNextOffsets() const {
    // Early offsets are used if we're in the middle of a refresh rate
    // change, or if we recently begin a transaction.
    if (mTransactionStart == Scheduler::TransactionStart::EARLY || mRemainingEarlyFrameCount > 0 ||
        mRefreshRateChangePending) {
        return mOffsetsConfig.early;
    } else if (mRemainingRenderEngineUsageCount > 0) {
        return mOffsetsConfig.earlyGl;
    } else {
        return mOffsetsConfig.late;
    }
}

void VSyncModulator::updateOffsets() {
    std::lock_guard<std::mutex> lock(mMutex);
    updateOffsetsLocked();
}

void VSyncModulator::updateOffsetsLocked() {
    const Offsets& offsets = getNextOffsets();

    mScheduler.setPhaseOffset(mSfConnectionHandle, offsets.sf);
    mScheduler.setPhaseOffset(mAppConnectionHandle, offsets.app);

    mOffsets = offsets;

    if (!mTraceDetailedInfo) {
        return;
    }

    const bool isDefault = mOffsets.fpsMode == RefreshRateType::DEFAULT;
    const bool isPerformance = mOffsets.fpsMode == RefreshRateType::PERFORMANCE;
    const bool isEarly = &offsets == &mOffsetsConfig.early;
    const bool isEarlyGl = &offsets == &mOffsetsConfig.earlyGl;
    const bool isLate = &offsets == &mOffsetsConfig.late;

    ATRACE_INT("Vsync-EarlyOffsetsOn", isDefault && isEarly);
    ATRACE_INT("Vsync-EarlyGLOffsetsOn", isDefault && isEarlyGl);
    ATRACE_INT("Vsync-LateOffsetsOn", isDefault && isLate);
    ATRACE_INT("Vsync-HighFpsEarlyOffsetsOn", isPerformance && isEarly);
    ATRACE_INT("Vsync-HighFpsEarlyGLOffsetsOn", isPerformance && isEarlyGl);
    ATRACE_INT("Vsync-HighFpsLateOffsetsOn", isPerformance && isLate);
}

} // namespace android::scheduler
