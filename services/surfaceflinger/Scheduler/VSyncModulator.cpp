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

#include "VSyncModulator.h"

#include <cinttypes>
#include <mutex>

namespace android {

void VSyncModulator::setPhaseOffsets(Offsets early, Offsets earlyGl, Offsets late,
                                     nsecs_t thresholdForNextVsync) {
    mEarlyOffsets = early;
    mEarlyGlOffsets = earlyGl;
    mLateOffsets = late;
    mThresholdForNextVsync = thresholdForNextVsync;

    if (mSfConnectionHandle && late.sf != mOffsets.load().sf) {
        mScheduler->setPhaseOffset(mSfConnectionHandle, late.sf);
    }

    if (mAppConnectionHandle && late.app != mOffsets.load().app) {
        mScheduler->setPhaseOffset(mAppConnectionHandle, late.app);
    }
    mOffsets = late;
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

VSyncModulator::Offsets VSyncModulator::getOffsets() {
    // Early offsets are used if we're in the middle of a refresh rate
    // change, or if we recently begin a transaction.
    if (mTransactionStart == Scheduler::TransactionStart::EARLY || mRemainingEarlyFrameCount > 0 ||
        mRefreshRateChangePending) {
        return mEarlyOffsets;
    } else if (mRemainingRenderEngineUsageCount > 0) {
        return mEarlyGlOffsets;
    } else {
        return mLateOffsets;
    }
}

void VSyncModulator::updateOffsets() {
    const Offsets desired = getOffsets();
    const Offsets current = mOffsets;

    bool changed = false;
    if (desired.sf != current.sf) {
        if (mSfConnectionHandle != nullptr) {
            mScheduler->setPhaseOffset(mSfConnectionHandle, desired.sf);
        } else {
            mSfEventThread->setPhaseOffset(desired.sf);
        }
        changed = true;
    }
    if (desired.app != current.app) {
        if (mAppConnectionHandle != nullptr) {
            mScheduler->setPhaseOffset(mAppConnectionHandle, desired.app);
        } else {
            mAppEventThread->setPhaseOffset(desired.app);
        }
        changed = true;
    }

    if (changed) {
        mOffsets = desired;
    }
}

} // namespace android
