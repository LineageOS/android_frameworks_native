/*
 * Copyright 2018 The Android Open Source Project
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

#include <utils/Errors.h>

#include <mutex>

using namespace android::surfaceflinger;

namespace android {

/*
 * Modulates the vsync-offsets depending on current SurfaceFlinger state.
 */
class VSyncModulator {
private:

    // Number of frames we'll keep the early phase offsets once they are activated. This acts as a
    // low-pass filter in case the client isn't quick enough in sending new transactions.
    const int MIN_EARLY_FRAME_COUNT = 2;

public:

    struct Offsets {
        nsecs_t sf;
        nsecs_t app;
    };

    enum TransactionStart {
        EARLY,
        NORMAL
    };

    // Sets the phase offsets
    //
    // sfEarly: The phase offset when waking up SF early, which happens when marking a transaction
    //          as early. May be the same as late, in which case we don't shift offsets.
    // sfEarlyGl: Like sfEarly, but only if we used GL composition. If we use both GL composition
    //            and the transaction was marked as early, we'll use sfEarly.
    // sfLate: The regular SF vsync phase offset.
    // appEarly: Like sfEarly, but for the app-vsync
    // appEarlyGl: Like sfEarlyGl, but for the app-vsync.
    // appLate: The regular app vsync phase offset.
    void setPhaseOffsets(Offsets early, Offsets earlyGl, Offsets late) {
        mEarlyOffsets = early;
        mEarlyGlOffsets = earlyGl;
        mLateOffsets = late;
        mOffsets = late;
    }

    Offsets getEarlyOffsets() const {
        return mEarlyOffsets;
    }

    Offsets getEarlyGlOffsets() const {
        return mEarlyGlOffsets;
    }

    void setEventThreads(EventThread* sfEventThread, EventThread* appEventThread) {
        mSfEventThread = sfEventThread;
        mAppEventThread = appEventThread;
    }

    void setTransactionStart(TransactionStart transactionStart) {

        if (transactionStart == TransactionStart::EARLY) {
            mRemainingEarlyFrameCount = MIN_EARLY_FRAME_COUNT;
        }

        // An early transaction stays an early transaction.
        if (transactionStart == mTransactionStart || mTransactionStart == TransactionStart::EARLY) {
            return;
        }
        mTransactionStart = transactionStart;
        updateOffsets();
    }

    void onTransactionHandled() {
        if (mTransactionStart == TransactionStart::NORMAL) return;
        mTransactionStart = TransactionStart::NORMAL;
        updateOffsets();
    }

    void onRefreshed(bool usedRenderEngine) {
        bool updateOffsetsNeeded = false;
        if (mRemainingEarlyFrameCount > 0) {
            mRemainingEarlyFrameCount--;
            updateOffsetsNeeded = true;
        }
        if (usedRenderEngine != mLastFrameUsedRenderEngine) {
            mLastFrameUsedRenderEngine = usedRenderEngine;
            updateOffsetsNeeded = true;
        }
        if (updateOffsetsNeeded) {
            updateOffsets();
        }
    }

private:

    void updateOffsets() {
        const Offsets desired = getOffsets();
        const Offsets current = mOffsets;

        bool changed = false;
        if (desired.sf != current.sf) {
            mSfEventThread->setPhaseOffset(desired.sf);
            changed = true;
        }
        if (desired.app != current.app) {
            mAppEventThread->setPhaseOffset(desired.app);
            changed = true;
        }

        if (changed) {
            mOffsets = desired;
        }
    }

    Offsets getOffsets() {
        if (mTransactionStart == TransactionStart::EARLY || mRemainingEarlyFrameCount > 0) {
            return mEarlyOffsets;
        } else if (mLastFrameUsedRenderEngine) {
            return mEarlyGlOffsets;
        } else {
            return mLateOffsets;
        }
    }

    Offsets mLateOffsets;
    Offsets mEarlyOffsets;
    Offsets mEarlyGlOffsets;

    EventThread* mSfEventThread = nullptr;
    EventThread* mAppEventThread = nullptr;

    std::atomic<Offsets> mOffsets;

    std::atomic<TransactionStart> mTransactionStart = TransactionStart::NORMAL;
    std::atomic<bool> mLastFrameUsedRenderEngine = false;
    std::atomic<int> mRemainingEarlyFrameCount = 0;
};

} // namespace android
