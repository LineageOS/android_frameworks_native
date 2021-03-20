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

#include <chrono>
#include <mutex>
#include <optional>

#include <android-base/thread_annotations.h>
#include <utils/Timers.h>

namespace android::scheduler {

// State machine controlled by transaction flags. VsyncModulator switches to early phase offsets
// when a transaction is flagged EarlyStart or Early, lasting until an EarlyEnd transaction or a
// fixed number of frames, respectively.
enum class TransactionSchedule {
    Late,  // Default.
    EarlyStart,
    EarlyEnd
};

// Modulates VSYNC phase depending on transaction schedule and refresh rate changes.
class VsyncModulator {
public:
    // Number of frames to keep early offsets after an early transaction or GPU composition.
    // This acts as a low-pass filter in case subsequent transactions are delayed, or if the
    // composition strategy alternates on subsequent frames.
    static constexpr int MIN_EARLY_TRANSACTION_FRAMES = 2;
    static constexpr int MIN_EARLY_GPU_FRAMES = 2;

    // Duration to delay the MIN_EARLY_TRANSACTION_FRAMES countdown after an early transaction.
    // This may keep early offsets for an extra frame, but avoids a race with transaction commit.
    static const std::chrono::nanoseconds MIN_EARLY_TRANSACTION_TIME;

    // Phase offsets and work durations for SF and app deadlines from VSYNC.
    struct VsyncConfig {
        nsecs_t sfOffset;
        nsecs_t appOffset;
        std::chrono::nanoseconds sfWorkDuration;
        std::chrono::nanoseconds appWorkDuration;

        bool operator==(const VsyncConfig& other) const {
            return sfOffset == other.sfOffset && appOffset == other.appOffset &&
                    sfWorkDuration == other.sfWorkDuration &&
                    appWorkDuration == other.appWorkDuration;
        }

        bool operator!=(const VsyncConfig& other) const { return !(*this == other); }
    };

    using VsyncConfigOpt = std::optional<VsyncConfig>;

    struct VsyncConfigSet {
        VsyncConfig early;    // Used for early transactions, and during refresh rate change.
        VsyncConfig earlyGpu; // Used during GPU composition.
        VsyncConfig late;     // Default.

        bool operator==(const VsyncConfigSet& other) const {
            return early == other.early && earlyGpu == other.earlyGpu && late == other.late;
        }

        bool operator!=(const VsyncConfigSet& other) const { return !(*this == other); }
    };

    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Now = TimePoint (*)();

    explicit VsyncModulator(const VsyncConfigSet&, Now = Clock::now);

    VsyncConfig getVsyncConfig() const EXCLUDES(mMutex);

    [[nodiscard]] VsyncConfig setVsyncConfigSet(const VsyncConfigSet&) EXCLUDES(mMutex);

    // Changes offsets in response to transaction flags or commit.
    [[nodiscard]] VsyncConfigOpt setTransactionSchedule(TransactionSchedule);
    [[nodiscard]] VsyncConfigOpt onTransactionCommit();

    // Called when we send a refresh rate change to hardware composer, so that
    // we can move into early offsets.
    [[nodiscard]] VsyncConfigOpt onRefreshRateChangeInitiated();

    // Called when we detect from VSYNC signals that the refresh rate changed.
    // This way we can move out of early offsets if no longer necessary.
    [[nodiscard]] VsyncConfigOpt onRefreshRateChangeCompleted();

    [[nodiscard]] VsyncConfigOpt onDisplayRefresh(bool usedGpuComposition);

private:
    const VsyncConfig& getNextVsyncConfig() const REQUIRES(mMutex);
    [[nodiscard]] VsyncConfig updateVsyncConfig() EXCLUDES(mMutex);
    [[nodiscard]] VsyncConfig updateVsyncConfigLocked() REQUIRES(mMutex);

    mutable std::mutex mMutex;
    VsyncConfigSet mVsyncConfigSet GUARDED_BY(mMutex);

    VsyncConfig mVsyncConfig GUARDED_BY(mMutex){mVsyncConfigSet.late};

    using Schedule = TransactionSchedule;
    std::atomic<Schedule> mTransactionSchedule = Schedule::Late;
    std::atomic<bool> mEarlyWakeup = false;

    std::atomic<bool> mRefreshRateChangePending = false;

    std::atomic<int> mEarlyTransactionFrames = 0;
    std::atomic<int> mEarlyGpuFrames = 0;
    std::atomic<TimePoint> mEarlyTransactionStartTime = TimePoint();
    std::atomic<TimePoint> mLastTransactionCommitTime = TimePoint();

    const Now mNow;
    const bool mTraceDetailedInfo;
};

} // namespace android::scheduler
