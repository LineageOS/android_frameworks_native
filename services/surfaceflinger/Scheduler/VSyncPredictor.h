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

#pragma once

#include <deque>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <android-base/thread_annotations.h>
#include <scheduler/TimeKeeper.h>
#include <ui/DisplayId.h>

#include "VSyncTracker.h"

namespace android::scheduler {

class VSyncPredictor : public VSyncTracker {
public:
    /*
     * \param [in] Clock The clock abstraction. Useful for unit tests.
     * \param [in] PhysicalDisplayid The display this corresponds to.
     * \param [in] modePtr  The initial display mode
     * \param [in] historySize  The internal amount of entries to store in the model.
     * \param [in] minimumSamplesForPrediction The minimum number of samples to collect before
     * predicting. \param [in] outlierTolerancePercent a number 0 to 100 that will be used to filter
     * samples that fall outlierTolerancePercent from an anticipated vsync event.
     */
    VSyncPredictor(std::unique_ptr<Clock>, ftl::NonNull<DisplayModePtr> modePtr, size_t historySize,
                   size_t minimumSamplesForPrediction, uint32_t outlierTolerancePercent);
    ~VSyncPredictor();

    bool addVsyncTimestamp(nsecs_t timestamp) final EXCLUDES(mMutex);
    nsecs_t nextAnticipatedVSyncTimeFrom(nsecs_t timePoint,
                                         std::optional<nsecs_t> lastVsyncOpt = {}) final
            EXCLUDES(mMutex);
    nsecs_t currentPeriod() const final EXCLUDES(mMutex);
    Period minFramePeriod() const final EXCLUDES(mMutex);
    void resetModel() final EXCLUDES(mMutex);

    /* Query if the model is in need of more samples to make a prediction.
     * \return  True, if model would benefit from more samples, False if not.
     */
    bool needsMoreSamples() const final EXCLUDES(mMutex);

    struct Model {
        nsecs_t slope;
        nsecs_t intercept;
    };

    VSyncPredictor::Model getVSyncPredictionModel() const EXCLUDES(mMutex);

    bool isVSyncInPhase(nsecs_t timePoint, Fps frameRate) final EXCLUDES(mMutex);

    void setDisplayModePtr(ftl::NonNull<DisplayModePtr>) final EXCLUDES(mMutex);

    bool isCurrentMode(const ftl::NonNull<DisplayModePtr>& modePtr) const EXCLUDES(mMutex) {
        std::lock_guard lock(mMutex);
        return mDisplayModePtr->getId() == modePtr->getId() &&
                mDisplayModePtr->getVsyncRate().getPeriodNsecs() ==
                mRateMap.find(idealPeriod())->second.slope;
    }

    void setRenderRate(Fps, bool applyImmediately) final EXCLUDES(mMutex);

    void onFrameBegin(TimePoint expectedPresentTime, TimePoint lastConfirmedPresentTime) final
            EXCLUDES(mMutex);
    void onFrameMissed(TimePoint expectedPresentTime) final EXCLUDES(mMutex);

    void dump(std::string& result) const final EXCLUDES(mMutex);

private:
    struct VsyncSequence {
        nsecs_t vsyncTime;
        int64_t seq;
    };

    struct MissedVsync {
        TimePoint vsync = TimePoint::fromNs(0);
        Duration fixup = Duration::fromNs(0);
    };

    class VsyncTimeline {
    public:
        VsyncTimeline(TimePoint knownVsync, Period idealPeriod, std::optional<Fps> renderRateOpt);
        std::optional<TimePoint> nextAnticipatedVSyncTimeFrom(
                Model model, std::optional<Period> minFramePeriodOpt, nsecs_t vsyncTime,
                MissedVsync lastMissedVsync, std::optional<nsecs_t> lastVsyncOpt = {});
        void freeze(TimePoint lastVsync);
        std::optional<TimePoint> validUntil() const { return mValidUntil; }
        bool isVSyncInPhase(Model, nsecs_t vsync, Fps frameRate);
        void shiftVsyncSequence(Duration phase);
        void setRenderRate(std::optional<Fps> renderRateOpt) { mRenderRateOpt = renderRateOpt; }

    private:
        nsecs_t snapToVsyncAlignedWithRenderRate(Model model, nsecs_t vsync);
        VsyncSequence getVsyncSequenceLocked(Model, nsecs_t vsync);
        std::optional<VsyncSequence> makeVsyncSequence(TimePoint knownVsync);

        const Period mIdealPeriod = Duration::fromNs(0);
        std::optional<Fps> mRenderRateOpt;
        std::optional<TimePoint> mValidUntil;
        std::optional<VsyncSequence> mLastVsyncSequence;
    };

    VSyncPredictor(VSyncPredictor const&) = delete;
    VSyncPredictor& operator=(VSyncPredictor const&) = delete;
    void clearTimestamps() REQUIRES(mMutex);

    const std::unique_ptr<Clock> mClock;
    const PhysicalDisplayId mId;

    inline void traceInt64If(const char* name, int64_t value) const;
    inline void traceInt64(const char* name, int64_t value) const;

    size_t next(size_t i) const REQUIRES(mMutex);
    bool validate(nsecs_t timestamp) const REQUIRES(mMutex);
    Model getVSyncPredictionModelLocked() const REQUIRES(mMutex);
    nsecs_t snapToVsync(nsecs_t timePoint) const REQUIRES(mMutex);
    Period minFramePeriodLocked() const REQUIRES(mMutex);
    Duration ensureMinFrameDurationIsKept(TimePoint, TimePoint) REQUIRES(mMutex);
    void purgeTimelines(android::TimePoint now) REQUIRES(mMutex);

    nsecs_t idealPeriod() const REQUIRES(mMutex);

    bool const mTraceOn;
    size_t const kHistorySize;
    size_t const kMinimumSamplesForPrediction;
    size_t const kOutlierTolerancePercent;
    std::mutex mutable mMutex;

    std::optional<nsecs_t> mKnownTimestamp GUARDED_BY(mMutex);

    // Map between ideal vsync period and the calculated model
    std::unordered_map<nsecs_t, Model> mutable mRateMap GUARDED_BY(mMutex);

    size_t mLastTimestampIndex GUARDED_BY(mMutex) = 0;
    std::vector<nsecs_t> mTimestamps GUARDED_BY(mMutex);

    ftl::NonNull<DisplayModePtr> mDisplayModePtr GUARDED_BY(mMutex);
    int mNumVsyncsForFrame GUARDED_BY(mMutex);

    std::deque<TimePoint> mPastExpectedPresentTimes GUARDED_BY(mMutex);

    MissedVsync mMissedVsync GUARDED_BY(mMutex);

    std::deque<VsyncTimeline> mTimelines GUARDED_BY(mMutex);
    TimePoint mLastCommittedVsync GUARDED_BY(mMutex) = TimePoint::fromNs(0);
    Period mIdealPeriod GUARDED_BY(mMutex) = Duration::fromNs(0);
    std::optional<Fps> mRenderRateOpt GUARDED_BY(mMutex);
};

} // namespace android::scheduler
