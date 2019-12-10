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
//#define LOG_NDEBUG 0
#include "VSyncPredictor.h"
#include <android-base/logging.h>
#include <cutils/compiler.h>
#include <utils/Log.h>
#include <utils/Trace.h>
#include <algorithm>
#include <chrono>
#include <sstream>
#include "SchedulerUtils.h"

namespace android::scheduler {
static auto constexpr kNeedsSamplesTag = "SamplesRequested";
static auto constexpr kMaxPercent = 100u;

VSyncPredictor::~VSyncPredictor() = default;

VSyncPredictor::VSyncPredictor(nsecs_t idealPeriod, size_t historySize,
                               size_t minimumSamplesForPrediction, uint32_t outlierTolerancePercent)
      : kHistorySize(historySize),
        kMinimumSamplesForPrediction(minimumSamplesForPrediction),
        kOutlierTolerancePercent(std::min(outlierTolerancePercent, kMaxPercent)),
        mIdealPeriod(idealPeriod) {
    mRateMap[mIdealPeriod] = {idealPeriod, 0};
}

inline size_t VSyncPredictor::next(int i) const {
    return (i + 1) % timestamps.size();
}

bool VSyncPredictor::validate(nsecs_t timestamp) const {
    if (lastTimestampIndex < 0 || timestamps.empty()) {
        return true;
    }

    auto const aValidTimestamp = timestamps[lastTimestampIndex];
    auto const percent = (timestamp - aValidTimestamp) % mIdealPeriod * kMaxPercent / mIdealPeriod;
    return percent < kOutlierTolerancePercent || percent > (kMaxPercent - kOutlierTolerancePercent);
}

nsecs_t VSyncPredictor::currentPeriod() const {
    std::lock_guard<std::mutex> lk(mMutex);
    return std::get<0>(mRateMap.find(mIdealPeriod)->second);
}

void VSyncPredictor::addVsyncTimestamp(nsecs_t timestamp) {
    std::lock_guard<std::mutex> lk(mMutex);

    if (!validate(timestamp)) {
        ALOGW("timestamp was too far off the last known timestamp");
        return;
    }

    if (timestamps.size() != kHistorySize) {
        timestamps.push_back(timestamp);
        lastTimestampIndex = next(lastTimestampIndex);
    } else {
        lastTimestampIndex = next(lastTimestampIndex);
        timestamps[lastTimestampIndex] = timestamp;
    }

    if (timestamps.size() < kMinimumSamplesForPrediction) {
        mRateMap[mIdealPeriod] = {mIdealPeriod, 0};
        return;
    }

    // This is a 'simple linear regression' calculation of Y over X, with Y being the
    // vsync timestamps, and X being the ordinal of vsync count.
    // The calculated slope is the vsync period.
    // Formula for reference:
    // Sigma_i: means sum over all timestamps.
    // mean(variable): statistical mean of variable.
    // X: snapped ordinal of the timestamp
    // Y: vsync timestamp
    //
    //         Sigma_i( (X_i - mean(X)) * (Y_i - mean(Y) )
    // slope = -------------------------------------------
    //         Sigma_i ( X_i - mean(X) ) ^ 2
    //
    // intercept = mean(Y) - slope * mean(X)
    //
    std::vector<nsecs_t> vsyncTS(timestamps.size());
    std::vector<nsecs_t> ordinals(timestamps.size());

    // normalizing to the oldest timestamp cuts down on error in calculating the intercept.
    auto const oldest_ts = *std::min_element(timestamps.begin(), timestamps.end());
    auto it = mRateMap.find(mIdealPeriod);
    auto const currentPeriod = std::get<0>(it->second);
    // TODO (b/144707443): its important that there's some precision in the mean of the ordinals
    //                     for the intercept calculation, so scale the ordinals by 10 to continue
    //                     fixed point calculation. Explore expanding
    //                     scheduler::utils::calculate_mean to have a fixed point fractional part.
    static constexpr int kScalingFactor = 10;

    for (auto i = 0u; i < timestamps.size(); i++) {
        vsyncTS[i] = timestamps[i] - oldest_ts;
        ordinals[i] = ((vsyncTS[i] + (currentPeriod / 2)) / currentPeriod) * kScalingFactor;
    }

    auto meanTS = scheduler::calculate_mean(vsyncTS);
    auto meanOrdinal = scheduler::calculate_mean(ordinals);
    for (auto i = 0; i < vsyncTS.size(); i++) {
        vsyncTS[i] -= meanTS;
        ordinals[i] -= meanOrdinal;
    }

    auto top = 0ll;
    auto bottom = 0ll;
    for (auto i = 0; i < vsyncTS.size(); i++) {
        top += vsyncTS[i] * ordinals[i];
        bottom += ordinals[i] * ordinals[i];
    }

    if (CC_UNLIKELY(bottom == 0)) {
        it->second = {mIdealPeriod, 0};
        return;
    }

    nsecs_t const anticipatedPeriod = top / bottom * kScalingFactor;
    nsecs_t const intercept = meanTS - (anticipatedPeriod * meanOrdinal / kScalingFactor);

    it->second = {anticipatedPeriod, intercept};

    ALOGV("model update ts: %" PRId64 " slope: %" PRId64 " intercept: %" PRId64, timestamp,
          anticipatedPeriod, intercept);
}

nsecs_t VSyncPredictor::nextAnticipatedVSyncTimeFrom(nsecs_t timePoint) const {
    std::lock_guard<std::mutex> lk(mMutex);

    auto const [slope, intercept] = getVSyncPredictionModel(lk);

    if (timestamps.empty()) {
        auto const knownTimestamp = mKnownTimestamp ? *mKnownTimestamp : timePoint;
        auto const numPeriodsOut = ((timePoint - knownTimestamp) / mIdealPeriod) + 1;
        return knownTimestamp + numPeriodsOut * mIdealPeriod;
    }

    auto const oldest = *std::min_element(timestamps.begin(), timestamps.end());

    // See b/145667109, the ordinal calculation must take into account the intercept.
    auto const zeroPoint = oldest + intercept;
    auto const ordinalRequest = (timePoint - zeroPoint + slope) / slope;
    auto const prediction = (ordinalRequest * slope) + intercept + oldest;

    auto const printer = [&, slope = slope, intercept = intercept] {
        std::stringstream str;
        str << "prediction made from: " << timePoint << "prediction: " << prediction << " (+"
            << prediction - timePoint << ") slope: " << slope << " intercept: " << intercept
            << "oldestTS: " << oldest << " ordinal: " << ordinalRequest;
        return str.str();
    };

    ALOGV("%s", printer().c_str());
    LOG_ALWAYS_FATAL_IF(prediction < timePoint, "VSyncPredictor: model miscalculation: %s",
                        printer().c_str());

    return prediction;
}

std::tuple<nsecs_t, nsecs_t> VSyncPredictor::getVSyncPredictionModel() const {
    std::lock_guard<std::mutex> lk(mMutex);
    return VSyncPredictor::getVSyncPredictionModel(lk);
}

std::tuple<nsecs_t, nsecs_t> VSyncPredictor::getVSyncPredictionModel(
        std::lock_guard<std::mutex> const&) const {
    return mRateMap.find(mIdealPeriod)->second;
}

void VSyncPredictor::setPeriod(nsecs_t period) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lk(mMutex);
    static constexpr size_t kSizeLimit = 30;
    if (CC_UNLIKELY(mRateMap.size() == kSizeLimit)) {
        mRateMap.erase(mRateMap.begin());
    }

    mIdealPeriod = period;
    if (mRateMap.find(period) == mRateMap.end()) {
        mRateMap[mIdealPeriod] = {period, 0};
    }

    if (!timestamps.empty()) {
        mKnownTimestamp = *std::max_element(timestamps.begin(), timestamps.end());
        timestamps.clear();
        lastTimestampIndex = 0;
    }
}

bool VSyncPredictor::needsMoreSamples(nsecs_t now) const {
    using namespace std::literals::chrono_literals;
    std::lock_guard<std::mutex> lk(mMutex);
    bool needsMoreSamples = true;
    if (timestamps.size() >= kMinimumSamplesForPrediction) {
        nsecs_t constexpr aLongTime =
                std::chrono::duration_cast<std::chrono::nanoseconds>(500ms).count();
        if (!(lastTimestampIndex < 0 || timestamps.empty())) {
            auto const lastTimestamp = timestamps[lastTimestampIndex];
            needsMoreSamples = !((lastTimestamp + aLongTime) > now);
        }
    }

    ATRACE_INT(kNeedsSamplesTag, needsMoreSamples);
    return needsMoreSamples;
}

} // namespace android::scheduler
