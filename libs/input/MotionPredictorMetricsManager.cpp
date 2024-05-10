/*
 * Copyright 2023 The Android Open Source Project
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

#define LOG_TAG "MotionPredictorMetricsManager"

#include <input/MotionPredictorMetricsManager.h>

#include <algorithm>

#include <android-base/logging.h>
#ifdef __ANDROID__
#include <statslog_libinput.h>
#endif // __ANDROID__

#include "Eigen/Core"
#include "Eigen/Geometry"

namespace android {
namespace {

inline constexpr int NANOS_PER_SECOND = 1'000'000'000; // nanoseconds per second
inline constexpr int NANOS_PER_MILLIS = 1'000'000;     // nanoseconds per millisecond

// Velocity threshold at which we report "high-velocity" metrics, in pixels per second.
// This value was selected from manual experimentation, as a threshold that separates "fast"
// (semi-sloppy) handwriting from more careful medium to slow handwriting.
inline constexpr float HIGH_VELOCITY_THRESHOLD = 1100.0;

// Small value to add to the path length when computing scale-invariant error to avoid division by
// zero.
inline constexpr float PATH_LENGTH_EPSILON = 0.001;

} // namespace

void MotionPredictorMetricsManager::defaultReportAtomFunction(
        const MotionPredictorMetricsManager::AtomFields& atomFields) {
#ifdef __ANDROID__
    android::libinput::stats_write(android::libinput::STYLUS_PREDICTION_METRICS_REPORTED,
                                   /*stylus_vendor_id=*/0,
                                   /*stylus_product_id=*/0,
                                   atomFields.deltaTimeBucketMilliseconds,
                                   atomFields.alongTrajectoryErrorMeanMillipixels,
                                   atomFields.alongTrajectoryErrorStdMillipixels,
                                   atomFields.offTrajectoryRmseMillipixels,
                                   atomFields.pressureRmseMilliunits,
                                   atomFields.highVelocityAlongTrajectoryRmse,
                                   atomFields.highVelocityOffTrajectoryRmse,
                                   atomFields.scaleInvariantAlongTrajectoryRmse,
                                   atomFields.scaleInvariantOffTrajectoryRmse);
#endif // __ANDROID__
}

MotionPredictorMetricsManager::MotionPredictorMetricsManager(
        nsecs_t predictionInterval,
        size_t maxNumPredictions,
        ReportAtomFunction reportAtomFunction)
      : mPredictionInterval(predictionInterval),
        mMaxNumPredictions(maxNumPredictions),
        mRecentGroundTruthPoints(maxNumPredictions + 1),
        mAggregatedMetrics(maxNumPredictions),
        mAtomFields(maxNumPredictions),
        mReportAtomFunction(reportAtomFunction ? reportAtomFunction : defaultReportAtomFunction) {}

void MotionPredictorMetricsManager::onRecord(const MotionEvent& inputEvent) {
    // Convert MotionEvent to GroundTruthPoint.
    const PointerCoords* coords = inputEvent.getRawPointerCoords(/*pointerIndex=*/0);
    LOG_ALWAYS_FATAL_IF(coords == nullptr);
    const GroundTruthPoint groundTruthPoint{{.position = Eigen::Vector2f{coords->getY(),
                                                                         coords->getX()},
                                             .pressure =
                                                     inputEvent.getPressure(/*pointerIndex=*/0)},
                                            .timestamp = inputEvent.getEventTime()};

    // Handle event based on action type.
    switch (inputEvent.getActionMasked()) {
        case AMOTION_EVENT_ACTION_DOWN: {
            clearStrokeData();
            incorporateNewGroundTruth(groundTruthPoint);
            break;
        }
        case AMOTION_EVENT_ACTION_MOVE: {
            incorporateNewGroundTruth(groundTruthPoint);
            break;
        }
        case AMOTION_EVENT_ACTION_UP:
        case AMOTION_EVENT_ACTION_CANCEL: {
            // Only expect meaningful predictions when given at least two input points.
            if (mRecentGroundTruthPoints.size() >= 2) {
                computeAtomFields();
                reportMetrics();
            }
            break;
        }
    }
}

// Adds new predictions to mRecentPredictions and maintains the invariant that elements are
// sorted in ascending order of targetTimestamp.
void MotionPredictorMetricsManager::onPredict(const MotionEvent& predictionEvent) {
    const size_t numPredictions = predictionEvent.getHistorySize() + 1;
    if (numPredictions > mMaxNumPredictions) {
        LOG(WARNING) << "numPredictions (" << numPredictions << ") > mMaxNumPredictions ("
                     << mMaxNumPredictions << "). Ignoring extra predictions in metrics.";
    }
    for (size_t i = 0; (i < numPredictions) && (i < mMaxNumPredictions); ++i) {
        // Convert MotionEvent to PredictionPoint.
        const PointerCoords* coords =
                predictionEvent.getHistoricalRawPointerCoords(/*pointerIndex=*/0, i);
        LOG_ALWAYS_FATAL_IF(coords == nullptr);
        const nsecs_t targetTimestamp = predictionEvent.getHistoricalEventTime(i);
        mRecentPredictions.push_back(
                PredictionPoint{{.position = Eigen::Vector2f{coords->getY(), coords->getX()},
                                 .pressure =
                                         predictionEvent.getHistoricalPressure(/*pointerIndex=*/0,
                                                                               i)},
                                .originTimestamp = mRecentGroundTruthPoints.back().timestamp,
                                .targetTimestamp = targetTimestamp});
    }

    std::sort(mRecentPredictions.begin(), mRecentPredictions.end());
}

void MotionPredictorMetricsManager::clearStrokeData() {
    mRecentGroundTruthPoints.clear();
    mRecentPredictions.clear();
    std::fill(mAggregatedMetrics.begin(), mAggregatedMetrics.end(), AggregatedStrokeMetrics{});
    std::fill(mAtomFields.begin(), mAtomFields.end(), AtomFields{});
}

void MotionPredictorMetricsManager::incorporateNewGroundTruth(
        const GroundTruthPoint& groundTruthPoint) {
    // Note: this removes the oldest point if `mRecentGroundTruthPoints` is already at capacity.
    mRecentGroundTruthPoints.pushBack(groundTruthPoint);

    // Remove outdated predictions – those that can never be matched with the current or any future
    // ground truth points. We use fuzzy association for the timestamps here, because ground truth
    // and prediction timestamps may not be perfectly synchronized.
    const nsecs_t fuzzy_association_time_delta = mPredictionInterval / 4;
    const auto firstCurrentIt =
            std::find_if(mRecentPredictions.begin(), mRecentPredictions.end(),
                         [&groundTruthPoint,
                          fuzzy_association_time_delta](const PredictionPoint& prediction) {
                             return prediction.targetTimestamp >
                                     groundTruthPoint.timestamp - fuzzy_association_time_delta;
                         });
    mRecentPredictions.erase(mRecentPredictions.begin(), firstCurrentIt);

    // Fuzzily match the new ground truth's timestamp to recent predictions' targetTimestamp and
    // update the corresponding metrics.
    for (const PredictionPoint& prediction : mRecentPredictions) {
        if ((prediction.targetTimestamp >
             groundTruthPoint.timestamp - fuzzy_association_time_delta) &&
            (prediction.targetTimestamp <
             groundTruthPoint.timestamp + fuzzy_association_time_delta)) {
            updateAggregatedMetrics(prediction);
        }
    }
}

void MotionPredictorMetricsManager::updateAggregatedMetrics(
        const PredictionPoint& predictionPoint) {
    if (mRecentGroundTruthPoints.size() < 2) {
        return;
    }

    const GroundTruthPoint& latestGroundTruthPoint = mRecentGroundTruthPoints.back();
    const GroundTruthPoint& previousGroundTruthPoint =
            mRecentGroundTruthPoints[mRecentGroundTruthPoints.size() - 2];
    // Calculate prediction error vector.
    const Eigen::Vector2f groundTruthTrajectory =
            latestGroundTruthPoint.position - previousGroundTruthPoint.position;
    const Eigen::Vector2f predictionTrajectory =
            predictionPoint.position - previousGroundTruthPoint.position;
    const Eigen::Vector2f predictionError = predictionTrajectory - groundTruthTrajectory;

    // By default, prediction error counts fully as both off-trajectory and along-trajectory error.
    // This serves as the fallback when the two most recent ground truth points are equal.
    const float predictionErrorNorm = predictionError.norm();
    float alongTrajectoryError = predictionErrorNorm;
    float offTrajectoryError = predictionErrorNorm;
    if (groundTruthTrajectory.squaredNorm() > 0) {
        // Rotate the prediction error vector by the angle of the ground truth trajectory vector.
        // This yields a vector whose first component is the along-trajectory error and whose
        // second component is the off-trajectory error.
        const float theta = std::atan2(groundTruthTrajectory[1], groundTruthTrajectory[0]);
        const Eigen::Vector2f rotatedPredictionError = Eigen::Rotation2Df(-theta) * predictionError;
        alongTrajectoryError = rotatedPredictionError[0];
        offTrajectoryError = rotatedPredictionError[1];
    }

    // Compute the multiple of mPredictionInterval nearest to the amount of time into the
    // future being predicted. This serves as the time bucket index into mAggregatedMetrics.
    const float timestampDeltaFloat =
            static_cast<float>(predictionPoint.targetTimestamp - predictionPoint.originTimestamp);
    const size_t tIndex =
            static_cast<size_t>(std::round(timestampDeltaFloat / mPredictionInterval - 1));

    // Aggregate values into "general errors".
    mAggregatedMetrics[tIndex].alongTrajectoryErrorSum += alongTrajectoryError;
    mAggregatedMetrics[tIndex].alongTrajectorySumSquaredErrors +=
            alongTrajectoryError * alongTrajectoryError;
    mAggregatedMetrics[tIndex].offTrajectorySumSquaredErrors +=
            offTrajectoryError * offTrajectoryError;
    const float pressureError = predictionPoint.pressure - latestGroundTruthPoint.pressure;
    mAggregatedMetrics[tIndex].pressureSumSquaredErrors += pressureError * pressureError;
    ++mAggregatedMetrics[tIndex].generalErrorsCount;

    // Aggregate values into high-velocity metrics, if we are in one of the last two time buckets
    // and the velocity is above the threshold. Velocity here is measured in pixels per second.
    const float velocity = groundTruthTrajectory.norm() /
            (static_cast<float>(latestGroundTruthPoint.timestamp -
                                previousGroundTruthPoint.timestamp) /
             NANOS_PER_SECOND);
    if ((tIndex + 2 >= mMaxNumPredictions) && (velocity > HIGH_VELOCITY_THRESHOLD)) {
        mAggregatedMetrics[tIndex].highVelocityAlongTrajectorySse +=
                alongTrajectoryError * alongTrajectoryError;
        mAggregatedMetrics[tIndex].highVelocityOffTrajectorySse +=
                offTrajectoryError * offTrajectoryError;
        ++mAggregatedMetrics[tIndex].highVelocityErrorsCount;
    }

    // Compute path length for scale-invariant errors.
    float pathLength = 0;
    for (size_t i = 1; i < mRecentGroundTruthPoints.size(); ++i) {
        pathLength +=
                (mRecentGroundTruthPoints[i].position - mRecentGroundTruthPoints[i - 1].position)
                        .norm();
    }
    // Avoid overweighting errors at the beginning of a stroke: compute the path length as if there
    // were a full ground truth history by filling in missing segments with the average length.
    // Note: the "- 1" is needed to translate from number of endpoints to number of segments.
    pathLength *= static_cast<float>(mRecentGroundTruthPoints.capacity() - 1) /
            (mRecentGroundTruthPoints.size() - 1);
    pathLength += PATH_LENGTH_EPSILON; // Ensure path length is nonzero (>= PATH_LENGTH_EPSILON).

    // Compute and aggregate scale-invariant errors.
    const float scaleInvariantAlongTrajectoryError = alongTrajectoryError / pathLength;
    const float scaleInvariantOffTrajectoryError = offTrajectoryError / pathLength;
    mAggregatedMetrics[tIndex].scaleInvariantAlongTrajectorySse +=
            scaleInvariantAlongTrajectoryError * scaleInvariantAlongTrajectoryError;
    mAggregatedMetrics[tIndex].scaleInvariantOffTrajectorySse +=
            scaleInvariantOffTrajectoryError * scaleInvariantOffTrajectoryError;
    ++mAggregatedMetrics[tIndex].scaleInvariantErrorsCount;
}

void MotionPredictorMetricsManager::computeAtomFields() {
    for (size_t i = 0; i < mAggregatedMetrics.size(); ++i) {
        if (mAggregatedMetrics[i].generalErrorsCount == 0) {
            // We have not received data corresponding to metrics for this time bucket.
            continue;
        }

        mAtomFields[i].deltaTimeBucketMilliseconds =
                static_cast<int>(mPredictionInterval / NANOS_PER_MILLIS * (i + 1));

        // Note: we need the "* 1000"s below because we report values in integral milli-units.

        { // General errors: reported for every time bucket.
            const float alongTrajectoryErrorMean = mAggregatedMetrics[i].alongTrajectoryErrorSum /
                    mAggregatedMetrics[i].generalErrorsCount;
            mAtomFields[i].alongTrajectoryErrorMeanMillipixels =
                    static_cast<int>(alongTrajectoryErrorMean * 1000);

            const float alongTrajectoryMse = mAggregatedMetrics[i].alongTrajectorySumSquaredErrors /
                    mAggregatedMetrics[i].generalErrorsCount;
            // Take the max with 0 to avoid negative values caused by numerical instability.
            const float alongTrajectoryErrorVariance =
                    std::max(0.0f,
                             alongTrajectoryMse -
                                     alongTrajectoryErrorMean * alongTrajectoryErrorMean);
            const float alongTrajectoryErrorStd = std::sqrt(alongTrajectoryErrorVariance);
            mAtomFields[i].alongTrajectoryErrorStdMillipixels =
                    static_cast<int>(alongTrajectoryErrorStd * 1000);

            LOG_ALWAYS_FATAL_IF(mAggregatedMetrics[i].offTrajectorySumSquaredErrors < 0,
                                "mAggregatedMetrics[%zu].offTrajectorySumSquaredErrors = %f should "
                                "not be negative",
                                i, mAggregatedMetrics[i].offTrajectorySumSquaredErrors);
            const float offTrajectoryRmse =
                    std::sqrt(mAggregatedMetrics[i].offTrajectorySumSquaredErrors /
                              mAggregatedMetrics[i].generalErrorsCount);
            mAtomFields[i].offTrajectoryRmseMillipixels =
                    static_cast<int>(offTrajectoryRmse * 1000);

            LOG_ALWAYS_FATAL_IF(mAggregatedMetrics[i].pressureSumSquaredErrors < 0,
                                "mAggregatedMetrics[%zu].pressureSumSquaredErrors = %f should not "
                                "be negative",
                                i, mAggregatedMetrics[i].pressureSumSquaredErrors);
            const float pressureRmse = std::sqrt(mAggregatedMetrics[i].pressureSumSquaredErrors /
                                                 mAggregatedMetrics[i].generalErrorsCount);
            mAtomFields[i].pressureRmseMilliunits = static_cast<int>(pressureRmse * 1000);
        }

        // High-velocity errors: reported only for last two time buckets.
        // Check if we are in one of the last two time buckets, and there is high-velocity data.
        if ((i + 2 >= mMaxNumPredictions) && (mAggregatedMetrics[i].highVelocityErrorsCount > 0)) {
            LOG_ALWAYS_FATAL_IF(mAggregatedMetrics[i].highVelocityAlongTrajectorySse < 0,
                                "mAggregatedMetrics[%zu].highVelocityAlongTrajectorySse = %f "
                                "should not be negative",
                                i, mAggregatedMetrics[i].highVelocityAlongTrajectorySse);
            const float alongTrajectoryRmse =
                    std::sqrt(mAggregatedMetrics[i].highVelocityAlongTrajectorySse /
                              mAggregatedMetrics[i].highVelocityErrorsCount);
            mAtomFields[i].highVelocityAlongTrajectoryRmse =
                    static_cast<int>(alongTrajectoryRmse * 1000);

            LOG_ALWAYS_FATAL_IF(mAggregatedMetrics[i].highVelocityOffTrajectorySse < 0,
                                "mAggregatedMetrics[%zu].highVelocityOffTrajectorySse = %f should "
                                "not be negative",
                                i, mAggregatedMetrics[i].highVelocityOffTrajectorySse);
            const float offTrajectoryRmse =
                    std::sqrt(mAggregatedMetrics[i].highVelocityOffTrajectorySse /
                              mAggregatedMetrics[i].highVelocityErrorsCount);
            mAtomFields[i].highVelocityOffTrajectoryRmse =
                    static_cast<int>(offTrajectoryRmse * 1000);
        }
    }

    // Scale-invariant errors: the average scale-invariant error across all time buckets
    // is reported in the last time bucket.
    {
        // Compute error averages.
        float alongTrajectoryRmseSum = 0;
        float offTrajectoryRmseSum = 0;
        int bucket_count = 0;
        for (size_t j = 0; j < mAggregatedMetrics.size(); ++j) {
            if (mAggregatedMetrics[j].scaleInvariantErrorsCount == 0) {
                continue;
            }

            LOG_ALWAYS_FATAL_IF(mAggregatedMetrics[j].scaleInvariantAlongTrajectorySse < 0,
                                "mAggregatedMetrics[%zu].scaleInvariantAlongTrajectorySse = %f "
                                "should not be negative",
                                j, mAggregatedMetrics[j].scaleInvariantAlongTrajectorySse);
            alongTrajectoryRmseSum +=
                    std::sqrt(mAggregatedMetrics[j].scaleInvariantAlongTrajectorySse /
                              mAggregatedMetrics[j].scaleInvariantErrorsCount);

            LOG_ALWAYS_FATAL_IF(mAggregatedMetrics[j].scaleInvariantOffTrajectorySse < 0,
                                "mAggregatedMetrics[%zu].scaleInvariantOffTrajectorySse = %f "
                                "should not be negative",
                                j, mAggregatedMetrics[j].scaleInvariantOffTrajectorySse);
            offTrajectoryRmseSum += std::sqrt(mAggregatedMetrics[j].scaleInvariantOffTrajectorySse /
                                              mAggregatedMetrics[j].scaleInvariantErrorsCount);

            ++bucket_count;
        }

        if (bucket_count > 0) {
            const float averageAlongTrajectoryRmse = alongTrajectoryRmseSum / bucket_count;
            mAtomFields.back().scaleInvariantAlongTrajectoryRmse =
                    static_cast<int>(averageAlongTrajectoryRmse * 1000);

            const float averageOffTrajectoryRmse = offTrajectoryRmseSum / bucket_count;
            mAtomFields.back().scaleInvariantOffTrajectoryRmse =
                    static_cast<int>(averageOffTrajectoryRmse * 1000);
        }
    }
}

void MotionPredictorMetricsManager::reportMetrics() {
    LOG_ALWAYS_FATAL_IF(!mReportAtomFunction);
    // Report one atom for each prediction time bucket.
    for (size_t i = 0; i < mAtomFields.size(); ++i) {
        mReportAtomFunction(mAtomFields[i]);
    }
}

} // namespace android
