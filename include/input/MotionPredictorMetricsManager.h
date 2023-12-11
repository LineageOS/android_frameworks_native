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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <vector>

#include <input/Input.h> // for MotionEvent
#include <input/RingBuffer.h>
#include <utils/Timers.h> // for nsecs_t

#include "Eigen/Core"

namespace android {

/**
 * Class to handle computing and reporting metrics for MotionPredictor.
 *
 * The public API provides two methods: `onRecord` and `onPredict`, which expect to receive the
 * MotionEvents from the corresponding methods in MotionPredictor.
 *
 * This class stores AggregatedStrokeMetrics, updating them as new MotionEvents are passed in. When
 * onRecord receives an UP or CANCEL event, this indicates the end of the stroke, and the final
 * AtomFields are computed and reported to the stats library. The number of atoms reported is equal
 * to the value of `maxNumPredictions` passed to the constructor. Each atom corresponds to one
 * "prediction time bucket" — the amount of time into the future being predicted.
 *
 * If mMockLoggedAtomFields is set, the batch of AtomFields that are reported to the stats library
 * for one stroke are also stored in mMockLoggedAtomFields at the time they're reported.
 */
class MotionPredictorMetricsManager {
public:
    struct AtomFields;

    using ReportAtomFunction = std::function<void(const AtomFields&)>;

    static void defaultReportAtomFunction(const AtomFields& atomFields);

    // Parameters:
    //  • predictionInterval: the time interval between successive prediction target timestamps.
    //    Note: the MetricsManager assumes that the input interval equals the prediction interval.
    //  • maxNumPredictions: the maximum number of distinct target timestamps the prediction model
    //    will generate predictions for. The MetricsManager reports this many atoms per stroke.
    //  • [Optional] reportAtomFunction: the function that will be called to report metrics. If
    //    omitted (or if an empty function is given), the `stats_write(…)` function from the Android
    //    stats library will be used.
    MotionPredictorMetricsManager(
            nsecs_t predictionInterval,
            size_t maxNumPredictions,
            ReportAtomFunction reportAtomFunction = defaultReportAtomFunction);

    // This method should be called once for each call to MotionPredictor::record, receiving the
    // forwarded MotionEvent argument.
    void onRecord(const MotionEvent& inputEvent);

    // This method should be called once for each call to MotionPredictor::predict, receiving the
    // MotionEvent that will be returned by MotionPredictor::predict.
    void onPredict(const MotionEvent& predictionEvent);

    // Simple structs to hold relevant touch input information. Public so they can be used in tests.

    struct TouchPoint {
        Eigen::Vector2f position; // (y, x) in pixels
        float pressure;
    };

    struct GroundTruthPoint : TouchPoint {
        nsecs_t timestamp;
    };

    struct PredictionPoint : TouchPoint {
        // The timestamp of the last ground truth point when the prediction was made.
        nsecs_t originTimestamp;

        nsecs_t targetTimestamp;

        // Order by targetTimestamp when sorting.
        bool operator<(const PredictionPoint& other) const {
            return this->targetTimestamp < other.targetTimestamp;
        }
    };

    // Metrics aggregated so far for the current stroke. These are not the final fields to be
    // reported in the atom (see AtomFields below), but rather an intermediate representation of the
    // data that can be conveniently aggregated and from which the atom fields can be derived later.
    //
    // Displacement units are in pixels.
    //
    // "Along-trajectory error" is the dot product of the prediction error with the unit vector
    // pointing towards the ground truth point whose timestamp corresponds to the prediction
    // target timestamp, originating from the preceding ground truth point.
    //
    // "Off-trajectory error" is the component of the prediction error orthogonal to the
    // "along-trajectory" unit vector described above.
    //
    // "High-velocity" errors are errors that are only accumulated when the velocity between the
    // most recent two input events exceeds a certain threshold.
    //
    // "Scale-invariant errors" are the errors produced when the path length of the stroke is
    // scaled to 1. (In other words, the error distances are normalized by the path length.)
    struct AggregatedStrokeMetrics {
        // General errors
        float alongTrajectoryErrorSum = 0;
        float alongTrajectorySumSquaredErrors = 0;
        float offTrajectorySumSquaredErrors = 0;
        float pressureSumSquaredErrors = 0;
        size_t generalErrorsCount = 0;

        // High-velocity errors
        float highVelocityAlongTrajectorySse = 0;
        float highVelocityOffTrajectorySse = 0;
        size_t highVelocityErrorsCount = 0;

        // Scale-invariant errors
        float scaleInvariantAlongTrajectorySse = 0;
        float scaleInvariantOffTrajectorySse = 0;
        size_t scaleInvariantErrorsCount = 0;
    };

    // In order to explicitly indicate "no relevant data" for a metric, we report this
    // large-magnitude negative sentinel value. (Most metrics are non-negative, so this value is
    // completely unobtainable. For along-trajectory error mean, which can be negative, the
    // magnitude makes it unobtainable in practice.)
    static const int NO_DATA_SENTINEL = std::numeric_limits<int32_t>::min();

    // Final metric values reported in the atom.
    struct AtomFields {
        int deltaTimeBucketMilliseconds = 0;

        // General errors
        int alongTrajectoryErrorMeanMillipixels = NO_DATA_SENTINEL;
        int alongTrajectoryErrorStdMillipixels = NO_DATA_SENTINEL;
        int offTrajectoryRmseMillipixels = NO_DATA_SENTINEL;
        int pressureRmseMilliunits = NO_DATA_SENTINEL;

        // High-velocity errors
        int highVelocityAlongTrajectoryRmse = NO_DATA_SENTINEL; // millipixels
        int highVelocityOffTrajectoryRmse = NO_DATA_SENTINEL;   // millipixels

        // Scale-invariant errors
        int scaleInvariantAlongTrajectoryRmse = NO_DATA_SENTINEL; // millipixels
        int scaleInvariantOffTrajectoryRmse = NO_DATA_SENTINEL;   // millipixels
    };

private:
    // The interval between consecutive predictions' target timestamps. We assume that the input
    // interval also equals this value.
    const nsecs_t mPredictionInterval;

    // The maximum number of input frames into the future the model can predict.
    // Used to perform time-bucketing of metrics.
    const size_t mMaxNumPredictions;

    // History of mMaxNumPredictions + 1 ground truth points, used to compute scale-invariant
    // error. (Also, the last two points are used to compute the ground truth trajectory.)
    RingBuffer<GroundTruthPoint> mRecentGroundTruthPoints;

    // Predictions having a targetTimestamp after the most recent ground truth point's timestamp.
    // Invariant: sorted in ascending order of targetTimestamp.
    std::vector<PredictionPoint> mRecentPredictions;

    // Containers for the intermediate representation of stroke metrics and the final atom fields.
    // These are indexed by the number of input frames into the future being predicted minus one,
    // and always have size mMaxNumPredictions.
    std::vector<AggregatedStrokeMetrics> mAggregatedMetrics;
    std::vector<AtomFields> mAtomFields;

    const ReportAtomFunction mReportAtomFunction;

    // Helper methods for the implementation of onRecord and onPredict.

    // Clears stored ground truth and prediction points, as well as all stored metrics for the
    // current stroke.
    void clearStrokeData();

    // Adds the new ground truth point to mRecentGroundTruths, removes outdated predictions from
    // mRecentPredictions, and updates the aggregated metrics to include the recent predictions that
    // fuzzily match with the new ground truth point.
    void incorporateNewGroundTruth(const GroundTruthPoint& groundTruthPoint);

    // Given a new prediction with targetTimestamp matching the latest ground truth point's
    // timestamp, computes the corresponding metrics and updates mAggregatedMetrics.
    void updateAggregatedMetrics(const PredictionPoint& predictionPoint);

    // Computes the atom fields to mAtomFields from the values in mAggregatedMetrics.
    void computeAtomFields();

    // Reports the current data in mAtomFields by calling mReportAtomFunction.
    void reportMetrics();
};

} // namespace android
