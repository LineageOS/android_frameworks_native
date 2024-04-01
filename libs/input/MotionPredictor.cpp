/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "MotionPredictor"

#include <input/MotionPredictor.h>

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android/input.h>
#include <com_android_input_flags.h>

#include <attestation/HmacKeyManager.h>
#include <ftl/enum.h>
#include <input/TfLiteMotionPredictor.h>

namespace input_flags = com::android::input::flags;

namespace android {
namespace {

/**
 * Log debug messages about predictions.
 * Enable this via "adb shell setprop log.tag.MotionPredictor DEBUG"
 */
bool isDebug() {
    return __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG, ANDROID_LOG_INFO);
}

// Converts a prediction of some polar (r, phi) to Cartesian (x, y) when applied to an axis.
TfLiteMotionPredictorSample::Point convertPrediction(
        const TfLiteMotionPredictorSample::Point& axisFrom,
        const TfLiteMotionPredictorSample::Point& axisTo, float r, float phi) {
    const TfLiteMotionPredictorSample::Point axis = axisTo - axisFrom;
    const float axis_phi = std::atan2(axis.y, axis.x);
    const float x_delta = r * std::cos(axis_phi + phi);
    const float y_delta = r * std::sin(axis_phi + phi);
    return {.x = axisTo.x + x_delta, .y = axisTo.y + y_delta};
}

float normalizeRange(float x, float min, float max) {
    const float normalized = (x - min) / (max - min);
    return std::min(1.0f, std::max(0.0f, normalized));
}

} // namespace

// --- JerkTracker ---

JerkTracker::JerkTracker(bool normalizedDt) : mNormalizedDt(normalizedDt) {}

void JerkTracker::pushSample(int64_t timestamp, float xPos, float yPos) {
    mTimestamps.pushBack(timestamp);
    const int numSamples = mTimestamps.size();

    std::array<float, 4> newXDerivatives;
    std::array<float, 4> newYDerivatives;

    /**
     * Diagram showing the calculation of higher order derivatives of sample x3
     * collected at time=t3.
     * Terms in parentheses are not stored (and not needed for calculations)
     *  t0 ----- t1  ----- t2 ----- t3
     * (x0)-----(x1) ----- x2 ----- x3
     * (x'0) --- x'1 ---  x'2
     *  x''0  -  x''1
     *  x'''0
     *
     * In this example:
     * x'2 = (x3 - x2) / (t3 - t2)
     * x''1 = (x'2 - x'1) / (t2 - t1)
     * x'''0 = (x''1 - x''0) / (t1 - t0)
     * Therefore, timestamp history is needed to calculate higher order derivatives,
     * compared to just the last calculated derivative sample.
     *
     * If mNormalizedDt = true, then dt = 1 and the division is moot.
     */
    for (int i = 0; i < numSamples; ++i) {
        if (i == 0) {
            newXDerivatives[i] = xPos;
            newYDerivatives[i] = yPos;
        } else {
            newXDerivatives[i] = newXDerivatives[i - 1] - mXDerivatives[i - 1];
            newYDerivatives[i] = newYDerivatives[i - 1] - mYDerivatives[i - 1];
            if (!mNormalizedDt) {
                const float dt = mTimestamps[numSamples - i] - mTimestamps[numSamples - i - 1];
                newXDerivatives[i] = newXDerivatives[i] / dt;
                newYDerivatives[i] = newYDerivatives[i] / dt;
            }
        }
    }

    std::swap(newXDerivatives, mXDerivatives);
    std::swap(newYDerivatives, mYDerivatives);
}

void JerkTracker::reset() {
    mTimestamps.clear();
}

std::optional<float> JerkTracker::jerkMagnitude() const {
    if (mTimestamps.size() == mTimestamps.capacity()) {
        return std::hypot(mXDerivatives[3], mYDerivatives[3]);
    }
    return std::nullopt;
}

// --- MotionPredictor ---

MotionPredictor::MotionPredictor(nsecs_t predictionTimestampOffsetNanos,
                                 std::function<bool()> checkMotionPredictionEnabled,
                                 ReportAtomFunction reportAtomFunction)
      : mPredictionTimestampOffsetNanos(predictionTimestampOffsetNanos),
        mCheckMotionPredictionEnabled(std::move(checkMotionPredictionEnabled)),
        mReportAtomFunction(reportAtomFunction) {}

android::base::Result<void> MotionPredictor::record(const MotionEvent& event) {
    if (mLastEvent && mLastEvent->getDeviceId() != event.getDeviceId()) {
        // We still have an active gesture for another device. The provided MotionEvent is not
        // consistent with the previous gesture.
        LOG(ERROR) << "Inconsistent event stream: last event is " << *mLastEvent << ", but "
                   << __func__ << " is called with " << event;
        return android::base::Error()
                << "Inconsistent event stream: still have an active gesture from device "
                << mLastEvent->getDeviceId() << ", but received " << event;
    }
    if (!isPredictionAvailable(event.getDeviceId(), event.getSource())) {
        ALOGE("Prediction not supported for device %d's %s source", event.getDeviceId(),
              inputEventSourceToString(event.getSource()).c_str());
        return {};
    }

    // Initialise the model now that it's likely to be used.
    if (!mModel) {
        mModel = TfLiteMotionPredictorModel::create();
        LOG_ALWAYS_FATAL_IF(!mModel);
    }

    if (!mBuffers) {
        mBuffers = std::make_unique<TfLiteMotionPredictorBuffers>(mModel->inputLength());
    }

    // Pass input event to the MetricsManager.
    if (!mMetricsManager) {
        mMetricsManager.emplace(mModel->config().predictionInterval, mModel->outputLength(),
                                mReportAtomFunction);
    }
    mMetricsManager->onRecord(event);

    const int32_t action = event.getActionMasked();
    if (action == AMOTION_EVENT_ACTION_UP || action == AMOTION_EVENT_ACTION_CANCEL) {
        ALOGD_IF(isDebug(), "End of event stream");
        mBuffers->reset();
        mJerkTracker.reset();
        mLastEvent.reset();
        return {};
    } else if (action != AMOTION_EVENT_ACTION_DOWN && action != AMOTION_EVENT_ACTION_MOVE) {
        ALOGD_IF(isDebug(), "Skipping unsupported %s action",
                 MotionEvent::actionToString(action).c_str());
        return {};
    }

    if (event.getPointerCount() != 1) {
        ALOGD_IF(isDebug(), "Prediction not supported for multiple pointers");
        return {};
    }

    const ToolType toolType = event.getPointerProperties(0)->toolType;
    if (toolType != ToolType::STYLUS) {
        ALOGD_IF(isDebug(), "Prediction not supported for non-stylus tool: %s",
                 ftl::enum_string(toolType).c_str());
        return {};
    }

    for (size_t i = 0; i <= event.getHistorySize(); ++i) {
        if (event.isResampled(0, i)) {
            continue;
        }
        const PointerCoords* coords = event.getHistoricalRawPointerCoords(0, i);
        mBuffers->pushSample(event.getHistoricalEventTime(i),
                             {
                                     .position.x = coords->getAxisValue(AMOTION_EVENT_AXIS_X),
                                     .position.y = coords->getAxisValue(AMOTION_EVENT_AXIS_Y),
                                     .pressure = event.getHistoricalPressure(0, i),
                                     .tilt = event.getHistoricalAxisValue(AMOTION_EVENT_AXIS_TILT,
                                                                          0, i),
                                     .orientation = event.getHistoricalOrientation(0, i),
                             });
        mJerkTracker.pushSample(event.getHistoricalEventTime(i),
                                coords->getAxisValue(AMOTION_EVENT_AXIS_X),
                                coords->getAxisValue(AMOTION_EVENT_AXIS_Y));
    }

    if (!mLastEvent) {
        mLastEvent = MotionEvent();
    }
    mLastEvent->copyFrom(&event, /*keepHistory=*/false);

    return {};
}

std::unique_ptr<MotionEvent> MotionPredictor::predict(nsecs_t timestamp) {
    if (mBuffers == nullptr || !mBuffers->isReady()) {
        return nullptr;
    }

    LOG_ALWAYS_FATAL_IF(!mModel);
    mBuffers->copyTo(*mModel);
    LOG_ALWAYS_FATAL_IF(!mModel->invoke());

    // Read out the predictions.
    const std::span<const float> predictedR = mModel->outputR();
    const std::span<const float> predictedPhi = mModel->outputPhi();
    const std::span<const float> predictedPressure = mModel->outputPressure();

    TfLiteMotionPredictorSample::Point axisFrom = mBuffers->axisFrom().position;
    TfLiteMotionPredictorSample::Point axisTo = mBuffers->axisTo().position;

    if (isDebug()) {
        ALOGD("axisFrom: %f, %f", axisFrom.x, axisFrom.y);
        ALOGD("axisTo: %f, %f", axisTo.x, axisTo.y);
        ALOGD("mInputR: %s", base::Join(mModel->inputR(), ", ").c_str());
        ALOGD("mInputPhi: %s", base::Join(mModel->inputPhi(), ", ").c_str());
        ALOGD("mInputPressure: %s", base::Join(mModel->inputPressure(), ", ").c_str());
        ALOGD("mInputTilt: %s", base::Join(mModel->inputTilt(), ", ").c_str());
        ALOGD("mInputOrientation: %s", base::Join(mModel->inputOrientation(), ", ").c_str());
        ALOGD("predictedR: %s", base::Join(predictedR, ", ").c_str());
        ALOGD("predictedPhi: %s", base::Join(predictedPhi, ", ").c_str());
        ALOGD("predictedPressure: %s", base::Join(predictedPressure, ", ").c_str());
    }

    LOG_ALWAYS_FATAL_IF(!mLastEvent);
    const MotionEvent& event = *mLastEvent;
    bool hasPredictions = false;
    std::unique_ptr<MotionEvent> prediction = std::make_unique<MotionEvent>();
    int64_t predictionTime = mBuffers->lastTimestamp();
    const int64_t futureTime = timestamp + mPredictionTimestampOffsetNanos;

    const float jerkMagnitude = mJerkTracker.jerkMagnitude().value_or(0);
    const float fractionKept =
            1 - normalizeRange(jerkMagnitude, mModel->config().lowJerk, mModel->config().highJerk);
    // float to ensure proper division below.
    const float predictionTimeWindow = futureTime - predictionTime;
    const int maxNumPredictions = static_cast<int>(
            std::ceil(predictionTimeWindow / mModel->config().predictionInterval * fractionKept));
    ALOGD_IF(isDebug(),
             "jerk (d^3p/normalizedDt^3): %f, fraction of prediction window pruned: %f, max number "
             "of predictions: %d",
             jerkMagnitude, 1 - fractionKept, maxNumPredictions);
    for (size_t i = 0; i < static_cast<size_t>(predictedR.size()) && predictionTime <= futureTime;
         ++i) {
        if (predictedR[i] < mModel->config().distanceNoiseFloor) {
            // Stop predicting when the predicted output is below the model's noise floor.
            //
            // We assume that all subsequent predictions in the batch are unreliable because later
            // predictions are conditional on earlier predictions, and a state of noise is not a
            // good basis for prediction.
            //
            // The UX trade-off is that this potentially sacrifices some predictions when the input
            // device starts to speed up, but avoids producing noisy predictions as it slows down.
            break;
        }
        if (input_flags::enable_prediction_pruning_via_jerk_thresholding()) {
            if (i >= static_cast<size_t>(maxNumPredictions)) {
                break;
            }
        }
        // TODO(b/266747654): Stop predictions if confidence is < some
        // threshold. Currently predictions are pruned via jerk thresholding.

        const TfLiteMotionPredictorSample::Point predictedPoint =
                convertPrediction(axisFrom, axisTo, predictedR[i], predictedPhi[i]);

        ALOGD_IF(isDebug(), "prediction %zu: %f, %f", i, predictedPoint.x, predictedPoint.y);
        PointerCoords coords;
        coords.clear();
        coords.setAxisValue(AMOTION_EVENT_AXIS_X, predictedPoint.x);
        coords.setAxisValue(AMOTION_EVENT_AXIS_Y, predictedPoint.y);
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, predictedPressure[i]);
        // Copy forward tilt and orientation from the last event until they are predicted
        // (b/291789258).
        coords.setAxisValue(AMOTION_EVENT_AXIS_TILT,
                            event.getAxisValue(AMOTION_EVENT_AXIS_TILT, 0));
        coords.setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION,
                            event.getRawPointerCoords(0)->getAxisValue(
                                    AMOTION_EVENT_AXIS_ORIENTATION));

        predictionTime += mModel->config().predictionInterval;
        if (i == 0) {
            hasPredictions = true;
            prediction->initialize(InputEvent::nextId(), event.getDeviceId(), event.getSource(),
                                   event.getDisplayId(), INVALID_HMAC, AMOTION_EVENT_ACTION_MOVE,
                                   event.getActionButton(), event.getFlags(), event.getEdgeFlags(),
                                   event.getMetaState(), event.getButtonState(),
                                   event.getClassification(), event.getTransform(),
                                   event.getXPrecision(), event.getYPrecision(),
                                   event.getRawXCursorPosition(), event.getRawYCursorPosition(),
                                   event.getRawTransform(), event.getDownTime(), predictionTime,
                                   event.getPointerCount(), event.getPointerProperties(), &coords);
        } else {
            prediction->addSample(predictionTime, &coords);
        }

        axisFrom = axisTo;
        axisTo = predictedPoint;
    }

    if (!hasPredictions) {
        return nullptr;
    }

    // Pass predictions to the MetricsManager.
    LOG_ALWAYS_FATAL_IF(!mMetricsManager);
    mMetricsManager->onPredict(*prediction);

    return prediction;
}

bool MotionPredictor::isPredictionAvailable(int32_t /*deviceId*/, int32_t source) {
    // Global flag override
    if (!mCheckMotionPredictionEnabled()) {
        ALOGD_IF(isDebug(), "Prediction not available due to flag override");
        return false;
    }

    // Prediction is only supported for stylus sources.
    if (!isFromSource(source, AINPUT_SOURCE_STYLUS)) {
        ALOGD_IF(isDebug(), "Prediction not available for non-stylus source: %s",
                 inputEventSourceToString(source).c_str());
        return false;
    }
    return true;
}

} // namespace android
