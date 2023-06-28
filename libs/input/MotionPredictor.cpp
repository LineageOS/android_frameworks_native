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

#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <android-base/strings.h>
#include <android/input.h>
#include <log/log.h>

#include <attestation/HmacKeyManager.h>
#include <ftl/enum.h>
#include <input/TfLiteMotionPredictor.h>

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

} // namespace

// --- MotionPredictor ---

MotionPredictor::MotionPredictor(nsecs_t predictionTimestampOffsetNanos,
                                 std::function<bool()> checkMotionPredictionEnabled)
      : mPredictionTimestampOffsetNanos(predictionTimestampOffsetNanos),
        mCheckMotionPredictionEnabled(std::move(checkMotionPredictionEnabled)) {}

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

    const int32_t action = event.getActionMasked();
    if (action == AMOTION_EVENT_ACTION_UP || action == AMOTION_EVENT_ACTION_CANCEL) {
        ALOGD_IF(isDebug(), "End of event stream");
        mBuffers->reset();
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
    }

    if (!mLastEvent) {
        mLastEvent = MotionEvent();
    }
    mLastEvent->copyFrom(&event, /*keepHistory=*/false);

    // Pass input event to the MetricsManager.
    if (!mMetricsManager) {
        mMetricsManager =
                std::make_optional<MotionPredictorMetricsManager>(mModel->predictionInterval(),
                                                                  mModel->outputLength());
    }
    mMetricsManager->onRecord(event);

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

    for (int i = 0; i < predictedR.size() && predictionTime <= futureTime; ++i) {
        // TODO(b/266747654): Stop predictions if confidence and/or predicted pressure are below
        // some thresholds.

        const TfLiteMotionPredictorSample::Point predictedPoint =
                convertPrediction(axisFrom, axisTo, predictedR[i], predictedPhi[i]);

        ALOGD_IF(isDebug(), "prediction %d: %f, %f", i, predictedPoint.x, predictedPoint.y);
        PointerCoords coords;
        coords.clear();
        coords.setAxisValue(AMOTION_EVENT_AXIS_X, predictedPoint.x);
        coords.setAxisValue(AMOTION_EVENT_AXIS_Y, predictedPoint.y);
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, predictedPressure[i]);

        predictionTime += mModel->predictionInterval();
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
