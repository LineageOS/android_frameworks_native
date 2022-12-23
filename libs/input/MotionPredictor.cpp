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

/**
 * Log debug messages about predictions.
 * Enable this via "adb shell setprop log.tag.MotionPredictor DEBUG"
 */
static bool isDebug() {
    return __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG, ANDROID_LOG_INFO);
}

namespace android {

// --- MotionPredictor ---

MotionPredictor::MotionPredictor(nsecs_t predictionTimestampOffsetNanos,
                                 std::function<bool()> checkMotionPredictionEnabled)
      : mPredictionTimestampOffsetNanos(predictionTimestampOffsetNanos),
        mCheckMotionPredictionEnabled(std::move(checkMotionPredictionEnabled)) {}

void MotionPredictor::record(const MotionEvent& event) {
    mEvents.push_back({});
    mEvents.back().copyFrom(&event, /*keepHistory=*/true);
    if (mEvents.size() > 2) {
        // Just need 2 samples in order to extrapolate
        mEvents.erase(mEvents.begin());
    }
}

/**
 * This is an example implementation that should be replaced with the actual prediction.
 * The returned MotionEvent should be similar to the incoming MotionEvent, except for the
 * fields that are predicted:
 *
 * 1) event.getEventTime
 * 2) event.getPointerCoords
 *
 * The returned event should not contain any of the real, existing data. It should only
 * contain the predicted samples.
 */
std::vector<std::unique_ptr<MotionEvent>> MotionPredictor::predict() {
    if (mEvents.size() < 2) {
        return {};
    }

    const MotionEvent& event = mEvents.back();
    if (!isPredictionAvailable(event.getDeviceId(), event.getSource())) {
        return {};
    }

    std::unique_ptr<MotionEvent> prediction = std::make_unique<MotionEvent>();
    std::vector<PointerCoords> futureCoords;
    const int64_t futureTime = getExpectedPresentationTimeNanos() + mPredictionTimestampOffsetNanos;
    const nsecs_t currentTime = event.getEventTime();
    const MotionEvent& previous = mEvents.rbegin()[1];
    const nsecs_t oldTime = previous.getEventTime();
    if (currentTime == oldTime) {
        // This can happen if it's an ACTION_POINTER_DOWN event, for example.
        return {}; // prevent division by zero.
    }

    for (size_t i = 0; i < event.getPointerCount(); i++) {
        const int32_t pointerId = event.getPointerId(i);
        PointerCoords coords;
        coords.clear();

        ssize_t index = previous.findPointerIndex(pointerId);
        if (index >= 0) {
            // We have old data for this pointer. Compute the prediction.
            const float oldX = previous.getRawX(index);
            const float oldY = previous.getRawY(index);
            const float currentX = event.getRawX(i);
            const float currentY = event.getRawY(i);

            // Let's do a linear interpolation while waiting for a real model
            const float scale =
                    static_cast<float>(futureTime - currentTime) / (currentTime - oldTime);
            const float futureX = currentX + (currentX - oldX) * scale;
            const float futureY = currentY + (currentY - oldY) * scale;

            coords.setAxisValue(AMOTION_EVENT_AXIS_X, futureX);
            coords.setAxisValue(AMOTION_EVENT_AXIS_Y, futureY);
        }

        futureCoords.push_back(coords);
    }

    ALOGD_IF(isDebug(), "Prediction is %.1f ms away from the event",
             (futureTime - event.getEventTime()) * 1E-6);
    /**
     * The process of adding samples is different for the first and subsequent samples:
     * 1. Add the first sample via 'initialize' as below
     * 2. Add subsequent samples via 'addSample'
     */
    prediction->initialize(event.getId(), event.getDeviceId(), event.getSource(),
                           event.getDisplayId(), event.getHmac(), event.getAction(),
                           event.getActionButton(), event.getFlags(), event.getEdgeFlags(),
                           event.getMetaState(), event.getButtonState(), event.getClassification(),
                           event.getTransform(), event.getXPrecision(), event.getYPrecision(),
                           event.getRawXCursorPosition(), event.getRawYCursorPosition(),
                           event.getRawTransform(), event.getDownTime(), futureTime,
                           event.getPointerCount(), event.getPointerProperties(),
                           futureCoords.data());

    // To add more predicted samples, use 'addSample':
    prediction->addSample(futureTime + 1, futureCoords.data());

    std::vector<std::unique_ptr<MotionEvent>> out;
    out.push_back(std::move(prediction));
    return out;
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

int64_t MotionPredictor::getExpectedPresentationTimeNanos() {
    std::scoped_lock lock(mLock);
    return mExpectedPresentationTimeNanos;
}

void MotionPredictor::setExpectedPresentationTimeNanos(int64_t expectedPresentationTimeNanos) {
    std::scoped_lock lock(mLock);
    mExpectedPresentationTimeNanos = expectedPresentationTimeNanos;
}

} // namespace android
