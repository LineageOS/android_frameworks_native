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

#pragma once

#include <android-base/thread_annotations.h>
#include <android/sysprop/InputProperties.sysprop.h>
#include <input/Input.h>

namespace android {

static inline bool isMotionPredictionEnabled() {
    return sysprop::InputProperties::enable_motion_prediction().value_or(true);
}

/**
 * Given a set of MotionEvents for the current gesture, predict the motion. The returned MotionEvent
 * contains a set of samples in the future, up to "presentation time + offset".
 *
 * The typical usage is like this:
 *
 * MotionPredictor predictor(offset = MY_OFFSET);
 * predictor.setExpectedPresentationTimeNanos(NEXT_PRESENT_TIME);
 * predictor.record(DOWN_MOTION_EVENT);
 * predictor.record(MOVE_MOTION_EVENT);
 * prediction = predictor.predict();
 *
 * The presentation time should be set some time before calling .predict(). It could be set before
 * or after the recorded motion events. Must be done on every frame.
 *
 * The resulting motion event will have eventTime <= (NEXT_PRESENT_TIME + MY_OFFSET). It might
 * contain historical data, which are additional samples from the latest recorded MotionEvent's
 * eventTime to the NEXT_PRESENT_TIME + MY_OFFSET.
 *
 * The offset is used to provide additional flexibility to the caller, in case the default present
 * time (typically provided by the choreographer) does not account for some delays, or to simply
 * reduce the aggressiveness of the prediction. Offset can be both positive and negative.
 */
class MotionPredictor {
public:
    /**
     * Parameters:
     * predictionTimestampOffsetNanos: additional, constant shift to apply to the target
     * presentation time. The prediction will target the time t=(presentationTime +
     * predictionTimestampOffsetNanos).
     *
     * checkEnableMotionPredition: the function to check whether the prediction should run. Used to
     * provide an additional way of turning prediction on and off. Can be toggled at runtime.
     */
    MotionPredictor(nsecs_t predictionTimestampOffsetNanos,
                    std::function<bool()> checkEnableMotionPrediction = isMotionPredictionEnabled);
    void record(const MotionEvent& event);
    std::vector<std::unique_ptr<MotionEvent>> predict(nsecs_t timestamp);
    bool isPredictionAvailable(int32_t deviceId, int32_t source);

private:
    std::vector<MotionEvent> mEvents;
    const nsecs_t mPredictionTimestampOffsetNanos;
    const std::function<bool()> mCheckMotionPredictionEnabled;
};

} // namespace android
