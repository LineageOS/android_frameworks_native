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

#include <ftl/static_vector.h>
#include <optional>
#include "InputListener.h"

namespace android {

/**
 * When stylus is down, we ignore all touch.
 * TODO(b/210159205): delete this when simultaneous stylus and touch is supported
 */
class PreferStylusOverTouchBlocker {
public:
    /**
     * Process the provided event and emit up to 2 events in response.
     * In the majority of cases, the returned result will just be the provided args (array with
     * only 1 element), unmodified.
     *
     * If the gesture should be blocked, the returned result may be:
     *
     * a) An empty array, if the current event should just be ignored completely
     * b) An array of 2 elements, containing an event with ACTION_CANCEL and the current event.
     *
     * bool is set to 'true'.
     * NotifyMotionArgs potentially contains an event that should be used to cancel the existing
     * gesture.
     *
     * If the event should not be blocked, bool contains 'false'.
     */
    ftl::StaticVector<NotifyMotionArgs, 2> processMotion(const NotifyMotionArgs& args);
    std::string dump();

private:
    bool mIsTouchDown = false;
    bool mIsStylusDown = false;
    // Provide some default values for the stored MotionEvent to allow printint the event before
    // any real event is received.
    NotifyMotionArgs mLastTouchEvent{0 /*id*/,
                                     0 /*eventTime*/,
                                     0 /*readTime*/,
                                     0 /*deviceId*/,
                                     AINPUT_SOURCE_TOUCHSCREEN,
                                     0 /*displayId*/,
                                     0 /*policyFlags*/,
                                     0 /*action*/,
                                     0 /*actionButton*/,
                                     0 /*flags*/,
                                     0 /*metaState*/,
                                     0 /*buttonState*/,
                                     MotionClassification::NONE,
                                     AMOTION_EVENT_EDGE_FLAG_NONE,
                                     0 /*pointerCount*/,
                                     nullptr /*properties*/,
                                     nullptr /*coords*/,
                                     0. /*xPrecision*/,
                                     0. /*yPrecision*/,
                                     AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                     AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                     0 /*downTime*/,
                                     {}};
    bool mCurrentTouchIsCanceled = false;
};

} // namespace android