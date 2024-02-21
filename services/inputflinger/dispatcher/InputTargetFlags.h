/*
 * Copyright 2024 The Android Open Source Project
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

#include <ftl/flags.h>

namespace android::inputdispatcher {

enum class InputTargetFlags : uint32_t {
    /* This flag indicates that the event is being delivered to a foreground application. */
    FOREGROUND = 1 << 0,

    /* This flag indicates that the MotionEvent falls within the area of the target
     * obscured by another visible window above it.  The motion event should be
     * delivered with flag AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED. */
    WINDOW_IS_OBSCURED = 1 << 1,

    /* This flag indicates that a motion event is being split across multiple windows. */
    SPLIT = 1 << 2,

    /* This flag indicates that the pointer coordinates dispatched to the application
     * will be zeroed out to avoid revealing information to an application. This is
     * used in conjunction with FLAG_DISPATCH_AS_OUTSIDE to prevent apps not sharing
     * the same UID from watching all touches. */
    ZERO_COORDS = 1 << 3,

    /* This flag indicates that the event will not cause a focus change if it is directed to an
     * unfocused window, even if it an ACTION_DOWN. This is typically used to allow gestures to be
     * directed to an unfocused window without bringing it into focus. The motion event should be
     * delivered with flag AMOTION_EVENT_FLAG_NO_FOCUS_CHANGE. */
    NO_FOCUS_CHANGE = 1 << 4,

    /* This flag indicates that the target of a MotionEvent is partly or wholly
     * obscured by another visible window above it.  The motion event should be
     * delivered with flag AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED. */
    WINDOW_IS_PARTIALLY_OBSCURED = 1 << 14,
};

} // namespace android::inputdispatcher
