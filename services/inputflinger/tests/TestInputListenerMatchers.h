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

#include <android/input.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {

MATCHER_P(WithMotionAction, action, "InputEvent with specified action") {
    if (action == AMOTION_EVENT_ACTION_CANCEL) {
        *result_listener << "expected FLAG_CANCELED to be set with ACTION_CANCEL, but was not set";
        return (arg.flags & AMOTION_EVENT_FLAG_CANCELED) != 0;
    }
    *result_listener << "expected action " << MotionEvent::actionToString(action) << ", but got "
                     << MotionEvent::actionToString(arg.action);
    return action == arg.action;
}

MATCHER_P(WithSource, source, "InputEvent with specified source") {
    *result_listener << "expected source " << source << ", but got " << arg.source;
    return arg.source == source;
}

MATCHER_P(WithDisplayId, displayId, "InputEvent with specified displayId") {
    *result_listener << "expected displayId " << displayId << ", but got " << arg.displayId;
    return arg.displayId == displayId;
}

MATCHER_P2(WithCoords, x, y, "InputEvent with specified coords") {
    const auto argX = arg.pointerCoords[0].getX();
    const auto argY = arg.pointerCoords[0].getY();
    *result_listener << "expected coords (" << x << ", " << y << "), but got (" << argX << ", "
                     << argY << ")";
    return argX == x && argY == y;
}

MATCHER_P(WithFlags, flags, "InputEvent with specified flags") {
    *result_listener << "expected flags " << flags << ", but got " << arg.flags;
    return arg.flags == flags;
}

} // namespace android
