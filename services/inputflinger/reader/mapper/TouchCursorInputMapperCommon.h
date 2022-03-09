/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef _UI_INPUTREADER_TOUCH_CURSOR_INPUT_MAPPER_COMMON_H
#define _UI_INPUTREADER_TOUCH_CURSOR_INPUT_MAPPER_COMMON_H

#include <InputFlingerProperties.sysprop.h>
#include <input/DisplayViewport.h>
#include <stdint.h>

#include "EventHub.h"
#include "InputListener.h"
#include "InputReaderContext.h"

namespace android {

// --- Static Definitions ---

// When per-window input rotation is enabled, display transformations such as rotation and
// projection are part of the input window's transform. This means InputReader should work in the
// un-rotated coordinate space.
static bool isPerWindowInputRotationEnabled() {
    return sysprop::InputFlingerProperties::per_window_input_rotation().value_or(false);
}

static int32_t getInverseRotation(int32_t orientation) {
    switch (orientation) {
        case DISPLAY_ORIENTATION_90:
            return DISPLAY_ORIENTATION_270;
        case DISPLAY_ORIENTATION_270:
            return DISPLAY_ORIENTATION_90;
        default:
            return orientation;
    }
}

static void rotateDelta(int32_t orientation, float* deltaX, float* deltaY) {
    float temp;
    switch (orientation) {
        case DISPLAY_ORIENTATION_90:
            temp = *deltaX;
            *deltaX = *deltaY;
            *deltaY = -temp;
            break;

        case DISPLAY_ORIENTATION_180:
            *deltaX = -*deltaX;
            *deltaY = -*deltaY;
            break;

        case DISPLAY_ORIENTATION_270:
            temp = *deltaX;
            *deltaX = -*deltaY;
            *deltaY = temp;
            break;

        default:
            break;
    }
}

// Rotates the given point (x, y) by the supplied orientation. The width and height are the
// dimensions of the surface prior to this rotation being applied.
static void rotatePoint(int32_t orientation, float& x, float& y, int32_t width, int32_t height) {
    rotateDelta(orientation, &x, &y);
    switch (orientation) {
        case DISPLAY_ORIENTATION_90:
            y += width;
            break;
        case DISPLAY_ORIENTATION_180:
            x += width;
            y += height;
            break;
        case DISPLAY_ORIENTATION_270:
            x += height;
            break;
        default:
            break;
    }
}

// Returns true if the pointer should be reported as being down given the specified
// button states.  This determines whether the event is reported as a touch event.
static bool isPointerDown(int32_t buttonState) {
    return buttonState &
            (AMOTION_EVENT_BUTTON_PRIMARY | AMOTION_EVENT_BUTTON_SECONDARY |
             AMOTION_EVENT_BUTTON_TERTIARY);
}

static void synthesizeButtonKey(InputReaderContext* context, int32_t action, nsecs_t when,
                                nsecs_t readTime, int32_t deviceId, uint32_t source,
                                int32_t displayId, uint32_t policyFlags, int32_t lastButtonState,
                                int32_t currentButtonState, int32_t buttonState, int32_t keyCode) {
    if ((action == AKEY_EVENT_ACTION_DOWN && !(lastButtonState & buttonState) &&
         (currentButtonState & buttonState)) ||
        (action == AKEY_EVENT_ACTION_UP && (lastButtonState & buttonState) &&
         !(currentButtonState & buttonState))) {
        NotifyKeyArgs args(context->getNextId(), when, readTime, deviceId, source, displayId,
                           policyFlags, action, 0, keyCode, 0, context->getGlobalMetaState(), when);
        context->getListener()->notifyKey(&args);
    }
}

static void synthesizeButtonKeys(InputReaderContext* context, int32_t action, nsecs_t when,
                                 nsecs_t readTime, int32_t deviceId, uint32_t source,
                                 int32_t displayId, uint32_t policyFlags, int32_t lastButtonState,
                                 int32_t currentButtonState) {
    synthesizeButtonKey(context, action, when, readTime, deviceId, source, displayId, policyFlags,
                        lastButtonState, currentButtonState, AMOTION_EVENT_BUTTON_BACK,
                        AKEYCODE_BACK);
    synthesizeButtonKey(context, action, when, readTime, deviceId, source, displayId, policyFlags,
                        lastButtonState, currentButtonState, AMOTION_EVENT_BUTTON_FORWARD,
                        AKEYCODE_FORWARD);
}

} // namespace android

#endif // _UI_INPUTREADER_TOUCH_CURSOR_INPUT_MAPPER_COMMON_H
