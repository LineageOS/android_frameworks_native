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

#include <fuzzer/FuzzedDataProvider.h>

namespace android {

namespace {
static constexpr int32_t MAX_RANDOM_POINTERS = 4;
static constexpr int32_t MAX_RANDOM_DEVICES = 4;
} // namespace

int getFuzzedMotionAction(FuzzedDataProvider& fdp) {
    int actionMasked = fdp.PickValueInArray<int>({
            AMOTION_EVENT_ACTION_DOWN, AMOTION_EVENT_ACTION_UP, AMOTION_EVENT_ACTION_MOVE,
            AMOTION_EVENT_ACTION_HOVER_ENTER, AMOTION_EVENT_ACTION_HOVER_MOVE,
            AMOTION_EVENT_ACTION_HOVER_EXIT, AMOTION_EVENT_ACTION_CANCEL,
            // do not inject AMOTION_EVENT_ACTION_OUTSIDE,
            AMOTION_EVENT_ACTION_SCROLL, AMOTION_EVENT_ACTION_POINTER_DOWN,
            AMOTION_EVENT_ACTION_POINTER_UP,
            // do not send buttons until verifier supports them
            // AMOTION_EVENT_ACTION_BUTTON_PRESS,
            // AMOTION_EVENT_ACTION_BUTTON_RELEASE,
    });
    switch (actionMasked) {
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
        case AMOTION_EVENT_ACTION_POINTER_UP: {
            const int32_t index = fdp.ConsumeIntegralInRange(0, MAX_RANDOM_POINTERS - 1);
            const int32_t action =
                    actionMasked | (index << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
            return action;
        }
        default:
            return actionMasked;
    }
}

/**
 * For now, focus on the 3 main sources.
 */
int getFuzzedSource(FuzzedDataProvider& fdp) {
    return fdp.PickValueInArray<int>({
            // AINPUT_SOURCE_UNKNOWN,
            // AINPUT_SOURCE_KEYBOARD,
            // AINPUT_SOURCE_DPAD,
            // AINPUT_SOURCE_GAMEPAD,
            AINPUT_SOURCE_TOUCHSCREEN, AINPUT_SOURCE_MOUSE, AINPUT_SOURCE_STYLUS,
            // AINPUT_SOURCE_BLUETOOTH_STYLUS,
            // AINPUT_SOURCE_TRACKBALL,
            // AINPUT_SOURCE_MOUSE_RELATIVE,
            // AINPUT_SOURCE_TOUCHPAD,
            // AINPUT_SOURCE_TOUCH_NAVIGATION,
            // AINPUT_SOURCE_JOYSTICK,
            // AINPUT_SOURCE_HDMI,
            // AINPUT_SOURCE_SENSOR,
            // AINPUT_SOURCE_ROTARY_ENCODER,
            // AINPUT_SOURCE_ANY,
    });
}

int getFuzzedButtonState(FuzzedDataProvider& fdp) {
    return fdp.PickValueInArray<int>({
            0,
            // AMOTION_EVENT_BUTTON_PRIMARY,
            // AMOTION_EVENT_BUTTON_SECONDARY,
            // AMOTION_EVENT_BUTTON_TERTIARY,
            // AMOTION_EVENT_BUTTON_BACK,
            // AMOTION_EVENT_BUTTON_FORWARD,
            // AMOTION_EVENT_BUTTON_STYLUS_PRIMARY,
            // AMOTION_EVENT_BUTTON_STYLUS_SECONDARY,
    });
}

int32_t getFuzzedFlags(FuzzedDataProvider& fdp, int32_t action) {
    constexpr std::array<int32_t, 4> FLAGS{
            AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED,
            AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED,
            AMOTION_EVENT_FLAG_IS_ACCESSIBILITY_EVENT,
            AMOTION_EVENT_FLAG_NO_FOCUS_CHANGE,
    };

    int32_t flags = 0;
    for (size_t i = 0; i < fdp.ConsumeIntegralInRange(size_t(0), FLAGS.size()); i++) {
        flags |= fdp.PickValueInArray<int32_t>(FLAGS);
    }
    if (action == AMOTION_EVENT_ACTION_CANCEL) {
        flags |= AMOTION_EVENT_FLAG_CANCELED;
    }
    if (MotionEvent::getActionMasked(action) == AMOTION_EVENT_ACTION_POINTER_UP) {
        if (fdp.ConsumeBool()) {
            flags |= AMOTION_EVENT_FLAG_CANCELED;
        }
    }
    return flags;
}

int32_t getFuzzedPointerCount(FuzzedDataProvider& fdp, int32_t action) {
    switch (MotionEvent::getActionMasked(action)) {
        case AMOTION_EVENT_ACTION_DOWN:
        case AMOTION_EVENT_ACTION_UP: {
            return 1;
        }
        case AMOTION_EVENT_ACTION_OUTSIDE:
        case AMOTION_EVENT_ACTION_CANCEL:
        case AMOTION_EVENT_ACTION_MOVE:
            return fdp.ConsumeIntegralInRange<int32_t>(1, MAX_RANDOM_POINTERS);
        case AMOTION_EVENT_ACTION_HOVER_ENTER:
        case AMOTION_EVENT_ACTION_HOVER_MOVE:
        case AMOTION_EVENT_ACTION_HOVER_EXIT:
            return 1;
        case AMOTION_EVENT_ACTION_SCROLL:
            return 1;
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
        case AMOTION_EVENT_ACTION_POINTER_UP: {
            const uint8_t actionIndex = MotionEvent::getActionIndex(action);
            const int32_t count =
                    std::max(actionIndex + 1,
                             fdp.ConsumeIntegralInRange<int32_t>(1, MAX_RANDOM_POINTERS));
            // Need to have at least 2 pointers
            return std::max(2, count);
        }
        case AMOTION_EVENT_ACTION_BUTTON_PRESS:
        case AMOTION_EVENT_ACTION_BUTTON_RELEASE: {
            return 1;
        }
    }
    return 1;
}

ToolType getToolType(int32_t source) {
    switch (source) {
        case AINPUT_SOURCE_TOUCHSCREEN:
            return ToolType::FINGER;
        case AINPUT_SOURCE_MOUSE:
            return ToolType::MOUSE;
        case AINPUT_SOURCE_STYLUS:
            return ToolType::STYLUS;
    }
    return ToolType::UNKNOWN;
}

inline nsecs_t now() {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

NotifyMotionArgs generateFuzzedMotionArgs(IdGenerator& idGenerator, FuzzedDataProvider& fdp,
                                          int32_t maxDisplays) {
    // Create a basic motion event for testing
    const int32_t source = getFuzzedSource(fdp);
    const ToolType toolType = getToolType(source);
    const int32_t action = getFuzzedMotionAction(fdp);
    const int32_t pointerCount = getFuzzedPointerCount(fdp, action);
    std::vector<PointerProperties> pointerProperties;
    std::vector<PointerCoords> pointerCoords;
    for (int i = 0; i < pointerCount; i++) {
        PointerProperties properties{};
        properties.id = i;
        properties.toolType = toolType;
        pointerProperties.push_back(properties);

        PointerCoords coords{};
        coords.setAxisValue(AMOTION_EVENT_AXIS_X, fdp.ConsumeIntegralInRange<int>(-1000, 1000));
        coords.setAxisValue(AMOTION_EVENT_AXIS_Y, fdp.ConsumeIntegralInRange<int>(-1000, 1000));
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1);
        pointerCoords.push_back(coords);
    }

    const ui::LogicalDisplayId displayId{fdp.ConsumeIntegralInRange<int32_t>(0, maxDisplays - 1)};
    const int32_t deviceId = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_RANDOM_DEVICES - 1);

    // Current time +- 5 seconds
    const nsecs_t currentTime = now();
    const nsecs_t downTime =
            fdp.ConsumeIntegralInRange<nsecs_t>(currentTime - 5E9, currentTime + 5E9);
    const nsecs_t readTime = downTime;
    const nsecs_t eventTime = fdp.ConsumeIntegralInRange<nsecs_t>(downTime, downTime + 1E9);

    const float cursorX = fdp.ConsumeIntegralInRange<int>(-10000, 10000);
    const float cursorY = fdp.ConsumeIntegralInRange<int>(-10000, 10000);
    return NotifyMotionArgs(idGenerator.nextId(), eventTime, readTime, deviceId, source, displayId,
                            POLICY_FLAG_PASS_TO_USER, action,
                            /*actionButton=*/fdp.ConsumeIntegral<int32_t>(),
                            getFuzzedFlags(fdp, action), AMETA_NONE, getFuzzedButtonState(fdp),
                            MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, pointerCount,
                            pointerProperties.data(), pointerCoords.data(),
                            /*xPrecision=*/0,
                            /*yPrecision=*/0, cursorX, cursorY, downTime,
                            /*videoFrames=*/{});
}

} // namespace android
