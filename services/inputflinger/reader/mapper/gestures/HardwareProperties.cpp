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

#include "HardwareProperties.h"

namespace android {

namespace {

unsigned short getMaxTouchCount(const InputDeviceContext& context) {
    if (context.hasScanCode(BTN_TOOL_QUINTTAP)) return 5;
    if (context.hasScanCode(BTN_TOOL_QUADTAP)) return 4;
    if (context.hasScanCode(BTN_TOOL_TRIPLETAP)) return 3;
    if (context.hasScanCode(BTN_TOOL_DOUBLETAP)) return 2;
    if (context.hasScanCode(BTN_TOOL_FINGER)) return 1;
    return 0;
}

} // namespace

HardwareProperties createHardwareProperties(const InputDeviceContext& context) {
    HardwareProperties props;
    RawAbsoluteAxisInfo absMtPositionX;
    context.getAbsoluteAxisInfo(ABS_MT_POSITION_X, &absMtPositionX);
    props.left = absMtPositionX.minValue;
    props.right = absMtPositionX.maxValue;
    props.res_x = absMtPositionX.resolution;

    RawAbsoluteAxisInfo absMtPositionY;
    context.getAbsoluteAxisInfo(ABS_MT_POSITION_Y, &absMtPositionY);
    props.top = absMtPositionY.minValue;
    props.bottom = absMtPositionY.maxValue;
    props.res_y = absMtPositionY.resolution;

    RawAbsoluteAxisInfo absMtOrientation;
    context.getAbsoluteAxisInfo(ABS_MT_ORIENTATION, &absMtOrientation);
    props.orientation_minimum = absMtOrientation.minValue;
    props.orientation_maximum = absMtOrientation.maxValue;

    RawAbsoluteAxisInfo absMtSlot;
    context.getAbsoluteAxisInfo(ABS_MT_SLOT, &absMtSlot);
    props.max_finger_cnt = absMtSlot.maxValue - absMtSlot.minValue + 1;
    props.max_touch_cnt = getMaxTouchCount(context);

    // T5R2 ("Track 5, Report 2") is a feature of some old Synaptics touchpads that could track 5
    // fingers but only report the coordinates of 2 of them. We don't know of any external touchpads
    // that did this, so assume false.
    props.supports_t5r2 = false;

    props.support_semi_mt = context.hasInputProperty(INPUT_PROP_SEMI_MT);
    props.is_button_pad = context.hasInputProperty(INPUT_PROP_BUTTONPAD);

    // Mouse-only properties, which will always be false.
    props.has_wheel = false;
    props.wheel_is_hi_res = false;

    // Linux Kernel haptic touchpad support isn't merged yet, so for now assume that no touchpads
    // are haptic.
    props.is_haptic_pad = false;

    RawAbsoluteAxisInfo absMtPressure;
    context.getAbsoluteAxisInfo(ABS_MT_PRESSURE, &absMtPressure);
    props.reports_pressure = absMtPressure.valid;
    return props;
}

} // namespace android
