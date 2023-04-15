/*
 * Copyright 2022 The Android Open Source Project
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

#include "../Macros.h"

#include <limits>
#include <optional>

#include <android/input.h>
#include <ftl/enum.h>
#include <input/PrintTools.h>
#include <linux/input-event-codes.h>
#include <log/log_main.h>
#include "TouchCursorInputMapperCommon.h"
#include "TouchpadInputMapper.h"
#include "ui/Rotation.h"

namespace android {

namespace {

/**
 * Log details of each gesture output by the gestures library.
 * Enable this via "adb shell setprop log.tag.TouchpadInputMapperGestures DEBUG" (requires
 * restarting the shell)
 */
const bool DEBUG_TOUCHPAD_GESTURES =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, "TouchpadInputMapperGestures",
                                  ANDROID_LOG_INFO);

// Describes a segment of the acceleration curve.
struct CurveSegment {
    // The maximum pointer speed which this segment should apply. The last segment in a curve should
    // always set this to infinity.
    double maxPointerSpeedMmPerS;
    double slope;
    double intercept;
};

const std::vector<CurveSegment> segments = {
        {10.922, 3.19, 0},
        {31.750, 4.79, -17.526},
        {98.044, 7.28, -96.52},
        {std::numeric_limits<double>::infinity(), 15.04, -857.758},
};

const std::vector<double> sensitivityFactors = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 18};

std::vector<double> createAccelerationCurveForSensitivity(int32_t sensitivity,
                                                          size_t propertySize) {
    LOG_ALWAYS_FATAL_IF(propertySize < 4 * segments.size());
    std::vector<double> output(propertySize, 0);

    // The Gestures library uses functions of the following form to define curve segments, where a,
    // b, and c can be specified by us:
    //     output_speed(input_speed_mm) = a * input_speed_mm ^ 2 + b * input_speed_mm + c
    //
    // (a, b, and c are also called sqr_, mul_, and int_ in the Gestures library code.)
    //
    // We are trying to implement the following function, where slope and intercept are the
    // parameters specified in the `segments` array above:
    //     gain(input_speed_mm) =
    //             0.64 * (sensitivityFactor / 10) * (slope + intercept / input_speed_mm)
    // Where "gain" is a multiplier applied to the input speed to produce the output speed:
    //     output_speed(input_speed_mm) = input_speed_mm * gain(input_speed_mm)
    //
    // To put our function in the library's form, we substitute it into the function above:
    //     output_speed(input_speed_mm) =
    //             input_speed_mm * (0.64 * (sensitivityFactor / 10) *
    //             (slope + 25.4 * intercept / input_speed_mm))
    // then expand the brackets so that input_speed_mm cancels out for the intercept term:
    //     gain(input_speed_mm) =
    //             0.64 * (sensitivityFactor / 10) * slope * input_speed_mm +
    //             0.64 * (sensitivityFactor / 10) * intercept
    //
    // This gives us the following parameters for the Gestures library function form:
    //     a = 0
    //     b = 0.64 * (sensitivityFactor / 10) * slope
    //     c = 0.64 * (sensitivityFactor / 10) * intercept

    double commonFactor = 0.64 * sensitivityFactors[sensitivity + 7] / 10;

    size_t i = 0;
    for (CurveSegment seg : segments) {
        // The library's curve format consists of four doubles per segment:
        // * maximum pointer speed for the segment (mm/s)
        // * multiplier for the x² term (a.k.a. "a" or "sqr")
        // * multiplier for the x term (a.k.a. "b" or "mul")
        // * the intercept (a.k.a. "c" or "int")
        // (see struct CurveSegment in the library's AccelFilterInterpreter)
        output[i + 0] = seg.maxPointerSpeedMmPerS;
        output[i + 1] = 0;
        output[i + 2] = commonFactor * seg.slope;
        output[i + 3] = commonFactor * seg.intercept;
        i += 4;
    }

    return output;
}

short getMaxTouchCount(const InputDeviceContext& context) {
    if (context.hasScanCode(BTN_TOOL_QUINTTAP)) return 5;
    if (context.hasScanCode(BTN_TOOL_QUADTAP)) return 4;
    if (context.hasScanCode(BTN_TOOL_TRIPLETAP)) return 3;
    if (context.hasScanCode(BTN_TOOL_DOUBLETAP)) return 2;
    if (context.hasScanCode(BTN_TOOL_FINGER)) return 1;
    return 0;
}

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
    return props;
}

void gestureInterpreterCallback(void* clientData, const Gesture* gesture) {
    TouchpadInputMapper* mapper = static_cast<TouchpadInputMapper*>(clientData);
    mapper->consumeGesture(gesture);
}

} // namespace

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext,
                                         const InputReaderConfiguration& readerConfig)
      : InputMapper(deviceContext, readerConfig),
        mGestureInterpreter(NewGestureInterpreter(), DeleteGestureInterpreter),
        mPointerController(getContext()->getPointerController(getDeviceId())),
        mStateConverter(deviceContext),
        mGestureConverter(*getContext(), deviceContext, getDeviceId()) {
    mGestureInterpreter->Initialize(GESTURES_DEVCLASS_TOUCHPAD);
    mGestureInterpreter->SetHardwareProperties(createHardwareProperties(deviceContext));
    // Even though we don't explicitly delete copy/move semantics, it's safe to
    // give away pointers to TouchpadInputMapper and its members here because
    // 1) mGestureInterpreter's lifecycle is determined by TouchpadInputMapper, and
    // 2) TouchpadInputMapper is stored as a unique_ptr and not moved.
    mGestureInterpreter->SetPropProvider(const_cast<GesturesPropProvider*>(&gesturePropProvider),
                                         &mPropertyProvider);
    mGestureInterpreter->SetCallback(gestureInterpreterCallback, this);
    // TODO(b/251196347): set a timer provider, so the library can use timers.
}

TouchpadInputMapper::~TouchpadInputMapper() {
    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
    }

    // The gesture interpreter's destructor will call its property provider's free function for all
    // gesture properties, in this case calling PropertyProvider::freeProperty using a raw pointer
    // to mPropertyProvider. Depending on the declaration order in TouchpadInputMapper.h, this may
    // happen after mPropertyProvider has been destructed, causing allocation errors. Depending on
    // declaration order to avoid crashes seems rather fragile, so explicitly clear the property
    // provider here to ensure all the freeProperty calls happen before mPropertyProvider is
    // destructed.
    mGestureInterpreter->SetPropProvider(nullptr, nullptr);
}

uint32_t TouchpadInputMapper::getSources() const {
    return AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD;
}

void TouchpadInputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    InputMapper::populateDeviceInfo(info);
    mGestureConverter.populateMotionRanges(info);
}

void TouchpadInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Touchpad Input Mapper:\n";
    dump += INDENT3 "Gesture converter:\n";
    dump += addLinePrefix(mGestureConverter.dump(), INDENT4);
    dump += INDENT3 "Gesture properties:\n";
    dump += addLinePrefix(mPropertyProvider.dump(), INDENT4);
}

std::list<NotifyArgs> TouchpadInputMapper::reconfigure(nsecs_t when,
                                                       const InputReaderConfiguration& config,
                                                       uint32_t changes) {
    if (!changes) {
        // First time configuration
        mPropertyProvider.loadPropertiesFromIdcFile(getDeviceContext().getConfiguration());
    }

    if (!changes || (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO)) {
        std::optional<int32_t> displayId = mPointerController->getDisplayId();
        ui::Rotation orientation = ui::ROTATION_0;
        if (displayId.has_value()) {
            if (auto viewport = config.getDisplayViewportById(*displayId); viewport) {
                orientation = getInverseRotation(viewport->orientation);
            }
        }
        mGestureConverter.setOrientation(orientation);
    }
    if (!changes || (changes & InputReaderConfiguration::CHANGE_TOUCHPAD_SETTINGS)) {
        mPropertyProvider.getProperty("Use Custom Touchpad Pointer Accel Curve")
                .setBoolValues({true});
        GesturesProp accelCurveProp = mPropertyProvider.getProperty("Pointer Accel Curve");
        accelCurveProp.setRealValues(
                createAccelerationCurveForSensitivity(config.touchpadPointerSpeed,
                                                      accelCurveProp.getCount()));
        mPropertyProvider.getProperty("Invert Scrolling")
                .setBoolValues({config.touchpadNaturalScrollingEnabled});
        mPropertyProvider.getProperty("Tap Enable")
                .setBoolValues({config.touchpadTapToClickEnabled});
        mPropertyProvider.getProperty("Button Right Click Zone Enable")
                .setBoolValues({config.touchpadRightClickZoneEnabled});
    }
    return {};
}

std::list<NotifyArgs> TouchpadInputMapper::reset(nsecs_t when) {
    mStateConverter.reset();
    std::list<NotifyArgs> out = mGestureConverter.reset(when);
    out += InputMapper::reset(when);
    return out;
}

std::list<NotifyArgs> TouchpadInputMapper::process(const RawEvent* rawEvent) {
    std::optional<SelfContainedHardwareState> state = mStateConverter.processRawEvent(rawEvent);
    if (state) {
        return sendHardwareState(rawEvent->when, rawEvent->readTime, *state);
    } else {
        return {};
    }
}

std::list<NotifyArgs> TouchpadInputMapper::sendHardwareState(nsecs_t when, nsecs_t readTime,
                                                             SelfContainedHardwareState schs) {
    ALOGD_IF(DEBUG_TOUCHPAD_GESTURES, "New hardware state: %s", schs.state.String().c_str());
    mProcessing = true;
    mGestureInterpreter->PushHardwareState(&schs.state);
    mProcessing = false;

    return processGestures(when, readTime);
}

void TouchpadInputMapper::consumeGesture(const Gesture* gesture) {
    ALOGD_IF(DEBUG_TOUCHPAD_GESTURES, "Gesture ready: %s", gesture->String().c_str());
    if (!mProcessing) {
        ALOGE("Received gesture outside of the normal processing flow; ignoring it.");
        return;
    }
    mGesturesToProcess.push_back(*gesture);
}

std::list<NotifyArgs> TouchpadInputMapper::processGestures(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out = {};
    for (Gesture& gesture : mGesturesToProcess) {
        out += mGestureConverter.handleGesture(when, readTime, gesture);
    }
    mGesturesToProcess.clear();
    return out;
}

} // namespace android
