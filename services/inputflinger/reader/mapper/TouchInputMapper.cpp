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

// clang-format off
#include "../Macros.h"
// clang-format on

#include "TouchInputMapper.h"

#include <ftl/enum.h>
#include <input/PrintTools.h>

#include "CursorButtonAccumulator.h"
#include "CursorScrollAccumulator.h"
#include "TouchButtonAccumulator.h"
#include "TouchCursorInputMapperCommon.h"
#include "ui/Rotation.h"

namespace android {

// --- Constants ---

// Artificial latency on synthetic events created from stylus data without corresponding touch
// data.
static constexpr nsecs_t STYLUS_DATA_LATENCY = ms2ns(10);

// Minimum width between two pointers to determine a gesture as freeform gesture in mm
static const float MIN_FREEFORM_GESTURE_WIDTH_IN_MILLIMETER = 30;
// --- Static Definitions ---

static const DisplayViewport kUninitializedViewport;

static std::string toString(const Rect& rect) {
    return base::StringPrintf("Rect{%d, %d, %d, %d}", rect.left, rect.top, rect.right, rect.bottom);
}

static std::string toString(const ui::Size& size) {
    return base::StringPrintf("%dx%d", size.width, size.height);
}

static bool isPointInRect(const Rect& rect, vec2 p) {
    return p.x >= rect.left && p.x < rect.right && p.y >= rect.top && p.y < rect.bottom;
}

static std::string toString(const InputDeviceUsiVersion& v) {
    return base::StringPrintf("%d.%d", v.majorVersion, v.minorVersion);
}

template <typename T>
inline static void swap(T& a, T& b) {
    T temp = a;
    a = b;
    b = temp;
}

static float calculateCommonVector(float a, float b) {
    if (a > 0 && b > 0) {
        return a < b ? a : b;
    } else if (a < 0 && b < 0) {
        return a > b ? a : b;
    } else {
        return 0;
    }
}

inline static float distance(float x1, float y1, float x2, float y2) {
    return hypotf(x1 - x2, y1 - y2);
}

inline static int32_t signExtendNybble(int32_t value) {
    return value >= 8 ? value - 16 : value;
}

static ui::Size getNaturalDisplaySize(const DisplayViewport& viewport) {
    ui::Size rotatedDisplaySize{viewport.deviceWidth, viewport.deviceHeight};
    if (viewport.orientation == ui::ROTATION_90 || viewport.orientation == ui::ROTATION_270) {
        std::swap(rotatedDisplaySize.width, rotatedDisplaySize.height);
    }
    return rotatedDisplaySize;
}

static int32_t filterButtonState(InputReaderConfiguration& config, int32_t buttonState) {
    if (!config.stylusButtonMotionEventsEnabled) {
        buttonState &=
                ~(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY | AMOTION_EVENT_BUTTON_STYLUS_SECONDARY);
    }
    return buttonState;
}

// --- RawPointerData ---

void RawPointerData::getCentroidOfTouchingPointers(float* outX, float* outY) const {
    float x = 0, y = 0;
    uint32_t count = touchingIdBits.count();
    if (count) {
        for (BitSet32 idBits(touchingIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const Pointer& pointer = pointerForId(id);
            x += pointer.x;
            y += pointer.y;
        }
        x /= count;
        y /= count;
    }
    *outX = x;
    *outY = y;
}

// --- TouchInputMapper ---

TouchInputMapper::TouchInputMapper(InputDeviceContext& deviceContext,
                                   const InputReaderConfiguration& readerConfig)
      : InputMapper(deviceContext, readerConfig),
        mTouchButtonAccumulator(deviceContext),
        mSource(0),
        mDeviceMode(DeviceMode::DISABLED),
        mInputDeviceOrientation(ui::ROTATION_0) {}

TouchInputMapper::~TouchInputMapper() {}

uint32_t TouchInputMapper::getSources() const {
    return mSource;
}

void TouchInputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    InputMapper::populateDeviceInfo(info);

    if (mDeviceMode == DeviceMode::DISABLED) {
        return;
    }

    info.addMotionRange(mOrientedRanges.x);
    info.addMotionRange(mOrientedRanges.y);
    info.addMotionRange(mOrientedRanges.pressure);

    if (mDeviceMode == DeviceMode::UNSCALED && mSource == AINPUT_SOURCE_TOUCHPAD) {
        // Populate RELATIVE_X and RELATIVE_Y motion ranges for touchpad capture mode.
        //
        // RELATIVE_X and RELATIVE_Y motion ranges should be the largest possible relative
        // motion, i.e. the hardware dimensions, as the finger could move completely across the
        // touchpad in one sample cycle.
        const InputDeviceInfo::MotionRange& x = mOrientedRanges.x;
        const InputDeviceInfo::MotionRange& y = mOrientedRanges.y;
        info.addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_X, mSource, -x.max, x.max, x.flat, x.fuzz,
                            x.resolution);
        info.addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_Y, mSource, -y.max, y.max, y.flat, y.fuzz,
                            y.resolution);
    }

    if (mOrientedRanges.size) {
        info.addMotionRange(*mOrientedRanges.size);
    }

    if (mOrientedRanges.touchMajor) {
        info.addMotionRange(*mOrientedRanges.touchMajor);
        info.addMotionRange(*mOrientedRanges.touchMinor);
    }

    if (mOrientedRanges.toolMajor) {
        info.addMotionRange(*mOrientedRanges.toolMajor);
        info.addMotionRange(*mOrientedRanges.toolMinor);
    }

    if (mOrientedRanges.orientation) {
        info.addMotionRange(*mOrientedRanges.orientation);
    }

    if (mOrientedRanges.distance) {
        info.addMotionRange(*mOrientedRanges.distance);
    }

    if (mOrientedRanges.tilt) {
        info.addMotionRange(*mOrientedRanges.tilt);
    }

    if (mCursorScrollAccumulator.haveRelativeVWheel()) {
        info.addMotionRange(AMOTION_EVENT_AXIS_VSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }
    if (mCursorScrollAccumulator.haveRelativeHWheel()) {
        info.addMotionRange(AMOTION_EVENT_AXIS_HSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }
    info.setButtonUnderPad(mParameters.hasButtonUnderPad);
    info.setUsiVersion(mParameters.usiVersion);
}

void TouchInputMapper::dump(std::string& dump) {
    dump += StringPrintf(INDENT2 "Touch Input Mapper (mode - %s):\n",
                         ftl::enum_string(mDeviceMode).c_str());
    dumpParameters(dump);
    dumpVirtualKeys(dump);
    dumpRawPointerAxes(dump);
    dumpCalibration(dump);
    dumpAffineTransformation(dump);
    dumpDisplay(dump);

    dump += StringPrintf(INDENT3 "Translation and Scaling Factors:\n");
    mRawToDisplay.dump(dump, "RawToDisplay Transform:", INDENT4);
    mRawRotation.dump(dump, "RawRotation Transform:", INDENT4);
    dump += StringPrintf(INDENT4 "OrientedXPrecision: %0.3f\n", mOrientedXPrecision);
    dump += StringPrintf(INDENT4 "OrientedYPrecision: %0.3f\n", mOrientedYPrecision);
    dump += StringPrintf(INDENT4 "GeometricScale: %0.3f\n", mGeometricScale);
    dump += StringPrintf(INDENT4 "PressureScale: %0.3f\n", mPressureScale);
    dump += StringPrintf(INDENT4 "SizeScale: %0.3f\n", mSizeScale);
    dump += StringPrintf(INDENT4 "OrientationScale: %0.3f\n", mOrientationScale);
    dump += StringPrintf(INDENT4 "DistanceScale: %0.3f\n", mDistanceScale);
    dump += StringPrintf(INDENT4 "HaveTilt: %s\n", toString(mHaveTilt));
    dump += StringPrintf(INDENT4 "TiltXCenter: %0.3f\n", mTiltXCenter);
    dump += StringPrintf(INDENT4 "TiltXScale: %0.3f\n", mTiltXScale);
    dump += StringPrintf(INDENT4 "TiltYCenter: %0.3f\n", mTiltYCenter);
    dump += StringPrintf(INDENT4 "TiltYScale: %0.3f\n", mTiltYScale);

    dump += StringPrintf(INDENT3 "Last Raw Button State: 0x%08x\n", mLastRawState.buttonState);
    dump += StringPrintf(INDENT3 "Last Raw Touch: pointerCount=%d\n",
                         mLastRawState.rawPointerData.pointerCount);
    for (uint32_t i = 0; i < mLastRawState.rawPointerData.pointerCount; i++) {
        const RawPointerData::Pointer& pointer = mLastRawState.rawPointerData.pointers[i];
        dump += StringPrintf(INDENT4 "[%d]: id=%d, x=%d, y=%d, pressure=%d, "
                                     "touchMajor=%d, touchMinor=%d, toolMajor=%d, toolMinor=%d, "
                                     "orientation=%d, tiltX=%d, tiltY=%d, distance=%d, "
                                     "toolType=%s, isHovering=%s\n",
                             i, pointer.id, pointer.x, pointer.y, pointer.pressure,
                             pointer.touchMajor, pointer.touchMinor, pointer.toolMajor,
                             pointer.toolMinor, pointer.orientation, pointer.tiltX, pointer.tiltY,
                             pointer.distance, ftl::enum_string(pointer.toolType).c_str(),
                             toString(pointer.isHovering));
    }

    dump += StringPrintf(INDENT3 "Last Cooked Button State: 0x%08x\n",
                         mLastCookedState.buttonState);
    dump += StringPrintf(INDENT3 "Last Cooked Touch: pointerCount=%d\n",
                         mLastCookedState.cookedPointerData.pointerCount);
    for (uint32_t i = 0; i < mLastCookedState.cookedPointerData.pointerCount; i++) {
        const PointerProperties& pointerProperties =
                mLastCookedState.cookedPointerData.pointerProperties[i];
        const PointerCoords& pointerCoords = mLastCookedState.cookedPointerData.pointerCoords[i];
        dump += StringPrintf(INDENT4 "[%d]: id=%d, x=%0.3f, y=%0.3f, dx=%0.3f, dy=%0.3f, "
                                     "pressure=%0.3f, touchMajor=%0.3f, touchMinor=%0.3f, "
                                     "toolMajor=%0.3f, toolMinor=%0.3f, "
                                     "orientation=%0.3f, tilt=%0.3f, distance=%0.3f, "
                                     "toolType=%s, isHovering=%s\n",
                             i, pointerProperties.id, pointerCoords.getX(), pointerCoords.getY(),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TILT),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_DISTANCE),
                             ftl::enum_string(pointerProperties.toolType).c_str(),
                             toString(mLastCookedState.cookedPointerData.isHovering(i)));
    }

    dump += INDENT3 "Stylus Fusion:\n";
    dump += StringPrintf(INDENT4 "ExternalStylusConnected: %s\n",
                         toString(mExternalStylusConnected));
    dump += StringPrintf(INDENT4 "Fused External Stylus Pointer ID: %s\n",
                         toString(mFusedStylusPointerId).c_str());
    dump += StringPrintf(INDENT4 "External Stylus Data Timeout: %" PRId64 "\n",
                         mExternalStylusFusionTimeout);
    dump += StringPrintf(INDENT4 " External Stylus Buttons Applied: 0x%08x",
                         mExternalStylusButtonsApplied);
    dump += INDENT3 "External Stylus State:\n";
    dumpStylusState(dump, mExternalStylusState);

    if (mDeviceMode == DeviceMode::POINTER) {
        dump += StringPrintf(INDENT3 "Pointer Gesture Detector:\n");
        dump += StringPrintf(INDENT4 "XMovementScale: %0.3f\n", mPointerXMovementScale);
        dump += StringPrintf(INDENT4 "YMovementScale: %0.3f\n", mPointerYMovementScale);
        dump += StringPrintf(INDENT4 "XZoomScale: %0.3f\n", mPointerXZoomScale);
        dump += StringPrintf(INDENT4 "YZoomScale: %0.3f\n", mPointerYZoomScale);
        dump += StringPrintf(INDENT4 "MaxSwipeWidth: %f\n", mPointerGestureMaxSwipeWidth);
    }
}

std::list<NotifyArgs> TouchInputMapper::reconfigure(nsecs_t when,
                                                    const InputReaderConfiguration& config,
                                                    uint32_t changes) {
    std::list<NotifyArgs> out = InputMapper::reconfigure(when, config, changes);

    mConfig = config;

    // Full configuration should happen the first time configure is called and
    // when the device type is changed. Changing a device type can affect
    // various other parameters so should result in a reconfiguration.
    if (!changes || (changes & InputReaderConfiguration::CHANGE_DEVICE_TYPE)) {
        // Configure basic parameters.
        configureParameters();

        // Configure common accumulators.
        mCursorScrollAccumulator.configure(getDeviceContext());
        mTouchButtonAccumulator.configure();

        // Configure absolute axis information.
        configureRawPointerAxes();

        // Prepare input device calibration.
        parseCalibration();
        resolveCalibration();
    }

    if (!changes || (changes & InputReaderConfiguration::CHANGE_TOUCH_AFFINE_TRANSFORMATION)) {
        // Update location calibration to reflect current settings
        updateAffineTransformation();
    }

    if (!changes || (changes & InputReaderConfiguration::CHANGE_POINTER_SPEED)) {
        // Update pointer speed.
        mPointerVelocityControl.setParameters(mConfig.pointerVelocityControlParameters);
        mWheelXVelocityControl.setParameters(mConfig.wheelVelocityControlParameters);
        mWheelYVelocityControl.setParameters(mConfig.wheelVelocityControlParameters);
    }

    bool resetNeeded = false;
    if (!changes ||
        (changes &
         (InputReaderConfiguration::CHANGE_DISPLAY_INFO |
          InputReaderConfiguration::CHANGE_POINTER_CAPTURE |
          InputReaderConfiguration::CHANGE_POINTER_GESTURE_ENABLEMENT |
          InputReaderConfiguration::CHANGE_SHOW_TOUCHES |
          InputReaderConfiguration::CHANGE_EXTERNAL_STYLUS_PRESENCE |
          InputReaderConfiguration::CHANGE_DEVICE_TYPE))) {
        // Configure device sources, display dimensions, orientation and
        // scaling factors.
        configureInputDevice(when, &resetNeeded);
    }

    if (changes && resetNeeded) {
        out += reset(when);

        // Send reset, unless this is the first time the device has been configured,
        // in which case the reader will call reset itself after all mappers are ready.
        out.emplace_back(NotifyDeviceResetArgs(getContext()->getNextId(), when, getDeviceId()));
    }
    return out;
}

void TouchInputMapper::resolveExternalStylusPresence() {
    std::vector<InputDeviceInfo> devices;
    getContext()->getExternalStylusDevices(devices);
    mExternalStylusConnected = !devices.empty();

    if (!mExternalStylusConnected) {
        resetExternalStylus();
    }
}

void TouchInputMapper::configureParameters() {
    // Use the pointer presentation mode for devices that do not support distinct
    // multitouch.  The spot-based presentation relies on being able to accurately
    // locate two or more fingers on the touch pad.
    mParameters.gestureMode = getDeviceContext().hasInputProperty(INPUT_PROP_SEMI_MT)
            ? Parameters::GestureMode::SINGLE_TOUCH
            : Parameters::GestureMode::MULTI_TOUCH;

    const PropertyMap& config = getDeviceContext().getConfiguration();
    std::optional<std::string> gestureModeString = config.getString("touch.gestureMode");
    if (gestureModeString.has_value()) {
        if (*gestureModeString == "single-touch") {
            mParameters.gestureMode = Parameters::GestureMode::SINGLE_TOUCH;
        } else if (*gestureModeString == "multi-touch") {
            mParameters.gestureMode = Parameters::GestureMode::MULTI_TOUCH;
        } else if (*gestureModeString != "default") {
            ALOGW("Invalid value for touch.gestureMode: '%s'", gestureModeString->c_str());
        }
    }

    configureDeviceType();

    mParameters.hasButtonUnderPad = getDeviceContext().hasInputProperty(INPUT_PROP_BUTTONPAD);

    mParameters.orientationAware =
            config.getBool("touch.orientationAware")
                    .value_or(mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN);

    mParameters.orientation = ui::ROTATION_0;
    std::optional<std::string> orientationString = config.getString("touch.orientation");
    if (orientationString.has_value()) {
        if (mParameters.deviceType != Parameters::DeviceType::TOUCH_SCREEN) {
            ALOGW("The configuration 'touch.orientation' is only supported for touchscreens.");
        } else if (*orientationString == "ORIENTATION_90") {
            mParameters.orientation = ui::ROTATION_90;
        } else if (*orientationString == "ORIENTATION_180") {
            mParameters.orientation = ui::ROTATION_180;
        } else if (*orientationString == "ORIENTATION_270") {
            mParameters.orientation = ui::ROTATION_270;
        } else if (*orientationString != "ORIENTATION_0") {
            ALOGW("Invalid value for touch.orientation: '%s'", orientationString->c_str());
        }
    }

    mParameters.hasAssociatedDisplay = false;
    mParameters.associatedDisplayIsExternal = false;
    if (mParameters.orientationAware ||
        mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN ||
        mParameters.deviceType == Parameters::DeviceType::POINTER ||
        (mParameters.deviceType == Parameters::DeviceType::TOUCH_NAVIGATION &&
         getDeviceContext().getAssociatedViewport())) {
        mParameters.hasAssociatedDisplay = true;
        if (mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN) {
            mParameters.associatedDisplayIsExternal = getDeviceContext().isExternal();
            mParameters.uniqueDisplayId = config.getString("touch.displayId").value_or("").c_str();
        }
    }
    if (getDeviceContext().getAssociatedDisplayPort()) {
        mParameters.hasAssociatedDisplay = true;
    }

    // Initial downs on external touch devices should wake the device.
    // Normally we don't do this for internal touch screens to prevent them from waking
    // up in your pocket but you can enable it using the input device configuration.
    mParameters.wake = config.getBool("touch.wake").value_or(getDeviceContext().isExternal());

    std::optional<int32_t> usiVersionMajor = config.getInt("touch.usiVersionMajor");
    std::optional<int32_t> usiVersionMinor = config.getInt("touch.usiVersionMinor");
    if (usiVersionMajor.has_value() && usiVersionMinor.has_value()) {
        mParameters.usiVersion = {
                .majorVersion = *usiVersionMajor,
                .minorVersion = *usiVersionMinor,
        };
    }

    mParameters.enableForInactiveViewport =
            config.getBool("touch.enableForInactiveViewport").value_or(false);
}

void TouchInputMapper::configureDeviceType() {
    if (getDeviceContext().hasInputProperty(INPUT_PROP_DIRECT)) {
        // The device is a touch screen.
        mParameters.deviceType = Parameters::DeviceType::TOUCH_SCREEN;
    } else if (getDeviceContext().hasInputProperty(INPUT_PROP_POINTER)) {
        // The device is a pointing device like a track pad.
        mParameters.deviceType = Parameters::DeviceType::POINTER;
    } else {
        // The device is a touch pad of unknown purpose.
        mParameters.deviceType = Parameters::DeviceType::POINTER;
    }

    // Type association takes precedence over the device type found in the idc file.
    std::string deviceTypeString = getDeviceContext().getDeviceTypeAssociation().value_or("");
    if (deviceTypeString.empty()) {
        deviceTypeString =
                getDeviceContext().getConfiguration().getString("touch.deviceType").value_or("");
    }
    if (deviceTypeString == "touchScreen") {
        mParameters.deviceType = Parameters::DeviceType::TOUCH_SCREEN;
    } else if (deviceTypeString == "touchNavigation") {
        mParameters.deviceType = Parameters::DeviceType::TOUCH_NAVIGATION;
    } else if (deviceTypeString == "pointer") {
        mParameters.deviceType = Parameters::DeviceType::POINTER;
    } else if (deviceTypeString != "default" && deviceTypeString != "") {
        ALOGW("Invalid value for touch.deviceType: '%s'", deviceTypeString.c_str());
    }
}

void TouchInputMapper::dumpParameters(std::string& dump) {
    dump += INDENT3 "Parameters:\n";

    dump += INDENT4 "GestureMode: " + ftl::enum_string(mParameters.gestureMode) + "\n";

    dump += INDENT4 "DeviceType: " + ftl::enum_string(mParameters.deviceType) + "\n";

    dump += StringPrintf(INDENT4 "AssociatedDisplay: hasAssociatedDisplay=%s, isExternal=%s, "
                                 "displayId='%s'\n",
                         toString(mParameters.hasAssociatedDisplay),
                         toString(mParameters.associatedDisplayIsExternal),
                         mParameters.uniqueDisplayId.c_str());
    dump += StringPrintf(INDENT4 "OrientationAware: %s\n", toString(mParameters.orientationAware));
    dump += INDENT4 "Orientation: " + ftl::enum_string(mParameters.orientation) + "\n";
    dump += StringPrintf(INDENT4 "UsiVersion: %s\n",
                         toString(mParameters.usiVersion, toString).c_str());
    dump += StringPrintf(INDENT4 "EnableForInactiveViewport: %s\n",
                         toString(mParameters.enableForInactiveViewport));
}

void TouchInputMapper::configureRawPointerAxes() {
    mRawPointerAxes.clear();
}

void TouchInputMapper::dumpRawPointerAxes(std::string& dump) {
    dump += INDENT3 "Raw Touch Axes:\n";
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.x, "X");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.y, "Y");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.pressure, "Pressure");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.touchMajor, "TouchMajor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.touchMinor, "TouchMinor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.toolMajor, "ToolMajor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.toolMinor, "ToolMinor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.orientation, "Orientation");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.distance, "Distance");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.tiltX, "TiltX");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.tiltY, "TiltY");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.trackingId, "TrackingId");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.slot, "Slot");
}

bool TouchInputMapper::hasExternalStylus() const {
    return mExternalStylusConnected;
}

/**
 * Determine which DisplayViewport to use.
 * 1. If a device has associated display, get the matching viewport.
 * 2. Always use the suggested viewport from WindowManagerService for pointers.
 * 3. Get the matching viewport by either unique id in idc file or by the display type
 * (internal or external).
 * 4. Otherwise, use a non-display viewport.
 */
std::optional<DisplayViewport> TouchInputMapper::findViewport() {
    if (mParameters.hasAssociatedDisplay && mDeviceMode != DeviceMode::UNSCALED) {
        if (getDeviceContext().getAssociatedViewport()) {
            return getDeviceContext().getAssociatedViewport();
        }

        const std::optional<std::string> associatedDisplayUniqueId =
                getDeviceContext().getAssociatedDisplayUniqueId();
        if (associatedDisplayUniqueId) {
            return getDeviceContext().getAssociatedViewport();
        }

        if (mDeviceMode == DeviceMode::POINTER) {
            std::optional<DisplayViewport> viewport =
                    mConfig.getDisplayViewportById(mConfig.defaultPointerDisplayId);
            if (viewport) {
                return viewport;
            } else {
                ALOGW("Can't find designated display viewport with ID %" PRId32 " for pointers.",
                      mConfig.defaultPointerDisplayId);
            }
        }

        // Check if uniqueDisplayId is specified in idc file.
        if (!mParameters.uniqueDisplayId.empty()) {
            return mConfig.getDisplayViewportByUniqueId(mParameters.uniqueDisplayId);
        }

        ViewportType viewportTypeToUse;
        if (mParameters.associatedDisplayIsExternal) {
            viewportTypeToUse = ViewportType::EXTERNAL;
        } else {
            viewportTypeToUse = ViewportType::INTERNAL;
        }

        std::optional<DisplayViewport> viewport =
                mConfig.getDisplayViewportByType(viewportTypeToUse);
        if (!viewport && viewportTypeToUse == ViewportType::EXTERNAL) {
            ALOGW("Input device %s should be associated with external display, "
                  "fallback to internal one for the external viewport is not found.",
                  getDeviceName().c_str());
            viewport = mConfig.getDisplayViewportByType(ViewportType::INTERNAL);
        }

        return viewport;
    }

    // No associated display, return a non-display viewport.
    DisplayViewport newViewport;
    // Raw width and height in the natural orientation.
    int32_t rawWidth = mRawPointerAxes.getRawWidth();
    int32_t rawHeight = mRawPointerAxes.getRawHeight();
    newViewport.setNonDisplayViewport(rawWidth, rawHeight);
    return std::make_optional(newViewport);
}

int32_t TouchInputMapper::clampResolution(const char* axisName, int32_t resolution) const {
    if (resolution < 0) {
        ALOGE("Invalid %s resolution %" PRId32 " for device %s", axisName, resolution,
              getDeviceName().c_str());
        return 0;
    }
    return resolution;
}

void TouchInputMapper::initializeSizeRanges() {
    if (mCalibration.sizeCalibration == Calibration::SizeCalibration::NONE) {
        mSizeScale = 0.0f;
        return;
    }

    // Size of diagonal axis.
    const float diagonalSize = hypotf(mDisplayBounds.width, mDisplayBounds.height);

    // Size factors.
    if (mRawPointerAxes.touchMajor.valid && mRawPointerAxes.touchMajor.maxValue != 0) {
        mSizeScale = 1.0f / mRawPointerAxes.touchMajor.maxValue;
    } else if (mRawPointerAxes.toolMajor.valid && mRawPointerAxes.toolMajor.maxValue != 0) {
        mSizeScale = 1.0f / mRawPointerAxes.toolMajor.maxValue;
    } else {
        mSizeScale = 0.0f;
    }

    mOrientedRanges.touchMajor = InputDeviceInfo::MotionRange{
            .axis = AMOTION_EVENT_AXIS_TOUCH_MAJOR,
            .source = mSource,
            .min = 0,
            .max = diagonalSize,
            .flat = 0,
            .fuzz = 0,
            .resolution = 0,
    };

    if (mRawPointerAxes.touchMajor.valid) {
        mRawPointerAxes.touchMajor.resolution =
                clampResolution("touchMajor", mRawPointerAxes.touchMajor.resolution);
        mOrientedRanges.touchMajor->resolution = mRawPointerAxes.touchMajor.resolution;
    }

    mOrientedRanges.touchMinor = mOrientedRanges.touchMajor;
    mOrientedRanges.touchMinor->axis = AMOTION_EVENT_AXIS_TOUCH_MINOR;
    if (mRawPointerAxes.touchMinor.valid) {
        mRawPointerAxes.touchMinor.resolution =
                clampResolution("touchMinor", mRawPointerAxes.touchMinor.resolution);
        mOrientedRanges.touchMinor->resolution = mRawPointerAxes.touchMinor.resolution;
    }

    mOrientedRanges.toolMajor = InputDeviceInfo::MotionRange{
            .axis = AMOTION_EVENT_AXIS_TOOL_MAJOR,
            .source = mSource,
            .min = 0,
            .max = diagonalSize,
            .flat = 0,
            .fuzz = 0,
            .resolution = 0,
    };
    if (mRawPointerAxes.toolMajor.valid) {
        mRawPointerAxes.toolMajor.resolution =
                clampResolution("toolMajor", mRawPointerAxes.toolMajor.resolution);
        mOrientedRanges.toolMajor->resolution = mRawPointerAxes.toolMajor.resolution;
    }

    mOrientedRanges.toolMinor = mOrientedRanges.toolMajor;
    mOrientedRanges.toolMinor->axis = AMOTION_EVENT_AXIS_TOOL_MINOR;
    if (mRawPointerAxes.toolMinor.valid) {
        mRawPointerAxes.toolMinor.resolution =
                clampResolution("toolMinor", mRawPointerAxes.toolMinor.resolution);
        mOrientedRanges.toolMinor->resolution = mRawPointerAxes.toolMinor.resolution;
    }

    if (mCalibration.sizeCalibration == Calibration::SizeCalibration::GEOMETRIC) {
        mOrientedRanges.touchMajor->resolution *= mGeometricScale;
        mOrientedRanges.touchMinor->resolution *= mGeometricScale;
        mOrientedRanges.toolMajor->resolution *= mGeometricScale;
        mOrientedRanges.toolMinor->resolution *= mGeometricScale;
    } else {
        // Support for other calibrations can be added here.
        ALOGW("%s calibration is not supported for size ranges at the moment. "
              "Using raw resolution instead",
              ftl::enum_string(mCalibration.sizeCalibration).c_str());
    }

    mOrientedRanges.size = InputDeviceInfo::MotionRange{
            .axis = AMOTION_EVENT_AXIS_SIZE,
            .source = mSource,
            .min = 0,
            .max = 1.0,
            .flat = 0,
            .fuzz = 0,
            .resolution = 0,
    };
}

void TouchInputMapper::initializeOrientedRanges() {
    // Configure X and Y factors.
    const float orientedScaleX = mRawToDisplay.getScaleX();
    const float orientedScaleY = mRawToDisplay.getScaleY();
    mOrientedXPrecision = 1.0f / orientedScaleX;
    mOrientedYPrecision = 1.0f / orientedScaleY;

    mOrientedRanges.x.axis = AMOTION_EVENT_AXIS_X;
    mOrientedRanges.x.source = mSource;
    mOrientedRanges.y.axis = AMOTION_EVENT_AXIS_Y;
    mOrientedRanges.y.source = mSource;

    // Scale factor for terms that are not oriented in a particular axis.
    // If the pixels are square then xScale == yScale otherwise we fake it
    // by choosing an average.
    mGeometricScale = avg(orientedScaleX, orientedScaleY);

    initializeSizeRanges();

    // Pressure factors.
    mPressureScale = 0;
    float pressureMax = 1.0;
    if (mCalibration.pressureCalibration == Calibration::PressureCalibration::PHYSICAL ||
        mCalibration.pressureCalibration == Calibration::PressureCalibration::AMPLITUDE) {
        if (mCalibration.pressureScale) {
            mPressureScale = *mCalibration.pressureScale;
            pressureMax = mPressureScale * mRawPointerAxes.pressure.maxValue;
        } else if (mRawPointerAxes.pressure.valid && mRawPointerAxes.pressure.maxValue != 0) {
            mPressureScale = 1.0f / mRawPointerAxes.pressure.maxValue;
        }
    }

    mOrientedRanges.pressure = InputDeviceInfo::MotionRange{
            .axis = AMOTION_EVENT_AXIS_PRESSURE,
            .source = mSource,
            .min = 0,
            .max = pressureMax,
            .flat = 0,
            .fuzz = 0,
            .resolution = 0,
    };

    // Tilt
    mTiltXCenter = 0;
    mTiltXScale = 0;
    mTiltYCenter = 0;
    mTiltYScale = 0;
    mHaveTilt = mRawPointerAxes.tiltX.valid && mRawPointerAxes.tiltY.valid;
    if (mHaveTilt) {
        mTiltXCenter = avg(mRawPointerAxes.tiltX.minValue, mRawPointerAxes.tiltX.maxValue);
        mTiltYCenter = avg(mRawPointerAxes.tiltY.minValue, mRawPointerAxes.tiltY.maxValue);
        mTiltXScale = M_PI / 180;
        mTiltYScale = M_PI / 180;

        if (mRawPointerAxes.tiltX.resolution) {
            mTiltXScale = 1.0 / mRawPointerAxes.tiltX.resolution;
        }
        if (mRawPointerAxes.tiltY.resolution) {
            mTiltYScale = 1.0 / mRawPointerAxes.tiltY.resolution;
        }

        mOrientedRanges.tilt = InputDeviceInfo::MotionRange{
                .axis = AMOTION_EVENT_AXIS_TILT,
                .source = mSource,
                .min = 0,
                .max = M_PI_2,
                .flat = 0,
                .fuzz = 0,
                .resolution = 0,
        };
    }

    // Orientation
    mOrientationScale = 0;
    if (mHaveTilt) {
        mOrientedRanges.orientation = InputDeviceInfo::MotionRange{
                .axis = AMOTION_EVENT_AXIS_ORIENTATION,
                .source = mSource,
                .min = -M_PI,
                .max = M_PI,
                .flat = 0,
                .fuzz = 0,
                .resolution = 0,
        };

    } else if (mCalibration.orientationCalibration != Calibration::OrientationCalibration::NONE) {
        if (mCalibration.orientationCalibration ==
            Calibration::OrientationCalibration::INTERPOLATED) {
            if (mRawPointerAxes.orientation.valid) {
                if (mRawPointerAxes.orientation.maxValue > 0) {
                    mOrientationScale = M_PI_2 / mRawPointerAxes.orientation.maxValue;
                } else if (mRawPointerAxes.orientation.minValue < 0) {
                    mOrientationScale = -M_PI_2 / mRawPointerAxes.orientation.minValue;
                } else {
                    mOrientationScale = 0;
                }
            }
        }

        mOrientedRanges.orientation = InputDeviceInfo::MotionRange{
                .axis = AMOTION_EVENT_AXIS_ORIENTATION,
                .source = mSource,
                .min = -M_PI_2,
                .max = M_PI_2,
                .flat = 0,
                .fuzz = 0,
                .resolution = 0,
        };
    }

    // Distance
    mDistanceScale = 0;
    if (mCalibration.distanceCalibration != Calibration::DistanceCalibration::NONE) {
        if (mCalibration.distanceCalibration == Calibration::DistanceCalibration::SCALED) {
            mDistanceScale = mCalibration.distanceScale.value_or(1.0f);
        }

        mOrientedRanges.distance = InputDeviceInfo::MotionRange{

                .axis = AMOTION_EVENT_AXIS_DISTANCE,
                .source = mSource,
                .min = mRawPointerAxes.distance.minValue * mDistanceScale,
                .max = mRawPointerAxes.distance.maxValue * mDistanceScale,
                .flat = 0,
                .fuzz = mRawPointerAxes.distance.fuzz * mDistanceScale,
                .resolution = 0,
        };
    }

    // Oriented X/Y range (in the rotated display's orientation)
    const FloatRect rawFrame = Rect{mRawPointerAxes.x.minValue, mRawPointerAxes.y.minValue,
                                    mRawPointerAxes.x.maxValue, mRawPointerAxes.y.maxValue}
                                       .toFloatRect();
    const auto orientedRangeRect = mRawToRotatedDisplay.transform(rawFrame);
    mOrientedRanges.x.min = orientedRangeRect.left;
    mOrientedRanges.y.min = orientedRangeRect.top;
    mOrientedRanges.x.max = orientedRangeRect.right;
    mOrientedRanges.y.max = orientedRangeRect.bottom;

    // Oriented flat (in the rotated display's orientation)
    const auto orientedFlat =
            transformWithoutTranslation(mRawToRotatedDisplay,
                                        {static_cast<float>(mRawPointerAxes.x.flat),
                                         static_cast<float>(mRawPointerAxes.y.flat)});
    mOrientedRanges.x.flat = std::abs(orientedFlat.x);
    mOrientedRanges.y.flat = std::abs(orientedFlat.y);

    // Oriented fuzz (in the rotated display's orientation)
    const auto orientedFuzz =
            transformWithoutTranslation(mRawToRotatedDisplay,
                                        {static_cast<float>(mRawPointerAxes.x.fuzz),
                                         static_cast<float>(mRawPointerAxes.y.fuzz)});
    mOrientedRanges.x.fuzz = std::abs(orientedFuzz.x);
    mOrientedRanges.y.fuzz = std::abs(orientedFuzz.y);

    // Oriented resolution (in the rotated display's orientation)
    const auto orientedRes =
            transformWithoutTranslation(mRawToRotatedDisplay,
                                        {static_cast<float>(mRawPointerAxes.x.resolution),
                                         static_cast<float>(mRawPointerAxes.y.resolution)});
    mOrientedRanges.x.resolution = std::abs(orientedRes.x);
    mOrientedRanges.y.resolution = std::abs(orientedRes.y);
}

void TouchInputMapper::computeInputTransforms() {
    constexpr auto isRotated = [](const ui::Transform::RotationFlags& rotation) {
        return rotation == ui::Transform::ROT_90 || rotation == ui::Transform::ROT_270;
    };

    // See notes about input coordinates in the inputflinger docs:
    // //frameworks/native/services/inputflinger/docs/input_coordinates.md

    // Step 1: Undo the raw offset so that the raw coordinate space now starts at (0, 0).
    ui::Transform undoOffsetInRaw;
    undoOffsetInRaw.set(-mRawPointerAxes.x.minValue, -mRawPointerAxes.y.minValue);

    // Step 2: Rotate the raw coordinates to account for input device orientation. The coordinates
    // will now be in the same orientation as the display in ROTATION_0.
    // Note: Negating an ui::Rotation value will give its inverse rotation.
    const auto inputDeviceOrientation = ui::Transform::toRotationFlags(-mParameters.orientation);
    const ui::Size orientedRawSize = isRotated(inputDeviceOrientation)
            ? ui::Size{mRawPointerAxes.getRawHeight(), mRawPointerAxes.getRawWidth()}
            : ui::Size{mRawPointerAxes.getRawWidth(), mRawPointerAxes.getRawHeight()};
    // When rotating raw values, account for the extra unit added when calculating the raw range.
    const auto orientInRaw = ui::Transform(inputDeviceOrientation, orientedRawSize.width - 1,
                                           orientedRawSize.height - 1);

    // Step 3: Rotate the raw coordinates to account for the display rotation. The coordinates will
    // now be in the same orientation as the rotated display. There is no need to rotate the
    // coordinates to the display rotation if the device is not orientation-aware.
    const auto viewportRotation = ui::Transform::toRotationFlags(-mViewport.orientation);
    const auto rotatedRawSize = mParameters.orientationAware && isRotated(viewportRotation)
            ? ui::Size{orientedRawSize.height, orientedRawSize.width}
            : orientedRawSize;
    // When rotating raw values, account for the extra unit added when calculating the raw range.
    const auto rotateInRaw = mParameters.orientationAware
            ? ui::Transform(viewportRotation, rotatedRawSize.width - 1, rotatedRawSize.height - 1)
            : ui::Transform();

    // Step 4: Scale the raw coordinates to the display space.
    // - In DIRECT mode, we assume that the raw surface of the touch device maps perfectly to
    //   the surface of the display panel. This is usually true for touchscreens.
    // - In POINTER mode, we cannot assume that the display and the touch device have the same
    //   aspect ratio, since it is likely to be untrue for devices like external drawing tablets.
    //   In this case, we used a fixed scale so that 1) we use the same scale across both the x and
    //   y axes to ensure the mapping does not stretch gestures, and 2) the entire region of the
    //   display can be reached by the touch device.
    // - From this point onward, we are no longer in the discrete space of the raw coordinates but
    //   are in the continuous space of the logical display.
    ui::Transform scaleRawToDisplay;
    const float xScale = static_cast<float>(mViewport.deviceWidth) / rotatedRawSize.width;
    const float yScale = static_cast<float>(mViewport.deviceHeight) / rotatedRawSize.height;
    if (mDeviceMode == DeviceMode::DIRECT) {
        scaleRawToDisplay.set(xScale, 0, 0, yScale);
    } else if (mDeviceMode == DeviceMode::POINTER) {
        const float fixedScale = std::max(xScale, yScale);
        scaleRawToDisplay.set(fixedScale, 0, 0, fixedScale);
    } else {
        LOG_ALWAYS_FATAL("computeInputTransform can only be used for DIRECT and POINTER modes");
    }

    // Step 5: Undo the display rotation to bring us back to the un-rotated display coordinate space
    // that InputReader uses.
    const auto undoRotateInDisplay =
            ui::Transform(viewportRotation, mViewport.deviceWidth, mViewport.deviceHeight)
                    .inverse();

    // Now put it all together!
    mRawToRotatedDisplay = (scaleRawToDisplay * (rotateInRaw * (orientInRaw * undoOffsetInRaw)));
    mRawToDisplay = (undoRotateInDisplay * mRawToRotatedDisplay);
    mRawRotation = ui::Transform{mRawToDisplay.getOrientation()};
}

void TouchInputMapper::configureInputDevice(nsecs_t when, bool* outResetNeeded) {
    const DeviceMode oldDeviceMode = mDeviceMode;

    resolveExternalStylusPresence();

    // Determine device mode.
    if (mParameters.deviceType == Parameters::DeviceType::POINTER &&
        mConfig.pointerGesturesEnabled && !mConfig.pointerCaptureRequest.enable) {
        mSource = AINPUT_SOURCE_MOUSE;
        mDeviceMode = DeviceMode::POINTER;
        if (hasStylus()) {
            mSource |= AINPUT_SOURCE_STYLUS;
        }
    } else if (isTouchScreen()) {
        mSource = AINPUT_SOURCE_TOUCHSCREEN;
        mDeviceMode = DeviceMode::DIRECT;
        if (hasStylus()) {
            mSource |= AINPUT_SOURCE_STYLUS;
        }
        if (hasExternalStylus()) {
            mSource |= AINPUT_SOURCE_BLUETOOTH_STYLUS;
        }
    } else if (mParameters.deviceType == Parameters::DeviceType::TOUCH_NAVIGATION) {
        mSource = AINPUT_SOURCE_TOUCH_NAVIGATION;
        mDeviceMode = DeviceMode::NAVIGATION;
    } else {
        mSource = AINPUT_SOURCE_TOUCHPAD;
        mDeviceMode = DeviceMode::UNSCALED;
    }

    const std::optional<DisplayViewport> newViewportOpt = findViewport();

    // Ensure the device is valid and can be used.
    if (!mRawPointerAxes.x.valid || !mRawPointerAxes.y.valid) {
        ALOGW("Touch device '%s' did not report support for X or Y axis!  "
              "The device will be inoperable.",
              getDeviceName().c_str());
        mDeviceMode = DeviceMode::DISABLED;
    } else if (!newViewportOpt) {
        ALOGI("Touch device '%s' could not query the properties of its associated "
              "display.  The device will be inoperable until the display size "
              "becomes available.",
              getDeviceName().c_str());
        mDeviceMode = DeviceMode::DISABLED;
    } else if (!mParameters.enableForInactiveViewport && !newViewportOpt->isActive) {
        ALOGI("Disabling %s (device %i) because the associated viewport is not active",
              getDeviceName().c_str(), getDeviceId());
        mDeviceMode = DeviceMode::DISABLED;
    }

    // Raw width and height in the natural orientation.
    const ui::Size rawSize{mRawPointerAxes.getRawWidth(), mRawPointerAxes.getRawHeight()};
    const int32_t rawXResolution = mRawPointerAxes.x.resolution;
    const int32_t rawYResolution = mRawPointerAxes.y.resolution;
    // Calculate the mean resolution when both x and y resolution are set, otherwise set it to 0.
    const float rawMeanResolution =
            (rawXResolution > 0 && rawYResolution > 0) ? (rawXResolution + rawYResolution) / 2 : 0;

    const DisplayViewport& newViewport = newViewportOpt.value_or(kUninitializedViewport);
    const bool viewportChanged = mViewport != newViewport;
    bool skipViewportUpdate = false;
    if (viewportChanged) {
        const bool viewportOrientationChanged = mViewport.orientation != newViewport.orientation;
        const bool viewportDisplayIdChanged = mViewport.displayId != newViewport.displayId;
        mViewport = newViewport;

        if (mDeviceMode == DeviceMode::DIRECT || mDeviceMode == DeviceMode::POINTER) {
            const auto oldDisplayBounds = mDisplayBounds;

            mDisplayBounds = getNaturalDisplaySize(mViewport);
            mPhysicalFrameInRotatedDisplay = {mViewport.physicalLeft, mViewport.physicalTop,
                                              mViewport.physicalRight, mViewport.physicalBottom};

            // TODO(b/257118693): Remove the dependence on the old orientation/rotation logic that
            //     uses mInputDeviceOrientation. The new logic uses the transforms calculated in
            //     computeInputTransforms().
            // InputReader works in the un-rotated display coordinate space, so we don't need to do
            // anything if the device is already orientation-aware. If the device is not
            // orientation-aware, then we need to apply the inverse rotation of the display so that
            // when the display rotation is applied later as a part of the per-window transform, we
            // get the expected screen coordinates.
            mInputDeviceOrientation = mParameters.orientationAware
                    ? ui::ROTATION_0
                    : getInverseRotation(mViewport.orientation);
            // For orientation-aware devices that work in the un-rotated coordinate space, the
            // viewport update should be skipped if it is only a change in the orientation.
            skipViewportUpdate = !viewportDisplayIdChanged && mParameters.orientationAware &&
                    mDisplayBounds == oldDisplayBounds && viewportOrientationChanged;

            // Apply the input device orientation for the device.
            mInputDeviceOrientation = mInputDeviceOrientation + mParameters.orientation;
            computeInputTransforms();
        } else {
            mDisplayBounds = rawSize;
            mPhysicalFrameInRotatedDisplay = Rect{mDisplayBounds};
            mInputDeviceOrientation = ui::ROTATION_0;
            mRawToDisplay.reset();
            mRawToDisplay.set(-mRawPointerAxes.x.minValue, -mRawPointerAxes.y.minValue);
            mRawToRotatedDisplay = mRawToDisplay;
        }
    }

    // If moving between pointer modes, need to reset some state.
    bool deviceModeChanged = mDeviceMode != oldDeviceMode;
    if (deviceModeChanged) {
        mOrientedRanges.clear();
    }

    // Create and preserve the pointer controller in the following cases:
    const bool isPointerControllerNeeded =
            // - when the device is in pointer mode, to show the mouse cursor;
            (mDeviceMode == DeviceMode::POINTER) ||
            // - when pointer capture is enabled, to preserve the mouse cursor position;
            (mParameters.deviceType == Parameters::DeviceType::POINTER &&
             mConfig.pointerCaptureRequest.enable) ||
            // - when we should be showing touches;
            (mDeviceMode == DeviceMode::DIRECT && mConfig.showTouches) ||
            // - when we should be showing a pointer icon for direct styluses.
            (mDeviceMode == DeviceMode::DIRECT && mConfig.stylusPointerIconEnabled && hasStylus());
    if (isPointerControllerNeeded) {
        if (mPointerController == nullptr) {
            mPointerController = getContext()->getPointerController(getDeviceId());
        }
        if (mConfig.pointerCaptureRequest.enable) {
            mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
        }
    } else {
        if (mPointerController != nullptr && mDeviceMode == DeviceMode::DIRECT &&
            !mConfig.showTouches) {
            mPointerController->clearSpots();
        }
        mPointerController.reset();
    }

    if ((viewportChanged && !skipViewportUpdate) || deviceModeChanged) {
        ALOGI("Device reconfigured: id=%d, name='%s', size %s, orientation %d, mode %d, "
              "display id %d",
              getDeviceId(), getDeviceName().c_str(), toString(mDisplayBounds).c_str(),
              mInputDeviceOrientation, mDeviceMode, mViewport.displayId);

        configureVirtualKeys();

        initializeOrientedRanges();

        // Location
        updateAffineTransformation();

        if (mDeviceMode == DeviceMode::POINTER) {
            // Compute pointer gesture detection parameters.
            float rawDiagonal = hypotf(rawSize.width, rawSize.height);
            float displayDiagonal = hypotf(mDisplayBounds.width, mDisplayBounds.height);

            // Scale movements such that one whole swipe of the touch pad covers a
            // given area relative to the diagonal size of the display when no acceleration
            // is applied.
            // Assume that the touch pad has a square aspect ratio such that movements in
            // X and Y of the same number of raw units cover the same physical distance.
            mPointerXMovementScale =
                    mConfig.pointerGestureMovementSpeedRatio * displayDiagonal / rawDiagonal;
            mPointerYMovementScale = mPointerXMovementScale;

            // Scale zooms to cover a smaller range of the display than movements do.
            // This value determines the area around the pointer that is affected by freeform
            // pointer gestures.
            mPointerXZoomScale =
                    mConfig.pointerGestureZoomSpeedRatio * displayDiagonal / rawDiagonal;
            mPointerYZoomScale = mPointerXZoomScale;

            // Calculate the min freeform gesture width. It will be 0 when the resolution of any
            // axis is non positive value.
            const float minFreeformGestureWidth =
                    rawMeanResolution * MIN_FREEFORM_GESTURE_WIDTH_IN_MILLIMETER;

            mPointerGestureMaxSwipeWidth =
                    std::max(mConfig.pointerGestureSwipeMaxWidthRatio * rawDiagonal,
                             minFreeformGestureWidth);
        }

        // Inform the dispatcher about the changes.
        *outResetNeeded = true;
        bumpGeneration();
    }
}

void TouchInputMapper::dumpDisplay(std::string& dump) {
    dump += StringPrintf(INDENT3 "%s\n", mViewport.toString().c_str());
    dump += StringPrintf(INDENT3 "DisplayBounds: %s\n", toString(mDisplayBounds).c_str());
    dump += StringPrintf(INDENT3 "PhysicalFrameInRotatedDisplay: %s\n",
                         toString(mPhysicalFrameInRotatedDisplay).c_str());
    dump += StringPrintf(INDENT3 "InputDeviceOrientation: %d\n", mInputDeviceOrientation);
}

void TouchInputMapper::configureVirtualKeys() {
    std::vector<VirtualKeyDefinition> virtualKeyDefinitions;
    getDeviceContext().getVirtualKeyDefinitions(virtualKeyDefinitions);

    mVirtualKeys.clear();

    if (virtualKeyDefinitions.size() == 0) {
        return;
    }

    int32_t touchScreenLeft = mRawPointerAxes.x.minValue;
    int32_t touchScreenTop = mRawPointerAxes.y.minValue;
    int32_t touchScreenWidth = mRawPointerAxes.getRawWidth();
    int32_t touchScreenHeight = mRawPointerAxes.getRawHeight();

    for (const VirtualKeyDefinition& virtualKeyDefinition : virtualKeyDefinitions) {
        VirtualKey virtualKey;

        virtualKey.scanCode = virtualKeyDefinition.scanCode;
        int32_t keyCode;
        int32_t dummyKeyMetaState;
        uint32_t flags;
        if (getDeviceContext().mapKey(virtualKey.scanCode, 0, 0, &keyCode, &dummyKeyMetaState,
                                      &flags)) {
            ALOGW(INDENT "VirtualKey %d: could not obtain key code, ignoring", virtualKey.scanCode);
            continue; // drop the key
        }

        virtualKey.keyCode = keyCode;
        virtualKey.flags = flags;

        // convert the key definition's display coordinates into touch coordinates for a hit box
        int32_t halfWidth = virtualKeyDefinition.width / 2;
        int32_t halfHeight = virtualKeyDefinition.height / 2;

        virtualKey.hitLeft = (virtualKeyDefinition.centerX - halfWidth) * touchScreenWidth /
                        mDisplayBounds.width +
                touchScreenLeft;
        virtualKey.hitRight = (virtualKeyDefinition.centerX + halfWidth) * touchScreenWidth /
                        mDisplayBounds.width +
                touchScreenLeft;
        virtualKey.hitTop = (virtualKeyDefinition.centerY - halfHeight) * touchScreenHeight /
                        mDisplayBounds.height +
                touchScreenTop;
        virtualKey.hitBottom = (virtualKeyDefinition.centerY + halfHeight) * touchScreenHeight /
                        mDisplayBounds.height +
                touchScreenTop;
        mVirtualKeys.push_back(virtualKey);
    }
}

void TouchInputMapper::dumpVirtualKeys(std::string& dump) {
    if (!mVirtualKeys.empty()) {
        dump += INDENT3 "Virtual Keys:\n";

        for (size_t i = 0; i < mVirtualKeys.size(); i++) {
            const VirtualKey& virtualKey = mVirtualKeys[i];
            dump += StringPrintf(INDENT4 "%zu: scanCode=%d, keyCode=%d, "
                                         "hitLeft=%d, hitRight=%d, hitTop=%d, hitBottom=%d\n",
                                 i, virtualKey.scanCode, virtualKey.keyCode, virtualKey.hitLeft,
                                 virtualKey.hitRight, virtualKey.hitTop, virtualKey.hitBottom);
        }
    }
}

void TouchInputMapper::parseCalibration() {
    const PropertyMap& in = getDeviceContext().getConfiguration();
    Calibration& out = mCalibration;

    // Size
    out.sizeCalibration = Calibration::SizeCalibration::DEFAULT;
    std::optional<std::string> sizeCalibrationString = in.getString("touch.size.calibration");
    if (sizeCalibrationString.has_value()) {
        if (*sizeCalibrationString == "none") {
            out.sizeCalibration = Calibration::SizeCalibration::NONE;
        } else if (*sizeCalibrationString == "geometric") {
            out.sizeCalibration = Calibration::SizeCalibration::GEOMETRIC;
        } else if (*sizeCalibrationString == "diameter") {
            out.sizeCalibration = Calibration::SizeCalibration::DIAMETER;
        } else if (*sizeCalibrationString == "box") {
            out.sizeCalibration = Calibration::SizeCalibration::BOX;
        } else if (*sizeCalibrationString == "area") {
            out.sizeCalibration = Calibration::SizeCalibration::AREA;
        } else if (*sizeCalibrationString != "default") {
            ALOGW("Invalid value for touch.size.calibration: '%s'", sizeCalibrationString->c_str());
        }
    }

    out.sizeScale = in.getFloat("touch.size.scale");
    out.sizeBias = in.getFloat("touch.size.bias");
    out.sizeIsSummed = in.getBool("touch.size.isSummed");

    // Pressure
    out.pressureCalibration = Calibration::PressureCalibration::DEFAULT;
    std::optional<std::string> pressureCalibrationString =
            in.getString("touch.pressure.calibration");
    if (pressureCalibrationString.has_value()) {
        if (*pressureCalibrationString == "none") {
            out.pressureCalibration = Calibration::PressureCalibration::NONE;
        } else if (*pressureCalibrationString == "physical") {
            out.pressureCalibration = Calibration::PressureCalibration::PHYSICAL;
        } else if (*pressureCalibrationString == "amplitude") {
            out.pressureCalibration = Calibration::PressureCalibration::AMPLITUDE;
        } else if (*pressureCalibrationString != "default") {
            ALOGW("Invalid value for touch.pressure.calibration: '%s'",
                  pressureCalibrationString->c_str());
        }
    }

    out.pressureScale = in.getFloat("touch.pressure.scale");

    // Orientation
    out.orientationCalibration = Calibration::OrientationCalibration::DEFAULT;
    std::optional<std::string> orientationCalibrationString =
            in.getString("touch.orientation.calibration");
    if (orientationCalibrationString.has_value()) {
        if (*orientationCalibrationString == "none") {
            out.orientationCalibration = Calibration::OrientationCalibration::NONE;
        } else if (*orientationCalibrationString == "interpolated") {
            out.orientationCalibration = Calibration::OrientationCalibration::INTERPOLATED;
        } else if (*orientationCalibrationString == "vector") {
            out.orientationCalibration = Calibration::OrientationCalibration::VECTOR;
        } else if (*orientationCalibrationString != "default") {
            ALOGW("Invalid value for touch.orientation.calibration: '%s'",
                  orientationCalibrationString->c_str());
        }
    }

    // Distance
    out.distanceCalibration = Calibration::DistanceCalibration::DEFAULT;
    std::optional<std::string> distanceCalibrationString =
            in.getString("touch.distance.calibration");
    if (distanceCalibrationString.has_value()) {
        if (*distanceCalibrationString == "none") {
            out.distanceCalibration = Calibration::DistanceCalibration::NONE;
        } else if (*distanceCalibrationString == "scaled") {
            out.distanceCalibration = Calibration::DistanceCalibration::SCALED;
        } else if (*distanceCalibrationString != "default") {
            ALOGW("Invalid value for touch.distance.calibration: '%s'",
                  distanceCalibrationString->c_str());
        }
    }

    out.distanceScale = in.getFloat("touch.distance.scale");
}

void TouchInputMapper::resolveCalibration() {
    // Size
    if (mRawPointerAxes.touchMajor.valid || mRawPointerAxes.toolMajor.valid) {
        if (mCalibration.sizeCalibration == Calibration::SizeCalibration::DEFAULT) {
            mCalibration.sizeCalibration = Calibration::SizeCalibration::GEOMETRIC;
        }
    } else {
        mCalibration.sizeCalibration = Calibration::SizeCalibration::NONE;
    }

    // Pressure
    if (mRawPointerAxes.pressure.valid) {
        if (mCalibration.pressureCalibration == Calibration::PressureCalibration::DEFAULT) {
            mCalibration.pressureCalibration = Calibration::PressureCalibration::PHYSICAL;
        }
    } else {
        mCalibration.pressureCalibration = Calibration::PressureCalibration::NONE;
    }

    // Orientation
    if (mRawPointerAxes.orientation.valid) {
        if (mCalibration.orientationCalibration == Calibration::OrientationCalibration::DEFAULT) {
            mCalibration.orientationCalibration = Calibration::OrientationCalibration::INTERPOLATED;
        }
    } else {
        mCalibration.orientationCalibration = Calibration::OrientationCalibration::NONE;
    }

    // Distance
    if (mRawPointerAxes.distance.valid) {
        if (mCalibration.distanceCalibration == Calibration::DistanceCalibration::DEFAULT) {
            mCalibration.distanceCalibration = Calibration::DistanceCalibration::SCALED;
        }
    } else {
        mCalibration.distanceCalibration = Calibration::DistanceCalibration::NONE;
    }
}

void TouchInputMapper::dumpCalibration(std::string& dump) {
    dump += INDENT3 "Calibration:\n";

    dump += INDENT4 "touch.size.calibration: ";
    dump += ftl::enum_string(mCalibration.sizeCalibration) + "\n";

    if (mCalibration.sizeScale) {
        dump += StringPrintf(INDENT4 "touch.size.scale: %0.3f\n", *mCalibration.sizeScale);
    }

    if (mCalibration.sizeBias) {
        dump += StringPrintf(INDENT4 "touch.size.bias: %0.3f\n", *mCalibration.sizeBias);
    }

    if (mCalibration.sizeIsSummed) {
        dump += StringPrintf(INDENT4 "touch.size.isSummed: %s\n",
                             toString(*mCalibration.sizeIsSummed));
    }

    // Pressure
    switch (mCalibration.pressureCalibration) {
        case Calibration::PressureCalibration::NONE:
            dump += INDENT4 "touch.pressure.calibration: none\n";
            break;
        case Calibration::PressureCalibration::PHYSICAL:
            dump += INDENT4 "touch.pressure.calibration: physical\n";
            break;
        case Calibration::PressureCalibration::AMPLITUDE:
            dump += INDENT4 "touch.pressure.calibration: amplitude\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    if (mCalibration.pressureScale) {
        dump += StringPrintf(INDENT4 "touch.pressure.scale: %0.3f\n", *mCalibration.pressureScale);
    }

    // Orientation
    switch (mCalibration.orientationCalibration) {
        case Calibration::OrientationCalibration::NONE:
            dump += INDENT4 "touch.orientation.calibration: none\n";
            break;
        case Calibration::OrientationCalibration::INTERPOLATED:
            dump += INDENT4 "touch.orientation.calibration: interpolated\n";
            break;
        case Calibration::OrientationCalibration::VECTOR:
            dump += INDENT4 "touch.orientation.calibration: vector\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    // Distance
    switch (mCalibration.distanceCalibration) {
        case Calibration::DistanceCalibration::NONE:
            dump += INDENT4 "touch.distance.calibration: none\n";
            break;
        case Calibration::DistanceCalibration::SCALED:
            dump += INDENT4 "touch.distance.calibration: scaled\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    if (mCalibration.distanceScale) {
        dump += StringPrintf(INDENT4 "touch.distance.scale: %0.3f\n", *mCalibration.distanceScale);
    }
}

void TouchInputMapper::dumpAffineTransformation(std::string& dump) {
    dump += INDENT3 "Affine Transformation:\n";

    dump += StringPrintf(INDENT4 "X scale: %0.3f\n", mAffineTransform.x_scale);
    dump += StringPrintf(INDENT4 "X ymix: %0.3f\n", mAffineTransform.x_ymix);
    dump += StringPrintf(INDENT4 "X offset: %0.3f\n", mAffineTransform.x_offset);
    dump += StringPrintf(INDENT4 "Y xmix: %0.3f\n", mAffineTransform.y_xmix);
    dump += StringPrintf(INDENT4 "Y scale: %0.3f\n", mAffineTransform.y_scale);
    dump += StringPrintf(INDENT4 "Y offset: %0.3f\n", mAffineTransform.y_offset);
}

void TouchInputMapper::updateAffineTransformation() {
    mAffineTransform = getPolicy()->getTouchAffineTransformation(getDeviceContext().getDescriptor(),
                                                                 mInputDeviceOrientation);
}

std::list<NotifyArgs> TouchInputMapper::reset(nsecs_t when) {
    std::list<NotifyArgs> out = cancelTouch(when, when);
    updateTouchSpots();

    mCursorButtonAccumulator.reset(getDeviceContext());
    mCursorScrollAccumulator.reset(getDeviceContext());
    mTouchButtonAccumulator.reset();

    mPointerVelocityControl.reset();
    mWheelXVelocityControl.reset();
    mWheelYVelocityControl.reset();

    mRawStatesPending.clear();
    mCurrentRawState.clear();
    mCurrentCookedState.clear();
    mLastRawState.clear();
    mLastCookedState.clear();
    mPointerUsage = PointerUsage::NONE;
    mSentHoverEnter = false;
    mHavePointerIds = false;
    mCurrentMotionAborted = false;
    mDownTime = 0;

    mCurrentVirtualKey.down = false;

    mPointerGesture.reset();
    mPointerSimple.reset();
    resetExternalStylus();

    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
        mPointerController->clearSpots();
    }

    return out += InputMapper::reset(when);
}

void TouchInputMapper::resetExternalStylus() {
    mExternalStylusState.clear();
    mFusedStylusPointerId.reset();
    mExternalStylusFusionTimeout = LLONG_MAX;
    mExternalStylusDataPending = false;
    mExternalStylusButtonsApplied = 0;
}

void TouchInputMapper::clearStylusDataPendingFlags() {
    mExternalStylusDataPending = false;
    mExternalStylusFusionTimeout = LLONG_MAX;
}

std::list<NotifyArgs> TouchInputMapper::process(const RawEvent* rawEvent) {
    mCursorButtonAccumulator.process(rawEvent);
    mCursorScrollAccumulator.process(rawEvent);
    mTouchButtonAccumulator.process(rawEvent);

    std::list<NotifyArgs> out;
    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        out += sync(rawEvent->when, rawEvent->readTime);
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::sync(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    if (mDeviceMode == DeviceMode::DISABLED) {
        // Only save the last pending state when the device is disabled.
        mRawStatesPending.clear();
    }
    // Push a new state.
    mRawStatesPending.emplace_back();

    RawState& next = mRawStatesPending.back();
    next.clear();
    next.when = when;
    next.readTime = readTime;

    // Sync button state.
    next.buttonState = filterButtonState(mConfig,
                                         mTouchButtonAccumulator.getButtonState() |
                                                 mCursorButtonAccumulator.getButtonState());

    // Sync scroll
    next.rawVScroll = mCursorScrollAccumulator.getRelativeVWheel();
    next.rawHScroll = mCursorScrollAccumulator.getRelativeHWheel();
    mCursorScrollAccumulator.finishSync();

    // Sync touch
    syncTouch(when, &next);

    // The last RawState is the actually second to last, since we just added a new state
    const RawState& last =
            mRawStatesPending.size() == 1 ? mCurrentRawState : mRawStatesPending.rbegin()[1];

    std::tie(next.when, next.readTime) =
            applyBluetoothTimestampSmoothening(getDeviceContext().getDeviceIdentifier(), when,
                                               readTime, last.when);

    // Assign pointer ids.
    if (!mHavePointerIds) {
        assignPointerIds(last, next);
    }

    ALOGD_IF(debugRawEvents(),
             "syncTouch: pointerCount %d -> %d, touching ids 0x%08x -> 0x%08x, "
             "hovering ids 0x%08x -> 0x%08x, canceled ids 0x%08x",
             last.rawPointerData.pointerCount, next.rawPointerData.pointerCount,
             last.rawPointerData.touchingIdBits.value, next.rawPointerData.touchingIdBits.value,
             last.rawPointerData.hoveringIdBits.value, next.rawPointerData.hoveringIdBits.value,
             next.rawPointerData.canceledIdBits.value);

    if (!next.rawPointerData.touchingIdBits.isEmpty() &&
        !next.rawPointerData.hoveringIdBits.isEmpty() &&
        last.rawPointerData.hoveringIdBits != next.rawPointerData.hoveringIdBits) {
        ALOGI("Multi-touch contains some hovering ids 0x%08x",
              next.rawPointerData.hoveringIdBits.value);
    }

    out += processRawTouches(/*timeout=*/false);
    return out;
}

std::list<NotifyArgs> TouchInputMapper::processRawTouches(bool timeout) {
    std::list<NotifyArgs> out;
    if (mDeviceMode == DeviceMode::DISABLED) {
        // Do not process raw event while the device is disabled.
        return out;
    }

    // Drain any pending touch states. The invariant here is that the mCurrentRawState is always
    // valid and must go through the full cook and dispatch cycle. This ensures that anything
    // touching the current state will only observe the events that have been dispatched to the
    // rest of the pipeline.
    const size_t N = mRawStatesPending.size();
    size_t count;
    for (count = 0; count < N; count++) {
        const RawState& next = mRawStatesPending[count];

        // A failure to assign the stylus id means that we're waiting on stylus data
        // and so should defer the rest of the pipeline.
        if (assignExternalStylusId(next, timeout)) {
            break;
        }

        // All ready to go.
        clearStylusDataPendingFlags();
        mCurrentRawState = next;
        if (mCurrentRawState.when < mLastRawState.when) {
            mCurrentRawState.when = mLastRawState.when;
            mCurrentRawState.readTime = mLastRawState.readTime;
        }
        out += cookAndDispatch(mCurrentRawState.when, mCurrentRawState.readTime);
    }
    if (count != 0) {
        mRawStatesPending.erase(mRawStatesPending.begin(), mRawStatesPending.begin() + count);
    }

    if (mExternalStylusDataPending) {
        if (timeout) {
            nsecs_t when = mExternalStylusFusionTimeout - STYLUS_DATA_LATENCY;
            clearStylusDataPendingFlags();
            mCurrentRawState = mLastRawState;
            ALOGD_IF(DEBUG_STYLUS_FUSION,
                     "Timeout expired, synthesizing event with new stylus data");
            const nsecs_t readTime = when; // consider this synthetic event to be zero latency
            out += cookAndDispatch(when, readTime);
        } else if (mExternalStylusFusionTimeout == LLONG_MAX) {
            mExternalStylusFusionTimeout = mExternalStylusState.when + TOUCH_DATA_TIMEOUT;
            getContext()->requestTimeoutAtTime(mExternalStylusFusionTimeout);
        }
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::cookAndDispatch(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    // Always start with a clean state.
    mCurrentCookedState.clear();

    // Apply stylus buttons to current raw state.
    applyExternalStylusButtonState(when);

    // Handle policy on initial down or hover events.
    bool initialDown = mLastRawState.rawPointerData.pointerCount == 0 &&
            mCurrentRawState.rawPointerData.pointerCount != 0;

    uint32_t policyFlags = 0;
    bool buttonsPressed = mCurrentRawState.buttonState & ~mLastRawState.buttonState;
    if (initialDown || buttonsPressed) {
        // If this is a touch screen, hide the pointer on an initial down.
        if (mDeviceMode == DeviceMode::DIRECT) {
            getContext()->fadePointer();
        }

        if (mParameters.wake) {
            policyFlags |= POLICY_FLAG_WAKE;
        }
    }

    // Consume raw off-screen touches before cooking pointer data.
    // If touches are consumed, subsequent code will not receive any pointer data.
    bool consumed;
    out += consumeRawTouches(when, readTime, policyFlags, consumed /*byref*/);
    if (consumed) {
        mCurrentRawState.rawPointerData.clear();
    }

    // Cook pointer data.  This call populates the mCurrentCookedState.cookedPointerData structure
    // with cooked pointer data that has the same ids and indices as the raw data.
    // The following code can use either the raw or cooked data, as needed.
    cookPointerData();

    // Apply stylus pressure to current cooked state.
    applyExternalStylusTouchState(when);

    // Synthesize key down from raw buttons if needed.
    out += synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_DOWN, when, readTime, getDeviceId(),
                                mSource, mViewport.displayId, policyFlags,
                                mLastCookedState.buttonState, mCurrentCookedState.buttonState);

    // Dispatch the touches either directly or by translation through a pointer on screen.
    if (mDeviceMode == DeviceMode::POINTER) {
        for (BitSet32 idBits(mCurrentRawState.rawPointerData.touchingIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            if (isStylusToolType(pointer.toolType)) {
                mCurrentCookedState.stylusIdBits.markBit(id);
            } else if (pointer.toolType == ToolType::FINGER ||
                       pointer.toolType == ToolType::UNKNOWN) {
                mCurrentCookedState.fingerIdBits.markBit(id);
            } else if (pointer.toolType == ToolType::MOUSE) {
                mCurrentCookedState.mouseIdBits.markBit(id);
            }
        }
        for (BitSet32 idBits(mCurrentRawState.rawPointerData.hoveringIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            if (isStylusToolType(pointer.toolType)) {
                mCurrentCookedState.stylusIdBits.markBit(id);
            }
        }

        // Stylus takes precedence over all tools, then mouse, then finger.
        PointerUsage pointerUsage = mPointerUsage;
        if (!mCurrentCookedState.stylusIdBits.isEmpty()) {
            mCurrentCookedState.mouseIdBits.clear();
            mCurrentCookedState.fingerIdBits.clear();
            pointerUsage = PointerUsage::STYLUS;
        } else if (!mCurrentCookedState.mouseIdBits.isEmpty()) {
            mCurrentCookedState.fingerIdBits.clear();
            pointerUsage = PointerUsage::MOUSE;
        } else if (!mCurrentCookedState.fingerIdBits.isEmpty() ||
                   isPointerDown(mCurrentRawState.buttonState)) {
            pointerUsage = PointerUsage::GESTURES;
        }

        out += dispatchPointerUsage(when, readTime, policyFlags, pointerUsage);
    } else {
        if (!mCurrentMotionAborted) {
            updateTouchSpots();
            out += dispatchButtonRelease(when, readTime, policyFlags);
            out += dispatchHoverExit(when, readTime, policyFlags);
            out += dispatchTouches(when, readTime, policyFlags);
            out += dispatchHoverEnterAndMove(when, readTime, policyFlags);
            out += dispatchButtonPress(when, readTime, policyFlags);
        }

        if (mCurrentCookedState.cookedPointerData.pointerCount == 0) {
            mCurrentMotionAborted = false;
        }
    }

    // Synthesize key up from raw buttons if needed.
    out += synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_UP, when, readTime, getDeviceId(),
                                mSource, mViewport.displayId, policyFlags,
                                mLastCookedState.buttonState, mCurrentCookedState.buttonState);

    // Clear some transient state.
    mCurrentRawState.rawVScroll = 0;
    mCurrentRawState.rawHScroll = 0;

    // Copy current touch to last touch in preparation for the next cycle.
    mLastRawState = mCurrentRawState;
    mLastCookedState = mCurrentCookedState;
    return out;
}

void TouchInputMapper::updateTouchSpots() {
    if (!mConfig.showTouches || mPointerController == nullptr) {
        return;
    }

    // Update touch spots when this is a touchscreen even when it's not enabled so that we can
    // clear touch spots.
    if (mDeviceMode != DeviceMode::DIRECT &&
        (mDeviceMode != DeviceMode::DISABLED || !isTouchScreen())) {
        return;
    }

    mPointerController->setPresentation(PointerControllerInterface::Presentation::SPOT);
    mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);

    mPointerController->setSpots(mCurrentCookedState.cookedPointerData.pointerCoords.cbegin(),
                                 mCurrentCookedState.cookedPointerData.idToIndex.cbegin(),
                                 mCurrentCookedState.cookedPointerData.touchingIdBits |
                                         mCurrentCookedState.cookedPointerData.hoveringIdBits,
                                 mViewport.displayId);
}

bool TouchInputMapper::isTouchScreen() {
    return mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN &&
            mParameters.hasAssociatedDisplay;
}

void TouchInputMapper::applyExternalStylusButtonState(nsecs_t when) {
    if (mDeviceMode == DeviceMode::DIRECT && hasExternalStylus()) {
        // If any of the external buttons are already pressed by the touch device, ignore them.
        const int32_t pressedButtons =
                filterButtonState(mConfig,
                                  ~mCurrentRawState.buttonState & mExternalStylusState.buttons);
        const int32_t releasedButtons =
                mExternalStylusButtonsApplied & ~mExternalStylusState.buttons;

        mCurrentRawState.buttonState |= pressedButtons;
        mCurrentRawState.buttonState &= ~releasedButtons;

        mExternalStylusButtonsApplied |= pressedButtons;
        mExternalStylusButtonsApplied &= ~releasedButtons;
    }
}

void TouchInputMapper::applyExternalStylusTouchState(nsecs_t when) {
    CookedPointerData& currentPointerData = mCurrentCookedState.cookedPointerData;
    const CookedPointerData& lastPointerData = mLastCookedState.cookedPointerData;
    if (!mFusedStylusPointerId || !currentPointerData.isTouching(*mFusedStylusPointerId)) {
        return;
    }

    float pressure = lastPointerData.isTouching(*mFusedStylusPointerId)
            ? lastPointerData.pointerCoordsForId(*mFusedStylusPointerId)
                      .getAxisValue(AMOTION_EVENT_AXIS_PRESSURE)
            : 0.f;
    if (mExternalStylusState.pressure && *mExternalStylusState.pressure > 0.f) {
        pressure = *mExternalStylusState.pressure;
    }
    PointerCoords& coords = currentPointerData.editPointerCoordsWithId(*mFusedStylusPointerId);
    coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, pressure);

    if (mExternalStylusState.toolType != ToolType::UNKNOWN) {
        PointerProperties& properties =
                currentPointerData.editPointerPropertiesWithId(*mFusedStylusPointerId);
        properties.toolType = mExternalStylusState.toolType;
    }
}

bool TouchInputMapper::assignExternalStylusId(const RawState& state, bool timeout) {
    if (mDeviceMode != DeviceMode::DIRECT || !hasExternalStylus()) {
        return false;
    }

    // Check if the stylus pointer has gone up.
    if (mFusedStylusPointerId &&
        !state.rawPointerData.touchingIdBits.hasBit(*mFusedStylusPointerId)) {
        ALOGD_IF(DEBUG_STYLUS_FUSION, "Stylus pointer is going up");
        mFusedStylusPointerId.reset();
        return false;
    }

    const bool initialDown = mLastRawState.rawPointerData.pointerCount == 0 &&
            state.rawPointerData.pointerCount != 0;
    if (!initialDown) {
        return false;
    }

    if (!mExternalStylusState.pressure) {
        ALOGD_IF(DEBUG_STYLUS_FUSION, "Stylus does not support pressure, no pointer fusion needed");
        return false;
    }

    if (*mExternalStylusState.pressure != 0.0f) {
        ALOGD_IF(DEBUG_STYLUS_FUSION, "Have both stylus and touch data, beginning fusion");
        mFusedStylusPointerId = state.rawPointerData.touchingIdBits.firstMarkedBit();
        return false;
    }

    if (timeout) {
        ALOGD_IF(DEBUG_STYLUS_FUSION, "Timeout expired, assuming touch is not a stylus.");
        mFusedStylusPointerId.reset();
        mExternalStylusFusionTimeout = LLONG_MAX;
        return false;
    }

    // We are waiting for the external stylus to report a pressure value. Withhold touches from
    // being processed until we either get pressure data or timeout.
    if (mExternalStylusFusionTimeout == LLONG_MAX) {
        mExternalStylusFusionTimeout = state.when + EXTERNAL_STYLUS_DATA_TIMEOUT;
    }
    ALOGD_IF(DEBUG_STYLUS_FUSION,
             "No stylus data but stylus is connected, requesting timeout (%" PRId64 "ms)",
             mExternalStylusFusionTimeout);
    getContext()->requestTimeoutAtTime(mExternalStylusFusionTimeout);
    return true;
}

std::list<NotifyArgs> TouchInputMapper::timeoutExpired(nsecs_t when) {
    std::list<NotifyArgs> out;
    if (mDeviceMode == DeviceMode::POINTER) {
        if (mPointerUsage == PointerUsage::GESTURES) {
            // Since this is a synthetic event, we can consider its latency to be zero
            const nsecs_t readTime = when;
            out += dispatchPointerGestures(when, readTime, /*policyFlags=*/0, /*isTimeout=*/true);
        }
    } else if (mDeviceMode == DeviceMode::DIRECT) {
        if (mExternalStylusFusionTimeout <= when) {
            out += processRawTouches(/*timeout=*/true);
        } else if (mExternalStylusFusionTimeout != LLONG_MAX) {
            getContext()->requestTimeoutAtTime(mExternalStylusFusionTimeout);
        }
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::updateExternalStylusState(const StylusState& state) {
    std::list<NotifyArgs> out;
    const bool buttonsChanged = mExternalStylusState.buttons != state.buttons;
    mExternalStylusState = state;
    if (mFusedStylusPointerId || mExternalStylusFusionTimeout != LLONG_MAX || buttonsChanged) {
        // The following three cases are handled here:
        // - We're in the middle of a fused stream of data;
        // - We're waiting on external stylus data before dispatching the initial down; or
        // - Only the button state, which is not reported through a specific pointer, has changed.
        // Go ahead and dispatch now that we have fresh stylus data.
        mExternalStylusDataPending = true;
        out += processRawTouches(/*timeout=*/false);
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::consumeRawTouches(nsecs_t when, nsecs_t readTime,
                                                          uint32_t policyFlags, bool& outConsumed) {
    outConsumed = false;
    std::list<NotifyArgs> out;
    // Check for release of a virtual key.
    if (mCurrentVirtualKey.down) {
        if (mCurrentRawState.rawPointerData.touchingIdBits.isEmpty()) {
            // Pointer went up while virtual key was down.
            mCurrentVirtualKey.down = false;
            if (!mCurrentVirtualKey.ignored) {
                ALOGD_IF(DEBUG_VIRTUAL_KEYS,
                         "VirtualKeys: Generating key up: keyCode=%d, scanCode=%d",
                         mCurrentVirtualKey.keyCode, mCurrentVirtualKey.scanCode);
                out.push_back(dispatchVirtualKey(when, readTime, policyFlags, AKEY_EVENT_ACTION_UP,
                                                 AKEY_EVENT_FLAG_FROM_SYSTEM |
                                                         AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY));
            }
            outConsumed = true;
            return out;
        }

        if (mCurrentRawState.rawPointerData.touchingIdBits.count() == 1) {
            uint32_t id = mCurrentRawState.rawPointerData.touchingIdBits.firstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            const VirtualKey* virtualKey = findVirtualKeyHit(pointer.x, pointer.y);
            if (virtualKey && virtualKey->keyCode == mCurrentVirtualKey.keyCode) {
                // Pointer is still within the space of the virtual key.
                outConsumed = true;
                return out;
            }
        }

        // Pointer left virtual key area or another pointer also went down.
        // Send key cancellation but do not consume the touch yet.
        // This is useful when the user swipes through from the virtual key area
        // into the main display surface.
        mCurrentVirtualKey.down = false;
        if (!mCurrentVirtualKey.ignored) {
            ALOGD_IF(DEBUG_VIRTUAL_KEYS, "VirtualKeys: Canceling key: keyCode=%d, scanCode=%d",
                     mCurrentVirtualKey.keyCode, mCurrentVirtualKey.scanCode);
            out.push_back(dispatchVirtualKey(when, readTime, policyFlags, AKEY_EVENT_ACTION_UP,
                                             AKEY_EVENT_FLAG_FROM_SYSTEM |
                                                     AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY |
                                                     AKEY_EVENT_FLAG_CANCELED));
        }
    }

    if (!mCurrentRawState.rawPointerData.hoveringIdBits.isEmpty() &&
        mCurrentRawState.rawPointerData.touchingIdBits.isEmpty() &&
        mDeviceMode != DeviceMode::UNSCALED) {
        // We have hovering pointers, and there are no touching pointers.
        bool hoveringPointersInFrame = false;
        auto hoveringIds = mCurrentRawState.rawPointerData.hoveringIdBits;
        while (!hoveringIds.isEmpty()) {
            uint32_t id = hoveringIds.clearFirstMarkedBit();
            const auto& pointer = mCurrentRawState.rawPointerData.pointerForId(id);
            if (isPointInsidePhysicalFrame(pointer.x, pointer.y)) {
                hoveringPointersInFrame = true;
                break;
            }
        }
        if (!hoveringPointersInFrame) {
            // All hovering pointers are outside the physical frame.
            outConsumed = true;
            return out;
        }
    }

    if (mLastRawState.rawPointerData.touchingIdBits.isEmpty() &&
        !mCurrentRawState.rawPointerData.touchingIdBits.isEmpty()) {
        // Pointer just went down.  Check for virtual key press or off-screen touches.
        uint32_t id = mCurrentRawState.rawPointerData.touchingIdBits.firstMarkedBit();
        const RawPointerData::Pointer& pointer = mCurrentRawState.rawPointerData.pointerForId(id);
        // Skip checking whether the pointer is inside the physical frame if the device is in
        // unscaled mode.
        if (!isPointInsidePhysicalFrame(pointer.x, pointer.y) &&
            mDeviceMode != DeviceMode::UNSCALED) {
            // If exactly one pointer went down, check for virtual key hit.
            // Otherwise, we will drop the entire stroke.
            if (mCurrentRawState.rawPointerData.touchingIdBits.count() == 1) {
                const VirtualKey* virtualKey = findVirtualKeyHit(pointer.x, pointer.y);
                if (virtualKey) {
                    mCurrentVirtualKey.down = true;
                    mCurrentVirtualKey.downTime = when;
                    mCurrentVirtualKey.keyCode = virtualKey->keyCode;
                    mCurrentVirtualKey.scanCode = virtualKey->scanCode;
                    mCurrentVirtualKey.ignored =
                            getContext()->shouldDropVirtualKey(when, virtualKey->keyCode,
                                                               virtualKey->scanCode);

                    if (!mCurrentVirtualKey.ignored) {
                        ALOGD_IF(DEBUG_VIRTUAL_KEYS,
                                 "VirtualKeys: Generating key down: keyCode=%d, scanCode=%d",
                                 mCurrentVirtualKey.keyCode, mCurrentVirtualKey.scanCode);
                        out.push_back(dispatchVirtualKey(when, readTime, policyFlags,
                                                         AKEY_EVENT_ACTION_DOWN,
                                                         AKEY_EVENT_FLAG_FROM_SYSTEM |
                                                                 AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY));
                    }
                }
            }
            outConsumed = true;
            return out;
        }
    }

    // Disable all virtual key touches that happen within a short time interval of the
    // most recent touch within the screen area.  The idea is to filter out stray
    // virtual key presses when interacting with the touch screen.
    //
    // Problems we're trying to solve:
    //
    // 1. While scrolling a list or dragging the window shade, the user swipes down into a
    //    virtual key area that is implemented by a separate touch panel and accidentally
    //    triggers a virtual key.
    //
    // 2. While typing in the on screen keyboard, the user taps slightly outside the screen
    //    area and accidentally triggers a virtual key.  This often happens when virtual keys
    //    are layed out below the screen near to where the on screen keyboard's space bar
    //    is displayed.
    if (mConfig.virtualKeyQuietTime > 0 &&
        !mCurrentRawState.rawPointerData.touchingIdBits.isEmpty()) {
        getContext()->disableVirtualKeysUntil(when + mConfig.virtualKeyQuietTime);
    }
    return out;
}

NotifyKeyArgs TouchInputMapper::dispatchVirtualKey(nsecs_t when, nsecs_t readTime,
                                                   uint32_t policyFlags, int32_t keyEventAction,
                                                   int32_t keyEventFlags) {
    int32_t keyCode = mCurrentVirtualKey.keyCode;
    int32_t scanCode = mCurrentVirtualKey.scanCode;
    nsecs_t downTime = mCurrentVirtualKey.downTime;
    int32_t metaState = getContext()->getGlobalMetaState();
    policyFlags |= POLICY_FLAG_VIRTUAL;

    return NotifyKeyArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                         AINPUT_SOURCE_KEYBOARD, mViewport.displayId, policyFlags, keyEventAction,
                         keyEventFlags, keyCode, scanCode, metaState, downTime);
}

std::list<NotifyArgs> TouchInputMapper::abortTouches(nsecs_t when, nsecs_t readTime,
                                                     uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    if (mCurrentMotionAborted) {
        // Current motion event was already aborted.
        return out;
    }
    BitSet32 currentIdBits = mCurrentCookedState.cookedPointerData.touchingIdBits;
    if (!currentIdBits.isEmpty()) {
        int32_t metaState = getContext()->getGlobalMetaState();
        int32_t buttonState = mCurrentCookedState.buttonState;
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_CANCEL, 0, AMOTION_EVENT_FLAG_CANCELED,
                                     metaState, buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                                     mCurrentCookedState.cookedPointerData.pointerProperties,
                                     mCurrentCookedState.cookedPointerData.pointerCoords,
                                     mCurrentCookedState.cookedPointerData.idToIndex, currentIdBits,
                                     -1, mOrientedXPrecision, mOrientedYPrecision, mDownTime,
                                     MotionClassification::NONE));
        mCurrentMotionAborted = true;
    }
    return out;
}

// Updates pointer coords and properties for pointers with specified ids that have moved.
// Returns true if any of them changed.
static bool updateMovedPointers(const PropertiesArray& inProperties, CoordsArray& inCoords,
                                const IdToIndexArray& inIdToIndex, PropertiesArray& outProperties,
                                CoordsArray& outCoords, IdToIndexArray& outIdToIndex,
                                BitSet32 idBits) {
    bool changed = false;
    while (!idBits.isEmpty()) {
        uint32_t id = idBits.clearFirstMarkedBit();
        uint32_t inIndex = inIdToIndex[id];
        uint32_t outIndex = outIdToIndex[id];

        const PointerProperties& curInProperties = inProperties[inIndex];
        const PointerCoords& curInCoords = inCoords[inIndex];
        PointerProperties& curOutProperties = outProperties[outIndex];
        PointerCoords& curOutCoords = outCoords[outIndex];

        if (curInProperties != curOutProperties) {
            curOutProperties.copyFrom(curInProperties);
            changed = true;
        }

        if (curInCoords != curOutCoords) {
            curOutCoords.copyFrom(curInCoords);
            changed = true;
        }
    }
    return changed;
}

std::list<NotifyArgs> TouchInputMapper::dispatchTouches(nsecs_t when, nsecs_t readTime,
                                                        uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    BitSet32 currentIdBits = mCurrentCookedState.cookedPointerData.touchingIdBits;
    BitSet32 lastIdBits = mLastCookedState.cookedPointerData.touchingIdBits;
    int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mCurrentCookedState.buttonState;

    if (currentIdBits == lastIdBits) {
        if (!currentIdBits.isEmpty()) {
            // No pointer id changes so this is a move event.
            // The listener takes care of batching moves so we don't have to deal with that here.
            out.push_back(
                    dispatchMotion(when, readTime, policyFlags, mSource, AMOTION_EVENT_ACTION_MOVE,
                                   0, 0, metaState, buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                                   mCurrentCookedState.cookedPointerData.pointerProperties,
                                   mCurrentCookedState.cookedPointerData.pointerCoords,
                                   mCurrentCookedState.cookedPointerData.idToIndex, currentIdBits,
                                   -1, mOrientedXPrecision, mOrientedYPrecision, mDownTime,
                                   MotionClassification::NONE));
        }
    } else {
        // There may be pointers going up and pointers going down and pointers moving
        // all at the same time.
        BitSet32 upIdBits(lastIdBits.value & ~currentIdBits.value);
        BitSet32 downIdBits(currentIdBits.value & ~lastIdBits.value);
        BitSet32 moveIdBits(lastIdBits.value & currentIdBits.value);
        BitSet32 dispatchedIdBits(lastIdBits.value);

        // Update last coordinates of pointers that have moved so that we observe the new
        // pointer positions at the same time as other pointers that have just gone up.
        bool moveNeeded =
                updateMovedPointers(mCurrentCookedState.cookedPointerData.pointerProperties,
                                    mCurrentCookedState.cookedPointerData.pointerCoords,
                                    mCurrentCookedState.cookedPointerData.idToIndex,
                                    mLastCookedState.cookedPointerData.pointerProperties,
                                    mLastCookedState.cookedPointerData.pointerCoords,
                                    mLastCookedState.cookedPointerData.idToIndex, moveIdBits);
        if (buttonState != mLastCookedState.buttonState) {
            moveNeeded = true;
        }

        // Dispatch pointer up events.
        while (!upIdBits.isEmpty()) {
            uint32_t upId = upIdBits.clearFirstMarkedBit();
            bool isCanceled = mCurrentCookedState.cookedPointerData.canceledIdBits.hasBit(upId);
            if (isCanceled) {
                ALOGI("Canceling pointer %d for the palm event was detected.", upId);
            }
            out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                         AMOTION_EVENT_ACTION_POINTER_UP, 0,
                                         isCanceled ? AMOTION_EVENT_FLAG_CANCELED : 0, metaState,
                                         buttonState, 0,
                                         mLastCookedState.cookedPointerData.pointerProperties,
                                         mLastCookedState.cookedPointerData.pointerCoords,
                                         mLastCookedState.cookedPointerData.idToIndex,
                                         dispatchedIdBits, upId, mOrientedXPrecision,
                                         mOrientedYPrecision, mDownTime,
                                         MotionClassification::NONE));
            dispatchedIdBits.clearBit(upId);
            mCurrentCookedState.cookedPointerData.canceledIdBits.clearBit(upId);
        }

        // Dispatch move events if any of the remaining pointers moved from their old locations.
        // Although applications receive new locations as part of individual pointer up
        // events, they do not generally handle them except when presented in a move event.
        if (moveNeeded && !moveIdBits.isEmpty()) {
            ALOG_ASSERT(moveIdBits.value == dispatchedIdBits.value);
            out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                         AMOTION_EVENT_ACTION_MOVE, 0, 0, metaState, buttonState, 0,
                                         mCurrentCookedState.cookedPointerData.pointerProperties,
                                         mCurrentCookedState.cookedPointerData.pointerCoords,
                                         mCurrentCookedState.cookedPointerData.idToIndex,
                                         dispatchedIdBits, -1, mOrientedXPrecision,
                                         mOrientedYPrecision, mDownTime,
                                         MotionClassification::NONE));
        }

        // Dispatch pointer down events using the new pointer locations.
        while (!downIdBits.isEmpty()) {
            uint32_t downId = downIdBits.clearFirstMarkedBit();
            dispatchedIdBits.markBit(downId);

            if (dispatchedIdBits.count() == 1) {
                // First pointer is going down.  Set down time.
                mDownTime = when;
            }

            out.push_back(
                    dispatchMotion(when, readTime, policyFlags, mSource,
                                   AMOTION_EVENT_ACTION_POINTER_DOWN, 0, 0, metaState, buttonState,
                                   0, mCurrentCookedState.cookedPointerData.pointerProperties,
                                   mCurrentCookedState.cookedPointerData.pointerCoords,
                                   mCurrentCookedState.cookedPointerData.idToIndex,
                                   dispatchedIdBits, downId, mOrientedXPrecision,
                                   mOrientedYPrecision, mDownTime, MotionClassification::NONE));
        }
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchHoverExit(nsecs_t when, nsecs_t readTime,
                                                          uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    if (mSentHoverEnter &&
        (mCurrentCookedState.cookedPointerData.hoveringIdBits.isEmpty() ||
         !mCurrentCookedState.cookedPointerData.touchingIdBits.isEmpty())) {
        int32_t metaState = getContext()->getGlobalMetaState();
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_HOVER_EXIT, 0, 0, metaState,
                                     mLastCookedState.buttonState, 0,
                                     mLastCookedState.cookedPointerData.pointerProperties,
                                     mLastCookedState.cookedPointerData.pointerCoords,
                                     mLastCookedState.cookedPointerData.idToIndex,
                                     mLastCookedState.cookedPointerData.hoveringIdBits, -1,
                                     mOrientedXPrecision, mOrientedYPrecision, mDownTime,
                                     MotionClassification::NONE));
        mSentHoverEnter = false;
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchHoverEnterAndMove(nsecs_t when, nsecs_t readTime,
                                                                  uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    if (mCurrentCookedState.cookedPointerData.touchingIdBits.isEmpty() &&
        !mCurrentCookedState.cookedPointerData.hoveringIdBits.isEmpty()) {
        int32_t metaState = getContext()->getGlobalMetaState();
        if (!mSentHoverEnter) {
            out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                         AMOTION_EVENT_ACTION_HOVER_ENTER, 0, 0, metaState,
                                         mCurrentRawState.buttonState, 0,
                                         mCurrentCookedState.cookedPointerData.pointerProperties,
                                         mCurrentCookedState.cookedPointerData.pointerCoords,
                                         mCurrentCookedState.cookedPointerData.idToIndex,
                                         mCurrentCookedState.cookedPointerData.hoveringIdBits, -1,
                                         mOrientedXPrecision, mOrientedYPrecision, mDownTime,
                                         MotionClassification::NONE));
            mSentHoverEnter = true;
        }

        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0, metaState,
                                     mCurrentRawState.buttonState, 0,
                                     mCurrentCookedState.cookedPointerData.pointerProperties,
                                     mCurrentCookedState.cookedPointerData.pointerCoords,
                                     mCurrentCookedState.cookedPointerData.idToIndex,
                                     mCurrentCookedState.cookedPointerData.hoveringIdBits, -1,
                                     mOrientedXPrecision, mOrientedYPrecision, mDownTime,
                                     MotionClassification::NONE));
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchButtonRelease(nsecs_t when, nsecs_t readTime,
                                                              uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    BitSet32 releasedButtons(mLastCookedState.buttonState & ~mCurrentCookedState.buttonState);
    const BitSet32& idBits = findActiveIdBits(mLastCookedState.cookedPointerData);
    const int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mLastCookedState.buttonState;
    while (!releasedButtons.isEmpty()) {
        int32_t actionButton = BitSet32::valueForBit(releasedButtons.clearFirstMarkedBit());
        buttonState &= ~actionButton;
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_BUTTON_RELEASE, actionButton, 0,
                                     metaState, buttonState, 0,
                                     mLastCookedState.cookedPointerData.pointerProperties,
                                     mLastCookedState.cookedPointerData.pointerCoords,
                                     mLastCookedState.cookedPointerData.idToIndex, idBits, -1,
                                     mOrientedXPrecision, mOrientedYPrecision, mDownTime,
                                     MotionClassification::NONE));
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchButtonPress(nsecs_t when, nsecs_t readTime,
                                                            uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    BitSet32 pressedButtons(mCurrentCookedState.buttonState & ~mLastCookedState.buttonState);
    const BitSet32& idBits = findActiveIdBits(mCurrentCookedState.cookedPointerData);
    const int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mLastCookedState.buttonState;
    while (!pressedButtons.isEmpty()) {
        int32_t actionButton = BitSet32::valueForBit(pressedButtons.clearFirstMarkedBit());
        buttonState |= actionButton;
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_BUTTON_PRESS, actionButton, 0, metaState,
                                     buttonState, 0,
                                     mCurrentCookedState.cookedPointerData.pointerProperties,
                                     mCurrentCookedState.cookedPointerData.pointerCoords,
                                     mCurrentCookedState.cookedPointerData.idToIndex, idBits, -1,
                                     mOrientedXPrecision, mOrientedYPrecision, mDownTime,
                                     MotionClassification::NONE));
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchGestureButtonRelease(nsecs_t when,
                                                                     uint32_t policyFlags,
                                                                     BitSet32 idBits,
                                                                     nsecs_t readTime) {
    std::list<NotifyArgs> out;
    BitSet32 releasedButtons(mLastCookedState.buttonState & ~mCurrentCookedState.buttonState);
    const int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mLastCookedState.buttonState;

    while (!releasedButtons.isEmpty()) {
        int32_t actionButton = BitSet32::valueForBit(releasedButtons.clearFirstMarkedBit());
        buttonState &= ~actionButton;
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_BUTTON_RELEASE, actionButton, 0,
                                     metaState, buttonState, 0,
                                     mPointerGesture.lastGestureProperties,
                                     mPointerGesture.lastGestureCoords,
                                     mPointerGesture.lastGestureIdToIndex, idBits, -1,
                                     mOrientedXPrecision, mOrientedYPrecision,
                                     mPointerGesture.downTime, MotionClassification::NONE));
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchGestureButtonPress(nsecs_t when,
                                                                   uint32_t policyFlags,
                                                                   BitSet32 idBits,
                                                                   nsecs_t readTime) {
    std::list<NotifyArgs> out;
    BitSet32 pressedButtons(mCurrentCookedState.buttonState & ~mLastCookedState.buttonState);
    const int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mLastCookedState.buttonState;

    while (!pressedButtons.isEmpty()) {
        int32_t actionButton = BitSet32::valueForBit(pressedButtons.clearFirstMarkedBit());
        buttonState |= actionButton;
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_BUTTON_PRESS, actionButton, 0, metaState,
                                     buttonState, 0, mPointerGesture.currentGestureProperties,
                                     mPointerGesture.currentGestureCoords,
                                     mPointerGesture.currentGestureIdToIndex, idBits, -1,
                                     mOrientedXPrecision, mOrientedYPrecision,
                                     mPointerGesture.downTime, MotionClassification::NONE));
    }
    return out;
}

const BitSet32& TouchInputMapper::findActiveIdBits(const CookedPointerData& cookedPointerData) {
    if (!cookedPointerData.touchingIdBits.isEmpty()) {
        return cookedPointerData.touchingIdBits;
    }
    return cookedPointerData.hoveringIdBits;
}

void TouchInputMapper::cookPointerData() {
    uint32_t currentPointerCount = mCurrentRawState.rawPointerData.pointerCount;

    mCurrentCookedState.cookedPointerData.clear();
    mCurrentCookedState.cookedPointerData.pointerCount = currentPointerCount;
    mCurrentCookedState.cookedPointerData.hoveringIdBits =
            mCurrentRawState.rawPointerData.hoveringIdBits;
    mCurrentCookedState.cookedPointerData.touchingIdBits =
            mCurrentRawState.rawPointerData.touchingIdBits;
    mCurrentCookedState.cookedPointerData.canceledIdBits =
            mCurrentRawState.rawPointerData.canceledIdBits;

    if (mCurrentCookedState.cookedPointerData.pointerCount == 0) {
        mCurrentCookedState.buttonState = 0;
    } else {
        mCurrentCookedState.buttonState = mCurrentRawState.buttonState;
    }

    // Walk through the the active pointers and map device coordinates onto
    // display coordinates and adjust for display orientation.
    for (uint32_t i = 0; i < currentPointerCount; i++) {
        const RawPointerData::Pointer& in = mCurrentRawState.rawPointerData.pointers[i];

        // Size
        float touchMajor, touchMinor, toolMajor, toolMinor, size;
        switch (mCalibration.sizeCalibration) {
            case Calibration::SizeCalibration::GEOMETRIC:
            case Calibration::SizeCalibration::DIAMETER:
            case Calibration::SizeCalibration::BOX:
            case Calibration::SizeCalibration::AREA:
                if (mRawPointerAxes.touchMajor.valid && mRawPointerAxes.toolMajor.valid) {
                    touchMajor = in.touchMajor;
                    touchMinor = mRawPointerAxes.touchMinor.valid ? in.touchMinor : in.touchMajor;
                    toolMajor = in.toolMajor;
                    toolMinor = mRawPointerAxes.toolMinor.valid ? in.toolMinor : in.toolMajor;
                    size = mRawPointerAxes.touchMinor.valid ? avg(in.touchMajor, in.touchMinor)
                                                            : in.touchMajor;
                } else if (mRawPointerAxes.touchMajor.valid) {
                    toolMajor = touchMajor = in.touchMajor;
                    toolMinor = touchMinor =
                            mRawPointerAxes.touchMinor.valid ? in.touchMinor : in.touchMajor;
                    size = mRawPointerAxes.touchMinor.valid ? avg(in.touchMajor, in.touchMinor)
                                                            : in.touchMajor;
                } else if (mRawPointerAxes.toolMajor.valid) {
                    touchMajor = toolMajor = in.toolMajor;
                    touchMinor = toolMinor =
                            mRawPointerAxes.toolMinor.valid ? in.toolMinor : in.toolMajor;
                    size = mRawPointerAxes.toolMinor.valid ? avg(in.toolMajor, in.toolMinor)
                                                           : in.toolMajor;
                } else {
                    ALOG_ASSERT(false,
                                "No touch or tool axes.  "
                                "Size calibration should have been resolved to NONE.");
                    touchMajor = 0;
                    touchMinor = 0;
                    toolMajor = 0;
                    toolMinor = 0;
                    size = 0;
                }

                if (mCalibration.sizeIsSummed && *mCalibration.sizeIsSummed) {
                    uint32_t touchingCount = mCurrentRawState.rawPointerData.touchingIdBits.count();
                    if (touchingCount > 1) {
                        touchMajor /= touchingCount;
                        touchMinor /= touchingCount;
                        toolMajor /= touchingCount;
                        toolMinor /= touchingCount;
                        size /= touchingCount;
                    }
                }

                if (mCalibration.sizeCalibration == Calibration::SizeCalibration::GEOMETRIC) {
                    touchMajor *= mGeometricScale;
                    touchMinor *= mGeometricScale;
                    toolMajor *= mGeometricScale;
                    toolMinor *= mGeometricScale;
                } else if (mCalibration.sizeCalibration == Calibration::SizeCalibration::AREA) {
                    touchMajor = touchMajor > 0 ? sqrtf(touchMajor) : 0;
                    touchMinor = touchMajor;
                    toolMajor = toolMajor > 0 ? sqrtf(toolMajor) : 0;
                    toolMinor = toolMajor;
                } else if (mCalibration.sizeCalibration == Calibration::SizeCalibration::DIAMETER) {
                    touchMinor = touchMajor;
                    toolMinor = toolMajor;
                }

                mCalibration.applySizeScaleAndBias(touchMajor);
                mCalibration.applySizeScaleAndBias(touchMinor);
                mCalibration.applySizeScaleAndBias(toolMajor);
                mCalibration.applySizeScaleAndBias(toolMinor);
                size *= mSizeScale;
                break;
            case Calibration::SizeCalibration::DEFAULT:
                LOG_ALWAYS_FATAL("Resolution should not be 'DEFAULT' at this point");
                break;
            case Calibration::SizeCalibration::NONE:
                touchMajor = 0;
                touchMinor = 0;
                toolMajor = 0;
                toolMinor = 0;
                size = 0;
                break;
        }

        // Pressure
        float pressure;
        switch (mCalibration.pressureCalibration) {
            case Calibration::PressureCalibration::PHYSICAL:
            case Calibration::PressureCalibration::AMPLITUDE:
                pressure = in.pressure * mPressureScale;
                break;
            default:
                pressure = in.isHovering ? 0 : 1;
                break;
        }

        // Tilt and Orientation
        float tilt;
        float orientation;
        if (mHaveTilt) {
            float tiltXAngle = (in.tiltX - mTiltXCenter) * mTiltXScale;
            float tiltYAngle = (in.tiltY - mTiltYCenter) * mTiltYScale;
            orientation = transformAngle(mRawRotation, atan2f(-sinf(tiltXAngle), sinf(tiltYAngle)));
            tilt = acosf(cosf(tiltXAngle) * cosf(tiltYAngle));
        } else {
            tilt = 0;

            switch (mCalibration.orientationCalibration) {
                case Calibration::OrientationCalibration::INTERPOLATED:
                    orientation = transformAngle(mRawRotation, in.orientation * mOrientationScale);
                    break;
                case Calibration::OrientationCalibration::VECTOR: {
                    int32_t c1 = signExtendNybble((in.orientation & 0xf0) >> 4);
                    int32_t c2 = signExtendNybble(in.orientation & 0x0f);
                    if (c1 != 0 || c2 != 0) {
                        orientation = transformAngle(mRawRotation, atan2f(c1, c2) * 0.5f);
                        float confidence = hypotf(c1, c2);
                        float scale = 1.0f + confidence / 16.0f;
                        touchMajor *= scale;
                        touchMinor /= scale;
                        toolMajor *= scale;
                        toolMinor /= scale;
                    } else {
                        orientation = 0;
                    }
                    break;
                }
                default:
                    orientation = 0;
            }
        }

        // Distance
        float distance;
        switch (mCalibration.distanceCalibration) {
            case Calibration::DistanceCalibration::SCALED:
                distance = in.distance * mDistanceScale;
                break;
            default:
                distance = 0;
        }

        // Adjust X,Y coords for device calibration and convert to the natural display coordinates.
        vec2 transformed = {in.x, in.y};
        mAffineTransform.applyTo(transformed.x /*byRef*/, transformed.y /*byRef*/);
        transformed = mRawToDisplay.transform(transformed);

        // Write output coords.
        PointerCoords& out = mCurrentCookedState.cookedPointerData.pointerCoords[i];
        out.clear();
        out.setAxisValue(AMOTION_EVENT_AXIS_X, transformed.x);
        out.setAxisValue(AMOTION_EVENT_AXIS_Y, transformed.y);
        out.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, pressure);
        out.setAxisValue(AMOTION_EVENT_AXIS_SIZE, size);
        out.setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, touchMajor);
        out.setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, touchMinor);
        out.setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, orientation);
        out.setAxisValue(AMOTION_EVENT_AXIS_TILT, tilt);
        out.setAxisValue(AMOTION_EVENT_AXIS_DISTANCE, distance);
        out.setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, toolMajor);
        out.setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, toolMinor);

        // Write output relative fields if applicable.
        uint32_t id = in.id;
        if (mSource == AINPUT_SOURCE_TOUCHPAD &&
            mLastCookedState.cookedPointerData.hasPointerCoordsForId(id)) {
            const PointerCoords& p = mLastCookedState.cookedPointerData.pointerCoordsForId(id);
            float dx = transformed.x - p.getAxisValue(AMOTION_EVENT_AXIS_X);
            float dy = transformed.y - p.getAxisValue(AMOTION_EVENT_AXIS_Y);
            out.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, dx);
            out.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, dy);
        }

        // Write output properties.
        PointerProperties& properties = mCurrentCookedState.cookedPointerData.pointerProperties[i];
        properties.clear();
        properties.id = id;
        properties.toolType = in.toolType;

        // Write id index and mark id as valid.
        mCurrentCookedState.cookedPointerData.idToIndex[id] = i;
        mCurrentCookedState.cookedPointerData.validIdBits.markBit(id);
    }
}

std::list<NotifyArgs> TouchInputMapper::dispatchPointerUsage(nsecs_t when, nsecs_t readTime,
                                                             uint32_t policyFlags,
                                                             PointerUsage pointerUsage) {
    std::list<NotifyArgs> out;
    if (pointerUsage != mPointerUsage) {
        out += abortPointerUsage(when, readTime, policyFlags);
        mPointerUsage = pointerUsage;
    }

    switch (mPointerUsage) {
        case PointerUsage::GESTURES:
            out += dispatchPointerGestures(when, readTime, policyFlags, /*isTimeout=*/false);
            break;
        case PointerUsage::STYLUS:
            out += dispatchPointerStylus(when, readTime, policyFlags);
            break;
        case PointerUsage::MOUSE:
            out += dispatchPointerMouse(when, readTime, policyFlags);
            break;
        case PointerUsage::NONE:
            break;
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::abortPointerUsage(nsecs_t when, nsecs_t readTime,
                                                          uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    switch (mPointerUsage) {
        case PointerUsage::GESTURES:
            out += abortPointerGestures(when, readTime, policyFlags);
            break;
        case PointerUsage::STYLUS:
            out += abortPointerStylus(when, readTime, policyFlags);
            break;
        case PointerUsage::MOUSE:
            out += abortPointerMouse(when, readTime, policyFlags);
            break;
        case PointerUsage::NONE:
            break;
    }

    mPointerUsage = PointerUsage::NONE;
    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchPointerGestures(nsecs_t when, nsecs_t readTime,
                                                                uint32_t policyFlags,
                                                                bool isTimeout) {
    std::list<NotifyArgs> out;
    // Update current gesture coordinates.
    bool cancelPreviousGesture, finishPreviousGesture;
    bool sendEvents =
            preparePointerGestures(when, &cancelPreviousGesture, &finishPreviousGesture, isTimeout);
    if (!sendEvents) {
        return {};
    }
    if (finishPreviousGesture) {
        cancelPreviousGesture = false;
    }

    // Update the pointer presentation and spots.
    if (mParameters.gestureMode == Parameters::GestureMode::MULTI_TOUCH) {
        mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
        if (finishPreviousGesture || cancelPreviousGesture) {
            mPointerController->clearSpots();
        }

        if (mPointerGesture.currentGestureMode == PointerGesture::Mode::FREEFORM) {
            mPointerController->setSpots(mPointerGesture.currentGestureCoords.cbegin(),
                                         mPointerGesture.currentGestureIdToIndex.cbegin(),
                                         mPointerGesture.currentGestureIdBits,
                                         mPointerController->getDisplayId());
        }
    } else {
        mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
    }

    // Show or hide the pointer if needed.
    switch (mPointerGesture.currentGestureMode) {
        case PointerGesture::Mode::NEUTRAL:
        case PointerGesture::Mode::QUIET:
            if (mParameters.gestureMode == Parameters::GestureMode::MULTI_TOUCH &&
                mPointerGesture.lastGestureMode == PointerGesture::Mode::FREEFORM) {
                // Remind the user of where the pointer is after finishing a gesture with spots.
                mPointerController->unfade(PointerControllerInterface::Transition::GRADUAL);
            }
            break;
        case PointerGesture::Mode::TAP:
        case PointerGesture::Mode::TAP_DRAG:
        case PointerGesture::Mode::BUTTON_CLICK_OR_DRAG:
        case PointerGesture::Mode::HOVER:
        case PointerGesture::Mode::PRESS:
        case PointerGesture::Mode::SWIPE:
            // Unfade the pointer when the current gesture manipulates the
            // area directly under the pointer.
            mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
            break;
        case PointerGesture::Mode::FREEFORM:
            // Fade the pointer when the current gesture manipulates a different
            // area and there are spots to guide the user experience.
            if (mParameters.gestureMode == Parameters::GestureMode::MULTI_TOUCH) {
                mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
            } else {
                mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
            }
            break;
    }

    // Send events!
    int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mCurrentCookedState.buttonState;
    const MotionClassification classification =
            mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE
            ? MotionClassification::TWO_FINGER_SWIPE
            : MotionClassification::NONE;

    uint32_t flags = 0;

    if (!PointerGesture::canGestureAffectWindowFocus(mPointerGesture.currentGestureMode)) {
        flags |= AMOTION_EVENT_FLAG_NO_FOCUS_CHANGE;
    }

    // Update last coordinates of pointers that have moved so that we observe the new
    // pointer positions at the same time as other pointers that have just gone up.
    bool down = mPointerGesture.currentGestureMode == PointerGesture::Mode::TAP ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::TAP_DRAG ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::BUTTON_CLICK_OR_DRAG ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::PRESS ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::FREEFORM;
    bool moveNeeded = false;
    if (down && !cancelPreviousGesture && !finishPreviousGesture &&
        !mPointerGesture.lastGestureIdBits.isEmpty() &&
        !mPointerGesture.currentGestureIdBits.isEmpty()) {
        BitSet32 movedGestureIdBits(mPointerGesture.currentGestureIdBits.value &
                                    mPointerGesture.lastGestureIdBits.value);
        moveNeeded = updateMovedPointers(mPointerGesture.currentGestureProperties,
                                         mPointerGesture.currentGestureCoords,
                                         mPointerGesture.currentGestureIdToIndex,
                                         mPointerGesture.lastGestureProperties,
                                         mPointerGesture.lastGestureCoords,
                                         mPointerGesture.lastGestureIdToIndex, movedGestureIdBits);
        if (buttonState != mLastCookedState.buttonState) {
            moveNeeded = true;
        }
    }

    // Send motion events for all pointers that went up or were canceled.
    BitSet32 dispatchedGestureIdBits(mPointerGesture.lastGestureIdBits);
    if (!dispatchedGestureIdBits.isEmpty()) {
        if (cancelPreviousGesture) {
            const uint32_t cancelFlags = flags | AMOTION_EVENT_FLAG_CANCELED;
            out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                         AMOTION_EVENT_ACTION_CANCEL, 0, cancelFlags, metaState,
                                         buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                                         mPointerGesture.lastGestureProperties,
                                         mPointerGesture.lastGestureCoords,
                                         mPointerGesture.lastGestureIdToIndex,
                                         dispatchedGestureIdBits, -1, 0, 0,
                                         mPointerGesture.downTime, classification));

            dispatchedGestureIdBits.clear();
        } else {
            BitSet32 upGestureIdBits;
            if (finishPreviousGesture) {
                upGestureIdBits = dispatchedGestureIdBits;
            } else {
                upGestureIdBits.value =
                        dispatchedGestureIdBits.value & ~mPointerGesture.currentGestureIdBits.value;
            }
            while (!upGestureIdBits.isEmpty()) {
                if (((mLastCookedState.buttonState & AMOTION_EVENT_BUTTON_PRIMARY) != 0 ||
                     (mLastCookedState.buttonState & AMOTION_EVENT_BUTTON_SECONDARY) != 0) &&
                    mPointerGesture.lastGestureMode == PointerGesture::Mode::BUTTON_CLICK_OR_DRAG) {
                    out += dispatchGestureButtonRelease(when, policyFlags, dispatchedGestureIdBits,
                                                        readTime);
                }
                const uint32_t id = upGestureIdBits.clearFirstMarkedBit();
                out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                             AMOTION_EVENT_ACTION_POINTER_UP, 0, flags, metaState,
                                             buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                                             mPointerGesture.lastGestureProperties,
                                             mPointerGesture.lastGestureCoords,
                                             mPointerGesture.lastGestureIdToIndex,
                                             dispatchedGestureIdBits, id, 0, 0,
                                             mPointerGesture.downTime, classification));

                dispatchedGestureIdBits.clearBit(id);
            }
        }
    }

    // Send motion events for all pointers that moved.
    if (moveNeeded) {
        out.push_back(
                dispatchMotion(when, readTime, policyFlags, mSource, AMOTION_EVENT_ACTION_MOVE, 0,
                               flags, metaState, buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                               mPointerGesture.currentGestureProperties,
                               mPointerGesture.currentGestureCoords,
                               mPointerGesture.currentGestureIdToIndex, dispatchedGestureIdBits, -1,
                               0, 0, mPointerGesture.downTime, classification));
    }

    // Send motion events for all pointers that went down.
    if (down) {
        BitSet32 downGestureIdBits(mPointerGesture.currentGestureIdBits.value &
                                   ~dispatchedGestureIdBits.value);
        while (!downGestureIdBits.isEmpty()) {
            uint32_t id = downGestureIdBits.clearFirstMarkedBit();
            dispatchedGestureIdBits.markBit(id);

            if (dispatchedGestureIdBits.count() == 1) {
                mPointerGesture.downTime = when;
            }

            out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                         AMOTION_EVENT_ACTION_POINTER_DOWN, 0, flags, metaState,
                                         buttonState, 0, mPointerGesture.currentGestureProperties,
                                         mPointerGesture.currentGestureCoords,
                                         mPointerGesture.currentGestureIdToIndex,
                                         dispatchedGestureIdBits, id, 0, 0,
                                         mPointerGesture.downTime, classification));
            if (((buttonState & AMOTION_EVENT_BUTTON_PRIMARY) != 0 ||
                 (buttonState & AMOTION_EVENT_BUTTON_SECONDARY) != 0) &&
                mPointerGesture.currentGestureMode == PointerGesture::Mode::BUTTON_CLICK_OR_DRAG) {
                out += dispatchGestureButtonPress(when, policyFlags, dispatchedGestureIdBits,
                                                  readTime);
            }
        }
    }

    // Send motion events for hover.
    if (mPointerGesture.currentGestureMode == PointerGesture::Mode::HOVER) {
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_HOVER_MOVE, 0, flags, metaState,
                                     buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                                     mPointerGesture.currentGestureProperties,
                                     mPointerGesture.currentGestureCoords,
                                     mPointerGesture.currentGestureIdToIndex,
                                     mPointerGesture.currentGestureIdBits, -1, 0, 0,
                                     mPointerGesture.downTime, MotionClassification::NONE));
    } else if (dispatchedGestureIdBits.isEmpty() && !mPointerGesture.lastGestureIdBits.isEmpty()) {
        // Synthesize a hover move event after all pointers go up to indicate that
        // the pointer is hovering again even if the user is not currently touching
        // the touch pad.  This ensures that a view will receive a fresh hover enter
        // event after a tap.
        const auto [x, y] = mPointerController->getPosition();

        PointerProperties pointerProperties;
        pointerProperties.clear();
        pointerProperties.id = 0;
        pointerProperties.toolType = ToolType::FINGER;

        PointerCoords pointerCoords;
        pointerCoords.clear();
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);

        const int32_t displayId = mPointerController->getDisplayId();
        out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                       mSource, displayId, policyFlags,
                                       AMOTION_EVENT_ACTION_HOVER_MOVE, 0, flags, metaState,
                                       buttonState, MotionClassification::NONE,
                                       AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                       &pointerCoords, 0, 0, x, y, mPointerGesture.downTime,
                                       /* videoFrames */ {}));
    }

    // Update state.
    mPointerGesture.lastGestureMode = mPointerGesture.currentGestureMode;
    if (!down) {
        mPointerGesture.lastGestureIdBits.clear();
    } else {
        mPointerGesture.lastGestureIdBits = mPointerGesture.currentGestureIdBits;
        for (BitSet32 idBits(mPointerGesture.currentGestureIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            uint32_t index = mPointerGesture.currentGestureIdToIndex[id];
            mPointerGesture.lastGestureProperties[index].copyFrom(
                    mPointerGesture.currentGestureProperties[index]);
            mPointerGesture.lastGestureCoords[index].copyFrom(
                    mPointerGesture.currentGestureCoords[index]);
            mPointerGesture.lastGestureIdToIndex[id] = index;
        }
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::abortPointerGestures(nsecs_t when, nsecs_t readTime,
                                                             uint32_t policyFlags) {
    const MotionClassification classification =
            mPointerGesture.lastGestureMode == PointerGesture::Mode::SWIPE
            ? MotionClassification::TWO_FINGER_SWIPE
            : MotionClassification::NONE;
    std::list<NotifyArgs> out;
    // Cancel previously dispatches pointers.
    if (!mPointerGesture.lastGestureIdBits.isEmpty()) {
        int32_t metaState = getContext()->getGlobalMetaState();
        int32_t buttonState = mCurrentRawState.buttonState;
        out.push_back(dispatchMotion(when, readTime, policyFlags, mSource,
                                     AMOTION_EVENT_ACTION_CANCEL, 0, AMOTION_EVENT_FLAG_CANCELED,
                                     metaState, buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                                     mPointerGesture.lastGestureProperties,
                                     mPointerGesture.lastGestureCoords,
                                     mPointerGesture.lastGestureIdToIndex,
                                     mPointerGesture.lastGestureIdBits, -1, 0, 0,
                                     mPointerGesture.downTime, classification));
    }

    // Reset the current pointer gesture.
    mPointerGesture.reset();
    mPointerVelocityControl.reset();

    // Remove any current spots.
    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
        mPointerController->clearSpots();
    }
    return out;
}

bool TouchInputMapper::preparePointerGestures(nsecs_t when, bool* outCancelPreviousGesture,
                                              bool* outFinishPreviousGesture, bool isTimeout) {
    *outCancelPreviousGesture = false;
    *outFinishPreviousGesture = false;

    // Handle TAP timeout.
    if (isTimeout) {
        ALOGD_IF(DEBUG_GESTURES, "Gestures: Processing timeout");

        if (mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP) {
            if (when <= mPointerGesture.tapUpTime + mConfig.pointerGestureTapDragInterval) {
                // The tap/drag timeout has not yet expired.
                getContext()->requestTimeoutAtTime(mPointerGesture.tapUpTime +
                                                   mConfig.pointerGestureTapDragInterval);
            } else {
                // The tap is finished.
                ALOGD_IF(DEBUG_GESTURES, "Gestures: TAP finished");
                *outFinishPreviousGesture = true;

                mPointerGesture.activeGestureId = -1;
                mPointerGesture.currentGestureMode = PointerGesture::Mode::NEUTRAL;
                mPointerGesture.currentGestureIdBits.clear();

                mPointerVelocityControl.reset();
                return true;
            }
        }

        // We did not handle this timeout.
        return false;
    }

    const uint32_t currentFingerCount = mCurrentCookedState.fingerIdBits.count();
    const uint32_t lastFingerCount = mLastCookedState.fingerIdBits.count();

    // Update the velocity tracker.
    {
        for (BitSet32 idBits(mCurrentCookedState.fingerIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            const float x = pointer.x * mPointerXMovementScale;
            const float y = pointer.y * mPointerYMovementScale;
            mPointerGesture.velocityTracker.addMovement(when, id, AMOTION_EVENT_AXIS_X, x);
            mPointerGesture.velocityTracker.addMovement(when, id, AMOTION_EVENT_AXIS_Y, y);
        }
    }

    // If the gesture ever enters a mode other than TAP, HOVER or TAP_DRAG, without first returning
    // to NEUTRAL, then we should not generate tap event.
    if (mPointerGesture.lastGestureMode != PointerGesture::Mode::HOVER &&
        mPointerGesture.lastGestureMode != PointerGesture::Mode::TAP &&
        mPointerGesture.lastGestureMode != PointerGesture::Mode::TAP_DRAG) {
        mPointerGesture.resetTap();
    }

    // Pick a new active touch id if needed.
    // Choose an arbitrary pointer that just went down, if there is one.
    // Otherwise choose an arbitrary remaining pointer.
    // This guarantees we always have an active touch id when there is at least one pointer.
    // We keep the same active touch id for as long as possible.
    if (mPointerGesture.activeTouchId < 0) {
        if (!mCurrentCookedState.fingerIdBits.isEmpty()) {
            mPointerGesture.activeTouchId = mCurrentCookedState.fingerIdBits.firstMarkedBit();
            mPointerGesture.firstTouchTime = when;
        }
    } else if (!mCurrentCookedState.fingerIdBits.hasBit(mPointerGesture.activeTouchId)) {
        mPointerGesture.activeTouchId = !mCurrentCookedState.fingerIdBits.isEmpty()
                ? mCurrentCookedState.fingerIdBits.firstMarkedBit()
                : -1;
    }
    const int32_t& activeTouchId = mPointerGesture.activeTouchId;

    // Switch states based on button and pointer state.
    if (checkForTouchpadQuietTime(when)) {
        // Case 1: Quiet time. (QUIET)
        ALOGD_IF(DEBUG_GESTURES, "Gestures: QUIET for next %0.3fms",
                 (mPointerGesture.quietTime + mConfig.pointerGestureQuietInterval - when) *
                         0.000001f);
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::QUIET) {
            *outFinishPreviousGesture = true;
        }

        mPointerGesture.activeGestureId = -1;
        mPointerGesture.currentGestureMode = PointerGesture::Mode::QUIET;
        mPointerGesture.currentGestureIdBits.clear();

        mPointerVelocityControl.reset();
    } else if (isPointerDown(mCurrentRawState.buttonState)) {
        // Case 2: Button is pressed. (BUTTON_CLICK_OR_DRAG)
        // The pointer follows the active touch point.
        // Emit DOWN, MOVE, UP events at the pointer location.
        //
        // Only the active touch matters; other fingers are ignored.  This policy helps
        // to handle the case where the user places a second finger on the touch pad
        // to apply the necessary force to depress an integrated button below the surface.
        // We don't want the second finger to be delivered to applications.
        //
        // For this to work well, we need to make sure to track the pointer that is really
        // active.  If the user first puts one finger down to click then adds another
        // finger to drag then the active pointer should switch to the finger that is
        // being dragged.
        ALOGD_IF(DEBUG_GESTURES,
                 "Gestures: BUTTON_CLICK_OR_DRAG activeTouchId=%d, currentFingerCount=%d",
                 activeTouchId, currentFingerCount);
        // Reset state when just starting.
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::BUTTON_CLICK_OR_DRAG) {
            *outFinishPreviousGesture = true;
            mPointerGesture.activeGestureId = 0;
        }

        // Switch pointers if needed.
        // Find the fastest pointer and follow it.
        if (activeTouchId >= 0 && currentFingerCount > 1) {
            const auto [bestId, bestSpeed] = getFastestFinger();
            if (bestId >= 0 && bestId != activeTouchId) {
                mPointerGesture.activeTouchId = bestId;
                ALOGD_IF(DEBUG_GESTURES,
                         "Gestures: BUTTON_CLICK_OR_DRAG switched pointers, bestId=%d, "
                         "bestSpeed=%0.3f",
                         bestId, bestSpeed);
            }
        }

        if (activeTouchId >= 0 && mLastCookedState.fingerIdBits.hasBit(activeTouchId)) {
            // When using spots, the click will occur at the position of the anchor
            // spot and all other spots will move there.
            moveMousePointerFromPointerDelta(when, activeTouchId);
        } else {
            mPointerVelocityControl.reset();
        }

        const auto [x, y] = mPointerController->getPosition();

        mPointerGesture.currentGestureMode = PointerGesture::Mode::BUTTON_CLICK_OR_DRAG;
        mPointerGesture.currentGestureIdBits.clear();
        mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
        mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
        mPointerGesture.currentGestureProperties[0].clear();
        mPointerGesture.currentGestureProperties[0].id = mPointerGesture.activeGestureId;
        mPointerGesture.currentGestureProperties[0].toolType = ToolType::FINGER;
        mPointerGesture.currentGestureCoords[0].clear();
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
    } else if (currentFingerCount == 0) {
        // Case 3. No fingers down and button is not pressed. (NEUTRAL)
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::NEUTRAL) {
            *outFinishPreviousGesture = true;
        }

        // Watch for taps coming out of HOVER or TAP_DRAG mode.
        // Checking for taps after TAP_DRAG allows us to detect double-taps.
        bool tapped = false;
        if ((mPointerGesture.lastGestureMode == PointerGesture::Mode::HOVER ||
             mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP_DRAG) &&
            lastFingerCount == 1) {
            if (when <= mPointerGesture.tapDownTime + mConfig.pointerGestureTapInterval) {
                const auto [x, y] = mPointerController->getPosition();
                if (fabs(x - mPointerGesture.tapX) <= mConfig.pointerGestureTapSlop &&
                    fabs(y - mPointerGesture.tapY) <= mConfig.pointerGestureTapSlop) {
                    ALOGD_IF(DEBUG_GESTURES, "Gestures: TAP");

                    mPointerGesture.tapUpTime = when;
                    getContext()->requestTimeoutAtTime(when +
                                                       mConfig.pointerGestureTapDragInterval);

                    mPointerGesture.activeGestureId = 0;
                    mPointerGesture.currentGestureMode = PointerGesture::Mode::TAP;
                    mPointerGesture.currentGestureIdBits.clear();
                    mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
                    mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
                    mPointerGesture.currentGestureProperties[0].clear();
                    mPointerGesture.currentGestureProperties[0].id =
                            mPointerGesture.activeGestureId;
                    mPointerGesture.currentGestureProperties[0].toolType = ToolType::FINGER;
                    mPointerGesture.currentGestureCoords[0].clear();
                    mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                                                         mPointerGesture.tapX);
                    mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y,
                                                                         mPointerGesture.tapY);
                    mPointerGesture.currentGestureCoords[0]
                            .setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);

                    tapped = true;
                } else {
                    ALOGD_IF(DEBUG_GESTURES, "Gestures: Not a TAP, deltaX=%f, deltaY=%f",
                             x - mPointerGesture.tapX, y - mPointerGesture.tapY);
                }
            } else {
                if (DEBUG_GESTURES) {
                    if (mPointerGesture.tapDownTime != LLONG_MIN) {
                        ALOGD("Gestures: Not a TAP, %0.3fms since down",
                              (when - mPointerGesture.tapDownTime) * 0.000001f);
                    } else {
                        ALOGD("Gestures: Not a TAP, incompatible mode transitions");
                    }
                }
            }
        }

        mPointerVelocityControl.reset();

        if (!tapped) {
            ALOGD_IF(DEBUG_GESTURES, "Gestures: NEUTRAL");
            mPointerGesture.activeGestureId = -1;
            mPointerGesture.currentGestureMode = PointerGesture::Mode::NEUTRAL;
            mPointerGesture.currentGestureIdBits.clear();
        }
    } else if (currentFingerCount == 1) {
        // Case 4. Exactly one finger down, button is not pressed. (HOVER or TAP_DRAG)
        // The pointer follows the active touch point.
        // When in HOVER, emit HOVER_MOVE events at the pointer location.
        // When in TAP_DRAG, emit MOVE events at the pointer location.
        ALOG_ASSERT(activeTouchId >= 0);

        mPointerGesture.currentGestureMode = PointerGesture::Mode::HOVER;
        if (mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP) {
            if (when <= mPointerGesture.tapUpTime + mConfig.pointerGestureTapDragInterval) {
                const auto [x, y] = mPointerController->getPosition();
                if (fabs(x - mPointerGesture.tapX) <= mConfig.pointerGestureTapSlop &&
                    fabs(y - mPointerGesture.tapY) <= mConfig.pointerGestureTapSlop) {
                    mPointerGesture.currentGestureMode = PointerGesture::Mode::TAP_DRAG;
                } else {
                    ALOGD_IF(DEBUG_GESTURES, "Gestures: Not a TAP_DRAG, deltaX=%f, deltaY=%f",
                             x - mPointerGesture.tapX, y - mPointerGesture.tapY);
                }
            } else {
                ALOGD_IF(DEBUG_GESTURES, "Gestures: Not a TAP_DRAG, %0.3fms time since up",
                         (when - mPointerGesture.tapUpTime) * 0.000001f);
            }
        } else if (mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP_DRAG) {
            mPointerGesture.currentGestureMode = PointerGesture::Mode::TAP_DRAG;
        }

        if (mLastCookedState.fingerIdBits.hasBit(activeTouchId)) {
            // When using spots, the hover or drag will occur at the position of the anchor spot.
            moveMousePointerFromPointerDelta(when, activeTouchId);
        } else {
            mPointerVelocityControl.reset();
        }

        bool down;
        if (mPointerGesture.currentGestureMode == PointerGesture::Mode::TAP_DRAG) {
            ALOGD_IF(DEBUG_GESTURES, "Gestures: TAP_DRAG");
            down = true;
        } else {
            ALOGD_IF(DEBUG_GESTURES, "Gestures: HOVER");
            if (mPointerGesture.lastGestureMode != PointerGesture::Mode::HOVER) {
                *outFinishPreviousGesture = true;
            }
            mPointerGesture.activeGestureId = 0;
            down = false;
        }

        const auto [x, y] = mPointerController->getPosition();

        mPointerGesture.currentGestureIdBits.clear();
        mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
        mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
        mPointerGesture.currentGestureProperties[0].clear();
        mPointerGesture.currentGestureProperties[0].id = mPointerGesture.activeGestureId;
        mPointerGesture.currentGestureProperties[0].toolType = ToolType::FINGER;
        mPointerGesture.currentGestureCoords[0].clear();
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE,
                                                             down ? 1.0f : 0.0f);

        if (lastFingerCount == 0 && currentFingerCount != 0) {
            mPointerGesture.resetTap();
            mPointerGesture.tapDownTime = when;
            mPointerGesture.tapX = x;
            mPointerGesture.tapY = y;
        }
    } else {
        // Case 5. At least two fingers down, button is not pressed. (PRESS, SWIPE or FREEFORM)
        prepareMultiFingerPointerGestures(when, outCancelPreviousGesture, outFinishPreviousGesture);
    }

    if (DEBUG_GESTURES) {
        ALOGD("Gestures: finishPreviousGesture=%s, cancelPreviousGesture=%s, "
              "currentGestureMode=%d, currentGestureIdBits=0x%08x, "
              "lastGestureMode=%d, lastGestureIdBits=0x%08x",
              toString(*outFinishPreviousGesture), toString(*outCancelPreviousGesture),
              mPointerGesture.currentGestureMode, mPointerGesture.currentGestureIdBits.value,
              mPointerGesture.lastGestureMode, mPointerGesture.lastGestureIdBits.value);
        for (BitSet32 idBits = mPointerGesture.currentGestureIdBits; !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            uint32_t index = mPointerGesture.currentGestureIdToIndex[id];
            const PointerProperties& properties = mPointerGesture.currentGestureProperties[index];
            const PointerCoords& coords = mPointerGesture.currentGestureCoords[index];
            ALOGD("  currentGesture[%d]: index=%d, toolType=%s, "
                  "x=%0.3f, y=%0.3f, pressure=%0.3f",
                  id, index, ftl::enum_string(properties.toolType).c_str(),
                  coords.getAxisValue(AMOTION_EVENT_AXIS_X),
                  coords.getAxisValue(AMOTION_EVENT_AXIS_Y),
                  coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE));
        }
        for (BitSet32 idBits = mPointerGesture.lastGestureIdBits; !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            uint32_t index = mPointerGesture.lastGestureIdToIndex[id];
            const PointerProperties& properties = mPointerGesture.lastGestureProperties[index];
            const PointerCoords& coords = mPointerGesture.lastGestureCoords[index];
            ALOGD("  lastGesture[%d]: index=%d, toolType=%s, "
                  "x=%0.3f, y=%0.3f, pressure=%0.3f",
                  id, index, ftl::enum_string(properties.toolType).c_str(),
                  coords.getAxisValue(AMOTION_EVENT_AXIS_X),
                  coords.getAxisValue(AMOTION_EVENT_AXIS_Y),
                  coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE));
        }
    }
    return true;
}

bool TouchInputMapper::checkForTouchpadQuietTime(nsecs_t when) {
    if (mPointerGesture.activeTouchId < 0) {
        mPointerGesture.resetQuietTime();
        return false;
    }

    if (when < mPointerGesture.quietTime + mConfig.pointerGestureQuietInterval) {
        return true;
    }

    const uint32_t currentFingerCount = mCurrentCookedState.fingerIdBits.count();
    bool isQuietTime = false;
    if ((mPointerGesture.lastGestureMode == PointerGesture::Mode::PRESS ||
         mPointerGesture.lastGestureMode == PointerGesture::Mode::SWIPE ||
         mPointerGesture.lastGestureMode == PointerGesture::Mode::FREEFORM) &&
        currentFingerCount < 2) {
        // Enter quiet time when exiting swipe or freeform state.
        // This is to prevent accidentally entering the hover state and flinging the
        // pointer when finishing a swipe and there is still one pointer left onscreen.
        isQuietTime = true;
    } else if (mPointerGesture.lastGestureMode == PointerGesture::Mode::BUTTON_CLICK_OR_DRAG &&
               currentFingerCount >= 2 && !isPointerDown(mCurrentRawState.buttonState)) {
        // Enter quiet time when releasing the button and there are still two or more
        // fingers down.  This may indicate that one finger was used to press the button
        // but it has not gone up yet.
        isQuietTime = true;
    }
    if (isQuietTime) {
        mPointerGesture.quietTime = when;
    }
    return isQuietTime;
}

std::pair<int32_t, float> TouchInputMapper::getFastestFinger() {
    int32_t bestId = -1;
    float bestSpeed = mConfig.pointerGestureDragMinSwitchSpeed;
    for (BitSet32 idBits(mCurrentCookedState.fingerIdBits); !idBits.isEmpty();) {
        uint32_t id = idBits.clearFirstMarkedBit();
        std::optional<float> vx =
                mPointerGesture.velocityTracker.getVelocity(AMOTION_EVENT_AXIS_X, id);
        std::optional<float> vy =
                mPointerGesture.velocityTracker.getVelocity(AMOTION_EVENT_AXIS_Y, id);
        if (vx && vy) {
            float speed = hypotf(*vx, *vy);
            if (speed > bestSpeed) {
                bestId = id;
                bestSpeed = speed;
            }
        }
    }
    return std::make_pair(bestId, bestSpeed);
}

void TouchInputMapper::prepareMultiFingerPointerGestures(nsecs_t when, bool* cancelPreviousGesture,
                                                         bool* finishPreviousGesture) {
    // We need to provide feedback for each finger that goes down so we cannot wait for the fingers
    // to move before deciding what to do.
    //
    // The ambiguous case is deciding what to do when there are two fingers down but they have not
    // moved enough to determine whether they are part of a drag or part of a freeform gesture, or
    // just a press or long-press at the pointer location.
    //
    // When there are two fingers we start with the PRESS hypothesis and we generate a down at the
    // pointer location.
    //
    // When the two fingers move enough or when additional fingers are added, we make a decision to
    // transition into SWIPE or FREEFORM mode accordingly.
    const int32_t activeTouchId = mPointerGesture.activeTouchId;
    ALOG_ASSERT(activeTouchId >= 0);

    const uint32_t currentFingerCount = mCurrentCookedState.fingerIdBits.count();
    const uint32_t lastFingerCount = mLastCookedState.fingerIdBits.count();
    bool settled =
            when >= mPointerGesture.firstTouchTime + mConfig.pointerGestureMultitouchSettleInterval;
    if (mPointerGesture.lastGestureMode != PointerGesture::Mode::PRESS &&
        mPointerGesture.lastGestureMode != PointerGesture::Mode::SWIPE &&
        mPointerGesture.lastGestureMode != PointerGesture::Mode::FREEFORM) {
        *finishPreviousGesture = true;
    } else if (!settled && currentFingerCount > lastFingerCount) {
        // Additional pointers have gone down but not yet settled.
        // Reset the gesture.
        ALOGD_IF(DEBUG_GESTURES,
                 "Gestures: Resetting gesture since additional pointers went down for "
                 "MULTITOUCH, settle time remaining %0.3fms",
                 (mPointerGesture.firstTouchTime + mConfig.pointerGestureMultitouchSettleInterval -
                  when) * 0.000001f);
        *cancelPreviousGesture = true;
    } else {
        // Continue previous gesture.
        mPointerGesture.currentGestureMode = mPointerGesture.lastGestureMode;
    }

    if (*finishPreviousGesture || *cancelPreviousGesture) {
        mPointerGesture.currentGestureMode = PointerGesture::Mode::PRESS;
        mPointerGesture.activeGestureId = 0;
        mPointerGesture.referenceIdBits.clear();
        mPointerVelocityControl.reset();

        // Use the centroid and pointer location as the reference points for the gesture.
        ALOGD_IF(DEBUG_GESTURES,
                 "Gestures: Using centroid as reference for MULTITOUCH, settle time remaining "
                 "%0.3fms",
                 (mPointerGesture.firstTouchTime + mConfig.pointerGestureMultitouchSettleInterval -
                  when) * 0.000001f);
        mCurrentRawState.rawPointerData
                .getCentroidOfTouchingPointers(&mPointerGesture.referenceTouchX,
                                               &mPointerGesture.referenceTouchY);
        std::tie(mPointerGesture.referenceGestureX, mPointerGesture.referenceGestureY) =
                mPointerController->getPosition();
    }

    // Clear the reference deltas for fingers not yet included in the reference calculation.
    for (BitSet32 idBits(mCurrentCookedState.fingerIdBits.value &
                         ~mPointerGesture.referenceIdBits.value);
         !idBits.isEmpty();) {
        uint32_t id = idBits.clearFirstMarkedBit();
        mPointerGesture.referenceDeltas[id].dx = 0;
        mPointerGesture.referenceDeltas[id].dy = 0;
    }
    mPointerGesture.referenceIdBits = mCurrentCookedState.fingerIdBits;

    // Add delta for all fingers and calculate a common movement delta.
    int32_t commonDeltaRawX = 0, commonDeltaRawY = 0;
    BitSet32 commonIdBits(mLastCookedState.fingerIdBits.value &
                          mCurrentCookedState.fingerIdBits.value);
    for (BitSet32 idBits(commonIdBits); !idBits.isEmpty();) {
        bool first = (idBits == commonIdBits);
        uint32_t id = idBits.clearFirstMarkedBit();
        const RawPointerData::Pointer& cpd = mCurrentRawState.rawPointerData.pointerForId(id);
        const RawPointerData::Pointer& lpd = mLastRawState.rawPointerData.pointerForId(id);
        PointerGesture::Delta& delta = mPointerGesture.referenceDeltas[id];
        delta.dx += cpd.x - lpd.x;
        delta.dy += cpd.y - lpd.y;

        if (first) {
            commonDeltaRawX = delta.dx;
            commonDeltaRawY = delta.dy;
        } else {
            commonDeltaRawX = calculateCommonVector(commonDeltaRawX, delta.dx);
            commonDeltaRawY = calculateCommonVector(commonDeltaRawY, delta.dy);
        }
    }

    // Consider transitions from PRESS to SWIPE or MULTITOUCH.
    if (mPointerGesture.currentGestureMode == PointerGesture::Mode::PRESS) {
        float dist[MAX_POINTER_ID + 1];
        int32_t distOverThreshold = 0;
        for (BitSet32 idBits(mPointerGesture.referenceIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            PointerGesture::Delta& delta = mPointerGesture.referenceDeltas[id];
            dist[id] = hypotf(delta.dx * mPointerXZoomScale, delta.dy * mPointerYZoomScale);
            if (dist[id] > mConfig.pointerGestureMultitouchMinDistance) {
                distOverThreshold += 1;
            }
        }

        // Only transition when at least two pointers have moved further than
        // the minimum distance threshold.
        if (distOverThreshold >= 2) {
            if (currentFingerCount > 2) {
                // There are more than two pointers, switch to FREEFORM.
                ALOGD_IF(DEBUG_GESTURES,
                         "Gestures: PRESS transitioned to FREEFORM, number of pointers %d > 2",
                         currentFingerCount);
                *cancelPreviousGesture = true;
                mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
            } else {
                // There are exactly two pointers.
                BitSet32 idBits(mCurrentCookedState.fingerIdBits);
                uint32_t id1 = idBits.clearFirstMarkedBit();
                uint32_t id2 = idBits.firstMarkedBit();
                const RawPointerData::Pointer& p1 =
                        mCurrentRawState.rawPointerData.pointerForId(id1);
                const RawPointerData::Pointer& p2 =
                        mCurrentRawState.rawPointerData.pointerForId(id2);
                float mutualDistance = distance(p1.x, p1.y, p2.x, p2.y);
                if (mutualDistance > mPointerGestureMaxSwipeWidth) {
                    // There are two pointers but they are too far apart for a SWIPE,
                    // switch to FREEFORM.
                    ALOGD_IF(DEBUG_GESTURES,
                             "Gestures: PRESS transitioned to FREEFORM, distance %0.3f > %0.3f",
                             mutualDistance, mPointerGestureMaxSwipeWidth);
                    *cancelPreviousGesture = true;
                    mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
                } else {
                    // There are two pointers.  Wait for both pointers to start moving
                    // before deciding whether this is a SWIPE or FREEFORM gesture.
                    float dist1 = dist[id1];
                    float dist2 = dist[id2];
                    if (dist1 >= mConfig.pointerGestureMultitouchMinDistance &&
                        dist2 >= mConfig.pointerGestureMultitouchMinDistance) {
                        // Calculate the dot product of the displacement vectors.
                        // When the vectors are oriented in approximately the same direction,
                        // the angle betweeen them is near zero and the cosine of the angle
                        // approaches 1.0.  Recall that dot(v1, v2) = cos(angle) * mag(v1) *
                        // mag(v2).
                        PointerGesture::Delta& delta1 = mPointerGesture.referenceDeltas[id1];
                        PointerGesture::Delta& delta2 = mPointerGesture.referenceDeltas[id2];
                        float dx1 = delta1.dx * mPointerXZoomScale;
                        float dy1 = delta1.dy * mPointerYZoomScale;
                        float dx2 = delta2.dx * mPointerXZoomScale;
                        float dy2 = delta2.dy * mPointerYZoomScale;
                        float dot = dx1 * dx2 + dy1 * dy2;
                        float cosine = dot / (dist1 * dist2); // denominator always > 0
                        if (cosine >= mConfig.pointerGestureSwipeTransitionAngleCosine) {
                            // Pointers are moving in the same direction.  Switch to SWIPE.
                            ALOGD_IF(DEBUG_GESTURES,
                                     "Gestures: PRESS transitioned to SWIPE, "
                                     "dist1 %0.3f >= %0.3f, dist2 %0.3f >= %0.3f, "
                                     "cosine %0.3f >= %0.3f",
                                     dist1, mConfig.pointerGestureMultitouchMinDistance, dist2,
                                     mConfig.pointerGestureMultitouchMinDistance, cosine,
                                     mConfig.pointerGestureSwipeTransitionAngleCosine);
                            mPointerGesture.currentGestureMode = PointerGesture::Mode::SWIPE;
                        } else {
                            // Pointers are moving in different directions.  Switch to FREEFORM.
                            ALOGD_IF(DEBUG_GESTURES,
                                     "Gestures: PRESS transitioned to FREEFORM, "
                                     "dist1 %0.3f >= %0.3f, dist2 %0.3f >= %0.3f, "
                                     "cosine %0.3f < %0.3f",
                                     dist1, mConfig.pointerGestureMultitouchMinDistance, dist2,
                                     mConfig.pointerGestureMultitouchMinDistance, cosine,
                                     mConfig.pointerGestureSwipeTransitionAngleCosine);
                            *cancelPreviousGesture = true;
                            mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
                        }
                    }
                }
            }
        }
    } else if (mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE) {
        // Switch from SWIPE to FREEFORM if additional pointers go down.
        // Cancel previous gesture.
        if (currentFingerCount > 2) {
            ALOGD_IF(DEBUG_GESTURES,
                     "Gestures: SWIPE transitioned to FREEFORM, number of pointers %d > 2",
                     currentFingerCount);
            *cancelPreviousGesture = true;
            mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
        }
    }

    // Move the reference points based on the overall group motion of the fingers
    // except in PRESS mode while waiting for a transition to occur.
    if (mPointerGesture.currentGestureMode != PointerGesture::Mode::PRESS &&
        (commonDeltaRawX || commonDeltaRawY)) {
        for (BitSet32 idBits(mPointerGesture.referenceIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            PointerGesture::Delta& delta = mPointerGesture.referenceDeltas[id];
            delta.dx = 0;
            delta.dy = 0;
        }

        mPointerGesture.referenceTouchX += commonDeltaRawX;
        mPointerGesture.referenceTouchY += commonDeltaRawY;

        float commonDeltaX = commonDeltaRawX * mPointerXMovementScale;
        float commonDeltaY = commonDeltaRawY * mPointerYMovementScale;

        rotateDelta(mInputDeviceOrientation, &commonDeltaX, &commonDeltaY);
        mPointerVelocityControl.move(when, &commonDeltaX, &commonDeltaY);

        mPointerGesture.referenceGestureX += commonDeltaX;
        mPointerGesture.referenceGestureY += commonDeltaY;
    }

    // Report gestures.
    if (mPointerGesture.currentGestureMode == PointerGesture::Mode::PRESS ||
        mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE) {
        // PRESS or SWIPE mode.
        ALOGD_IF(DEBUG_GESTURES,
                 "Gestures: PRESS or SWIPE activeTouchId=%d, activeGestureId=%d, "
                 "currentTouchPointerCount=%d",
                 activeTouchId, mPointerGesture.activeGestureId, currentFingerCount);
        ALOG_ASSERT(mPointerGesture.activeGestureId >= 0);

        mPointerGesture.currentGestureIdBits.clear();
        mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
        mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
        mPointerGesture.currentGestureProperties[0].clear();
        mPointerGesture.currentGestureProperties[0].id = mPointerGesture.activeGestureId;
        mPointerGesture.currentGestureProperties[0].toolType = ToolType::FINGER;
        mPointerGesture.currentGestureCoords[0].clear();
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                                             mPointerGesture.referenceGestureX);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y,
                                                             mPointerGesture.referenceGestureY);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
        if (mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE) {
            float xOffset = static_cast<float>(commonDeltaRawX) /
                    (mRawPointerAxes.x.maxValue - mRawPointerAxes.x.minValue);
            float yOffset = static_cast<float>(commonDeltaRawY) /
                    (mRawPointerAxes.y.maxValue - mRawPointerAxes.y.minValue);
            mPointerGesture.currentGestureCoords[0]
                    .setAxisValue(AMOTION_EVENT_AXIS_GESTURE_X_OFFSET, xOffset);
            mPointerGesture.currentGestureCoords[0]
                    .setAxisValue(AMOTION_EVENT_AXIS_GESTURE_Y_OFFSET, yOffset);
        }
    } else if (mPointerGesture.currentGestureMode == PointerGesture::Mode::FREEFORM) {
        // FREEFORM mode.
        ALOGD_IF(DEBUG_GESTURES,
                 "Gestures: FREEFORM activeTouchId=%d, activeGestureId=%d, "
                 "currentTouchPointerCount=%d",
                 activeTouchId, mPointerGesture.activeGestureId, currentFingerCount);
        ALOG_ASSERT(mPointerGesture.activeGestureId >= 0);

        mPointerGesture.currentGestureIdBits.clear();

        BitSet32 mappedTouchIdBits;
        BitSet32 usedGestureIdBits;
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::FREEFORM) {
            // Initially, assign the active gesture id to the active touch point
            // if there is one.  No other touch id bits are mapped yet.
            if (!*cancelPreviousGesture) {
                mappedTouchIdBits.markBit(activeTouchId);
                usedGestureIdBits.markBit(mPointerGesture.activeGestureId);
                mPointerGesture.freeformTouchToGestureIdMap[activeTouchId] =
                        mPointerGesture.activeGestureId;
            } else {
                mPointerGesture.activeGestureId = -1;
            }
        } else {
            // Otherwise, assume we mapped all touches from the previous frame.
            // Reuse all mappings that are still applicable.
            mappedTouchIdBits.value =
                    mLastCookedState.fingerIdBits.value & mCurrentCookedState.fingerIdBits.value;
            usedGestureIdBits = mPointerGesture.lastGestureIdBits;

            // Check whether we need to choose a new active gesture id because the
            // current went went up.
            for (BitSet32 upTouchIdBits(mLastCookedState.fingerIdBits.value &
                                        ~mCurrentCookedState.fingerIdBits.value);
                 !upTouchIdBits.isEmpty();) {
                uint32_t upTouchId = upTouchIdBits.clearFirstMarkedBit();
                uint32_t upGestureId = mPointerGesture.freeformTouchToGestureIdMap[upTouchId];
                if (upGestureId == uint32_t(mPointerGesture.activeGestureId)) {
                    mPointerGesture.activeGestureId = -1;
                    break;
                }
            }
        }

        ALOGD_IF(DEBUG_GESTURES,
                 "Gestures: FREEFORM follow up mappedTouchIdBits=0x%08x, usedGestureIdBits=0x%08x, "
                 "activeGestureId=%d",
                 mappedTouchIdBits.value, usedGestureIdBits.value, mPointerGesture.activeGestureId);

        BitSet32 idBits(mCurrentCookedState.fingerIdBits);
        for (uint32_t i = 0; i < currentFingerCount; i++) {
            uint32_t touchId = idBits.clearFirstMarkedBit();
            uint32_t gestureId;
            if (!mappedTouchIdBits.hasBit(touchId)) {
                gestureId = usedGestureIdBits.markFirstUnmarkedBit();
                mPointerGesture.freeformTouchToGestureIdMap[touchId] = gestureId;
                ALOGD_IF(DEBUG_GESTURES,
                         "Gestures: FREEFORM new mapping for touch id %d -> gesture id %d", touchId,
                         gestureId);
            } else {
                gestureId = mPointerGesture.freeformTouchToGestureIdMap[touchId];
                ALOGD_IF(DEBUG_GESTURES,
                         "Gestures: FREEFORM existing mapping for touch id %d -> gesture id %d",
                         touchId, gestureId);
            }
            mPointerGesture.currentGestureIdBits.markBit(gestureId);
            mPointerGesture.currentGestureIdToIndex[gestureId] = i;

            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(touchId);
            float deltaX = (pointer.x - mPointerGesture.referenceTouchX) * mPointerXZoomScale;
            float deltaY = (pointer.y - mPointerGesture.referenceTouchY) * mPointerYZoomScale;
            rotateDelta(mInputDeviceOrientation, &deltaX, &deltaY);

            mPointerGesture.currentGestureProperties[i].clear();
            mPointerGesture.currentGestureProperties[i].id = gestureId;
            mPointerGesture.currentGestureProperties[i].toolType = ToolType::FINGER;
            mPointerGesture.currentGestureCoords[i].clear();
            mPointerGesture.currentGestureCoords[i].setAxisValue(AMOTION_EVENT_AXIS_X,
                                                                 mPointerGesture.referenceGestureX +
                                                                         deltaX);
            mPointerGesture.currentGestureCoords[i].setAxisValue(AMOTION_EVENT_AXIS_Y,
                                                                 mPointerGesture.referenceGestureY +
                                                                         deltaY);
            mPointerGesture.currentGestureCoords[i].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
        }

        if (mPointerGesture.activeGestureId < 0) {
            mPointerGesture.activeGestureId = mPointerGesture.currentGestureIdBits.firstMarkedBit();
            ALOGD_IF(DEBUG_GESTURES, "Gestures: FREEFORM new activeGestureId=%d",
                     mPointerGesture.activeGestureId);
        }
    }
}

void TouchInputMapper::moveMousePointerFromPointerDelta(nsecs_t when, uint32_t pointerId) {
    const RawPointerData::Pointer& currentPointer =
            mCurrentRawState.rawPointerData.pointerForId(pointerId);
    const RawPointerData::Pointer& lastPointer =
            mLastRawState.rawPointerData.pointerForId(pointerId);
    float deltaX = (currentPointer.x - lastPointer.x) * mPointerXMovementScale;
    float deltaY = (currentPointer.y - lastPointer.y) * mPointerYMovementScale;

    rotateDelta(mInputDeviceOrientation, &deltaX, &deltaY);
    mPointerVelocityControl.move(when, &deltaX, &deltaY);

    mPointerController->move(deltaX, deltaY);
}

std::list<NotifyArgs> TouchInputMapper::dispatchPointerStylus(nsecs_t when, nsecs_t readTime,
                                                              uint32_t policyFlags) {
    mPointerSimple.currentCoords.clear();
    mPointerSimple.currentProperties.clear();

    bool down, hovering;
    if (!mCurrentCookedState.stylusIdBits.isEmpty()) {
        uint32_t id = mCurrentCookedState.stylusIdBits.firstMarkedBit();
        uint32_t index = mCurrentCookedState.cookedPointerData.idToIndex[id];
        hovering = mCurrentCookedState.cookedPointerData.hoveringIdBits.hasBit(id);
        down = !hovering;

        float x = mCurrentCookedState.cookedPointerData.pointerCoords[index].getX();
        float y = mCurrentCookedState.cookedPointerData.pointerCoords[index].getY();
        // Styluses are configured specifically for one display. We only update the
        // PointerController for this stylus if the PointerController is configured for
        // the same display as this stylus,
        if (getAssociatedDisplayId() == mViewport.displayId) {
            mPointerController->setPosition(x, y);
            std::tie(x, y) = mPointerController->getPosition();
        }

        mPointerSimple.currentCoords.copyFrom(
                mCurrentCookedState.cookedPointerData.pointerCoords[index]);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerSimple.currentProperties.id = 0;
        mPointerSimple.currentProperties.toolType =
                mCurrentCookedState.cookedPointerData.pointerProperties[index].toolType;
    } else {
        down = false;
        hovering = false;
    }

    return dispatchPointerSimple(when, readTime, policyFlags, down, hovering, mViewport.displayId);
}

std::list<NotifyArgs> TouchInputMapper::abortPointerStylus(nsecs_t when, nsecs_t readTime,
                                                           uint32_t policyFlags) {
    return abortPointerSimple(when, readTime, policyFlags);
}

std::list<NotifyArgs> TouchInputMapper::dispatchPointerMouse(nsecs_t when, nsecs_t readTime,
                                                             uint32_t policyFlags) {
    mPointerSimple.currentCoords.clear();
    mPointerSimple.currentProperties.clear();

    bool down, hovering;
    if (!mCurrentCookedState.mouseIdBits.isEmpty()) {
        uint32_t id = mCurrentCookedState.mouseIdBits.firstMarkedBit();
        if (mLastCookedState.mouseIdBits.hasBit(id)) {
            moveMousePointerFromPointerDelta(when, id);
        } else {
            mPointerVelocityControl.reset();
        }

        down = isPointerDown(mCurrentRawState.buttonState);
        hovering = !down;

        const auto [x, y] = mPointerController->getPosition();
        const uint32_t currentIndex = mCurrentRawState.rawPointerData.idToIndex[id];
        mPointerSimple.currentCoords.copyFrom(
                mCurrentCookedState.cookedPointerData.pointerCoords[currentIndex]);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE,
                                                  hovering ? 0.0f : 1.0f);
        mPointerSimple.currentProperties.id = 0;
        mPointerSimple.currentProperties.toolType =
                mCurrentCookedState.cookedPointerData.pointerProperties[currentIndex].toolType;
    } else {
        mPointerVelocityControl.reset();

        down = false;
        hovering = false;
    }

    const int32_t displayId = mPointerController->getDisplayId();
    return dispatchPointerSimple(when, readTime, policyFlags, down, hovering, displayId);
}

std::list<NotifyArgs> TouchInputMapper::abortPointerMouse(nsecs_t when, nsecs_t readTime,
                                                          uint32_t policyFlags) {
    std::list<NotifyArgs> out = abortPointerSimple(when, readTime, policyFlags);

    mPointerVelocityControl.reset();

    return out;
}

std::list<NotifyArgs> TouchInputMapper::dispatchPointerSimple(nsecs_t when, nsecs_t readTime,
                                                              uint32_t policyFlags, bool down,
                                                              bool hovering, int32_t displayId) {
    LOG_ALWAYS_FATAL_IF(mDeviceMode != DeviceMode::POINTER,
                        "%s cannot be used when the device is not in POINTER mode.", __func__);
    std::list<NotifyArgs> out;
    int32_t metaState = getContext()->getGlobalMetaState();
    auto cursorPosition = mPointerSimple.currentCoords.getXYValue();

    if (displayId == mPointerController->getDisplayId()) {
        std::tie(cursorPosition.x, cursorPosition.y) = mPointerController->getPosition();
        if (down || hovering) {
            mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
            mPointerController->clearSpots();
            mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
        } else if (!down && !hovering && (mPointerSimple.down || mPointerSimple.hovering)) {
            mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
        }
    }

    if (mPointerSimple.down && !down) {
        mPointerSimple.down = false;

        // Send up.
        out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                       mSource, displayId, policyFlags, AMOTION_EVENT_ACTION_UP, 0,
                                       0, metaState, mLastRawState.buttonState,
                                       MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                       &mPointerSimple.lastProperties, &mPointerSimple.lastCoords,
                                       mOrientedXPrecision, mOrientedYPrecision,
                                       mPointerSimple.lastCursorX, mPointerSimple.lastCursorY,
                                       mPointerSimple.downTime,
                                       /* videoFrames */ {}));
    }

    if (mPointerSimple.hovering && !hovering) {
        mPointerSimple.hovering = false;

        // Send hover exit.
        out.push_back(
                NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(), mSource,
                                 displayId, policyFlags, AMOTION_EVENT_ACTION_HOVER_EXIT, 0, 0,
                                 metaState, mLastRawState.buttonState, MotionClassification::NONE,
                                 AMOTION_EVENT_EDGE_FLAG_NONE, 1, &mPointerSimple.lastProperties,
                                 &mPointerSimple.lastCoords, mOrientedXPrecision,
                                 mOrientedYPrecision, mPointerSimple.lastCursorX,
                                 mPointerSimple.lastCursorY, mPointerSimple.downTime,
                                 /* videoFrames */ {}));
    }

    if (down) {
        if (!mPointerSimple.down) {
            mPointerSimple.down = true;
            mPointerSimple.downTime = when;

            // Send down.
            out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                           mSource, displayId, policyFlags,
                                           AMOTION_EVENT_ACTION_DOWN, 0, 0, metaState,
                                           mCurrentRawState.buttonState, MotionClassification::NONE,
                                           AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                           &mPointerSimple.currentProperties,
                                           &mPointerSimple.currentCoords, mOrientedXPrecision,
                                           mOrientedYPrecision, cursorPosition.x, cursorPosition.y,
                                           mPointerSimple.downTime, /* videoFrames */ {}));
        }

        // Send move.
        out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                       mSource, displayId, policyFlags, AMOTION_EVENT_ACTION_MOVE,
                                       0, 0, metaState, mCurrentRawState.buttonState,
                                       MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                       &mPointerSimple.currentProperties,
                                       &mPointerSimple.currentCoords, mOrientedXPrecision,
                                       mOrientedYPrecision, cursorPosition.x, cursorPosition.y,
                                       mPointerSimple.downTime, /* videoFrames */ {}));
    }

    if (hovering) {
        if (!mPointerSimple.hovering) {
            mPointerSimple.hovering = true;

            // Send hover enter.
            out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                           mSource, displayId, policyFlags,
                                           AMOTION_EVENT_ACTION_HOVER_ENTER, 0, 0, metaState,
                                           mCurrentRawState.buttonState, MotionClassification::NONE,
                                           AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                           &mPointerSimple.currentProperties,
                                           &mPointerSimple.currentCoords, mOrientedXPrecision,
                                           mOrientedYPrecision, cursorPosition.x, cursorPosition.y,
                                           mPointerSimple.downTime, /* videoFrames */ {}));
        }

        // Send hover move.
        out.push_back(
                NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(), mSource,
                                 displayId, policyFlags, AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0,
                                 metaState, mCurrentRawState.buttonState,
                                 MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                 &mPointerSimple.currentProperties, &mPointerSimple.currentCoords,
                                 mOrientedXPrecision, mOrientedYPrecision, cursorPosition.x,
                                 cursorPosition.y, mPointerSimple.downTime, /* videoFrames */ {}));
    }

    if (mCurrentRawState.rawVScroll || mCurrentRawState.rawHScroll) {
        float vscroll = mCurrentRawState.rawVScroll;
        float hscroll = mCurrentRawState.rawHScroll;
        mWheelYVelocityControl.move(when, nullptr, &vscroll);
        mWheelXVelocityControl.move(when, &hscroll, nullptr);

        // Send scroll.
        PointerCoords pointerCoords;
        pointerCoords.copyFrom(mPointerSimple.currentCoords);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_VSCROLL, vscroll);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_HSCROLL, hscroll);

        out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                       mSource, displayId, policyFlags, AMOTION_EVENT_ACTION_SCROLL,
                                       0, 0, metaState, mCurrentRawState.buttonState,
                                       MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                       &mPointerSimple.currentProperties, &pointerCoords,
                                       mOrientedXPrecision, mOrientedYPrecision, cursorPosition.x,
                                       cursorPosition.y, mPointerSimple.downTime,
                                       /* videoFrames */ {}));
    }

    // Save state.
    if (down || hovering) {
        mPointerSimple.lastCoords.copyFrom(mPointerSimple.currentCoords);
        mPointerSimple.lastProperties.copyFrom(mPointerSimple.currentProperties);
        mPointerSimple.displayId = displayId;
        mPointerSimple.source = mSource;
        mPointerSimple.lastCursorX = cursorPosition.x;
        mPointerSimple.lastCursorY = cursorPosition.y;
    } else {
        mPointerSimple.reset();
    }
    return out;
}

std::list<NotifyArgs> TouchInputMapper::abortPointerSimple(nsecs_t when, nsecs_t readTime,
                                                           uint32_t policyFlags) {
    std::list<NotifyArgs> out;
    if (mPointerSimple.down || mPointerSimple.hovering) {
        int32_t metaState = getContext()->getGlobalMetaState();
        out.push_back(NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                       mPointerSimple.source, mPointerSimple.displayId, policyFlags,
                                       AMOTION_EVENT_ACTION_CANCEL, 0, AMOTION_EVENT_FLAG_CANCELED,
                                       metaState, mLastRawState.buttonState,
                                       MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                       &mPointerSimple.lastProperties, &mPointerSimple.lastCoords,
                                       mOrientedXPrecision, mOrientedYPrecision,
                                       mPointerSimple.lastCursorX, mPointerSimple.lastCursorY,
                                       mPointerSimple.downTime,
                                       /* videoFrames */ {}));
        if (mPointerController != nullptr) {
            mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
        }
    }
    mPointerSimple.reset();
    return out;
}

static bool isStylusEvent(uint32_t source, int32_t action, const PointerProperties* properties) {
    if (!isFromSource(source, AINPUT_SOURCE_STYLUS)) {
        return false;
    }
    const auto actionIndex = action >> AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
    return isStylusToolType(properties[actionIndex].toolType);
}

NotifyMotionArgs TouchInputMapper::dispatchMotion(
        nsecs_t when, nsecs_t readTime, uint32_t policyFlags, uint32_t source, int32_t action,
        int32_t actionButton, int32_t flags, int32_t metaState, int32_t buttonState,
        int32_t edgeFlags, const PropertiesArray& properties, const CoordsArray& coords,
        const IdToIndexArray& idToIndex, BitSet32 idBits, int32_t changedId, float xPrecision,
        float yPrecision, nsecs_t downTime, MotionClassification classification) {
    PointerCoords pointerCoords[MAX_POINTERS];
    PointerProperties pointerProperties[MAX_POINTERS];
    uint32_t pointerCount = 0;
    while (!idBits.isEmpty()) {
        uint32_t id = idBits.clearFirstMarkedBit();
        uint32_t index = idToIndex[id];
        pointerProperties[pointerCount].copyFrom(properties[index]);
        pointerCoords[pointerCount].copyFrom(coords[index]);

        if (changedId >= 0 && id == uint32_t(changedId)) {
            action |= pointerCount << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
        }

        pointerCount += 1;
    }

    ALOG_ASSERT(pointerCount != 0);

    if (changedId >= 0 && pointerCount == 1) {
        // Replace initial down and final up action.
        // We can compare the action without masking off the changed pointer index
        // because we know the index is 0.
        if (action == AMOTION_EVENT_ACTION_POINTER_DOWN) {
            action = AMOTION_EVENT_ACTION_DOWN;
        } else if (action == AMOTION_EVENT_ACTION_POINTER_UP) {
            if ((flags & AMOTION_EVENT_FLAG_CANCELED) != 0) {
                action = AMOTION_EVENT_ACTION_CANCEL;
            } else {
                action = AMOTION_EVENT_ACTION_UP;
            }
        } else {
            // Can't happen.
            ALOG_ASSERT(false);
        }
    }

    const int32_t displayId = getAssociatedDisplayId().value_or(ADISPLAY_ID_NONE);
    const bool showDirectStylusPointer = mConfig.stylusPointerIconEnabled &&
            mDeviceMode == DeviceMode::DIRECT && isStylusEvent(source, action, pointerProperties) &&
            mPointerController && displayId != ADISPLAY_ID_NONE &&
            displayId == mPointerController->getDisplayId();
    if (showDirectStylusPointer) {
        switch (action & AMOTION_EVENT_ACTION_MASK) {
            case AMOTION_EVENT_ACTION_HOVER_ENTER:
            case AMOTION_EVENT_ACTION_HOVER_MOVE:
                mPointerController->setPresentation(
                        PointerControllerInterface::Presentation::STYLUS_HOVER);
                mPointerController
                        ->setPosition(mCurrentCookedState.cookedPointerData.pointerCoords[0].getX(),
                                      mCurrentCookedState.cookedPointerData.pointerCoords[0]
                                              .getY());
                mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
                break;
            case AMOTION_EVENT_ACTION_HOVER_EXIT:
                mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
                break;
        }
    }

    float xCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    float yCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    if (mDeviceMode == DeviceMode::POINTER) {
        std::tie(xCursorPosition, yCursorPosition) = mPointerController->getPosition();
    }
    const int32_t deviceId = getDeviceId();
    std::vector<TouchVideoFrame> frames = getDeviceContext().getVideoFrames();
    std::for_each(frames.begin(), frames.end(),
                  [this](TouchVideoFrame& frame) { frame.rotate(this->mInputDeviceOrientation); });
    return NotifyMotionArgs(getContext()->getNextId(), when, readTime, deviceId, source, displayId,
                            policyFlags, action, actionButton, flags, metaState, buttonState,
                            classification, edgeFlags, pointerCount, pointerProperties,
                            pointerCoords, xPrecision, yPrecision, xCursorPosition, yCursorPosition,
                            downTime, std::move(frames));
}

std::list<NotifyArgs> TouchInputMapper::cancelTouch(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;
    out += abortPointerUsage(when, readTime, /*policyFlags=*/0);
    out += abortTouches(when, readTime, /* policyFlags=*/0);
    return out;
}

bool TouchInputMapper::isPointInsidePhysicalFrame(int32_t x, int32_t y) const {
    return x >= mRawPointerAxes.x.minValue && x <= mRawPointerAxes.x.maxValue &&
            y >= mRawPointerAxes.y.minValue && y <= mRawPointerAxes.y.maxValue &&
            isPointInRect(mPhysicalFrameInRotatedDisplay, mRawToRotatedDisplay.transform(x, y));
}

const TouchInputMapper::VirtualKey* TouchInputMapper::findVirtualKeyHit(int32_t x, int32_t y) {
    for (const VirtualKey& virtualKey : mVirtualKeys) {
        ALOGD_IF(DEBUG_VIRTUAL_KEYS,
                 "VirtualKeys: Hit test (%d, %d): keyCode=%d, scanCode=%d, "
                 "left=%d, top=%d, right=%d, bottom=%d",
                 x, y, virtualKey.keyCode, virtualKey.scanCode, virtualKey.hitLeft,
                 virtualKey.hitTop, virtualKey.hitRight, virtualKey.hitBottom);

        if (virtualKey.isHit(x, y)) {
            return &virtualKey;
        }
    }

    return nullptr;
}

void TouchInputMapper::assignPointerIds(const RawState& last, RawState& current) {
    uint32_t currentPointerCount = current.rawPointerData.pointerCount;
    uint32_t lastPointerCount = last.rawPointerData.pointerCount;

    current.rawPointerData.clearIdBits();

    if (currentPointerCount == 0) {
        // No pointers to assign.
        return;
    }

    if (lastPointerCount == 0) {
        // All pointers are new.
        for (uint32_t i = 0; i < currentPointerCount; i++) {
            uint32_t id = i;
            current.rawPointerData.pointers[i].id = id;
            current.rawPointerData.idToIndex[id] = i;
            current.rawPointerData.markIdBit(id, current.rawPointerData.isHovering(i));
        }
        return;
    }

    if (currentPointerCount == 1 && lastPointerCount == 1 &&
        current.rawPointerData.pointers[0].toolType == last.rawPointerData.pointers[0].toolType) {
        // Only one pointer and no change in count so it must have the same id as before.
        uint32_t id = last.rawPointerData.pointers[0].id;
        current.rawPointerData.pointers[0].id = id;
        current.rawPointerData.idToIndex[id] = 0;
        current.rawPointerData.markIdBit(id, current.rawPointerData.isHovering(0));
        return;
    }

    // General case.
    // We build a heap of squared euclidean distances between current and last pointers
    // associated with the current and last pointer indices.  Then, we find the best
    // match (by distance) for each current pointer.
    // The pointers must have the same tool type but it is possible for them to
    // transition from hovering to touching or vice-versa while retaining the same id.
    PointerDistanceHeapElement heap[MAX_POINTERS * MAX_POINTERS];

    uint32_t heapSize = 0;
    for (uint32_t currentPointerIndex = 0; currentPointerIndex < currentPointerCount;
         currentPointerIndex++) {
        for (uint32_t lastPointerIndex = 0; lastPointerIndex < lastPointerCount;
             lastPointerIndex++) {
            const RawPointerData::Pointer& currentPointer =
                    current.rawPointerData.pointers[currentPointerIndex];
            const RawPointerData::Pointer& lastPointer =
                    last.rawPointerData.pointers[lastPointerIndex];
            if (currentPointer.toolType == lastPointer.toolType) {
                int64_t deltaX = currentPointer.x - lastPointer.x;
                int64_t deltaY = currentPointer.y - lastPointer.y;

                uint64_t distance = uint64_t(deltaX * deltaX + deltaY * deltaY);

                // Insert new element into the heap (sift up).
                heap[heapSize].currentPointerIndex = currentPointerIndex;
                heap[heapSize].lastPointerIndex = lastPointerIndex;
                heap[heapSize].distance = distance;
                heapSize += 1;
            }
        }
    }

    // Heapify
    for (uint32_t startIndex = heapSize / 2; startIndex != 0;) {
        startIndex -= 1;
        for (uint32_t parentIndex = startIndex;;) {
            uint32_t childIndex = parentIndex * 2 + 1;
            if (childIndex >= heapSize) {
                break;
            }

            if (childIndex + 1 < heapSize &&
                heap[childIndex + 1].distance < heap[childIndex].distance) {
                childIndex += 1;
            }

            if (heap[parentIndex].distance <= heap[childIndex].distance) {
                break;
            }

            swap(heap[parentIndex], heap[childIndex]);
            parentIndex = childIndex;
        }
    }

    if (DEBUG_POINTER_ASSIGNMENT) {
        ALOGD("assignPointerIds - initial distance min-heap: size=%d", heapSize);
        for (size_t i = 0; i < heapSize; i++) {
            ALOGD("  heap[%zu]: cur=%" PRIu32 ", last=%" PRIu32 ", distance=%" PRIu64, i,
                  heap[i].currentPointerIndex, heap[i].lastPointerIndex, heap[i].distance);
        }
    }

    // Pull matches out by increasing order of distance.
    // To avoid reassigning pointers that have already been matched, the loop keeps track
    // of which last and current pointers have been matched using the matchedXXXBits variables.
    // It also tracks the used pointer id bits.
    BitSet32 matchedLastBits(0);
    BitSet32 matchedCurrentBits(0);
    BitSet32 usedIdBits(0);
    bool first = true;
    for (uint32_t i = min(currentPointerCount, lastPointerCount); heapSize > 0 && i > 0; i--) {
        while (heapSize > 0) {
            if (first) {
                // The first time through the loop, we just consume the root element of
                // the heap (the one with smallest distance).
                first = false;
            } else {
                // Previous iterations consumed the root element of the heap.
                // Pop root element off of the heap (sift down).
                heap[0] = heap[heapSize];
                for (uint32_t parentIndex = 0;;) {
                    uint32_t childIndex = parentIndex * 2 + 1;
                    if (childIndex >= heapSize) {
                        break;
                    }

                    if (childIndex + 1 < heapSize &&
                        heap[childIndex + 1].distance < heap[childIndex].distance) {
                        childIndex += 1;
                    }

                    if (heap[parentIndex].distance <= heap[childIndex].distance) {
                        break;
                    }

                    swap(heap[parentIndex], heap[childIndex]);
                    parentIndex = childIndex;
                }

                if (DEBUG_POINTER_ASSIGNMENT) {
                    ALOGD("assignPointerIds - reduced distance min-heap: size=%d", heapSize);
                    for (size_t j = 0; j < heapSize; j++) {
                        ALOGD("  heap[%zu]: cur=%" PRIu32 ", last=%" PRIu32 ", distance=%" PRIu64,
                              j, heap[j].currentPointerIndex, heap[j].lastPointerIndex,
                              heap[j].distance);
                    }
                }
            }

            heapSize -= 1;

            uint32_t currentPointerIndex = heap[0].currentPointerIndex;
            if (matchedCurrentBits.hasBit(currentPointerIndex)) continue; // already matched

            uint32_t lastPointerIndex = heap[0].lastPointerIndex;
            if (matchedLastBits.hasBit(lastPointerIndex)) continue; // already matched

            matchedCurrentBits.markBit(currentPointerIndex);
            matchedLastBits.markBit(lastPointerIndex);

            uint32_t id = last.rawPointerData.pointers[lastPointerIndex].id;
            current.rawPointerData.pointers[currentPointerIndex].id = id;
            current.rawPointerData.idToIndex[id] = currentPointerIndex;
            current.rawPointerData.markIdBit(id,
                                             current.rawPointerData.isHovering(
                                                     currentPointerIndex));
            usedIdBits.markBit(id);

            ALOGD_IF(DEBUG_POINTER_ASSIGNMENT,
                     "assignPointerIds - matched: cur=%" PRIu32 ", last=%" PRIu32 ", id=%" PRIu32
                     ", distance=%" PRIu64,
                     lastPointerIndex, currentPointerIndex, id, heap[0].distance);
            break;
        }
    }

    // Assign fresh ids to pointers that were not matched in the process.
    for (uint32_t i = currentPointerCount - matchedCurrentBits.count(); i != 0; i--) {
        uint32_t currentPointerIndex = matchedCurrentBits.markFirstUnmarkedBit();
        uint32_t id = usedIdBits.markFirstUnmarkedBit();

        current.rawPointerData.pointers[currentPointerIndex].id = id;
        current.rawPointerData.idToIndex[id] = currentPointerIndex;
        current.rawPointerData.markIdBit(id,
                                         current.rawPointerData.isHovering(currentPointerIndex));

        ALOGD_IF(DEBUG_POINTER_ASSIGNMENT,
                 "assignPointerIds - assigned: cur=%" PRIu32 ", id=%" PRIu32, currentPointerIndex,
                 id);
    }
}

int32_t TouchInputMapper::getKeyCodeState(uint32_t sourceMask, int32_t keyCode) {
    if (mCurrentVirtualKey.down && mCurrentVirtualKey.keyCode == keyCode) {
        return AKEY_STATE_VIRTUAL;
    }

    for (const VirtualKey& virtualKey : mVirtualKeys) {
        if (virtualKey.keyCode == keyCode) {
            return AKEY_STATE_UP;
        }
    }

    return AKEY_STATE_UNKNOWN;
}

int32_t TouchInputMapper::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    if (mCurrentVirtualKey.down && mCurrentVirtualKey.scanCode == scanCode) {
        return AKEY_STATE_VIRTUAL;
    }

    for (const VirtualKey& virtualKey : mVirtualKeys) {
        if (virtualKey.scanCode == scanCode) {
            return AKEY_STATE_UP;
        }
    }

    return AKEY_STATE_UNKNOWN;
}

bool TouchInputMapper::markSupportedKeyCodes(uint32_t sourceMask,
                                             const std::vector<int32_t>& keyCodes,
                                             uint8_t* outFlags) {
    for (const VirtualKey& virtualKey : mVirtualKeys) {
        for (size_t i = 0; i < keyCodes.size(); i++) {
            if (virtualKey.keyCode == keyCodes[i]) {
                outFlags[i] = 1;
            }
        }
    }

    return true;
}

std::optional<int32_t> TouchInputMapper::getAssociatedDisplayId() {
    if (mParameters.hasAssociatedDisplay) {
        if (mDeviceMode == DeviceMode::POINTER) {
            return std::make_optional(mPointerController->getDisplayId());
        } else {
            return std::make_optional(mViewport.displayId);
        }
    }
    return std::nullopt;
}

} // namespace android
