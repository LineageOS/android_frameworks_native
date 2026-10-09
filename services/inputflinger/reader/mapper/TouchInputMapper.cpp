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

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>

#include <math.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android/input.h>
#include <com_android_input_flags.h>
#include <ftl/enum.h>
#include <input/PrintTools.h>
#include <input/PropertyMap.h>
#include <input/VirtualKeyMap.h>
#include <linux/input-event-codes.h>
#include <log/log_main.h>
#include <math/vec2.h>
#include <ui/FloatRect.h>

#include "CursorButtonAccumulator.h"
#include "CursorScrollAccumulator.h"
#include "TouchButtonAccumulator.h"
#include "TouchCursorInputMapperCommon.h"
#include "ui/Rotation.h"

namespace android {

using std::chrono_literals::operator""ms;

namespace input_flags = com::android::input::flags;

// --- Constants ---

// Artificial latency on synthetic events created from stylus data without corresponding touch
// data.
static constexpr nsecs_t STYLUS_DATA_LATENCY = ms2ns(10);

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

std::ostream& operator<<(std::ostream& out, const RawPointerData::Pointer& p) {
    out << "id=" << p.id << ", x=" << p.x << ", y=" << p.y << ", pressure=" << p.pressure
        << ", touchMajor=" << p.touchMajor << ", touchMinor=" << p.touchMinor
        << ", toolMajor=" << p.toolMajor << ", toolMinor=" << p.toolMinor
        << ", orientation=" << p.orientation << ", tiltX=" << p.tiltX << ", tiltY=" << p.tiltY
        << ", distance=" << p.distance << ", toolType=" << ftl::enum_string(p.toolType)
        << ", isHovering=" << p.isHovering;
    return out;
}

std::ostream& operator<<(std::ostream& out, const RawPointerData& data) {
    out << data.pointerCount << " pointers:\n";
    for (uint32_t i = 0; i < data.pointerCount; i++) {
        out << INDENT << "[" << i << "]: " << data.pointers[i] << std::endl;
    }
    out << "ID bits: hovering = 0x" << std::hex << std::setfill('0') << std::setw(8)
        << data.hoveringIdBits.value << ", touching = 0x" << std::setfill('0') << std::setw(8)
        << data.touchingIdBits.value << ", canceled = 0x" << std::setfill('0') << std::setw(8)
        << data.canceledIdBits.value << std::dec;
    return out;
}

// --- TouchInputMapper::RawState ---

std::ostream& operator<<(std::ostream& out, const TouchInputMapper::RawState& state) {
    out << "When: " << state.when << std::endl;
    out << "Read time: " << state.readTime << std::endl;
    out << "Button state: 0x" << std::setfill('0') << std::setw(8) << std::hex << state.buttonState
        << std::dec << std::endl;
    out << "Raw pointer data:" << std::endl;
    out << addLinePrefix(streamableToString(state.rawPointerData), INDENT);
    return out;
}

// --- TouchInputMapper ---

TouchInputMapper::TouchInputMapper(InputDeviceContext& deviceContext,
                                   const InputReaderConfiguration& readerConfig)
      : InputMapper(deviceContext, readerConfig),
        mTouchButtonAccumulator(deviceContext),
        mConfig(readerConfig) {}

TouchInputMapper::~TouchInputMapper() {}

uint32_t TouchInputMapper::getSources() const {
    // The SOURCE_BLUETOOTH_STYLUS is added to events dynamically if the current stream is modified
    // by the external stylus state. That's why we don't add it directly to mSource during
    // configuration.
    return mSource |
            (mExternalStylusPresence == ExternalStylusPresence::TOUCH_FUSION
                     ? AINPUT_SOURCE_BLUETOOTH_STYLUS
                     : 0);
}

void TouchInputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    InputMapper::populateDeviceInfo(info);

    if (mDeviceMode == DeviceMode::DISABLED) {
        return;
    }

    info.addMotionRange(mOrientedRanges.x);
    info.addMotionRange(mOrientedRanges.y);
    info.addMotionRange(mOrientedRanges.pressure);

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
    dump += INDENT3 "Last Raw Touch:\n";
    dump += addLinePrefix(streamableToString(mLastRawState), INDENT4) + "\n";

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
    dump += StringPrintf(INDENT4 "ExternalStylusPresence: %s\n",
                         ftl::enum_string(mExternalStylusPresence).c_str());
    dump += StringPrintf(INDENT4 "Fused External Stylus Pointer ID: %s\n",
                         toString(mFusedStylusPointerId).c_str());
    dump += StringPrintf(INDENT4 "External Stylus Data Timeout: %" PRId64 "\n",
                         mExternalStylusFusionTimeout);
    dump += StringPrintf(INDENT4 "External Stylus Buttons Applied: 0x%08x\n",
                         mExternalStylusButtonsApplied);
    dump += INDENT3 "External Stylus State:\n";
    dumpStylusState(dump, mExternalStylusState);
}

std::list<NotifyArgs> TouchInputMapper::reconfigure(nsecs_t when,
                                                    const InputReaderConfiguration& config,
                                                    ConfigurationChanges changes) {
    std::list<NotifyArgs> out = InputMapper::reconfigure(when, config, changes);

    std::optional<ui::LogicalDisplayId> previousDisplayId = getAssociatedDisplayId();

    mConfig = config;

    // Full configuration should happen the first time configure is called or when the overrides
    // for the .idc properties of the device have changed. Changing a device configuration can
    // affect various other parameters so should result in a total reconfiguration.
    if (!changes.any() ||
        changes.test(InputReaderConfiguration::Change::DEVICE_CONFIGURATION_OVERRIDES)) {
        // Configure basic parameters.
        mParameters = computeParameters(getDeviceContext());

        // Configure common accumulators.
        mTouchButtonAccumulator.configure();

        // Configure absolute axis information.
        configureRawPointerAxes();

        // Prepare input device calibration.
        parseCalibration();
        resolveCalibration();
    }

    if (!changes.any() ||
        changes.test(InputReaderConfiguration::Change::TOUCH_AFFINE_TRANSFORMATION)) {
        // Update location calibration to reflect current settings
        updateAffineTransformation();
    }

    using namespace ftl::flag_operators;
    bool resetNeeded = false;
    if (!changes.any() ||
        changes.any(InputReaderConfiguration::Change::DISPLAY_INFO |
                    InputReaderConfiguration::Change::POINTER_CAPTURE |
                    InputReaderConfiguration::Change::POINTER_GESTURE_ENABLEMENT |
                    InputReaderConfiguration::Change::EXTERNAL_STYLUS_PRESENCE |
                    InputReaderConfiguration::Change::DEVICE_CONFIGURATION_OVERRIDES)) {
        // Configure device sources, display dimensions, orientation and
        // scaling factors.
        configureInputDevice(when, &resetNeeded);
    }

    if (changes.any() && resetNeeded) {
        // Touches should be aborted using the previous display id, so that the stream is consistent
        out += abortTouches(when, when, /*policyFlags=*/0, previousDisplayId);
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
    if (devices.empty()) {
        mExternalStylusPresence = ExternalStylusPresence::NONE;
        resetExternalStylus();
        return;
    }
    mExternalStylusPresence =
            std::any_of(devices.begin(), devices.end(),
                        [](const auto& info) {
                            return info.getMotionRange(AMOTION_EVENT_AXIS_PRESSURE,
                                                       AINPUT_SOURCE_STYLUS) != nullptr;
                        })
            ? ExternalStylusPresence::TOUCH_FUSION
            : ExternalStylusPresence::BUTTON_FUSION;
}

TouchInputMapper::Parameters TouchInputMapper::computeParameters(
        const InputDeviceContext& deviceContext) {
    Parameters parameters;
    const PropertyMap& config = deviceContext.getConfiguration();
    parameters.deviceType = computeDeviceType(deviceContext);

    parameters.orientationAware =
            config.getBool("touch.orientationAware")
                    .value_or(parameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN);

    parameters.orientation = ui::ROTATION_0;
    std::optional<std::string> orientationString = config.getString("touch.orientation");
    if (orientationString.has_value()) {
        if (parameters.deviceType != Parameters::DeviceType::TOUCH_SCREEN) {
            ALOGW("The configuration 'touch.orientation' is only supported for touchscreens.");
        } else if (*orientationString == "ORIENTATION_90") {
            parameters.orientation = ui::ROTATION_90;
        } else if (*orientationString == "ORIENTATION_180") {
            parameters.orientation = ui::ROTATION_180;
        } else if (*orientationString == "ORIENTATION_270") {
            parameters.orientation = ui::ROTATION_270;
        } else if (*orientationString != "ORIENTATION_0") {
            ALOGW("Invalid value for touch.orientation: '%s'", orientationString->c_str());
        }
    }

    parameters.associatedDisplayIsExternal = false;
    if (parameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN) {
        parameters.associatedDisplayIsExternal = deviceContext.isExternal();
        parameters.uniqueDisplayId = config.getString("touch.displayId").value_or("").c_str();
    }

    // Initial downs on external touch devices should wake the device.
    // Normally we don't do this for internal touch screens to prevent them from waking
    // up in your pocket but you can enable it using the input device configuration.
    parameters.wake = config.getBool("touch.wake").value_or(deviceContext.isExternal());

    std::optional<int32_t> usiVersionMajor = config.getInt("touch.usiVersionMajor");
    std::optional<int32_t> usiVersionMinor = config.getInt("touch.usiVersionMinor");
    if (usiVersionMajor.has_value() && usiVersionMinor.has_value()) {
        parameters.usiVersion = {
                .majorVersion = *usiVersionMajor,
                .minorVersion = *usiVersionMinor,
        };
    }

    parameters.enableForInactiveViewport =
            config.getBool("touch.enableForInactiveViewport").value_or(false);

    return parameters;
}

TouchInputMapper::Parameters::DeviceType TouchInputMapper::computeDeviceType(
        const InputDeviceContext& deviceContext) {
    Parameters::DeviceType deviceType;
    if (deviceContext.hasInputProperty(INPUT_PROP_DIRECT)) {
        // The device is a touch screen.
        deviceType = Parameters::DeviceType::TOUCH_SCREEN;
    } else if (deviceContext.hasInputProperty(INPUT_PROP_POINTER)) {
        // The device is a pointing device like a track pad.
        deviceType = Parameters::DeviceType::POINTER;
    } else {
        // The device is a touch pad of unknown purpose.
        deviceType = Parameters::DeviceType::POINTER;
    }

    // Type association takes precedence over the device type found in the idc file.
    std::string deviceTypeString = deviceContext.getDeviceTypeAssociation().value_or("");
    if (deviceTypeString.empty()) {
        deviceTypeString =
                deviceContext.getConfiguration().getString("touch.deviceType").value_or("");
    }
    if (deviceTypeString == "touchScreen") {
        deviceType = Parameters::DeviceType::TOUCH_SCREEN;
    } else if (deviceTypeString == "touchNavigation") {
        deviceType = Parameters::DeviceType::TOUCH_NAVIGATION;
    } else if (deviceTypeString == "pointer") {
        deviceType = Parameters::DeviceType::POINTER;
    } else if (deviceTypeString != "default" && deviceTypeString != "") {
        ALOGW("Invalid value for touch.deviceType: '%s'", deviceTypeString.c_str());
    }
    return deviceType;
}

void TouchInputMapper::dumpParameters(std::string& dump) {
    dump += INDENT3 "Parameters:\n";

    dump += INDENT4 "DeviceType: " + ftl::enum_string(mParameters.deviceType) + "\n";

    dump += StringPrintf(INDENT4 "AssociatedDisplay: isExternal=%s, displayId='%s'\n",
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
    return mExternalStylusPresence != ExternalStylusPresence::NONE;
}

/**
 * Determine which DisplayViewport to use.
 */
std::optional<DisplayViewport> TouchInputMapper::findViewport() {
    // 1. If a device has associated display, always use the matching viewport.
    if (getDeviceContext().getAssociatedViewport()) {
        return getDeviceContext().getAssociatedViewport();
    }

    // 2. Try to use the suggested viewport from WindowManagerService for pointers.
    if (mDeviceMode == DeviceMode::POINTER) {
        std::optional<DisplayViewport> viewport =
                mConfig.getDisplayViewportById(mConfig.defaultPointerDisplayId);
        if (viewport) {
            return viewport;
        } else {
            ALOGW("Can't find designated display viewport with ID %s for pointers.",
                  mConfig.defaultPointerDisplayId.toString().c_str());
        }
    }

    // 3. Get the matching viewport if uniqueDisplayId is specified in idc file.
    if (!mParameters.uniqueDisplayId.empty()) {
        return mConfig.getDisplayViewportByUniqueId(mParameters.uniqueDisplayId);
    }

    // 4. Use a non-display viewport for touch navigation devices.
    if (mParameters.deviceType == Parameters::DeviceType::TOUCH_NAVIGATION) {
        // Touch navigation devices can work without being associated with a display since they
        // are focus-dispatched events, so use a non-display viewport.
        DisplayViewport viewport;
        viewport.setNonDisplayViewport(mRawPointerAxes.getRawWidth(),
                                       mRawPointerAxes.getRawHeight());
        return viewport;
    }

    // 5. Fall back to using any appropriate viewport based on the display type
    //    (internal or external).
    const ViewportType viewportTypeToUse = mParameters.associatedDisplayIsExternal
            ? ViewportType::EXTERNAL
            : ViewportType::INTERNAL;
    std::optional<DisplayViewport> viewport = mConfig.getDisplayViewportByType(viewportTypeToUse);
    if (!viewport && viewportTypeToUse == ViewportType::EXTERNAL) {
        ALOGW("Input device %s should be associated with external display, "
              "fallback to internal one for the external viewport is not found.",
              getDeviceName().c_str());
        viewport = mConfig.getDisplayViewportByType(ViewportType::INTERNAL);
    }

    return viewport;
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
    if (mRawPointerAxes.touchMajor && mRawPointerAxes.touchMajor->maxValue != 0) {
        mSizeScale = 1.0f / mRawPointerAxes.touchMajor->maxValue;
    } else if (mRawPointerAxes.toolMajor && mRawPointerAxes.toolMajor->maxValue != 0) {
        mSizeScale = 1.0f / mRawPointerAxes.toolMajor->maxValue;
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

    if (mRawPointerAxes.touchMajor) {
        mRawPointerAxes.touchMajor->resolution =
                clampResolution("touchMajor", mRawPointerAxes.touchMajor->resolution);
        mOrientedRanges.touchMajor->resolution = mRawPointerAxes.touchMajor->resolution;
    }

    mOrientedRanges.touchMinor = mOrientedRanges.touchMajor;
    mOrientedRanges.touchMinor->axis = AMOTION_EVENT_AXIS_TOUCH_MINOR;
    if (mRawPointerAxes.touchMinor) {
        mRawPointerAxes.touchMinor->resolution =
                clampResolution("touchMinor", mRawPointerAxes.touchMinor->resolution);
        mOrientedRanges.touchMinor->resolution = mRawPointerAxes.touchMinor->resolution;
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
    if (mRawPointerAxes.toolMajor) {
        mRawPointerAxes.toolMajor->resolution =
                clampResolution("toolMajor", mRawPointerAxes.toolMajor->resolution);
        mOrientedRanges.toolMajor->resolution = mRawPointerAxes.toolMajor->resolution;
    }

    mOrientedRanges.toolMinor = mOrientedRanges.toolMajor;
    mOrientedRanges.toolMinor->axis = AMOTION_EVENT_AXIS_TOOL_MINOR;
    if (mRawPointerAxes.toolMinor) {
        mRawPointerAxes.toolMinor->resolution =
                clampResolution("toolMinor", mRawPointerAxes.toolMinor->resolution);
        mOrientedRanges.toolMinor->resolution = mRawPointerAxes.toolMinor->resolution;
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
            pressureMax = mPressureScale *
                    (mRawPointerAxes.pressure ? mRawPointerAxes.pressure->maxValue : 0);
        } else if (mRawPointerAxes.pressure && mRawPointerAxes.pressure->maxValue != 0) {
            mPressureScale = 1.0f / mRawPointerAxes.pressure->maxValue;
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
    mHaveTilt = mRawPointerAxes.tiltX && mRawPointerAxes.tiltY;
    if (mHaveTilt) {
        mTiltXCenter = avg(mRawPointerAxes.tiltX->minValue, mRawPointerAxes.tiltX->maxValue);
        mTiltYCenter = avg(mRawPointerAxes.tiltY->minValue, mRawPointerAxes.tiltY->maxValue);
        mTiltXScale = M_PI / 180;
        mTiltYScale = M_PI / 180;

        if (mRawPointerAxes.tiltX->resolution) {
            mTiltXScale = 1.0 / mRawPointerAxes.tiltX->resolution;
        }
        if (mRawPointerAxes.tiltY->resolution) {
            mTiltYScale = 1.0 / mRawPointerAxes.tiltY->resolution;
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
            if (mRawPointerAxes.orientation) {
                if (mRawPointerAxes.orientation->maxValue > 0) {
                    mOrientationScale = M_PI_2 / mRawPointerAxes.orientation->maxValue;
                } else if (mRawPointerAxes.orientation->minValue < 0) {
                    mOrientationScale = -M_PI_2 / mRawPointerAxes.orientation->minValue;
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

        const bool hasDistance = mRawPointerAxes.distance.has_value();
        mOrientedRanges.distance = InputDeviceInfo::MotionRange{
                .axis = AMOTION_EVENT_AXIS_DISTANCE,
                .source = mSource,
                .min = hasDistance ? mRawPointerAxes.distance->minValue * mDistanceScale : 0,
                .max = hasDistance ? mRawPointerAxes.distance->maxValue * mDistanceScale : 0,
                .flat = 0,
                .fuzz = hasDistance ? mRawPointerAxes.distance->fuzz * mDistanceScale : 0,
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
        mConfig.pointerGesturesEnabled && !mConfig.pointerCaptureRequest.isEnable()) {
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
    } else if (mParameters.deviceType == Parameters::DeviceType::TOUCH_NAVIGATION) {
        mSource = AINPUT_SOURCE_TOUCH_NAVIGATION | AINPUT_SOURCE_TOUCHPAD;
        mDeviceMode = DeviceMode::NAVIGATION;
    } else {
        ALOGW("Touch device '%s' has invalid parameters or configuration.  The device will be "
              "inoperable.",
              getDeviceName().c_str());
        mDeviceMode = DeviceMode::DISABLED;
    }

    const std::optional<DisplayViewport> newViewportOpt = findViewport();

    // Ensure the device is valid and can be used.
    if (!newViewportOpt) {
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

    const DisplayViewport& newViewport = newViewportOpt.value_or(kUninitializedViewport);
    bool viewportChanged;
    if (mParameters.enableForInactiveViewport) {
        // When touch is enabled for an inactive viewport, ignore the
        // viewport active status when checking whether the viewport has
        // changed.
        DisplayViewport tempViewport = mViewport;
        tempViewport.isActive = newViewport.isActive;
        viewportChanged = tempViewport != newViewport;
    } else {
        viewportChanged = mViewport != newViewport;
    }

    const bool deviceModeChanged = mDeviceMode != oldDeviceMode;
    bool skipViewportUpdate = false;
    if (viewportChanged || deviceModeChanged) {
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
    if (deviceModeChanged) {
        mOrientedRanges.clear();
    }

    if ((viewportChanged && !skipViewportUpdate) || deviceModeChanged) {
        ALOGI("Device reconfigured: id=%d, name='%s', size %s, orientation %s, mode %s, "
              "display id %s",
              getDeviceId(), getDeviceName().c_str(), toString(mDisplayBounds).c_str(),
              ftl::enum_string(mInputDeviceOrientation).c_str(),
              ftl::enum_string(mDeviceMode).c_str(), mViewport.displayId.toString().c_str());

        configureVirtualKeys();

        initializeOrientedRanges();

        // Location
        updateAffineTransformation();

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
    dump += StringPrintf(INDENT3 "InputDeviceOrientation: %s\n",
                         ftl::enum_string(mInputDeviceOrientation).c_str());
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
        std::optional<MappedKey> mappedKey = getDeviceContext().mapKey(virtualKey.scanCode, 0, 0);
        if (!mappedKey) {
            ALOGW(INDENT "VirtualKey %d: could not obtain key code, ignoring", virtualKey.scanCode);
            continue; // drop the key
        }

        virtualKey.keyCode = mappedKey->keyCode;
        virtualKey.flags = mappedKey->flags;

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
    if (mRawPointerAxes.touchMajor || mRawPointerAxes.toolMajor) {
        if (mCalibration.sizeCalibration == Calibration::SizeCalibration::DEFAULT) {
            mCalibration.sizeCalibration = Calibration::SizeCalibration::GEOMETRIC;
        }
    } else {
        mCalibration.sizeCalibration = Calibration::SizeCalibration::NONE;
    }

    // Pressure
    if (mRawPointerAxes.pressure) {
        if (mCalibration.pressureCalibration == Calibration::PressureCalibration::DEFAULT) {
            mCalibration.pressureCalibration = Calibration::PressureCalibration::PHYSICAL;
        }
    } else {
        mCalibration.pressureCalibration = Calibration::PressureCalibration::NONE;
    }

    // Orientation
    if (mRawPointerAxes.orientation) {
        if (mCalibration.orientationCalibration == Calibration::OrientationCalibration::DEFAULT) {
            mCalibration.orientationCalibration = Calibration::OrientationCalibration::INTERPOLATED;
        }
    } else {
        mCalibration.orientationCalibration = Calibration::OrientationCalibration::NONE;
    }

    // Distance
    if (mRawPointerAxes.distance) {
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

    mCursorButtonAccumulator.reset(getDeviceContext());
    mTouchButtonAccumulator.reset();

    mRawStatesPending.clear();
    mCurrentRawState.clear();
    mCurrentCookedState.clear();
    mLastRawState.clear();
    mLastCookedState.clear();
    mSentHoverEnter = false;
    mHavePointerIds = false;
    mCurrentMotionAborted = false;
    mDownTime = 0;

    mCurrentVirtualKey.down = false;

    resetExternalStylus();

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

std::list<NotifyArgs> TouchInputMapper::process(const RawEvent& rawEvent) {
    mCursorButtonAccumulator.process(rawEvent);
    mTouchButtonAccumulator.process(rawEvent);

    std::list<NotifyArgs> out;
    if (rawEvent.type == EV_SYN && rawEvent.code == SYN_REPORT) {
        out += sync(rawEvent.when, rawEvent.readTime);
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
        if (mParameters.wake) {
            policyFlags |= POLICY_FLAG_WAKE;
        }
    }

    // Consume raw off-screen touches before cooking pointer data.
    // If touches are consumed, subsequent code will not receive any pointer data.
    bool consumed;
    out += consumeRawTouches(when, readTime, policyFlags, consumed /*byref*/);
    if (consumed) {
        LOG_IF(INFO, debugRawEvents()) << "Touch consumed by consumeRawTouches, eventTime=" << when;
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

    // Dispatch the touches directly.
    if (!mCurrentMotionAborted) {
        out += dispatchButtonRelease(when, readTime, policyFlags);
        out += dispatchHoverExit(when, readTime, policyFlags);
        out += dispatchTouches(when, readTime, policyFlags);
        out += dispatchHoverEnterAndMove(when, readTime, policyFlags);
        out += dispatchButtonPress(when, readTime, policyFlags);
    }

    if (mCurrentCookedState.cookedPointerData.pointerCount == 0) {
        mCurrentMotionAborted = false;
    }

    // Synthesize key up from raw buttons if needed.
    out += synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_UP, when, readTime, getDeviceId(),
                                mSource, mViewport.displayId, policyFlags,
                                mLastCookedState.buttonState, mCurrentCookedState.buttonState);

    if (mCurrentCookedState.cookedPointerData.pointerCount == 0) {
        mCurrentStreamModifiedByExternalStylus = false;
    }

    // Copy current touch to last touch in preparation for the next cycle.
    mLastRawState = mCurrentRawState;
    mLastCookedState = mCurrentCookedState;
    return out;
}

bool TouchInputMapper::isTouchScreen() {
    return mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN;
}

ui::LogicalDisplayId TouchInputMapper::resolveDisplayId() const {
    return getAssociatedDisplayId().value_or(ui::LogicalDisplayId::INVALID);
};

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

        if (mExternalStylusButtonsApplied != 0 || releasedButtons != 0) {
            mCurrentStreamModifiedByExternalStylus = true;
        }
    }
}

void TouchInputMapper::applyExternalStylusTouchState(nsecs_t when) {
    CookedPointerData& currentPointerData = mCurrentCookedState.cookedPointerData;
    const CookedPointerData& lastPointerData = mLastCookedState.cookedPointerData;
    if (!mFusedStylusPointerId || !currentPointerData.isTouching(*mFusedStylusPointerId)) {
        return;
    }

    mCurrentStreamModifiedByExternalStylus = true;

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
    if (mDeviceMode == DeviceMode::DIRECT) {
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
        mCurrentRawState.rawPointerData.touchingIdBits.isEmpty()) {
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
            LOG(WARNING) << "Dropping hover, all pointers are outside the physical frame";
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
        // unscaled or pointer mode.
        if (!isPointInsidePhysicalFrame(pointer.x, pointer.y) &&
            mDeviceMode != DeviceMode::POINTER) {
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
            LOG(WARNING) << "Dropping pointer " << id << " at (" << pointer.x << ", " << pointer.y
                         << "), it is outside of the physical frame";
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

std::list<NotifyArgs> TouchInputMapper::abortTouches(
        nsecs_t when, nsecs_t readTime, uint32_t policyFlags,
        std::optional<ui::LogicalDisplayId> currentGestureDisplayId) {
    std::list<NotifyArgs> out;
    if (mCurrentMotionAborted) {
        // Current motion event was already aborted.
        return out;
    }
    BitSet32 currentIdBits = mCurrentCookedState.cookedPointerData.touchingIdBits;
    if (!currentIdBits.isEmpty()) {
        int32_t metaState = getContext()->getGlobalMetaState();
        int32_t buttonState = mCurrentCookedState.buttonState;
        out.push_back(dispatchMotion(when, readTime, policyFlags,
                                     currentGestureDisplayId.value_or(resolveDisplayId()),
                                     AMOTION_EVENT_ACTION_CANCEL, 0, AMOTION_EVENT_FLAG_CANCELED,
                                     metaState, buttonState,
                                     mCurrentCookedState.cookedPointerData.pointerProperties,
                                     mCurrentCookedState.cookedPointerData.pointerCoords,
                                     mCurrentCookedState.cookedPointerData.idToIndex, currentIdBits,
                                     -1));
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
            curOutProperties = curInProperties;
            changed = true;
        }

        if (curInCoords != curOutCoords) {
            curOutCoords = curInCoords;
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
            out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                         AMOTION_EVENT_ACTION_MOVE, 0, 0, metaState, buttonState,
                                         mCurrentCookedState.cookedPointerData.pointerProperties,
                                         mCurrentCookedState.cookedPointerData.pointerCoords,
                                         mCurrentCookedState.cookedPointerData.idToIndex,
                                         currentIdBits, -1));
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
            out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                         AMOTION_EVENT_ACTION_POINTER_UP, 0,
                                         isCanceled ? AMOTION_EVENT_FLAG_CANCELED : 0, metaState,
                                         buttonState,
                                         mLastCookedState.cookedPointerData.pointerProperties,
                                         mLastCookedState.cookedPointerData.pointerCoords,
                                         mLastCookedState.cookedPointerData.idToIndex,
                                         dispatchedIdBits, upId));
            dispatchedIdBits.clearBit(upId);
            mCurrentCookedState.cookedPointerData.canceledIdBits.clearBit(upId);
        }

        // Dispatch move events if any of the remaining pointers moved from their old locations.
        // Although applications receive new locations as part of individual pointer up
        // events, they do not generally handle them except when presented in a move event.
        if (moveNeeded && !moveIdBits.isEmpty()) {
            ALOG_ASSERT(moveIdBits.value == dispatchedIdBits.value);
            out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                         AMOTION_EVENT_ACTION_MOVE, 0, 0, metaState, buttonState,
                                         mCurrentCookedState.cookedPointerData.pointerProperties,
                                         mCurrentCookedState.cookedPointerData.pointerCoords,
                                         mCurrentCookedState.cookedPointerData.idToIndex,
                                         dispatchedIdBits, -1));
        }

        // Dispatch pointer down events using the new pointer locations.
        while (!downIdBits.isEmpty()) {
            uint32_t downId = downIdBits.clearFirstMarkedBit();
            dispatchedIdBits.markBit(downId);

            if (dispatchedIdBits.count() == 1) {
                // First pointer is going down.  Set down time.
                mDownTime = when;
            }

            out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                         AMOTION_EVENT_ACTION_POINTER_DOWN, 0, 0, metaState,
                                         buttonState,
                                         mCurrentCookedState.cookedPointerData.pointerProperties,
                                         mCurrentCookedState.cookedPointerData.pointerCoords,
                                         mCurrentCookedState.cookedPointerData.idToIndex,
                                         dispatchedIdBits, downId));
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
        out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                     AMOTION_EVENT_ACTION_HOVER_EXIT, 0, 0, metaState,
                                     mLastCookedState.buttonState,
                                     mLastCookedState.cookedPointerData.pointerProperties,
                                     mLastCookedState.cookedPointerData.pointerCoords,
                                     mLastCookedState.cookedPointerData.idToIndex,
                                     mLastCookedState.cookedPointerData.hoveringIdBits, -1));
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
            out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                         AMOTION_EVENT_ACTION_HOVER_ENTER, 0, 0, metaState,
                                         mCurrentRawState.buttonState,
                                         mCurrentCookedState.cookedPointerData.pointerProperties,
                                         mCurrentCookedState.cookedPointerData.pointerCoords,
                                         mCurrentCookedState.cookedPointerData.idToIndex,
                                         mCurrentCookedState.cookedPointerData.hoveringIdBits, -1));
            mSentHoverEnter = true;
        }

        out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                     AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0, metaState,
                                     mCurrentRawState.buttonState,
                                     mCurrentCookedState.cookedPointerData.pointerProperties,
                                     mCurrentCookedState.cookedPointerData.pointerCoords,
                                     mCurrentCookedState.cookedPointerData.idToIndex,
                                     mCurrentCookedState.cookedPointerData.hoveringIdBits, -1));
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
        out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                     AMOTION_EVENT_ACTION_BUTTON_RELEASE, actionButton, 0,
                                     metaState, buttonState,
                                     mLastCookedState.cookedPointerData.pointerProperties,
                                     mLastCookedState.cookedPointerData.pointerCoords,
                                     mLastCookedState.cookedPointerData.idToIndex, idBits, -1));
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
        out.push_back(dispatchMotion(when, readTime, policyFlags, resolveDisplayId(),
                                     AMOTION_EVENT_ACTION_BUTTON_PRESS, actionButton, 0, metaState,
                                     buttonState,
                                     mCurrentCookedState.cookedPointerData.pointerProperties,
                                     mCurrentCookedState.cookedPointerData.pointerCoords,
                                     mCurrentCookedState.cookedPointerData.idToIndex, idBits, -1));
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
    if (mCurrentCookedState.cookedPointerData.hoveringIdBits.count() > 1) {
        // Android does not support multiple hovering pointers.
        LOG(DEBUG) << "Multi-pointer hover detected. Suppressing hover events.";
        mCurrentCookedState.cookedPointerData.hoveringIdBits.clear();
    }
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

        bool isHovering = in.isHovering;

        // A tool MOUSE pointer is only down/touching when a mouse button is pressed.
        if (in.toolType == ToolType::MOUSE &&
            !mCurrentRawState.rawPointerData.canceledIdBits.hasBit(in.id)) {
            if (isPointerDown(mCurrentRawState.buttonState)) {
                isHovering = false;
                mCurrentCookedState.cookedPointerData.touchingIdBits.markBit(in.id);
                mCurrentCookedState.cookedPointerData.hoveringIdBits.clearBit(in.id);
            } else {
                isHovering = true;
                mCurrentCookedState.cookedPointerData.touchingIdBits.clearBit(in.id);
                mCurrentCookedState.cookedPointerData.hoveringIdBits.markBit(in.id);
            }
        }

        // Size
        float touchMajor, touchMinor, toolMajor, toolMinor, size;
        switch (mCalibration.sizeCalibration) {
            case Calibration::SizeCalibration::GEOMETRIC:
            case Calibration::SizeCalibration::DIAMETER:
            case Calibration::SizeCalibration::BOX:
            case Calibration::SizeCalibration::AREA:
                if (mRawPointerAxes.touchMajor && mRawPointerAxes.toolMajor) {
                    touchMajor = in.touchMajor;
                    touchMinor = mRawPointerAxes.touchMinor ? in.touchMinor : in.touchMajor;
                    toolMajor = in.toolMajor;
                    toolMinor = mRawPointerAxes.toolMinor ? in.toolMinor : in.toolMajor;
                    size = mRawPointerAxes.touchMinor ? avg(in.touchMajor, in.touchMinor)
                                                      : in.touchMajor;
                } else if (mRawPointerAxes.touchMajor) {
                    toolMajor = touchMajor = in.touchMajor;
                    toolMinor = touchMinor =
                            mRawPointerAxes.touchMinor ? in.touchMinor : in.touchMajor;
                    size = mRawPointerAxes.touchMinor ? avg(in.touchMajor, in.touchMinor)
                                                      : in.touchMajor;
                } else if (mRawPointerAxes.toolMajor) {
                    touchMajor = toolMajor = in.toolMajor;
                    touchMinor = toolMinor =
                            mRawPointerAxes.toolMinor ? in.toolMinor : in.toolMajor;
                    size = mRawPointerAxes.toolMinor ? avg(in.toolMajor, in.toolMinor)
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
                pressure = isHovering ? 0 : 1;
                break;
        }

        // Tilt and Orientation
        float tilt;
        float orientation;
        if (mHaveTilt) {
            float tiltXAngle = (in.tiltX - mTiltXCenter) * mTiltXScale;
            float tiltYAngle = (in.tiltY - mTiltYCenter) * mTiltYScale;
            orientation = transformAngle(mRawRotation, atan2f(-sinf(tiltXAngle), sinf(tiltYAngle)),
                                         /*isDirectional=*/true);
            tilt = acosf(cosf(tiltXAngle) * cosf(tiltYAngle));
        } else {
            tilt = 0;

            switch (mCalibration.orientationCalibration) {
                case Calibration::OrientationCalibration::INTERPOLATED:
                    orientation = transformAngle(mRawRotation, in.orientation * mOrientationScale,
                                                 /*isDirectional=*/true);
                    break;
                case Calibration::OrientationCalibration::VECTOR: {
                    int32_t c1 = signExtendNybble((in.orientation & 0xf0) >> 4);
                    int32_t c2 = signExtendNybble(in.orientation & 0x0f);
                    if (c1 != 0 || c2 != 0) {
                        orientation = transformAngle(mRawRotation, atan2f(c1, c2) * 0.5f,
                                                     /*isDirectional=*/true);
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

NotifyMotionArgs TouchInputMapper::dispatchMotion(
        nsecs_t when, nsecs_t readTime, uint32_t policyFlags, ui::LogicalDisplayId displayId,
        int32_t action, int32_t actionButton, int32_t flags, int32_t metaState, int32_t buttonState,
        const PropertiesArray& properties, const CoordsArray& coords,
        const IdToIndexArray& idToIndex, BitSet32 idBits, int32_t changedId) const {
    std::vector<PointerCoords> pointerCoords;
    std::vector<PointerProperties> pointerProperties;
    uint32_t pointerCount = 0;
    while (!idBits.isEmpty()) {
        uint32_t id = idBits.clearFirstMarkedBit();
        uint32_t index = idToIndex[id];
        pointerProperties.push_back(properties[index]);
        pointerCoords.push_back(coords[index]);

        if (changedId >= 0 && id == uint32_t(changedId)) {
            action |= pointerCount << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
        }

        pointerCount++;
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
    uint32_t source = mSource;
    if (mCurrentStreamModifiedByExternalStylus) {
        source |= AINPUT_SOURCE_BLUETOOTH_STYLUS;
    }
    if (mOrientedRanges.orientation.has_value()) {
        flags |= AMOTION_EVENT_PRIVATE_FLAG_SUPPORTS_ORIENTATION;
        if (mOrientedRanges.tilt.has_value()) {
            // In the current implementation, only devices that report a value for tilt supports
            // directional orientation.
            flags |= AMOTION_EVENT_PRIVATE_FLAG_SUPPORTS_DIRECTIONAL_ORIENTATION;
        }
    }

    float xCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    float yCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    if (mDeviceMode == DeviceMode::POINTER) {
        ALOGW_IF(pointerCount != 1,
                 "Only single pointer events are fully supported in POINTER mode");
        xCursorPosition = pointerCoords[0].getX();
        yCursorPosition = pointerCoords[0].getY();
    }
    const DeviceId deviceId = getDeviceId();
    std::vector<TouchVideoFrame> frames = getDeviceContext().getVideoFrames();
    std::for_each(frames.begin(), frames.end(),
                  [this](TouchVideoFrame& frame) { frame.rotate(this->mInputDeviceOrientation); });
    return NotifyMotionArgs(getContext()->getNextId(), when, readTime, deviceId, source, displayId,
                            policyFlags, action, actionButton, flags, metaState, buttonState,
                            MotionClassification::NONE, pointerCount, pointerProperties.data(),
                            pointerCoords.data(), mOrientedXPrecision, mOrientedYPrecision,
                            xCursorPosition, yCursorPosition, mDownTime, std::move(frames));
}

std::list<NotifyArgs> TouchInputMapper::cancelTouch(nsecs_t when, nsecs_t readTime) {
    return abortTouches(when, readTime, /* policyFlags=*/0, std::nullopt);
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
    struct PointerDistanceHeapElement {
        uint32_t currentPointerIndex : 8 {};
        uint32_t lastPointerIndex : 8 {};
        uint64_t distanceSq : 48 {};
    };
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

                uint64_t distanceSq = uint64_t(deltaX * deltaX + deltaY * deltaY);

                // Insert new element into the heap (sift up).
                heap[heapSize].currentPointerIndex = currentPointerIndex;
                heap[heapSize].lastPointerIndex = lastPointerIndex;
                heap[heapSize].distanceSq = distanceSq;
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
                heap[childIndex + 1].distanceSq < heap[childIndex].distanceSq) {
                childIndex += 1;
            }

            if (heap[parentIndex].distanceSq <= heap[childIndex].distanceSq) {
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
                  heap[i].currentPointerIndex, heap[i].lastPointerIndex, heap[i].distanceSq);
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
                        heap[childIndex + 1].distanceSq < heap[childIndex].distanceSq) {
                        childIndex += 1;
                    }

                    if (heap[parentIndex].distanceSq <= heap[childIndex].distanceSq) {
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
                              heap[j].distanceSq);
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
                     ", distanceSq=%" PRIu64,
                     lastPointerIndex, currentPointerIndex, id, heap[0].distanceSq);
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

std::optional<ui::LogicalDisplayId> TouchInputMapper::getAssociatedDisplayId() const {
    if (mViewport == kUninitializedViewport) {
        return std::nullopt;
    }
    return mViewport.displayId;
}

} // namespace android
