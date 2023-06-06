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

#include <algorithm>
#include <chrono>
#include <iterator>
#include <limits>
#include <map>
#include <optional>

#include <android-base/stringprintf.h>
#include <android/input.h>
#include <ftl/enum.h>
#include <input/PrintTools.h>
#include <linux/input-event-codes.h>
#include <log/log_main.h>
#include <stats_pull_atom_callback.h>
#include <statslog.h>
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

int32_t linuxBusToInputDeviceBusEnum(int32_t linuxBus) {
    // When adding cases to this switch, also add them to the copy of this method in
    // InputDeviceMetricsCollector.cpp.
    // TODO(b/286394420): deduplicate this method with the one in InputDeviceMetricsCollector.cpp.
    switch (linuxBus) {
        case BUS_USB:
            return util::INPUT_DEVICE_USAGE_REPORTED__DEVICE_BUS__USB;
        case BUS_BLUETOOTH:
            return util::INPUT_DEVICE_USAGE_REPORTED__DEVICE_BUS__BLUETOOTH;
        default:
            return util::INPUT_DEVICE_USAGE_REPORTED__DEVICE_BUS__OTHER;
    }
}

class MetricsAccumulator {
public:
    static MetricsAccumulator& getInstance() {
        static MetricsAccumulator sAccumulator;
        return sAccumulator;
    }

    void recordFinger(const TouchpadInputMapper::MetricsIdentifier& id) { mCounters[id].fingers++; }

    void recordPalm(const TouchpadInputMapper::MetricsIdentifier& id) { mCounters[id].palms++; }

    // Checks whether a Gesture struct is for the end of a gesture that we log metrics for, and
    // records it if so.
    void processGesture(const TouchpadInputMapper::MetricsIdentifier& id, const Gesture& gesture) {
        switch (gesture.type) {
            case kGestureTypeFling:
                if (gesture.details.fling.fling_state == GESTURES_FLING_START) {
                    // Indicates the end of a two-finger scroll gesture.
                    mCounters[id].twoFingerSwipeGestures++;
                }
                break;
            case kGestureTypeSwipeLift:
                mCounters[id].threeFingerSwipeGestures++;
                break;
            case kGestureTypeFourFingerSwipeLift:
                mCounters[id].fourFingerSwipeGestures++;
                break;
            case kGestureTypePinch:
                if (gesture.details.pinch.zoom_state == GESTURES_ZOOM_END) {
                    mCounters[id].pinchGestures++;
                }
                break;
            default:
                // We're not interested in any other gestures.
                break;
        }
    }

private:
    MetricsAccumulator() {
        AStatsManager_setPullAtomCallback(android::util::TOUCHPAD_USAGE, /*metadata=*/nullptr,
                                          MetricsAccumulator::pullAtomCallback, /*cookie=*/nullptr);
    }

    ~MetricsAccumulator() { AStatsManager_clearPullAtomCallback(android::util::TOUCHPAD_USAGE); }

    static AStatsManager_PullAtomCallbackReturn pullAtomCallback(int32_t atomTag,
                                                                 AStatsEventList* outEventList,
                                                                 void* cookie) {
        LOG_ALWAYS_FATAL_IF(atomTag != android::util::TOUCHPAD_USAGE);
        MetricsAccumulator& accumulator = MetricsAccumulator::getInstance();
        accumulator.produceAtoms(outEventList);
        accumulator.resetCounters();
        return AStatsManager_PULL_SUCCESS;
    }

    void produceAtoms(AStatsEventList* outEventList) const {
        for (auto& [id, counters] : mCounters) {
            auto [busId, vendorId, productId, versionId] = id;
            addAStatsEvent(outEventList, android::util::TOUCHPAD_USAGE, vendorId, productId,
                           versionId, linuxBusToInputDeviceBusEnum(busId), counters.fingers,
                           counters.palms, counters.twoFingerSwipeGestures,
                           counters.threeFingerSwipeGestures, counters.fourFingerSwipeGestures,
                           counters.pinchGestures);
        }
    }

    void resetCounters() { mCounters.clear(); }

    // Stores the counters for a specific touchpad model. Fields have the same meanings as those of
    // the TouchpadUsage atom; see that definition for detailed documentation.
    struct Counters {
        int32_t fingers = 0;
        int32_t palms = 0;

        int32_t twoFingerSwipeGestures = 0;
        int32_t threeFingerSwipeGestures = 0;
        int32_t fourFingerSwipeGestures = 0;
        int32_t pinchGestures = 0;
    };

    // Metrics are aggregated by device model and version, so if two devices of the same model and
    // version are connected at once, they will have the same counters.
    std::map<TouchpadInputMapper::MetricsIdentifier, Counters> mCounters;
};

} // namespace

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext,
                                         const InputReaderConfiguration& readerConfig)
      : InputMapper(deviceContext, readerConfig),
        mGestureInterpreter(NewGestureInterpreter(), DeleteGestureInterpreter),
        mPointerController(getContext()->getPointerController(getDeviceId())),
        mStateConverter(deviceContext, mMotionAccumulator),
        mGestureConverter(*getContext(), deviceContext, getDeviceId()),
        mCapturedEventConverter(*getContext(), deviceContext, mMotionAccumulator, getDeviceId()),
        mMetricsId(metricsIdFromInputDeviceIdentifier(deviceContext.getDeviceIdentifier())) {
    RawAbsoluteAxisInfo slotAxisInfo;
    deviceContext.getAbsoluteAxisInfo(ABS_MT_SLOT, &slotAxisInfo);
    if (!slotAxisInfo.valid || slotAxisInfo.maxValue <= 0) {
        ALOGW("Touchpad \"%s\" doesn't have a valid ABS_MT_SLOT axis, and probably won't work "
              "properly.",
              deviceContext.getName().c_str());
    }
    mMotionAccumulator.configure(deviceContext, slotAxisInfo.maxValue + 1, true);

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
    if (mPointerCaptured) {
        mCapturedEventConverter.populateMotionRanges(info);
    } else {
        mGestureConverter.populateMotionRanges(info);
    }
}

void TouchpadInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Touchpad Input Mapper:\n";
    if (mProcessing) {
        dump += INDENT3 "Currently processing a hardware state\n";
    }
    if (mResettingInterpreter) {
        dump += INDENT3 "Currently resetting gesture interpreter\n";
    }
    dump += StringPrintf(INDENT3 "Pointer captured: %s\n", toString(mPointerCaptured));
    dump += INDENT3 "Gesture converter:\n";
    dump += addLinePrefix(mGestureConverter.dump(), INDENT4);
    dump += INDENT3 "Gesture properties:\n";
    dump += addLinePrefix(mPropertyProvider.dump(), INDENT4);
    dump += INDENT3 "Captured event converter:\n";
    dump += addLinePrefix(mCapturedEventConverter.dump(), INDENT4);
}

std::list<NotifyArgs> TouchpadInputMapper::reconfigure(nsecs_t when,
                                                       const InputReaderConfiguration& config,
                                                       ConfigurationChanges changes) {
    if (!changes.any()) {
        // First time configuration
        mPropertyProvider.loadPropertiesFromIdcFile(getDeviceContext().getConfiguration());
    }

    if (!changes.any() || changes.test(InputReaderConfiguration::Change::DISPLAY_INFO)) {
        std::optional<int32_t> displayId = mPointerController->getDisplayId();
        ui::Rotation orientation = ui::ROTATION_0;
        if (displayId.has_value()) {
            if (auto viewport = config.getDisplayViewportById(*displayId); viewport) {
                orientation = getInverseRotation(viewport->orientation);
            }
        }
        mGestureConverter.setOrientation(orientation);
    }
    if (!changes.any() || changes.test(InputReaderConfiguration::Change::TOUCHPAD_SETTINGS)) {
        mPropertyProvider.getProperty("Use Custom Touchpad Pointer Accel Curve")
                .setBoolValues({true});
        GesturesProp accelCurveProp = mPropertyProvider.getProperty("Pointer Accel Curve");
        accelCurveProp.setRealValues(
                createAccelerationCurveForSensitivity(config.touchpadPointerSpeed,
                                                      accelCurveProp.getCount()));
        mPropertyProvider.getProperty("Use Custom Touchpad Scroll Accel Curve")
                .setBoolValues({true});
        GesturesProp scrollCurveProp = mPropertyProvider.getProperty("Scroll Accel Curve");
        scrollCurveProp.setRealValues(
                createAccelerationCurveForSensitivity(config.touchpadPointerSpeed,
                                                      scrollCurveProp.getCount()));
        mPropertyProvider.getProperty("Scroll X Out Scale").setRealValues({1.0});
        mPropertyProvider.getProperty("Scroll Y Out Scale").setRealValues({1.0});
        mPropertyProvider.getProperty("Invert Scrolling")
                .setBoolValues({config.touchpadNaturalScrollingEnabled});
        mPropertyProvider.getProperty("Tap Enable")
                .setBoolValues({config.touchpadTapToClickEnabled});
        mPropertyProvider.getProperty("Button Right Click Zone Enable")
                .setBoolValues({config.touchpadRightClickZoneEnabled});
    }
    std::list<NotifyArgs> out;
    if ((!changes.any() && config.pointerCaptureRequest.enable) ||
        changes.test(InputReaderConfiguration::Change::POINTER_CAPTURE)) {
        mPointerCaptured = config.pointerCaptureRequest.enable;
        // The motion ranges are going to change, so bump the generation to clear the cached ones.
        bumpGeneration();
        if (mPointerCaptured) {
            // The touchpad is being captured, so we need to tidy up any fake fingers etc. that are
            // still being reported for a gesture in progress.
            out += reset(when);
            mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
        } else {
            // We're transitioning from captured to uncaptured.
            mCapturedEventConverter.reset();
        }
        if (changes.any()) {
            out.push_back(NotifyDeviceResetArgs(getContext()->getNextId(), when, getDeviceId()));
        }
    }
    return out;
}

std::list<NotifyArgs> TouchpadInputMapper::reset(nsecs_t when) {
    mStateConverter.reset();
    resetGestureInterpreter(when);
    std::list<NotifyArgs> out = mGestureConverter.reset(when);
    out += InputMapper::reset(when);
    return out;
}

void TouchpadInputMapper::resetGestureInterpreter(nsecs_t when) {
    // The GestureInterpreter has no official reset method, but sending a HardwareState with no
    // fingers down or buttons pressed should get it into a clean state.
    HardwareState state;
    state.timestamp = std::chrono::duration<stime_t>(std::chrono::nanoseconds(when)).count();
    mResettingInterpreter = true;
    mGestureInterpreter->PushHardwareState(&state);
    mResettingInterpreter = false;
}

std::list<NotifyArgs> TouchpadInputMapper::process(const RawEvent* rawEvent) {
    if (mPointerCaptured) {
        return mCapturedEventConverter.process(*rawEvent);
    }
    std::optional<SelfContainedHardwareState> state = mStateConverter.processRawEvent(rawEvent);
    if (state) {
        updatePalmDetectionMetrics();
        return sendHardwareState(rawEvent->when, rawEvent->readTime, *state);
    } else {
        return {};
    }
}

void TouchpadInputMapper::updatePalmDetectionMetrics() {
    std::set<int32_t> currentTrackingIds;
    for (size_t i = 0; i < mMotionAccumulator.getSlotCount(); i++) {
        const MultiTouchMotionAccumulator::Slot& slot = mMotionAccumulator.getSlot(i);
        if (!slot.isInUse()) {
            continue;
        }
        currentTrackingIds.insert(slot.getTrackingId());
        if (slot.getToolType() == ToolType::PALM) {
            mPalmTrackingIds.insert(slot.getTrackingId());
        }
    }
    std::vector<int32_t> liftedTouches;
    std::set_difference(mLastFrameTrackingIds.begin(), mLastFrameTrackingIds.end(),
                        currentTrackingIds.begin(), currentTrackingIds.end(),
                        std::inserter(liftedTouches, liftedTouches.begin()));
    for (int32_t trackingId : liftedTouches) {
        if (mPalmTrackingIds.erase(trackingId) > 0) {
            MetricsAccumulator::getInstance().recordPalm(mMetricsId);
        } else {
            MetricsAccumulator::getInstance().recordFinger(mMetricsId);
        }
    }
    mLastFrameTrackingIds = currentTrackingIds;
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
    if (mResettingInterpreter) {
        // We already handle tidying up fake fingers etc. in GestureConverter::reset, so we should
        // ignore any gestures produced from the interpreter while we're resetting it.
        return;
    }
    if (!mProcessing) {
        ALOGE("Received gesture outside of the normal processing flow; ignoring it.");
        return;
    }
    mGesturesToProcess.push_back(*gesture);
}

std::list<NotifyArgs> TouchpadInputMapper::processGestures(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out = {};
    MetricsAccumulator& metricsAccumulator = MetricsAccumulator::getInstance();
    for (Gesture& gesture : mGesturesToProcess) {
        out += mGestureConverter.handleGesture(when, readTime, gesture);
        metricsAccumulator.processGesture(mMetricsId, gesture);
    }
    mGesturesToProcess.clear();
    return out;
}

} // namespace android
