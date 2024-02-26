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
#include <mutex>
#include <optional>

#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <android/input.h>
#include <com_android_input_flags.h>
#include <ftl/enum.h>
#include <input/AccelerationCurve.h>
#include <input/PrintTools.h>
#include <linux/input-event-codes.h>
#include <log/log_main.h>
#include <stats_pull_atom_callback.h>
#include <statslog.h>
#include "TouchCursorInputMapperCommon.h"
#include "TouchpadInputMapper.h"
#include "gestures/HardwareProperties.h"
#include "gestures/TimerProvider.h"
#include "ui/Rotation.h"

namespace input_flags = com::android::input::flags;

namespace android {

namespace {

static const bool ENABLE_POINTER_CHOREOGRAPHER = input_flags::enable_pointer_choreographer();

/**
 * Log details of each gesture output by the gestures library.
 * Enable this via "adb shell setprop log.tag.TouchpadInputMapperGestures DEBUG" (requires
 * restarting the shell)
 */
const bool DEBUG_TOUCHPAD_GESTURES =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, "TouchpadInputMapperGestures",
                                  ANDROID_LOG_INFO);

std::vector<double> createAccelerationCurveForSensitivity(int32_t sensitivity,
                                                          size_t propertySize) {
    std::vector<AccelerationCurveSegment> segments =
            createAccelerationCurveForPointerSensitivity(sensitivity);
    LOG_ALWAYS_FATAL_IF(propertySize < 4 * segments.size());
    std::vector<double> output(propertySize, 0);

    // The Gestures library uses functions of the following form to define curve segments, where a,
    // b, and c can be specified by us:
    //     output_speed(input_speed_mm) = a * input_speed_mm ^ 2 + b * input_speed_mm + c
    //
    // (a, b, and c are also called sqr_, mul_, and int_ in the Gestures library code.)
    //
    // createAccelerationCurveForPointerSensitivity gives us parameters for a function of the form:
    //     gain(input_speed_mm) = baseGain + reciprocal / input_speed_mm
    // Where "gain" is a multiplier applied to the input speed to produce the output speed:
    //     output_speed(input_speed_mm) = input_speed_mm * gain(input_speed_mm)
    //
    // To put our function in the library's form, we substitute it into the function above:
    //     output_speed(input_speed_mm) = input_speed_mm * (baseGain + reciprocal / input_speed_mm)
    // then expand the brackets so that input_speed_mm cancels out for the reciprocal term:
    //     gain(input_speed_mm) = baseGain * input_speed_mm + reciprocal
    //
    // This gives us the following parameters for the Gestures library function form:
    //     a = 0
    //     b = baseGain
    //     c = reciprocal

    size_t i = 0;
    for (AccelerationCurveSegment seg : segments) {
        // The library's curve format consists of four doubles per segment:
        // * maximum pointer speed for the segment (mm/s)
        // * multiplier for the x² term (a.k.a. "a" or "sqr")
        // * multiplier for the x term (a.k.a. "b" or "mul")
        // * the intercept (a.k.a. "c" or "int")
        // (see struct CurveSegment in the library's AccelFilterInterpreter)
        output[i + 0] = seg.maxPointerSpeedMmPerS;
        output[i + 1] = 0;
        output[i + 2] = seg.baseGain;
        output[i + 3] = seg.reciprocal;
        i += 4;
    }

    return output;
}

void gestureInterpreterCallback(void* clientData, const Gesture* gesture) {
    TouchpadInputMapper* mapper = static_cast<TouchpadInputMapper*>(clientData);
    mapper->consumeGesture(gesture);
}

int32_t linuxBusToInputDeviceBusEnum(int32_t linuxBus, bool isUsiStylus) {
    if (isUsiStylus) {
        // This is a stylus connected over the Universal Stylus Initiative (USI) protocol.
        // For metrics purposes, we treat this protocol as a separate bus.
        return util::INPUT_DEVICE_USAGE_REPORTED__DEVICE_BUS__USI;
    }

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

    void recordFinger(const TouchpadInputMapper::MetricsIdentifier& id) {
        std::scoped_lock lock(mLock);
        mCounters[id].fingers++;
    }

    void recordPalm(const TouchpadInputMapper::MetricsIdentifier& id) {
        std::scoped_lock lock(mLock);
        mCounters[id].palms++;
    }

    // Checks whether a Gesture struct is for the end of a gesture that we log metrics for, and
    // records it if so.
    void processGesture(const TouchpadInputMapper::MetricsIdentifier& id, const Gesture& gesture) {
        std::scoped_lock lock(mLock);
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
        accumulator.produceAtomsAndReset(*outEventList);
        return AStatsManager_PULL_SUCCESS;
    }

    void produceAtomsAndReset(AStatsEventList& outEventList) {
        std::scoped_lock lock(mLock);
        produceAtomsLocked(outEventList);
        resetCountersLocked();
    }

    void produceAtomsLocked(AStatsEventList& outEventList) const REQUIRES(mLock) {
        for (auto& [id, counters] : mCounters) {
            auto [busId, vendorId, productId, versionId] = id;
            addAStatsEvent(&outEventList, android::util::TOUCHPAD_USAGE, vendorId, productId,
                           versionId, linuxBusToInputDeviceBusEnum(busId, /*isUsi=*/false),
                           counters.fingers, counters.palms, counters.twoFingerSwipeGestures,
                           counters.threeFingerSwipeGestures, counters.fourFingerSwipeGestures,
                           counters.pinchGestures);
        }
    }

    void resetCountersLocked() REQUIRES(mLock) { mCounters.clear(); }

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
    std::map<TouchpadInputMapper::MetricsIdentifier, Counters> mCounters GUARDED_BY(mLock);

    // Metrics are pulled by a binder thread, so we need to guard them with a mutex.
    mutable std::mutex mLock;
};

} // namespace

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext,
                                         const InputReaderConfiguration& readerConfig)
      : TouchpadInputMapper(deviceContext, readerConfig, ENABLE_POINTER_CHOREOGRAPHER) {}

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext,
                                         const InputReaderConfiguration& readerConfig,
                                         bool enablePointerChoreographer)
      : InputMapper(deviceContext, readerConfig),
        mGestureInterpreter(NewGestureInterpreter(), DeleteGestureInterpreter),
        mPointerController(getContext()->getPointerController(getDeviceId())),
        mTimerProvider(*getContext()),
        mStateConverter(deviceContext, mMotionAccumulator),
        mGestureConverter(*getContext(), deviceContext, getDeviceId()),
        mCapturedEventConverter(*getContext(), deviceContext, mMotionAccumulator, getDeviceId()),
        mMetricsId(metricsIdFromInputDeviceIdentifier(deviceContext.getDeviceIdentifier())),
        mEnablePointerChoreographer(enablePointerChoreographer) {
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
    if (input_flags::enable_gestures_library_timer_provider()) {
        mGestureInterpreter->SetTimerProvider(const_cast<GesturesTimerProvider*>(
                                                      &kGestureTimerProvider),
                                              &mTimerProvider);
    }
    mGestureInterpreter->SetCallback(gestureInterpreterCallback, this);
}

TouchpadInputMapper::~TouchpadInputMapper() {
    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
    }

    // The gesture interpreter's destructor will try to free its property and timer providers,
    // calling PropertyProvider::freeProperty and TimerProvider::freeTimer using a raw pointers.
    // Depending on the declaration order in TouchpadInputMapper.h, those providers may have already
    // been freed, causing allocation errors or use-after-free bugs. Depending on declaration order
    // to avoid this seems rather fragile, so explicitly clear the providers here to ensure all the
    // freeProperty and freeTimer calls happen before the providers are destructed.
    mGestureInterpreter->SetPropProvider(nullptr, nullptr);
    mGestureInterpreter->SetTimerProvider(nullptr, nullptr);
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
    if (mResettingInterpreter) {
        dump += INDENT3 "Currently resetting gesture interpreter\n";
    }
    dump += StringPrintf(INDENT3 "Pointer captured: %s\n", toString(mPointerCaptured));
    dump += INDENT3 "Gesture converter:\n";
    dump += addLinePrefix(mGestureConverter.dump(), INDENT4);
    dump += INDENT3 "Gesture properties:\n";
    dump += addLinePrefix(mPropertyProvider.dump(), INDENT4);
    if (input_flags::enable_gestures_library_timer_provider()) {
        dump += INDENT3 "Timer provider:\n";
        dump += addLinePrefix(mTimerProvider.dump(), INDENT4);
    } else {
        dump += INDENT3 "Timer provider: disabled by flag\n";
    }
    dump += INDENT3 "Captured event converter:\n";
    dump += addLinePrefix(mCapturedEventConverter.dump(), INDENT4);
    dump += StringPrintf(INDENT3 "DisplayId: %s\n", toString(mDisplayId).c_str());
}

std::list<NotifyArgs> TouchpadInputMapper::reconfigure(nsecs_t when,
                                                       const InputReaderConfiguration& config,
                                                       ConfigurationChanges changes) {
    if (!changes.any()) {
        // First time configuration
        mPropertyProvider.loadPropertiesFromIdcFile(getDeviceContext().getConfiguration());
    }

    if (!changes.any() || changes.test(InputReaderConfiguration::Change::DISPLAY_INFO)) {
        mDisplayId = ADISPLAY_ID_NONE;
        std::optional<DisplayViewport> resolvedViewport;
        std::optional<FloatRect> boundsInLogicalDisplay;
        if (auto assocViewport = mDeviceContext.getAssociatedViewport(); assocViewport) {
            // This InputDevice is associated with a viewport.
            // Only generate events for the associated display.
            mDisplayId = assocViewport->displayId;
            resolvedViewport = *assocViewport;
            if (!mEnablePointerChoreographer) {
                const bool mismatchedPointerDisplay =
                        (assocViewport->displayId != mPointerController->getDisplayId());
                if (mismatchedPointerDisplay) {
                    ALOGW("Touchpad \"%s\" associated viewport display does not match pointer "
                          "controller",
                          mDeviceContext.getName().c_str());
                    mDisplayId.reset();
                }
            }
        } else {
            // The InputDevice is not associated with a viewport, but it controls the mouse pointer.
            if (mEnablePointerChoreographer) {
                // Always use DISPLAY_ID_NONE for touchpad events.
                // PointerChoreographer will make it target the correct the displayId later.
                resolvedViewport =
                        getContext()->getPolicy()->getPointerViewportForAssociatedDisplay();
                mDisplayId = resolvedViewport ? std::make_optional(ADISPLAY_ID_NONE) : std::nullopt;
            } else {
                mDisplayId = mPointerController->getDisplayId();
                if (auto v = config.getDisplayViewportById(*mDisplayId); v) {
                    resolvedViewport = *v;
                }
                if (auto bounds = mPointerController->getBounds(); bounds) {
                    boundsInLogicalDisplay = *bounds;
                }
            }
        }

        mGestureConverter.setDisplayId(mDisplayId);
        mGestureConverter.setOrientation(resolvedViewport
                                                 ? getInverseRotation(resolvedViewport->orientation)
                                                 : ui::ROTATION_0);

        if (!boundsInLogicalDisplay) {
            boundsInLogicalDisplay = resolvedViewport
                    ? FloatRect{static_cast<float>(resolvedViewport->logicalLeft),
                                static_cast<float>(resolvedViewport->logicalTop),
                                static_cast<float>(resolvedViewport->logicalRight - 1),
                                static_cast<float>(resolvedViewport->logicalBottom - 1)}
                    : FloatRect{0, 0, 0, 0};
        }
        mGestureConverter.setBoundsInLogicalDisplay(*boundsInLogicalDisplay);

        bumpGeneration();
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
        mPropertyProvider.getProperty("Tap Drag Enable")
                .setBoolValues({config.touchpadTapDraggingEnabled});
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
    if (mMotionAccumulator.getActiveSlotsCount() == 0) {
        mGestureStartTime = rawEvent->when;
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
    mGestureInterpreter->PushHardwareState(&schs.state);
    return processGestures(when, readTime);
}

std::list<NotifyArgs> TouchpadInputMapper::timeoutExpired(nsecs_t when) {
    if (!input_flags::enable_gestures_library_timer_provider()) {
        return {};
    }
    mTimerProvider.triggerCallbacks(when);
    return processGestures(when, when);
}

void TouchpadInputMapper::consumeGesture(const Gesture* gesture) {
    ALOGD_IF(DEBUG_TOUCHPAD_GESTURES, "Gesture ready: %s", gesture->String().c_str());
    if (mResettingInterpreter) {
        // We already handle tidying up fake fingers etc. in GestureConverter::reset, so we should
        // ignore any gestures produced from the interpreter while we're resetting it.
        return;
    }
    mGesturesToProcess.push_back(*gesture);
}

std::list<NotifyArgs> TouchpadInputMapper::processGestures(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out = {};
    if (mDisplayId) {
        MetricsAccumulator& metricsAccumulator = MetricsAccumulator::getInstance();
        for (Gesture& gesture : mGesturesToProcess) {
            out += mGestureConverter.handleGesture(when, readTime, mGestureStartTime, gesture);
            metricsAccumulator.processGesture(mMetricsId, gesture);
        }
    }
    mGesturesToProcess.clear();
    return out;
}

std::optional<int32_t> TouchpadInputMapper::getAssociatedDisplayId() {
    return mDisplayId;
}

} // namespace android
