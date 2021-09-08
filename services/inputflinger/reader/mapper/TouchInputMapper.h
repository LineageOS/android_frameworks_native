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

#ifndef _UI_INPUTREADER_TOUCH_INPUT_MAPPER_H
#define _UI_INPUTREADER_TOUCH_INPUT_MAPPER_H

#include "CursorButtonAccumulator.h"
#include "CursorScrollAccumulator.h"
#include "EventHub.h"
#include "InputMapper.h"
#include "InputReaderBase.h"
#include "TouchButtonAccumulator.h"

#include <stdint.h>

namespace android {

/* Raw axis information from the driver. */
struct RawPointerAxes {
    RawAbsoluteAxisInfo x;
    RawAbsoluteAxisInfo y;
    RawAbsoluteAxisInfo pressure;
    RawAbsoluteAxisInfo touchMajor;
    RawAbsoluteAxisInfo touchMinor;
    RawAbsoluteAxisInfo toolMajor;
    RawAbsoluteAxisInfo toolMinor;
    RawAbsoluteAxisInfo orientation;
    RawAbsoluteAxisInfo distance;
    RawAbsoluteAxisInfo tiltX;
    RawAbsoluteAxisInfo tiltY;
    RawAbsoluteAxisInfo trackingId;
    RawAbsoluteAxisInfo slot;

    RawPointerAxes();
    inline int32_t getRawWidth() const { return x.maxValue - x.minValue + 1; }
    inline int32_t getRawHeight() const { return y.maxValue - y.minValue + 1; }
    void clear();
};

/* Raw data for a collection of pointers including a pointer id mapping table. */
struct RawPointerData {
    struct Pointer {
        uint32_t id;
        int32_t x;
        int32_t y;
        int32_t pressure;
        int32_t touchMajor;
        int32_t touchMinor;
        int32_t toolMajor;
        int32_t toolMinor;
        int32_t orientation;
        int32_t distance;
        int32_t tiltX;
        int32_t tiltY;
        int32_t toolType; // a fully decoded AMOTION_EVENT_TOOL_TYPE constant
        bool isHovering;
    };

    uint32_t pointerCount;
    Pointer pointers[MAX_POINTERS];
    BitSet32 hoveringIdBits, touchingIdBits;
    uint32_t idToIndex[MAX_POINTER_ID + 1];

    RawPointerData();
    void clear();
    void copyFrom(const RawPointerData& other);
    void getCentroidOfTouchingPointers(float* outX, float* outY) const;

    inline void markIdBit(uint32_t id, bool isHovering) {
        if (isHovering) {
            hoveringIdBits.markBit(id);
        } else {
            touchingIdBits.markBit(id);
        }
    }

    inline void clearIdBits() {
        hoveringIdBits.clear();
        touchingIdBits.clear();
    }

    inline const Pointer& pointerForId(uint32_t id) const { return pointers[idToIndex[id]]; }

    inline bool isHovering(uint32_t pointerIndex) { return pointers[pointerIndex].isHovering; }
};

/* Cooked data for a collection of pointers including a pointer id mapping table. */
struct CookedPointerData {
    uint32_t pointerCount;
    PointerProperties pointerProperties[MAX_POINTERS];
    PointerCoords pointerCoords[MAX_POINTERS];
    BitSet32 hoveringIdBits, touchingIdBits;
    uint32_t idToIndex[MAX_POINTER_ID + 1];

    CookedPointerData();
    void clear();
    void copyFrom(const CookedPointerData& other);

    inline const PointerCoords& pointerCoordsForId(uint32_t id) const {
        return pointerCoords[idToIndex[id]];
    }

    inline PointerCoords& editPointerCoordsWithId(uint32_t id) {
        return pointerCoords[idToIndex[id]];
    }

    inline PointerProperties& editPointerPropertiesWithId(uint32_t id) {
        return pointerProperties[idToIndex[id]];
    }

    inline bool isHovering(uint32_t pointerIndex) const {
        return hoveringIdBits.hasBit(pointerProperties[pointerIndex].id);
    }

    inline bool isTouching(uint32_t pointerIndex) const {
        return touchingIdBits.hasBit(pointerProperties[pointerIndex].id);
    }
};

class TouchInputMapper : public InputMapper {
public:
    explicit TouchInputMapper(InputDeviceContext& deviceContext);
    virtual ~TouchInputMapper();

    virtual uint32_t getSources() override;
    virtual void populateDeviceInfo(InputDeviceInfo* deviceInfo) override;
    virtual void dump(std::string& dump) override;
    virtual void configure(nsecs_t when, const InputReaderConfiguration* config,
                           uint32_t changes) override;
    virtual void reset(nsecs_t when) override;
    virtual void process(const RawEvent* rawEvent) override;

    virtual int32_t getKeyCodeState(uint32_t sourceMask, int32_t keyCode) override;
    virtual int32_t getScanCodeState(uint32_t sourceMask, int32_t scanCode) override;
    virtual bool markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes,
                                       const int32_t* keyCodes, uint8_t* outFlags) override;

    virtual void cancelTouch(nsecs_t when) override;
    virtual void timeoutExpired(nsecs_t when) override;
    virtual void updateExternalStylusState(const StylusState& state) override;
    virtual std::optional<int32_t> getAssociatedDisplayId() override;

protected:
    CursorButtonAccumulator mCursorButtonAccumulator;
    CursorScrollAccumulator mCursorScrollAccumulator;
    TouchButtonAccumulator mTouchButtonAccumulator;

    struct VirtualKey {
        int32_t keyCode;
        int32_t scanCode;
        uint32_t flags;

        // computed hit box, specified in touch screen coords based on known display size
        int32_t hitLeft;
        int32_t hitTop;
        int32_t hitRight;
        int32_t hitBottom;

        inline bool isHit(int32_t x, int32_t y) const {
            return x >= hitLeft && x <= hitRight && y >= hitTop && y <= hitBottom;
        }
    };

    // Input sources and device mode.
    uint32_t mSource;

    enum DeviceMode {
        DEVICE_MODE_DISABLED,   // input is disabled
        DEVICE_MODE_DIRECT,     // direct mapping (touchscreen)
        DEVICE_MODE_UNSCALED,   // unscaled mapping (touchpad)
        DEVICE_MODE_NAVIGATION, // unscaled mapping with assist gesture (touch navigation)
        DEVICE_MODE_POINTER,    // pointer mapping (pointer)
    };
    DeviceMode mDeviceMode;

    // The reader's configuration.
    InputReaderConfiguration mConfig;

    // Immutable configuration parameters.
    struct Parameters {
        enum DeviceType {
            DEVICE_TYPE_TOUCH_SCREEN,
            DEVICE_TYPE_TOUCH_PAD,
            DEVICE_TYPE_TOUCH_NAVIGATION,
            DEVICE_TYPE_POINTER,
        };

        DeviceType deviceType;
        bool hasAssociatedDisplay;
        bool associatedDisplayIsExternal;
        bool orientationAware;
        bool hasButtonUnderPad;
        std::string uniqueDisplayId;

        enum GestureMode {
            GESTURE_MODE_SINGLE_TOUCH,
            GESTURE_MODE_MULTI_TOUCH,
        };
        GestureMode gestureMode;

        bool wake;
    } mParameters;

    // Immutable calibration parameters in parsed form.
    struct Calibration {
        // Size
        enum SizeCalibration {
            SIZE_CALIBRATION_DEFAULT,
            SIZE_CALIBRATION_NONE,
            SIZE_CALIBRATION_GEOMETRIC,
            SIZE_CALIBRATION_DIAMETER,
            SIZE_CALIBRATION_BOX,
            SIZE_CALIBRATION_AREA,
        };

        SizeCalibration sizeCalibration;

        bool haveSizeScale;
        float sizeScale;
        bool haveSizeBias;
        float sizeBias;
        bool haveSizeIsSummed;
        bool sizeIsSummed;

        // Pressure
        enum PressureCalibration {
            PRESSURE_CALIBRATION_DEFAULT,
            PRESSURE_CALIBRATION_NONE,
            PRESSURE_CALIBRATION_PHYSICAL,
            PRESSURE_CALIBRATION_AMPLITUDE,
        };

        PressureCalibration pressureCalibration;
        bool havePressureScale;
        float pressureScale;

        // Orientation
        enum OrientationCalibration {
            ORIENTATION_CALIBRATION_DEFAULT,
            ORIENTATION_CALIBRATION_NONE,
            ORIENTATION_CALIBRATION_INTERPOLATED,
            ORIENTATION_CALIBRATION_VECTOR,
        };

        OrientationCalibration orientationCalibration;

        // Distance
        enum DistanceCalibration {
            DISTANCE_CALIBRATION_DEFAULT,
            DISTANCE_CALIBRATION_NONE,
            DISTANCE_CALIBRATION_SCALED,
        };

        DistanceCalibration distanceCalibration;
        bool haveDistanceScale;
        float distanceScale;

        enum CoverageCalibration {
            COVERAGE_CALIBRATION_DEFAULT,
            COVERAGE_CALIBRATION_NONE,
            COVERAGE_CALIBRATION_BOX,
        };

        CoverageCalibration coverageCalibration;

        inline void applySizeScaleAndBias(float* outSize) const {
            if (haveSizeScale) {
                *outSize *= sizeScale;
            }
            if (haveSizeBias) {
                *outSize += sizeBias;
            }
            if (*outSize < 0) {
                *outSize = 0;
            }
        }
    } mCalibration;

    // Affine location transformation/calibration
    struct TouchAffineTransformation mAffineTransform;

    RawPointerAxes mRawPointerAxes;

    struct RawState {
        nsecs_t when;

        // Raw pointer sample data.
        RawPointerData rawPointerData;

        int32_t buttonState;

        // Scroll state.
        int32_t rawVScroll;
        int32_t rawHScroll;

        void copyFrom(const RawState& other) {
            when = other.when;
            rawPointerData.copyFrom(other.rawPointerData);
            buttonState = other.buttonState;
            rawVScroll = other.rawVScroll;
            rawHScroll = other.rawHScroll;
        }

        void clear() {
            when = 0;
            rawPointerData.clear();
            buttonState = 0;
            rawVScroll = 0;
            rawHScroll = 0;
        }
    };

    struct CookedState {
        // Cooked pointer sample data.
        CookedPointerData cookedPointerData;

        // Id bits used to differentiate fingers, stylus and mouse tools.
        BitSet32 fingerIdBits;
        BitSet32 stylusIdBits;
        BitSet32 mouseIdBits;

        int32_t buttonState;

        void copyFrom(const CookedState& other) {
            cookedPointerData.copyFrom(other.cookedPointerData);
            fingerIdBits = other.fingerIdBits;
            stylusIdBits = other.stylusIdBits;
            mouseIdBits = other.mouseIdBits;
            buttonState = other.buttonState;
        }

        void clear() {
            cookedPointerData.clear();
            fingerIdBits.clear();
            stylusIdBits.clear();
            mouseIdBits.clear();
            buttonState = 0;
        }
    };

    std::vector<RawState> mRawStatesPending;
    RawState mCurrentRawState;
    CookedState mCurrentCookedState;
    RawState mLastRawState;
    CookedState mLastCookedState;

    // State provided by an external stylus
    StylusState mExternalStylusState;
    int64_t mExternalStylusId;
    nsecs_t mExternalStylusFusionTimeout;
    bool mExternalStylusDataPending;

    // True if we sent a HOVER_ENTER event.
    bool mSentHoverEnter;

    // Have we assigned pointer IDs for this stream
    bool mHavePointerIds;

    // Is the current stream of direct touch events aborted
    bool mCurrentMotionAborted;

    // The time the primary pointer last went down.
    nsecs_t mDownTime;

    // The pointer controller, or null if the device is not a pointer.
    sp<PointerControllerInterface> mPointerController;

    std::vector<VirtualKey> mVirtualKeys;

    virtual void configureParameters();
    virtual void dumpParameters(std::string& dump);
    virtual void configureRawPointerAxes();
    virtual void dumpRawPointerAxes(std::string& dump);
    virtual void configureSurface(nsecs_t when, bool* outResetNeeded);
    virtual void dumpSurface(std::string& dump);
    virtual void configureVirtualKeys();
    virtual void dumpVirtualKeys(std::string& dump);
    virtual void parseCalibration();
    virtual void resolveCalibration();
    virtual void dumpCalibration(std::string& dump);
    virtual void updateAffineTransformation();
    virtual void dumpAffineTransformation(std::string& dump);
    virtual void resolveExternalStylusPresence();
    virtual bool hasStylus() const = 0;
    virtual bool hasExternalStylus() const;

    virtual void syncTouch(nsecs_t when, RawState* outState) = 0;

private:
    // The current viewport.
    // The components of the viewport are specified in the display's rotated orientation.
    DisplayViewport mViewport;

    // The surface orientation, width and height set by configureSurface().
    // The width and height are derived from the viewport but are specified
    // in the natural orientation.
    // They could be used for calculating diagonal, scaling factors, and virtual keys.
    int32_t mRawSurfaceWidth;
    int32_t mRawSurfaceHeight;

    // The surface origin specifies how the surface coordinates should be translated
    // to align with the logical display coordinate space.
    int32_t mSurfaceLeft;
    int32_t mSurfaceTop;
    int32_t mSurfaceRight;
    int32_t mSurfaceBottom;

    // Similar to the surface coordinates, but in the raw display coordinate space rather than in
    // the logical coordinate space.
    int32_t mPhysicalWidth;
    int32_t mPhysicalHeight;
    int32_t mPhysicalLeft;
    int32_t mPhysicalTop;

    // The orientation may be different from the viewport orientation as it specifies
    // the rotation of the surface coordinates required to produce the viewport's
    // requested orientation, so it will depend on whether the device is orientation aware.
    int32_t mSurfaceOrientation;

    // Translation and scaling factors, orientation-independent.
    float mXTranslate;
    float mXScale;
    float mXPrecision;

    float mYTranslate;
    float mYScale;
    float mYPrecision;

    float mGeometricScale;

    float mPressureScale;

    float mSizeScale;

    float mOrientationScale;

    float mDistanceScale;

    bool mHaveTilt;
    float mTiltXCenter;
    float mTiltXScale;
    float mTiltYCenter;
    float mTiltYScale;

    bool mExternalStylusConnected;

    // Oriented motion ranges for input device info.
    struct OrientedRanges {
        InputDeviceInfo::MotionRange x;
        InputDeviceInfo::MotionRange y;
        InputDeviceInfo::MotionRange pressure;

        bool haveSize;
        InputDeviceInfo::MotionRange size;

        bool haveTouchSize;
        InputDeviceInfo::MotionRange touchMajor;
        InputDeviceInfo::MotionRange touchMinor;

        bool haveToolSize;
        InputDeviceInfo::MotionRange toolMajor;
        InputDeviceInfo::MotionRange toolMinor;

        bool haveOrientation;
        InputDeviceInfo::MotionRange orientation;

        bool haveDistance;
        InputDeviceInfo::MotionRange distance;

        bool haveTilt;
        InputDeviceInfo::MotionRange tilt;

        OrientedRanges() { clear(); }

        void clear() {
            haveSize = false;
            haveTouchSize = false;
            haveToolSize = false;
            haveOrientation = false;
            haveDistance = false;
            haveTilt = false;
        }
    } mOrientedRanges;

    // Oriented dimensions and precision.
    float mOrientedXPrecision;
    float mOrientedYPrecision;

    struct CurrentVirtualKeyState {
        bool down;
        bool ignored;
        nsecs_t downTime;
        int32_t keyCode;
        int32_t scanCode;
    } mCurrentVirtualKey;

    // Scale factor for gesture or mouse based pointer movements.
    float mPointerXMovementScale;
    float mPointerYMovementScale;

    // Scale factor for gesture based zooming and other freeform motions.
    float mPointerXZoomScale;
    float mPointerYZoomScale;

    // The maximum swipe width.
    float mPointerGestureMaxSwipeWidth;

    struct PointerDistanceHeapElement {
        uint32_t currentPointerIndex : 8;
        uint32_t lastPointerIndex : 8;
        uint64_t distance : 48; // squared distance
    };

    enum PointerUsage {
        POINTER_USAGE_NONE,
        POINTER_USAGE_GESTURES,
        POINTER_USAGE_STYLUS,
        POINTER_USAGE_MOUSE,
    };
    PointerUsage mPointerUsage;

    struct PointerGesture {
        enum Mode {
            // No fingers, button is not pressed.
            // Nothing happening.
            NEUTRAL,

            // No fingers, button is not pressed.
            // Tap detected.
            // Emits DOWN and UP events at the pointer location.
            TAP,

            // Exactly one finger dragging following a tap.
            // Pointer follows the active finger.
            // Emits DOWN, MOVE and UP events at the pointer location.
            //
            // Detect double-taps when the finger goes up while in TAP_DRAG mode.
            TAP_DRAG,

            // Button is pressed.
            // Pointer follows the active finger if there is one.  Other fingers are ignored.
            // Emits DOWN, MOVE and UP events at the pointer location.
            BUTTON_CLICK_OR_DRAG,

            // Exactly one finger, button is not pressed.
            // Pointer follows the active finger.
            // Emits HOVER_MOVE events at the pointer location.
            //
            // Detect taps when the finger goes up while in HOVER mode.
            HOVER,

            // Exactly two fingers but neither have moved enough to clearly indicate
            // whether a swipe or freeform gesture was intended.  We consider the
            // pointer to be pressed so this enables clicking or long-pressing on buttons.
            // Pointer does not move.
            // Emits DOWN, MOVE and UP events with a single stationary pointer coordinate.
            PRESS,

            // Exactly two fingers moving in the same direction, button is not pressed.
            // Pointer does not move.
            // Emits DOWN, MOVE and UP events with a single pointer coordinate that
            // follows the midpoint between both fingers.
            SWIPE,

            // Two or more fingers moving in arbitrary directions, button is not pressed.
            // Pointer does not move.
            // Emits DOWN, POINTER_DOWN, MOVE, POINTER_UP and UP events that follow
            // each finger individually relative to the initial centroid of the finger.
            FREEFORM,

            // Waiting for quiet time to end before starting the next gesture.
            QUIET,
        };

        // Time the first finger went down.
        nsecs_t firstTouchTime;

        // The active pointer id from the raw touch data.
        int32_t activeTouchId; // -1 if none

        // The active pointer id from the gesture last delivered to the application.
        int32_t activeGestureId; // -1 if none

        // Pointer coords and ids for the current and previous pointer gesture.
        Mode currentGestureMode;
        BitSet32 currentGestureIdBits;
        uint32_t currentGestureIdToIndex[MAX_POINTER_ID + 1];
        PointerProperties currentGestureProperties[MAX_POINTERS];
        PointerCoords currentGestureCoords[MAX_POINTERS];

        Mode lastGestureMode;
        BitSet32 lastGestureIdBits;
        uint32_t lastGestureIdToIndex[MAX_POINTER_ID + 1];
        PointerProperties lastGestureProperties[MAX_POINTERS];
        PointerCoords lastGestureCoords[MAX_POINTERS];

        // Time the pointer gesture last went down.
        nsecs_t downTime;

        // Time when the pointer went down for a TAP.
        nsecs_t tapDownTime;

        // Time when the pointer went up for a TAP.
        nsecs_t tapUpTime;

        // Location of initial tap.
        float tapX, tapY;

        // Time we started waiting for quiescence.
        nsecs_t quietTime;

        // Reference points for multitouch gestures.
        float referenceTouchX; // reference touch X/Y coordinates in surface units
        float referenceTouchY;
        float referenceGestureX; // reference gesture X/Y coordinates in pixels
        float referenceGestureY;

        // Distance that each pointer has traveled which has not yet been
        // subsumed into the reference gesture position.
        BitSet32 referenceIdBits;
        struct Delta {
            float dx, dy;
        };
        Delta referenceDeltas[MAX_POINTER_ID + 1];

        // Describes how touch ids are mapped to gesture ids for freeform gestures.
        uint32_t freeformTouchToGestureIdMap[MAX_POINTER_ID + 1];

        // A velocity tracker for determining whether to switch active pointers during drags.
        VelocityTracker velocityTracker;

        void reset() {
            firstTouchTime = LLONG_MIN;
            activeTouchId = -1;
            activeGestureId = -1;
            currentGestureMode = NEUTRAL;
            currentGestureIdBits.clear();
            lastGestureMode = NEUTRAL;
            lastGestureIdBits.clear();
            downTime = 0;
            velocityTracker.clear();
            resetTap();
            resetQuietTime();
        }

        void resetTap() {
            tapDownTime = LLONG_MIN;
            tapUpTime = LLONG_MIN;
        }

        void resetQuietTime() { quietTime = LLONG_MIN; }
    } mPointerGesture;

    struct PointerSimple {
        PointerCoords currentCoords;
        PointerProperties currentProperties;
        PointerCoords lastCoords;
        PointerProperties lastProperties;

        // True if the pointer is down.
        bool down;

        // True if the pointer is hovering.
        bool hovering;

        // Time the pointer last went down.
        nsecs_t downTime;

        void reset() {
            currentCoords.clear();
            currentProperties.clear();
            lastCoords.clear();
            lastProperties.clear();
            down = false;
            hovering = false;
            downTime = 0;
        }
    } mPointerSimple;

    // The pointer and scroll velocity controls.
    VelocityControl mPointerVelocityControl;
    VelocityControl mWheelXVelocityControl;
    VelocityControl mWheelYVelocityControl;

    std::optional<DisplayViewport> findViewport();

    void resetExternalStylus();
    void clearStylusDataPendingFlags();

    void sync(nsecs_t when);

    bool consumeRawTouches(nsecs_t when, uint32_t policyFlags);
    void processRawTouches(bool timeout);
    void cookAndDispatch(nsecs_t when);
    void dispatchVirtualKey(nsecs_t when, uint32_t policyFlags, int32_t keyEventAction,
                            int32_t keyEventFlags);

    void dispatchTouches(nsecs_t when, uint32_t policyFlags);
    void dispatchHoverExit(nsecs_t when, uint32_t policyFlags);
    void dispatchHoverEnterAndMove(nsecs_t when, uint32_t policyFlags);
    void dispatchButtonRelease(nsecs_t when, uint32_t policyFlags);
    void dispatchButtonPress(nsecs_t when, uint32_t policyFlags);
    const BitSet32& findActiveIdBits(const CookedPointerData& cookedPointerData);
    void cookPointerData();
    void abortTouches(nsecs_t when, uint32_t policyFlags);

    void dispatchPointerUsage(nsecs_t when, uint32_t policyFlags, PointerUsage pointerUsage);
    void abortPointerUsage(nsecs_t when, uint32_t policyFlags);

    void dispatchPointerGestures(nsecs_t when, uint32_t policyFlags, bool isTimeout);
    void abortPointerGestures(nsecs_t when, uint32_t policyFlags);
    bool preparePointerGestures(nsecs_t when, bool* outCancelPreviousGesture,
                                bool* outFinishPreviousGesture, bool isTimeout);

    void dispatchPointerStylus(nsecs_t when, uint32_t policyFlags);
    void abortPointerStylus(nsecs_t when, uint32_t policyFlags);

    void dispatchPointerMouse(nsecs_t when, uint32_t policyFlags);
    void abortPointerMouse(nsecs_t when, uint32_t policyFlags);

    void dispatchPointerSimple(nsecs_t when, uint32_t policyFlags, bool down, bool hovering);
    void abortPointerSimple(nsecs_t when, uint32_t policyFlags);

    bool assignExternalStylusId(const RawState& state, bool timeout);
    void applyExternalStylusButtonState(nsecs_t when);
    void applyExternalStylusTouchState(nsecs_t when);

    // Dispatches a motion event.
    // If the changedId is >= 0 and the action is POINTER_DOWN or POINTER_UP, the
    // method will take care of setting the index and transmuting the action to DOWN or UP
    // it is the first / last pointer to go down / up.
    void dispatchMotion(nsecs_t when, uint32_t policyFlags, uint32_t source, int32_t action,
                        int32_t actionButton, int32_t flags, int32_t metaState, int32_t buttonState,
                        int32_t edgeFlags, const PointerProperties* properties,
                        const PointerCoords* coords, const uint32_t* idToIndex, BitSet32 idBits,
                        int32_t changedId, float xPrecision, float yPrecision, nsecs_t downTime);

    // Updates pointer coords and properties for pointers with specified ids that have moved.
    // Returns true if any of them changed.
    bool updateMovedPointers(const PointerProperties* inProperties, const PointerCoords* inCoords,
                             const uint32_t* inIdToIndex, PointerProperties* outProperties,
                             PointerCoords* outCoords, const uint32_t* outIdToIndex,
                             BitSet32 idBits) const;

    bool isPointInsideSurface(int32_t x, int32_t y);
    const VirtualKey* findVirtualKeyHit(int32_t x, int32_t y);

    static void assignPointerIds(const RawState& last, RawState& current);

    const char* modeToString(DeviceMode deviceMode);
    void rotateAndScale(float& x, float& y);
};

} // namespace android

#endif // _UI_INPUTREADER_TOUCH_INPUT_MAPPER_H