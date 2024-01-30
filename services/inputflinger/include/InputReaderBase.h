/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <android/os/IInputConstants.h>
#include <input/DisplayViewport.h>
#include <input/Input.h>
#include <input/InputDevice.h>
#include <input/VelocityControl.h>
#include <input/VelocityTracker.h>
#include <stddef.h>
#include <ui/Rotation.h>
#include <unistd.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include "PointerControllerInterface.h"
#include "VibrationElement.h"

// Maximum supported size of a vibration pattern.
// Must be at least 2.
#define MAX_VIBRATE_PATTERN_SIZE 100

namespace android {

// --- InputReaderConfiguration ---

/*
 * Input reader configuration.
 *
 * Specifies various options that modify the behavior of the input reader.
 */
struct InputReaderConfiguration {
    // Describes changes that have occurred.
    enum class Change : uint32_t {
        // The mouse pointer speed changed.
        POINTER_SPEED = 1u << 0,

        // The pointer gesture control changed.
        POINTER_GESTURE_ENABLEMENT = 1u << 1,

        // The display size or orientation changed.
        DISPLAY_INFO = 1u << 2,

        // The visible touches option changed.
        SHOW_TOUCHES = 1u << 3,

        // The keyboard layouts must be reloaded.
        KEYBOARD_LAYOUTS = 1u << 4,

        // The device name alias supplied by the may have changed for some devices.
        DEVICE_ALIAS = 1u << 5,

        // The location calibration matrix changed.
        TOUCH_AFFINE_TRANSFORMATION = 1u << 6,

        // The presence of an external stylus has changed.
        EXTERNAL_STYLUS_PRESENCE = 1u << 7,

        // The pointer capture mode has changed.
        POINTER_CAPTURE = 1u << 8,

        // The set of disabled input devices (disabledDevices) has changed.
        ENABLED_STATE = 1u << 9,

        // The device type has been updated.
        DEVICE_TYPE = 1u << 10,

        // The keyboard layout association has changed.
        KEYBOARD_LAYOUT_ASSOCIATION = 1u << 11,

        // The stylus button reporting configurations has changed.
        STYLUS_BUTTON_REPORTING = 1u << 12,

        // The touchpad settings changed.
        TOUCHPAD_SETTINGS = 1u << 13,

        // All devices must be reopened.
        MUST_REOPEN = 1u << 31,
    };

    // Gets the amount of time to disable virtual keys after the screen is touched
    // in order to filter out accidental virtual key presses due to swiping gestures
    // or taps near the edge of the display.  May be 0 to disable the feature.
    nsecs_t virtualKeyQuietTime;

    // The excluded device names for the platform.
    // Devices with these names will be ignored.
    std::vector<std::string> excludedDeviceNames;

    // The associations between input ports and display ports.
    // Used to determine which DisplayViewport should be tied to which InputDevice.
    std::unordered_map<std::string, uint8_t> portAssociations;

    // The associations between input device physical port locations and display unique ids.
    // Used to determine which DisplayViewport should be tied to which InputDevice.
    std::unordered_map<std::string, std::string> uniqueIdAssociations;

    // The associations between input device ports device types.
    // This is used to determine which device type and source should be tied to which InputDevice.
    std::unordered_map<std::string, std::string> deviceTypeAssociations;

    // The map from the input device physical port location to the input device layout info.
    // Can be used to determine the layout of the keyboard device.
    std::unordered_map<std::string, KeyboardLayoutInfo> keyboardLayoutAssociations;

    // The suggested display ID to show the cursor.
    int32_t defaultPointerDisplayId;

    // The mouse pointer speed, as a number from -7 (slowest) to 7 (fastest).
    //
    // Currently only used when the enable_new_mouse_pointer_ballistics flag is enabled.
    int32_t mousePointerSpeed;

    // Displays on which an acceleration curve shouldn't be applied for pointer movements from mice.
    //
    // Currently only used when the enable_new_mouse_pointer_ballistics flag is enabled.
    std::set<int32_t> displaysWithMousePointerAccelerationDisabled;

    // Velocity control parameters for mouse pointer movements.
    //
    // If the enable_new_mouse_pointer_ballistics flag is enabled, these are ignored and the values
    // of mousePointerSpeed and mousePointerAccelerationEnabled used instead.
    VelocityControlParameters pointerVelocityControlParameters;

    // Velocity control parameters for mouse wheel movements.
    VelocityControlParameters wheelVelocityControlParameters;

    // True if pointer gestures are enabled.
    bool pointerGesturesEnabled;

    // Quiet time between certain pointer gesture transitions.
    // Time to allow for all fingers or buttons to settle into a stable state before
    // starting a new gesture.
    nsecs_t pointerGestureQuietInterval;

    // The minimum speed that a pointer must travel for us to consider switching the active
    // touch pointer to it during a drag.  This threshold is set to avoid switching due
    // to noise from a finger resting on the touch pad (perhaps just pressing it down).
    float pointerGestureDragMinSwitchSpeed; // in pixels per second

    // Tap gesture delay time.
    // The time between down and up must be less than this to be considered a tap.
    nsecs_t pointerGestureTapInterval;

    // Tap drag gesture delay time.
    // The time between the previous tap's up and the next down must be less than
    // this to be considered a drag.  Otherwise, the previous tap is finished and a
    // new tap begins.
    //
    // Note that the previous tap will be held down for this entire duration so this
    // interval must be shorter than the long press timeout.
    nsecs_t pointerGestureTapDragInterval;

    // The distance in pixels that the pointer is allowed to move from initial down
    // to up and still be called a tap.
    float pointerGestureTapSlop; // in pixels

    // Time after the first touch points go down to settle on an initial centroid.
    // This is intended to be enough time to handle cases where the user puts down two
    // fingers at almost but not quite exactly the same time.
    nsecs_t pointerGestureMultitouchSettleInterval;

    // The transition from PRESS to SWIPE or FREEFORM gesture mode is made when
    // at least two pointers have moved at least this far from their starting place.
    float pointerGestureMultitouchMinDistance; // in pixels

    // The transition from PRESS to SWIPE gesture mode can only occur when the
    // cosine of the angle between the two vectors is greater than or equal to than this value
    // which indicates that the vectors are oriented in the same direction.
    // When the vectors are oriented in the exactly same direction, the cosine is 1.0.
    // (In exactly opposite directions, the cosine is -1.0.)
    float pointerGestureSwipeTransitionAngleCosine;

    // The transition from PRESS to SWIPE gesture mode can only occur when the
    // fingers are no more than this far apart relative to the diagonal size of
    // the touch pad.  For example, a ratio of 0.5 means that the fingers must be
    // no more than half the diagonal size of the touch pad apart.
    float pointerGestureSwipeMaxWidthRatio;

    // The gesture movement speed factor relative to the size of the display.
    // Movement speed applies when the fingers are moving in the same direction.
    // Without acceleration, a full swipe of the touch pad diagonal in movement mode
    // will cover this portion of the display diagonal.
    float pointerGestureMovementSpeedRatio;

    // The gesture zoom speed factor relative to the size of the display.
    // Zoom speed applies when the fingers are mostly moving relative to each other
    // to execute a scale gesture or similar.
    // Without acceleration, a full swipe of the touch pad diagonal in zoom mode
    // will cover this portion of the display diagonal.
    float pointerGestureZoomSpeedRatio;

    // True to show the location of touches on the touch screen as spots.
    bool showTouches;

    // The latest request to enable or disable Pointer Capture.
    PointerCaptureRequest pointerCaptureRequest;

    // The touchpad pointer speed, as a number from -7 (slowest) to 7 (fastest).
    int32_t touchpadPointerSpeed;

    // True to invert the touchpad scrolling direction, so that moving two fingers downwards on the
    // touchpad scrolls the content upwards.
    bool touchpadNaturalScrollingEnabled;

    // True to enable tap-to-click on touchpads.
    bool touchpadTapToClickEnabled;

    // True to enable tap dragging on touchpads.
    bool touchpadTapDraggingEnabled;

    // True to enable a zone on the right-hand side of touchpads where clicks will be turned into
    // context (a.k.a. "right") clicks.
    bool touchpadRightClickZoneEnabled;

    // The set of currently disabled input devices.
    std::set<int32_t> disabledDevices;

    // True if stylus button reporting through motion events should be enabled, in which case
    // stylus button state changes are reported through motion events.
    bool stylusButtonMotionEventsEnabled;

    // True if a pointer icon should be shown for direct stylus pointers.
    bool stylusPointerIconEnabled;

    InputReaderConfiguration()
          : virtualKeyQuietTime(0),
            mousePointerSpeed(0),
            displaysWithMousePointerAccelerationDisabled(),
            pointerVelocityControlParameters(1.0f, 500.0f, 3000.0f,
                                             static_cast<float>(
                                                     android::os::IInputConstants::
                                                             DEFAULT_POINTER_ACCELERATION)),
            wheelVelocityControlParameters(1.0f, 15.0f, 50.0f, 4.0f),
            pointerGesturesEnabled(true),
            pointerGestureQuietInterval(100 * 1000000LL),            // 100 ms
            pointerGestureDragMinSwitchSpeed(50),                    // 50 pixels per second
            pointerGestureTapInterval(150 * 1000000LL),              // 150 ms
            pointerGestureTapDragInterval(150 * 1000000LL),          // 150 ms
            pointerGestureTapSlop(10.0f),                            // 10 pixels
            pointerGestureMultitouchSettleInterval(100 * 1000000LL), // 100 ms
            pointerGestureMultitouchMinDistance(15),                 // 15 pixels
            pointerGestureSwipeTransitionAngleCosine(0.2588f),       // cosine of 75 degrees
            pointerGestureSwipeMaxWidthRatio(0.25f),
            pointerGestureMovementSpeedRatio(0.8f),
            pointerGestureZoomSpeedRatio(0.3f),
            showTouches(false),
            pointerCaptureRequest(),
            touchpadPointerSpeed(0),
            touchpadNaturalScrollingEnabled(true),
            touchpadTapToClickEnabled(true),
            touchpadTapDraggingEnabled(false),
            touchpadRightClickZoneEnabled(false),
            stylusButtonMotionEventsEnabled(true),
            stylusPointerIconEnabled(false) {}

    std::optional<DisplayViewport> getDisplayViewportByType(ViewportType type) const;
    std::optional<DisplayViewport> getDisplayViewportByUniqueId(const std::string& uniqueDisplayId)
            const;
    std::optional<DisplayViewport> getDisplayViewportByPort(uint8_t physicalPort) const;
    std::optional<DisplayViewport> getDisplayViewportById(int32_t displayId) const;
    void setDisplayViewports(const std::vector<DisplayViewport>& viewports);

    void dump(std::string& dump) const;
    void dumpViewport(std::string& dump, const DisplayViewport& viewport) const;

private:
    std::vector<DisplayViewport> mDisplays;
};

using ConfigurationChanges = ftl::Flags<InputReaderConfiguration::Change>;

// --- InputReaderInterface ---

/* The interface for the InputReader shared library.
 *
 * Manages one or more threads that process raw input events and sends cooked event data to an
 * input listener.
 *
 * The implementation must guarantee thread safety for this interface. However, since the input
 * listener is NOT thread safe, all calls to the listener must happen from the same thread.
 */
class InputReaderInterface {
public:
    InputReaderInterface() {}
    virtual ~InputReaderInterface() {}
    /* Dumps the state of the input reader.
     *
     * This method may be called on any thread (usually by the input manager). */
    virtual void dump(std::string& dump) = 0;

    /* Called by the heartbeat to ensures that the reader has not deadlocked. */
    virtual void monitor() = 0;

    /* Returns true if the input device is enabled. */
    virtual bool isInputDeviceEnabled(int32_t deviceId) = 0;

    /* Makes the reader start processing events from the kernel. */
    virtual status_t start() = 0;

    /* Makes the reader stop processing any more events. */
    virtual status_t stop() = 0;

    /* Gets information about all input devices.
     *
     * This method may be called on any thread (usually by the input manager).
     */
    virtual std::vector<InputDeviceInfo> getInputDevices() const = 0;

    /* Query current input state. */
    virtual int32_t getScanCodeState(int32_t deviceId, uint32_t sourceMask, int32_t scanCode) = 0;
    virtual int32_t getKeyCodeState(int32_t deviceId, uint32_t sourceMask, int32_t keyCode) = 0;
    virtual int32_t getSwitchState(int32_t deviceId, uint32_t sourceMask, int32_t sw) = 0;

    virtual void addKeyRemapping(int32_t deviceId, int32_t fromKeyCode,
                                 int32_t toKeyCode) const = 0;

    virtual int32_t getKeyCodeForKeyLocation(int32_t deviceId, int32_t locationKeyCode) const = 0;

    /* Toggle Caps Lock */
    virtual void toggleCapsLockState(int32_t deviceId) = 0;

    /* Determine whether physical keys exist for the given framework-domain key codes. */
    virtual bool hasKeys(int32_t deviceId, uint32_t sourceMask,
                         const std::vector<int32_t>& keyCodes, uint8_t* outFlags) = 0;

    /* Requests that a reconfiguration of all input devices.
     * The changes flag is a bitfield that indicates what has changed and whether
     * the input devices must all be reopened. */
    virtual void requestRefreshConfiguration(ConfigurationChanges changes) = 0;

    /* Controls the vibrator of a particular input device. */
    virtual void vibrate(int32_t deviceId, const VibrationSequence& sequence, ssize_t repeat,
                         int32_t token) = 0;
    virtual void cancelVibrate(int32_t deviceId, int32_t token) = 0;

    virtual bool isVibrating(int32_t deviceId) = 0;

    virtual std::vector<int32_t> getVibratorIds(int32_t deviceId) = 0;
    /* Get battery level of a particular input device. */
    virtual std::optional<int32_t> getBatteryCapacity(int32_t deviceId) = 0;
    /* Get battery status of a particular input device. */
    virtual std::optional<int32_t> getBatteryStatus(int32_t deviceId) = 0;
    /* Get the device path for the battery of an input device. */
    virtual std::optional<std::string> getBatteryDevicePath(int32_t deviceId) = 0;

    virtual std::vector<InputDeviceLightInfo> getLights(int32_t deviceId) = 0;

    virtual std::vector<InputDeviceSensorInfo> getSensors(int32_t deviceId) = 0;

    /* Return true if the device can send input events to the specified display. */
    virtual bool canDispatchToDisplay(int32_t deviceId, int32_t displayId) = 0;

    /* Enable sensor in input reader mapper. */
    virtual bool enableSensor(int32_t deviceId, InputDeviceSensorType sensorType,
                              std::chrono::microseconds samplingPeriod,
                              std::chrono::microseconds maxBatchReportLatency) = 0;

    /* Disable sensor in input reader mapper. */
    virtual void disableSensor(int32_t deviceId, InputDeviceSensorType sensorType) = 0;

    /* Flush sensor data in input reader mapper. */
    virtual void flushSensor(int32_t deviceId, InputDeviceSensorType sensorType) = 0;

    /* Set color for the light */
    virtual bool setLightColor(int32_t deviceId, int32_t lightId, int32_t color) = 0;
    /* Set player ID for the light */
    virtual bool setLightPlayerId(int32_t deviceId, int32_t lightId, int32_t playerId) = 0;
    /* Get light color */
    virtual std::optional<int32_t> getLightColor(int32_t deviceId, int32_t lightId) = 0;
    /* Get light player ID */
    virtual std::optional<int32_t> getLightPlayerId(int32_t deviceId, int32_t lightId) = 0;

    /* Get the Bluetooth address of an input device, if known. */
    virtual std::optional<std::string> getBluetoothAddress(int32_t deviceId) const = 0;

    /* Sysfs node change reported. Recreate device if required to incorporate the new sysfs nodes */
    virtual void sysfsNodeChanged(const std::string& sysfsNodePath) = 0;
};

// --- TouchAffineTransformation ---

struct TouchAffineTransformation {
    float x_scale;
    float x_ymix;
    float x_offset;
    float y_xmix;
    float y_scale;
    float y_offset;

    TouchAffineTransformation() :
        x_scale(1.0f), x_ymix(0.0f), x_offset(0.0f),
        y_xmix(0.0f), y_scale(1.0f), y_offset(0.0f) {
    }

    TouchAffineTransformation(float xscale, float xymix, float xoffset,
            float yxmix, float yscale, float yoffset) :
        x_scale(xscale), x_ymix(xymix), x_offset(xoffset),
        y_xmix(yxmix), y_scale(yscale), y_offset(yoffset) {
    }

    void applyTo(float& x, float& y) const;
};

// --- InputReaderPolicyInterface ---

/*
 * Input reader policy interface.
 *
 * The input reader policy is used by the input reader to interact with the Window Manager
 * and other system components.
 *
 * The actual implementation is partially supported by callbacks into the DVM
 * via JNI.  This interface is also mocked in the unit tests.
 *
 * These methods will NOT re-enter the input reader interface, so they may be called from
 * any method in the input reader interface.
 */
class InputReaderPolicyInterface : public virtual RefBase {
protected:
    InputReaderPolicyInterface() { }
    virtual ~InputReaderPolicyInterface() { }

public:
    /* Gets the input reader configuration. */
    virtual void getReaderConfiguration(InputReaderConfiguration* outConfig) = 0;

    /* Gets a pointer controller associated with the specified cursor device (ie. a mouse). */
    virtual std::shared_ptr<PointerControllerInterface> obtainPointerController(
            int32_t deviceId) = 0;

    /* Notifies the input reader policy that some input devices have changed
     * and provides information about all current input devices.
     */
    virtual void notifyInputDevicesChanged(const std::vector<InputDeviceInfo>& inputDevices) = 0;

    /* Gets the keyboard layout for a particular input device. */
    virtual std::shared_ptr<KeyCharacterMap> getKeyboardLayoutOverlay(
            const InputDeviceIdentifier& identifier,
            const std::optional<KeyboardLayoutInfo> keyboardLayoutInfo) = 0;

    /* Gets a user-supplied alias for a particular input device, or an empty string if none. */
    virtual std::string getDeviceAlias(const InputDeviceIdentifier& identifier) = 0;

    /* Gets the affine calibration associated with the specified device. */
    virtual TouchAffineTransformation getTouchAffineTransformation(
            const std::string& inputDeviceDescriptor, ui::Rotation surfaceRotation) = 0;
    /* Notifies the input reader policy that a stylus gesture has started. */
    virtual void notifyStylusGestureStarted(int32_t deviceId, nsecs_t eventTime) = 0;

    /* Returns true if any InputConnection is currently active. */
    virtual bool isInputMethodConnectionActive() = 0;

    /* Gets the viewport of a particular display that the pointer device is associated with. If
     * the pointer device is not associated with any display, it should ADISPLAY_IS_NONE to get
     * the viewport that should be used. The device should get a new viewport using this method
     * every time there is a display configuration change. The logical bounds of the viewport should
     * be used as the range of possible values for pointing devices, like mice and touchpads.
     */
    virtual std::optional<DisplayViewport> getPointerViewportForAssociatedDisplay(
            int32_t associatedDisplayId = ADISPLAY_ID_NONE) = 0;
};

} // namespace android
