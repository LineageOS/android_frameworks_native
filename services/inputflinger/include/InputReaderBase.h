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
#include <input/KeyCode.h>
#include <input/MotionEventAxis.h>
#include <input/VelocityControl.h>
#include <input/VelocityTracker.h>
#include <stddef.h>
#include <ui/Rotation.h>
#include <unistd.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include "PointerControllerInterface.h"
#include "TouchpadHardwareState.h"
#include "VibrationElement.h"
#include "include/gestures.h"

// Maximum supported size of a vibration pattern.
// Must be at least 2.
#define MAX_VIBRATE_PATTERN_SIZE 100

namespace android {

// Represents the overrides to the .idc properties for an input device. Typically, this is used for
// virtual input devices which do not have any physical .idc file.
struct InputDeviceConfigurationOverride {
    std::optional<std::string> deviceType;
    std::optional<InputDeviceViewBehavior> viewBehavior;
};

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

        // The overrides for the .idc properties of the device have been updated.
        DEVICE_CONFIGURATION_OVERRIDES = 1u << 10,

        // The keyboard layout association has changed.
        KEYBOARD_LAYOUT_ASSOCIATION = 1u << 11,

        // The stylus button reporting configurations has changed.
        STYLUS_BUTTON_REPORTING = 1u << 12,

        // The touchpad settings changed.
        TOUCHPAD_SETTINGS = 1u << 13,

        // The key remapping has changed.
        KEY_REMAPPING = 1u << 14,

        // The mouse settings changed, this includes mouse reverse vertical scrolling and swap
        // primary button.
        MOUSE_SETTINGS = 1u << 15,

        // The virtual devices list is updated
        VIRTUAL_DEVICES = 1u << 16,

        // The axis remapping has changed.
        AXIS_REMAPPING = 1u << 17,

        // Volume keys rotation option changed.
        VOLUME_KEYS_ROTATION = 1u << 18,

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
    std::unordered_map<std::string, uint8_t> inputPortToDisplayPortAssociations;

    // The associations between input device ports and display unique ids.
    // Used to determine which DisplayViewport should be tied to which InputDevice.
    std::unordered_map<std::string, std::string> inputPortToDisplayUniqueIdAssociations;

    // The associations between input device descriptor and display unique ids.
    // Used to determine which DisplayViewport should be tied to which InputDevice.
    std::unordered_map<std::string, std::string> inputDeviceDescriptorToDisplayUniqueIdAssociations;

    // The associations between input device ports to overrides on .idc properties. Typically, these
    // are used for virtual input devices which do not have any physical .idc file. If an input
    // device has an actual physical .idc file, then this override would be ignored for that input
    // device.
    std::unordered_map<std::string, InputDeviceConfigurationOverride> deviceConfigurationOverrides;

    // The map from the input device physical port location to the input device layout info.
    // Can be used to determine the layout of the keyboard device.
    std::unordered_map<std::string, KeyboardLayoutInfo> keyboardLayoutAssociations;

    // List of input device physical port locations of devices that are marked as virtual and should
    // not be treated as physically connected peripheral (e.g. created using VDM in userspace)
    std::set<std::string> virtualDevicePorts;

    // The suggested display ID to show the cursor.
    ui::LogicalDisplayId defaultPointerDisplayId;

    // The mouse pointer speed, as a number from -7 (slowest) to 7 (fastest).
    int32_t mousePointerSpeed;

    // Displays on which all pointer scaling, including linear scaling based on the
    // user's pointer speed setting, should be disabled for mice. This differs from
    // disabling acceleration via the 'mousePointerAccelerationEnabled' setting, where
    // the pointer speed setting still influences the scaling factor.
    std::set<ui::LogicalDisplayId> displaysWithMouseScalingDisabled;

    // True if the connected mouse should exhibit pointer acceleration. If false,
    // a flat acceleration curve (linear scaling) is used, but the user's pointer
    // speed setting still affects the scaling factor.
    bool mousePointerAccelerationEnabled;

    // True if the touchpad should exhibit pointer acceleration. If false,
    // a flat acceleration curve (linear scaling) is used, but the user's pointer
    // speed setting still affects the scaling factor.
    bool touchpadAccelerationEnabled;

    // Velocity control parameters for mouse wheel movements.
    VelocityControlParameters wheelVelocityControlParameters;

    // True if pointer gestures are enabled.
    bool pointerGesturesEnabled;

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

    // True if hardware state update notifications should be sent to the policy.
    bool shouldNotifyTouchpadHardwareState;

    // True to enable a zone on the right-hand side of touchpads where clicks will be turned into
    // context (a.k.a. "right") clicks.
    bool touchpadRightClickZoneEnabled;

    // True to use three-finger tap as a customizable shortcut; false to use it as a middle-click.
    bool touchpadThreeFingerTapShortcutEnabled;

    // True to enable system gestures (three- and four-finger swipes) on touchpads.
    bool touchpadSystemGesturesEnabled;

    // True to enable touchpads.
    bool touchpadsEnabled;

    // The set of currently disabled input devices.
    std::set<DeviceId> disabledDevices;

    // True if stylus button reporting through motion events should be enabled, in which case
    // stylus button state changes are reported through motion events.
    bool stylusButtonMotionEventsEnabled;

    // True if a pointer icon should be shown for direct stylus pointers.
    bool stylusPointerIconEnabled;

    // Keycodes to be remapped.
    std::unordered_map<int32_t /* fromKeyCode */, int32_t /* toKeyCode */> keyRemapping;

    // Keycodes to be remapped for device.
    std::unordered_map<DeviceId,
                       std::unordered_map<int32_t /* fromKeyCode */, int32_t /* toKeyCode */>>
            keyRemappingPerDevice;

    // Keycodes to axes remapping per device.
    std::map<DeviceId, std::map<KeyCode, MotionEventAxis>> keyToAxisRemappingPerDevice;

    // Per-device axis remapping: Only applied for joystick devices
    std::unordered_map<
            int32_t,
            std::unordered_map</* fromAndroidAxisId */ int32_t, /* toAndroidAxisId */ int32_t>>
            axisRemappingPerDevice;

    // True if the external mouse should have its vertical scrolling reversed, so that rotating the
    // wheel downwards scrolls the content upwards.
    bool mouseReverseVerticalScrollingEnabled;

    // True if the connected mouse should have its primary button (default: left click) swapped,
    // so that the right click will be the primary action button and the left click will be the
    // secondary action.
    bool mouseSwapPrimaryButtonEnabled;

    // Remap volume keys according to display rotation
    // 0 - disabled, 1 - phone or hybrid rotation mode, 2 - tablet rotation mode
    int volumeKeysRotationMode;

    InputReaderConfiguration()
          : virtualKeyQuietTime(0),
            defaultPointerDisplayId(ui::LogicalDisplayId::DEFAULT),
            mousePointerSpeed(0),
            displaysWithMouseScalingDisabled(),
            mousePointerAccelerationEnabled(true),
            touchpadAccelerationEnabled(true),
            wheelVelocityControlParameters(1.0f, 15.0f, 50.0f,
                                           static_cast<float>(
                                                   android::os::IInputConstants::
                                                           DEFAULT_MOUSE_WHEEL_ACCELERATION)),
            pointerGesturesEnabled(true),
            pointerCaptureRequest(),
            touchpadPointerSpeed(0),
            touchpadNaturalScrollingEnabled(true),
            touchpadTapToClickEnabled(true),
            touchpadTapDraggingEnabled(false),
            shouldNotifyTouchpadHardwareState(false),
            touchpadRightClickZoneEnabled(false),
            touchpadThreeFingerTapShortcutEnabled(false),
            touchpadSystemGesturesEnabled(true),
            touchpadsEnabled(true),
            stylusButtonMotionEventsEnabled(true),
            stylusPointerIconEnabled(false),
            mouseReverseVerticalScrollingEnabled(false),
            mouseSwapPrimaryButtonEnabled(false),
            volumeKeysRotationMode(0) {}

    std::optional<DisplayViewport> getDisplayViewportByType(ViewportType type) const;
    std::optional<DisplayViewport> getDisplayViewportByUniqueId(const std::string& uniqueDisplayId)
            const;
    std::optional<DisplayViewport> getDisplayViewportByPort(uint8_t physicalPort) const;
    std::optional<DisplayViewport> getDisplayViewportById(ui::LogicalDisplayId displayId) const;
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
    virtual int32_t getScanCodeState(DeviceId deviceId, uint32_t sourceMask, int32_t scanCode) = 0;
    virtual int32_t getKeyCodeState(DeviceId deviceId, uint32_t sourceMask, int32_t keyCode) = 0;
    virtual int32_t getSwitchState(DeviceId deviceId, uint32_t sourceMask, int32_t sw) = 0;

    virtual int32_t getKeyCodeForKeyLocation(DeviceId deviceId, int32_t locationKeyCode) const = 0;

    /* Toggle Caps Lock */
    virtual void toggleCapsLockState(DeviceId deviceId) = 0;

    /* Resets locked modifier state */
    virtual void resetLockedModifierState() = 0;

    /* Determine whether physical keys exist for the given framework-domain key codes. */
    virtual bool hasKeys(DeviceId deviceId, uint32_t sourceMask,
                         const std::vector<int32_t>& keyCodes, uint8_t* outFlags) = 0;

    /* Requests that a reconfiguration of all input devices.
     * The changes flag is a bitfield that indicates what has changed and whether
     * the input devices must all be reopened. */
    virtual void requestRefreshConfiguration(ConfigurationChanges changes) = 0;

    /* Controls the vibrator of a particular input device. */
    virtual void vibrate(DeviceId deviceId, const VibrationSequence& sequence, ssize_t repeat,
                         int32_t token) = 0;
    virtual void cancelVibrate(DeviceId deviceId, int32_t token) = 0;

    virtual bool isVibrating(DeviceId deviceId) = 0;

    virtual std::vector<int32_t> getVibratorIds(DeviceId deviceId) = 0;
    /* Get battery level of a particular input device. */
    virtual std::optional<int32_t> getBatteryCapacity(DeviceId deviceId) = 0;
    /* Get battery status of a particular input device. */
    virtual std::optional<int32_t> getBatteryStatus(DeviceId deviceId) = 0;
    /* Get the device path for the battery of an input device. */
    virtual std::optional<std::string> getBatteryDevicePath(DeviceId deviceId) = 0;

    virtual std::vector<InputDeviceLightInfo> getLights(DeviceId deviceId) = 0;

    virtual std::vector<InputDeviceSensorInfo> getSensors(DeviceId deviceId) = 0;

    virtual std::optional<HardwareProperties> getTouchpadHardwareProperties(DeviceId deviceId) = 0;

    /* Return true if the device can send input events to the specified display. */
    virtual bool canDispatchToDisplay(DeviceId deviceId, ui::LogicalDisplayId displayId) = 0;

    /* Enable sensor in input reader mapper. */
    virtual bool enableSensor(DeviceId deviceId, InputDeviceSensorType sensorType,
                              std::chrono::microseconds samplingPeriod,
                              std::chrono::microseconds maxBatchReportLatency) = 0;

    /* Disable sensor in input reader mapper. */
    virtual void disableSensor(DeviceId deviceId, InputDeviceSensorType sensorType) = 0;

    /* Flush sensor data in input reader mapper. */
    virtual void flushSensor(DeviceId deviceId, InputDeviceSensorType sensorType) = 0;

    /* Set color for the light */
    virtual bool setLightColor(DeviceId deviceId, int32_t lightId, int32_t color) = 0;
    /* Set player ID for the light */
    virtual bool setLightPlayerId(DeviceId deviceId, int32_t lightId, int32_t playerId) = 0;
    /* Get light color */
    virtual std::optional<int32_t> getLightColor(DeviceId deviceId, int32_t lightId) = 0;
    /* Get light player ID */
    virtual std::optional<int32_t> getLightPlayerId(DeviceId deviceId, int32_t lightId) = 0;

    /* Get the Bluetooth address of an input device, if known. */
    virtual std::optional<std::string> getBluetoothAddress(DeviceId deviceId) const = 0;
    /* Get the physical location path ("phys" ID) for an input device, if it is available. */
    virtual std::optional<std::string> getPhysicalLocationPath(DeviceId deviceId) const = 0;

    /* Gets the sysfs root path for this device. Returns an empty path if there is none. */
    virtual std::filesystem::path getSysfsRootPath(DeviceId deviceId) const = 0;

    /* Sysfs node change reported. Recreate device if required to incorporate the new sysfs nodes */
    virtual void sysfsNodeChanged(const std::string& sysfsNodePath) = 0;

    /* Get the ID of the InputDevice that was used most recently.
     *
     * Returns ReservedInputDeviceId::INVALID_INPUT_DEVICE_ID if no device has been used since boot.
     */
    virtual DeviceId getLastUsedInputDeviceId() = 0;

    /* Notifies that mouse cursor faded due to typing. */
    virtual void notifyMouseCursorFadedOnTyping() = 0;

    /* Set whether the given input device can wake up the kernel from sleep
     * when it generates input events. By default, usually only internal (built-in)
     * input devices can wake the kernel from sleep. For an external input device
     * that supports remote wakeup to be able to wake the kernel, this must be called
     * after each time the device is connected/added.
     *
     * Returns true if setting power wakeup was successful.
     */
    virtual bool setKernelWakeEnabled(DeviceId deviceId, bool enabled) = 0;
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

    /* Notifies the input reader policy that some input devices have changed
     * and provides information about all current input devices.
     */
    virtual void notifyInputDevicesChanged(const std::vector<InputDeviceInfo>& inputDevices) = 0;

    /* Sends the hardware state of a connected touchpad */
    virtual void notifyTouchpadHardwareState(const SelfContainedHardwareState& schs,
                                             DeviceId deviceId) = 0;

    /* Sends the Info of gestures that happen on the touchpad. */
    virtual void notifyTouchpadGestureInfo(GestureType type, DeviceId deviceId) = 0;

    /* Notifies the policy that the user has performed a three-finger touchpad tap. */
    virtual void notifyTouchpadThreeFingerTap() = 0;

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
    virtual void notifyStylusGestureStarted(DeviceId deviceId, nsecs_t eventTime) = 0;

    /* Returns true if any InputConnection is currently active. */
    virtual bool isInputMethodConnectionActive() = 0;

    /* Gets the viewport of a particular display that the pointer device is associated with. If
     * the pointer device is not associated with any display, it should ADISPLAY_IS_NONE to get
     * the viewport that should be used. The device should get a new viewport using this method
     * every time there is a display configuration change. The logical bounds of the viewport should
     * be used as the range of possible values for pointing devices, like mice and touchpads.
     */
    virtual std::optional<DisplayViewport> getPointerViewportForAssociatedDisplay(
            ui::LogicalDisplayId associatedDisplayId = ui::LogicalDisplayId::INVALID) = 0;
};

} // namespace android
