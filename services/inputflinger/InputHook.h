/*
 * Copyright (c) 2015-2017, NVIDIA CORPORATION.  All rights reserved.
 * NVIDIA CORPORATION and its licensors retain all intellectual property
 * and proprietary rights in and to this software, related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA CORPORATION is strictly prohibited.
 */

#ifndef _INPUTHOOK_INCLUDE
#define _INPUTHOOK_INCLUDE

#include <vendor/nvidia/hardware/shieldtech/inputflinger/2.0/IInputHook.h>
#include <vendor/nvidia/hardware/shieldtech/inputflinger/2.0/IInputHookCallback.h>

#include <input/InputDevice.h>
#include <linux/input.h>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace android {

class EventHub;
struct InputDeviceIdentifier;
struct RawAbsoluteAxisInfo;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class InputHook {
public:
    // Response
    typedef enum {
        EVENT_DEFAULT   = 0,
        EVENT_PROCESS   = 1,
        EVENT_SKIP      = 2,
        EVENT_ADD       = 3,
    } RESPONSE;

    // Constructor
    InputHook(android::EventHub* eventHub);
    static InputHook* getInstance();

    // Filters
    bool filterNewDevice(int fd, int32_t id, const String8& path, InputDeviceIdentifier& identifier);
    void filterCloseDevice(int32_t id);
    RESPONSE filterEvent(struct input_event& iev, int32_t& deviceId);

    // Notifiers
    bool notifyKeyState(int32_t deviceId, int32_t keyCode, bool handled);
    bool notifyMotionState(int32_t deviceId, PointerCoords* pc, bool handled);

    void addDevice(int id);
    void removeDevice(int id);

    // APIs
    void registerDevices();
    bool treatMouseAsTouch();

    // Local APIs
    void registerDevice(const vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::NewDevice& newDevice);

    // Hooked APIs
    status_t getAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t* outValue);
    status_t getAbsoluteAxisInfo(int32_t deviceId, int axis, RawAbsoluteAxisInfo* outAxisInfo);

private:
    static InputHook* mInstance;
    sp<vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::IInputHook> mRemoteHook;
    sp<vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::IInputHookCallback> mCallback;
    EventHub* mEventHub;

private:
    int32_t getScanCodeLocked(int32_t deviceId, int32_t keyCode) const;
    InputDeviceIdentifier* getInputDeviceIdentifier(const vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::InputIdentifier& ident);
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Extra bits for InputFlinger

void handleStbRotation(int32_t& surfaceWidth, int32_t& surfaceHeight, int32_t& surfaceOrientation);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

};

#endif // _INPUTHOOK_INCLUDE

