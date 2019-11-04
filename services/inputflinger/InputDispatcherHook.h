/*
 * Copyright (c) 2015-2017, NVIDIA CORPORATION.  All rights reserved.
 * NVIDIA CORPORATION and its licensors retain all intellectual property
 * and proprietary rights in and to this software, related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA CORPORATION is strictly prohibited.
 */

#ifndef _INPUTDISPATCHERHOOK_INCLUDE
#define _INPUTDISPATCHERHOOK_INCLUDE

#include <vendor/nvidia/hardware/shieldtech/inputflinger/2.0/IInputHook.h>

#include <input/InputDevice.h>
#include <linux/input.h>

namespace android {

class InputDispatcherHook {
public:
    InputDispatcherHook();

    // Notifiers
    bool notifyKeyState(int32_t deviceId, int32_t keyCode, bool handled);
    bool notifyMotionState(int32_t deviceId, PointerCoords* pc, bool handled);
private:
    sp<vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::IInputHook> mRemoteHook;
};

}

#endif // _INPUTDISPATCHERHOOK_INCLUDE

