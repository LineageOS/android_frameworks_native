/*
 * Copyright (c) 2015-2018, NVIDIA CORPORATION.  All rights reserved.
 * NVIDIA CORPORATION and its licensors retain all intellectual property
 * and proprietary rights in and to this software, related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA CORPORATION is strictly prohibited.
 */

#define LOG_TAG "NvInputDispatcherHook_Host"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/limits.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <unistd.h>

// #define LOG_NDEBUG 0

#include <hardware_legacy/power.h>

#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/threads.h>
#include <utils/Errors.h>

#include "InputDispatcherHook.h"

namespace android {

using vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::AnalogCoords;

InputDispatcherHook::InputDispatcherHook() {
    mRemoteHook = vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::IInputHook::getService();
    if (mRemoteHook == NULL)
        ALOGW("Unable to load ShieldTech support features");
    else
        ALOGI("ShieldTech loaded");
}

// Notifiers
bool InputDispatcherHook::notifyKeyState(int32_t deviceId, int32_t keyCode, bool handled) {
    if (mRemoteHook != NULL)    return mRemoteHook->notifyKeyState(deviceId, keyCode, handled);
    return false;
}

bool InputDispatcherHook::notifyMotionState(int32_t deviceId, PointerCoords* pc, bool handled) {
    if (mRemoteHook != NULL) {
        AnalogCoords coords;
        coords.lsX = pc->getAxisValue(AMOTION_EVENT_AXIS_X);
        coords.lsY = pc->getAxisValue(AMOTION_EVENT_AXIS_Y);
        coords.rsX = pc->getAxisValue(AMOTION_EVENT_AXIS_Z);
        coords.rsY = pc->getAxisValue(AMOTION_EVENT_AXIS_RZ);
        coords.dpadX = pc->getAxisValue(AMOTION_EVENT_AXIS_HAT_X);
        coords.dpadY = pc->getAxisValue(AMOTION_EVENT_AXIS_HAT_Y);
        return mRemoteHook->notifyMotionState(deviceId, coords, handled);
    }
    return false;
}

}
