/*
 * Copyright (c) 2015-2018, NVIDIA CORPORATION.  All rights reserved.
 * NVIDIA CORPORATION and its licensors retain all intellectual property
 * and proprietary rights in and to this software, related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA CORPORATION is strictly prohibited.
 */

#define LOG_TAG "NvInputReaderHook_Host"

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

#include "EventHub.h"

#include <hardware_legacy/power.h>

#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/threads.h>
#include <utils/Errors.h>

#include <input/KeyLayoutMap.h>
#include <input/KeyCharacterMap.h>
#include <input/VirtualKeyMap.h>

#include "InputReaderHook.h"

namespace android {

using vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::HidlInputEvent;
using vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::IInputHookCallback;
using vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::InputIdentifier;
using vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::Response;

namespace hardware {

class InputReaderHookCallbackImpl : public IInputHookCallback {
    InputReaderHook* mInputReaderHook;

public:
    InputReaderHookCallbackImpl(InputReaderHook* inputHook) {
        mInputReaderHook = inputHook;
    }

    Return<void> registerDevice(const vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::NewDevice& device) {
        ALOGD("InputReaderHookCallback::registerDevice called");
        mInputReaderHook->registerDevice(device);
        return Void();
    }

    Return<void> addDevice(int32_t id) {
        ALOGD("InputReaderHookCallback::addDevice called");
        InputReaderHook::getInstance()->addDevice(id);
        return Void();
    }

    Return<void> removeDevice(int32_t id) {
        ALOGD("InputReaderHookCallback::removeDevice called");
        InputReaderHook::getInstance()->removeDevice(id);
        return Void();
    }
};

};

InputReaderHook* InputReaderHook::mInstance = NULL;

InputReaderHook::InputReaderHook(EventHub* eventHub) {
    mInstance = this;
    mEventHub = eventHub;

    mRemoteHook = vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::IInputHook::getService();
    if (mRemoteHook == NULL) {
        ALOGW("Unable to load ShieldTech support features");
    } else {
        mCallback = new hardware::InputReaderHookCallbackImpl(this);
        if (!mRemoteHook->init(mCallback)) {
            mRemoteHook = NULL;
            ALOGI("ShieldTech rejected initialization");
        } else {
            ALOGI("ShieldTech loaded");
        }
    }
}

InputReaderHook* InputReaderHook::getInstance() {
    return mInstance;
}

static bool sResult;
static hardware::hidl_string sIdentifierName;

void filterNewDevice_response(bool result, const hardware::hidl_string& identiferName) {
    sResult = result;
    sIdentifierName = identiferName;
}

// Filters
bool InputReaderHook::filterNewDevice(int fd, int32_t id, const String8& path, InputDeviceIdentifier& identifier) {
    if (mRemoteHook != NULL) {
        native_handle_t* nativeHandle = native_handle_create(1, 0);
        nativeHandle->data[0] = fd;

        InputIdentifier ident;
        ident.vendor = identifier.vendor;
        ident.product = identifier.product;
        ident.name = identifier.name;
        ident.uniqueId = identifier.uniqueId;
        hardware::Return<void> ret = mRemoteHook->filterNewDevice(nativeHandle, id, path.string(), ident, filterNewDevice_response);
        if (ret.isOk()) {
            identifier.name = sIdentifierName.c_str();
            return sResult;
        }
        ALOGD("Remote Hook failed");
    }
    return true;
}

void InputReaderHook::filterCloseDevice(int32_t id) {
    if (mRemoteHook != NULL)    mRemoteHook->filterCloseDevice(id);
    return;
}


static Response sResponse;
static int32_t sReplacementId;
static HidlInputEvent sReplacementEvent;

void filterEvent_response(Response response, int32_t replacementDeviceId, const HidlInputEvent& replacementEvent) {
    sResponse = response;
    sReplacementId = replacementDeviceId;
    sReplacementEvent = replacementEvent;
}

InputReaderHook::RESPONSE InputReaderHook::filterEvent(struct input_event& iev, int32_t& deviceId) {
    if (mRemoteHook != NULL) {
        HidlInputEvent input;
        input.time.tv_sec = iev.time.tv_sec;
        input.time.tv_usec = iev.time.tv_usec;
        input.type = iev.type;
        input.code = iev.code;
        input.value = iev.value;

        mRemoteHook->filterEvent(input, deviceId, filterEvent_response);

        if (sReplacementEvent.type > 0x80) {
            sReplacementEvent.type -= 0x80;
            sReplacementEvent.code = getScanCodeLocked(sReplacementId, sReplacementEvent.code);
        }
        iev.time.tv_sec = sReplacementEvent.time.tv_sec;
        iev.time.tv_usec = sReplacementEvent.time.tv_usec;
        iev.type = sReplacementEvent.type;
        iev.code = sReplacementEvent.code;
        iev.value = sReplacementEvent.value;
        deviceId = sReplacementId;
        return (InputReaderHook::RESPONSE) ((int) sResponse);
    }
    return EVENT_DEFAULT;
}

// APIs
void InputReaderHook::registerDevices() {
    ALOGD("registerDevices called");
    if (mRemoteHook != NULL)    mRemoteHook->registerDevices();
    return;
}

void InputReaderHook::registerDevice(const vendor::nvidia::hardware::shieldtech::inputflinger::V2_0::NewDevice& device) {
    ALOGD("registerDevice callback called");

    auto handle = device.fd.getNativeHandle();
    if (!handle || handle->numFds == 0)     return;
    if (handle->numFds > 1)                 return;

    InputDeviceIdentifier* identifier = getInputDeviceIdentifier(device.identifier);

    mEventHub->assignDescriptorLocked(*identifier);

    EventHub::Device* newDevice = new EventHub::Device(dup(handle->data[0]), device.id, device.path, *identifier);
    newDevice->classes |= device.classMap;
    memcpy(newDevice->keyBitmask, &device.keyBitmask, sizeof(device.keyBitmask));
    memcpy(newDevice->absBitmask, &device.absBitmask, sizeof(device.absBitmask));
    memcpy(newDevice->relBitmask, &device.relBitmask, sizeof(device.relBitmask));
    mEventHub->loadKeyMapLocked(newDevice);

    // Free allocated memory
    delete identifier;

    // Register with epoll.
    struct epoll_event eventItem;
    memset(&eventItem, 0, sizeof(eventItem));
    eventItem.events = EPOLLIN;
    eventItem.data.u32 = newDevice->id;
    if (epoll_ctl(mEventHub->mEpollFd, EPOLL_CTL_ADD, newDevice->fd, &eventItem)) {
        ALOGE("Could not add device fd to epoll instance.  errno=%d", errno);
        delete newDevice;
        return;
    }

    mEventHub->addDeviceLocked(newDevice);
}

void InputReaderHook::addDevice(int id) {
    AutoMutex _l(mEventHub->mLock);

    char devname[PATH_MAX];
    snprintf(devname, sizeof devname, "/dev/input/event%d", id);
    mEventHub->openDeviceLocked(devname);
}

void InputReaderHook::removeDevice(int id) {
    AutoMutex _l(mEventHub->mLock);

    char devname[PATH_MAX];
    snprintf(devname, sizeof devname, "/dev/input/event%d", id);
    mEventHub->closeDeviceByPathLocked(devname);
}

InputDeviceIdentifier* InputReaderHook::getInputDeviceIdentifier(const InputIdentifier& ident) {
    InputDeviceIdentifier* identifier = new InputDeviceIdentifier();
    identifier->name = ident.name;
    identifier->uniqueId = ident.uniqueId;
    return identifier;
}

status_t InputReaderHook::getAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t* outValue) {
    if (deviceId == -2) {
        switch (axis) {
        case ABS_X:
            return 0;
        case ABS_Y:
            return 0;
        }
    }
    return -1;
}

status_t InputReaderHook::getAbsoluteAxisInfo(int32_t deviceId, int axis, RawAbsoluteAxisInfo* outAxisInfo) {
    if (deviceId == -2) {
        outAxisInfo->clear();
        switch (axis) {
        case ABS_X:
            outAxisInfo->maxValue = 3840;
            outAxisInfo->resolution = 320;
            outAxisInfo->valid = true;
            return OK;
        case ABS_Y:
            outAxisInfo->maxValue = 2160;
            outAxisInfo->resolution = 320;
            outAxisInfo->valid = true;
            return OK;
        }
    }
    return -1;
}

int32_t InputReaderHook::getScanCodeLocked(int32_t deviceId, int32_t keyCode) const {
    EventHub::Device* device = mEventHub->getDeviceLocked(deviceId);
    if (device && device->keyMap.haveKeyLayout()) {
        std::vector<int32_t> scanCodes;
        device->keyMap.keyLayoutMap->findScanCodesForKey(keyCode, &scanCodes);
        if (scanCodes.size() > 0) {
            return scanCodes.at(0);
        }
    }
    return -1;
}

void handleStbRotation(int32_t& surfaceWidth, int32_t& surfaceHeight, int32_t& surfaceOrientation) {
    // Console Mode support for touch scaling/rotation
    char stb[PROPERTY_VALUE_MAX];
    property_get("persist.vendor.tegra.stb.mode", stb, "0");
    if (*stb != '0') {
        int32_t tmp = surfaceWidth;
        surfaceWidth = surfaceHeight;
        surfaceHeight = tmp;
        surfaceOrientation = (surfaceOrientation + 1) % 4;
    }
}

}

