/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "UinputDevice.h"

#include <android-base/stringprintf.h>

namespace android {

// --- UinputDevice ---

UinputDevice::UinputDevice(const char* name) : mName(name) {}

UinputDevice::~UinputDevice() {
    if (ioctl(mDeviceFd, UI_DEV_DESTROY)) {
        ALOGE("Error while destroying uinput device: %s", strerror(errno));
    }
    mDeviceFd.reset();
}

void UinputDevice::init() {
    mDeviceFd = android::base::unique_fd(open("/dev/uinput", O_WRONLY | O_NONBLOCK));
    if (mDeviceFd < 0) {
        FAIL() << "Can't open /dev/uinput :" << strerror(errno);
    }

    struct uinput_user_dev device = {};
    strlcpy(device.name, mName, UINPUT_MAX_NAME_SIZE);
    device.id.bustype = BUS_USB;
    device.id.vendor = 0x01;
    device.id.product = 0x01;
    device.id.version = 1;

    // Using EXPECT instead of ASSERT to allow the device creation to continue even when
    // some failures are reported when configuring the device.
    EXPECT_NO_FATAL_FAILURE(configureDevice(mDeviceFd, &device));

    if (write(mDeviceFd, &device, sizeof(device)) < 0) {
        FAIL() << "Could not write uinput_user_dev struct into uinput file descriptor: "
               << strerror(errno);
    }

    if (ioctl(mDeviceFd, UI_DEV_CREATE)) {
        FAIL() << "Error in ioctl : UI_DEV_CREATE: " << strerror(errno);
    }
}

void UinputDevice::injectEvent(uint16_t type, uint16_t code, int32_t value) {
    struct input_event event = {};
    event.type = type;
    event.code = code;
    event.value = value;
    event.time = {}; // uinput ignores the timestamp

    if (write(mDeviceFd, &event, sizeof(input_event)) < 0) {
        std::string msg = base::StringPrintf("Could not write event %" PRIu16 " %" PRIu16
                                             " with value %" PRId32 " : %s",
                                             type, code, value, strerror(errno));
        ALOGE("%s", msg.c_str());
        ADD_FAILURE() << msg.c_str();
    }
}

// --- UinputKeyboard ---

UinputKeyboard::UinputKeyboard(std::initializer_list<int> keys)
      : UinputDevice(UinputKeyboard::KEYBOARD_NAME), mKeys(keys.begin(), keys.end()) {}

void UinputKeyboard::configureDevice(int fd, uinput_user_dev* device) {
    // enable key press/release event
    if (ioctl(fd, UI_SET_EVBIT, EV_KEY)) {
        ADD_FAILURE() << "Error in ioctl : UI_SET_EVBIT : EV_KEY: " << strerror(errno);
    }

    // enable set of KEY events
    std::for_each(mKeys.begin(), mKeys.end(), [fd](int key) {
        if (ioctl(fd, UI_SET_KEYBIT, key)) {
            ADD_FAILURE() << "Error in ioctl : UI_SET_KEYBIT : " << key << " : " << strerror(errno);
        }
    });

    // enable synchronization event
    if (ioctl(fd, UI_SET_EVBIT, EV_SYN)) {
        ADD_FAILURE() << "Error in ioctl : UI_SET_EVBIT : EV_SYN: " << strerror(errno);
    }
}

void UinputKeyboard::pressKey(int key) {
    if (mKeys.find(key) == mKeys.end()) {
        ADD_FAILURE() << mName << ": Cannot inject key press: Key not found: " << key;
    }
    EXPECT_NO_FATAL_FAILURE(injectEvent(EV_KEY, key, 1));
    EXPECT_NO_FATAL_FAILURE(injectEvent(EV_SYN, SYN_REPORT, 0));
}

void UinputKeyboard::releaseKey(int key) {
    if (mKeys.find(key) == mKeys.end()) {
        ADD_FAILURE() << mName << ": Cannot inject key release: Key not found: " << key;
    }
    EXPECT_NO_FATAL_FAILURE(injectEvent(EV_KEY, key, 0));
    EXPECT_NO_FATAL_FAILURE(injectEvent(EV_SYN, SYN_REPORT, 0));
}

void UinputKeyboard::pressAndReleaseKey(int key) {
    EXPECT_NO_FATAL_FAILURE(pressKey(key));
    EXPECT_NO_FATAL_FAILURE(releaseKey(key));
}

// --- UinputHomeKey---

UinputHomeKey::UinputHomeKey() : UinputKeyboard({KEY_HOME}) {}

void UinputHomeKey::pressAndReleaseHomeKey() {
    EXPECT_NO_FATAL_FAILURE(pressAndReleaseKey(KEY_HOME));
}

} // namespace android
