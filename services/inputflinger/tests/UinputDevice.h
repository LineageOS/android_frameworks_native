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

#ifndef _UI_TEST_INPUT_UINPUT_INJECTOR_H
#define _UI_TEST_INPUT_UINPUT_INJECTOR_H

#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <linux/uinput.h>
#include <log/log.h>
#include <ui/Point.h>
#include <ui/Rect.h>

#include <memory>

namespace android {

// This is the factory method that must be used to create a UinputDevice.
template <class D, class... Ts>
std::unique_ptr<D> createUinputDevice(Ts... args) {
    // Using `new` to access non-public constructors.
    std::unique_ptr<D> dev(new D(&args...));
    EXPECT_NO_FATAL_FAILURE(dev->init());
    return dev;
}

// --- UinputDevice ---

class UinputDevice {
public:
    virtual ~UinputDevice();

    inline const char* getName() const { return mName; }

    // Subclasses must either provide a public constructor or must be-friend the factory method.
    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

protected:
    const char* mName;

    UinputDevice(const char* name);

    // Signals which types of events this device supports before it is created.
    // This must be overridden by subclasses.
    virtual void configureDevice(int fd, uinput_user_dev* device) = 0;

    void injectEvent(uint16_t type, uint16_t code, int32_t value);

private:
    base::unique_fd mDeviceFd;

    // This is called once by the factory method createUinputDevice().
    void init();
};

// --- UinputKeyboard ---

class UinputKeyboard : public UinputDevice {
public:
    static constexpr const char* KEYBOARD_NAME = "Test Keyboard Device";

    // Injects key press and sync.
    void pressKey(int key);
    // Injects key release and sync.
    void releaseKey(int key);
    // Injects 4 events: key press, sync, key release, and sync.
    void pressAndReleaseKey(int key);

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

protected:
    UinputKeyboard(std::initializer_list<int> keys = {});

private:
    void configureDevice(int fd, uinput_user_dev* device) override;

    std::set<int> mKeys;
};

// --- UinputHomeKey---

// A keyboard device that has a single HOME key.
class UinputHomeKey : public UinputKeyboard {
public:
    // Injects 4 events: key press, sync, key release, and sync.
    void pressAndReleaseHomeKey();

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

private:
    UinputHomeKey();
};

// A joystick device that sends a BTN_GEAR_DOWN / BTN_WHEEL key.
class UinputSteamController : public UinputKeyboard {
public:
    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

private:
    UinputSteamController();
};

// --- UinputTouchScreen ---
// A touch screen device with specific size.
class UinputTouchScreen : public UinputDevice {
public:
    static constexpr const char* DEVICE_NAME = "Test Touch Screen";
    static const int32_t RAW_TOUCH_MIN = 0;
    static const int32_t RAW_TOUCH_MAX = 31;
    static const int32_t RAW_ID_MIN = 0;
    static const int32_t RAW_ID_MAX = 9;
    static const int32_t RAW_SLOT_MIN = 0;
    static const int32_t RAW_SLOT_MAX = 9;
    static const int32_t RAW_PRESSURE_MIN = 0;
    static const int32_t RAW_PRESSURE_MAX = 255;

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

    void sendSlot(int32_t slot);
    void sendTrackingId(int32_t trackingId);
    void sendDown(const Point& point);
    void sendMove(const Point& point);
    void sendUp();
    void sendToolType(int32_t toolType);

    const Point getCenterPoint();

protected:
    UinputTouchScreen(const Rect* size);

private:
    void configureDevice(int fd, uinput_user_dev* device) override;
    const Rect mSize;
};

} // namespace android

#endif // _UI_TEST_INPUT_UINPUT_INJECTOR_H
