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

#pragma once

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
    std::unique_ptr<D> dev(new D(args...));
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
    const int16_t mProductId;

    explicit UinputDevice(const char* name, int16_t productId);

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
    static constexpr const char* KEYBOARD_NAME = "Test Uinput Keyboard Device";
    static constexpr int16_t PRODUCT_ID = 42;

    // Injects key press and sync.
    void pressKey(int key);
    // Injects key release and sync.
    void releaseKey(int key);
    // Injects 4 events: key press, sync, key release, and sync.
    void pressAndReleaseKey(int key);

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

protected:
    explicit UinputKeyboard(const char* name, int16_t productId = PRODUCT_ID,
                            std::initializer_list<int> keys = {});

    void configureDevice(int fd, uinput_user_dev* device) override;

private:
    std::set<int> mKeys;
};

// --- UinputHomeKey---

// A keyboard device that has a single HOME key.
class UinputHomeKey : public UinputKeyboard {
public:
    static constexpr const char* DEVICE_NAME = "Test Uinput Home Key";
    static constexpr int16_t PRODUCT_ID = 43;

    // Injects 4 events: key press, sync, key release, and sync.
    void pressAndReleaseHomeKey();

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

private:
    explicit UinputHomeKey();
};

// --- UinputSteamController ---

// A joystick device that sends a BTN_GEAR_DOWN / BTN_WHEEL key.
class UinputSteamController : public UinputKeyboard {
public:
    static constexpr const char* DEVICE_NAME = "Test Uinput Steam Controller";
    static constexpr int16_t PRODUCT_ID = 44;

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

private:
    explicit UinputSteamController();
};

// --- UinputExternalStylus ---

// A stylus that reports button presses.
class UinputExternalStylus : public UinputKeyboard {
public:
    static constexpr const char* DEVICE_NAME = "Test Uinput External Stylus";
    static constexpr int16_t PRODUCT_ID = 45;

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

private:
    explicit UinputExternalStylus();
};

// --- UinputExternalStylusWithPressure ---

// A stylus that reports button presses and pressure values.
class UinputExternalStylusWithPressure : public UinputKeyboard {
public:
    static constexpr const char* DEVICE_NAME = "Test Uinput External Stylus With Pressure";
    static constexpr int16_t PRODUCT_ID = 46;

    static constexpr int32_t RAW_PRESSURE_MIN = 0;
    static constexpr int32_t RAW_PRESSURE_MAX = 255;

    void setPressure(int32_t pressure);

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

private:
    void configureDevice(int fd, uinput_user_dev* device) override;

    explicit UinputExternalStylusWithPressure();
};

// --- UinputKeyboardWithUsage ---
// A keyboard that supports EV_MSC MSC_SCAN through which it can report HID usage codes.

class UinputKeyboardWithHidUsage : public UinputKeyboard {
public:
    static constexpr const char* DEVICE_NAME = "Test Uinput Keyboard With Usage";
    static constexpr int16_t PRODUCT_ID = 47;

    template <class D, class... Ts>
    friend std::unique_ptr<D> createUinputDevice(Ts... args);

protected:
    explicit UinputKeyboardWithHidUsage(std::initializer_list<int> keys);

    void configureDevice(int fd, uinput_user_dev* device) override;
};

// --- UinputTouchScreen ---

// A multi-touch touchscreen device with specific size that also supports styluses.
class UinputTouchScreen : public UinputKeyboard {
public:
    static constexpr const char* DEVICE_NAME = "Test Uinput Touch Screen";
    static constexpr int16_t PRODUCT_ID = 48;

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
    void sendPressure(int32_t pressure);
    void sendPointerUp();
    void sendUp();
    void sendToolType(int32_t toolType);
    void sendSync();

    const Point getCenterPoint();

protected:
    explicit UinputTouchScreen(const Rect& size, const std::string& physicalPort = "");

private:
    void configureDevice(int fd, uinput_user_dev* device) override;
    const Rect mSize;
    const std::string mPhysicalPort;
};

} // namespace android
