/*
 * Copyright 2023 The Android Open Source Project
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

namespace android {

enum class UinputAction {
    RELEASE = 0,
    PRESS = 1,
    MOVE = 2,
    CANCEL = 3,
};

class VirtualInputDevice {
public:
    VirtualInputDevice(android::base::unique_fd fd);
    virtual ~VirtualInputDevice();

protected:
    const android::base::unique_fd mFd;
    bool writeInputEvent(uint16_t type, uint16_t code, int32_t value,
                         std::chrono::nanoseconds eventTime);
    bool writeEvKeyEvent(int32_t androidCode, int32_t androidAction,
                         const std::map<int, int>& evKeyCodeMapping,
                         const std::map<int, UinputAction>& actionMapping,
                         std::chrono::nanoseconds eventTime);
};

class VirtualKeyboard : public VirtualInputDevice {
public:
    static const std::map<int, int> KEY_CODE_MAPPING;
    // Expose to share with VirtualDpad.
    static const std::map<int, UinputAction> KEY_ACTION_MAPPING;
    VirtualKeyboard(android::base::unique_fd fd);
    virtual ~VirtualKeyboard() override;
    bool writeKeyEvent(int32_t androidKeyCode, int32_t androidAction,
                       std::chrono::nanoseconds eventTime);
};

class VirtualDpad : public VirtualInputDevice {
public:
    static const std::map<int, int> DPAD_KEY_CODE_MAPPING;
    VirtualDpad(android::base::unique_fd fd);
    virtual ~VirtualDpad() override;
    bool writeDpadKeyEvent(int32_t androidKeyCode, int32_t androidAction,
                           std::chrono::nanoseconds eventTime);
};

class VirtualMouse : public VirtualInputDevice {
public:
    // Expose to share with VirtualStylus.
    static const std::map<int, UinputAction> BUTTON_ACTION_MAPPING;
    VirtualMouse(android::base::unique_fd fd);
    virtual ~VirtualMouse() override;
    bool writeButtonEvent(int32_t androidButtonCode, int32_t androidAction,
                          std::chrono::nanoseconds eventTime);
    // TODO(b/259554911): changing float parameters to int32_t.
    bool writeRelativeEvent(float relativeX, float relativeY, std::chrono::nanoseconds eventTime);
    bool writeScrollEvent(float xAxisMovement, float yAxisMovement,
                          std::chrono::nanoseconds eventTime);

private:
    static const std::map<int, int> BUTTON_CODE_MAPPING;
};

class VirtualTouchscreen : public VirtualInputDevice {
public:
    // Expose to share with VirtualStylus.
    static const std::map<int, UinputAction> TOUCH_ACTION_MAPPING;
    VirtualTouchscreen(android::base::unique_fd fd);
    virtual ~VirtualTouchscreen() override;
    // TODO(b/259554911): changing float parameters to int32_t.
    bool writeTouchEvent(int32_t pointerId, int32_t toolType, int32_t action, float locationX,
                         float locationY, float pressure, float majorAxisSize,
                         std::chrono::nanoseconds eventTime);

private:
    static const std::map<int, int> TOOL_TYPE_MAPPING;
    /* The set of active touch pointers on this device.
     * We only allow pointer id to go up to MAX_POINTERS because the maximum slots of virtual
     * touchscreen is set up with MAX_POINTERS. Note that in other cases Android allows pointer id
     * to go up to MAX_POINTERS_ID.
     */
    std::bitset<MAX_POINTERS> mActivePointers{};
    bool isValidPointerId(int32_t pointerId, UinputAction uinputAction);
    bool handleTouchDown(int32_t pointerId, std::chrono::nanoseconds eventTime);
    bool handleTouchUp(int32_t pointerId, std::chrono::nanoseconds eventTime);
};

class VirtualStylus : public VirtualInputDevice {
public:
    VirtualStylus(android::base::unique_fd fd);
    ~VirtualStylus() override;
    bool writeMotionEvent(int32_t toolType, int32_t action, int32_t locationX, int32_t locationY,
                          int32_t pressure, int32_t tiltX, int32_t tiltY,
                          std::chrono::nanoseconds eventTime);
    bool writeButtonEvent(int32_t androidButtonCode, int32_t androidAction,
                          std::chrono::nanoseconds eventTime);

private:
    static const std::map<int, int> TOOL_TYPE_MAPPING;
    static const std::map<int, int> BUTTON_CODE_MAPPING;
    // True if the stylus is touching or hovering on the screen.
    bool mIsStylusDown;
    bool handleStylusDown(uint16_t tool, std::chrono::nanoseconds eventTime);
    bool handleStylusUp(uint16_t tool, std::chrono::nanoseconds eventTime);
};

} // namespace android
