/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef _UI_INPUTREADER_INPUT_READER_CONTEXT_H
#define _UI_INPUTREADER_INPUT_READER_CONTEXT_H

#include <input/InputDevice.h>

#include <vector>

namespace android {

class EventHubInterface;
class InputDevice;
class InputListenerInterface;
class InputMapper;
class InputReaderPolicyInterface;
class PointerControllerInterface;
struct StylusState;

/* Internal interface used by individual input devices to access global input device state
 * and parameters maintained by the input reader.
 */
class InputReaderContext {
public:
    InputReaderContext() {}
    virtual ~InputReaderContext() {}

    virtual void updateGlobalMetaState() = 0;
    virtual int32_t getGlobalMetaState() = 0;

    virtual void disableVirtualKeysUntil(nsecs_t time) = 0;
    virtual bool shouldDropVirtualKey(nsecs_t now, int32_t keyCode, int32_t scanCode) = 0;

    virtual void fadePointer() = 0;
    virtual std::shared_ptr<PointerControllerInterface> getPointerController(int32_t deviceId) = 0;

    virtual void requestTimeoutAtTime(nsecs_t when) = 0;
    virtual int32_t bumpGeneration() = 0;

    virtual void getExternalStylusDevices(std::vector<InputDeviceInfo>& outDevices) = 0;
    virtual void dispatchExternalStylusState(const StylusState& outState) = 0;

    virtual InputReaderPolicyInterface* getPolicy() = 0;
    virtual EventHubInterface* getEventHub() = 0;

    virtual void updateLedMetaState(int32_t metaState) = 0;
    virtual int32_t getLedMetaState() = 0;

    // Send events to InputListener interface

    virtual void notifyConfigurationChanged(nsecs_t when) = 0;
    virtual void notifyKey(nsecs_t eventTime, int32_t deviceId, uint32_t source, int32_t displayId,
                           uint32_t policyFlags, int32_t action, int32_t flags, int32_t keyCode,
                           int32_t scanCode, int32_t metaState, nsecs_t downTime) = 0;
    virtual void notifyMotion(nsecs_t eventTime, int32_t deviceId, uint32_t source,
                              int32_t displayId, uint32_t policyFlags, int32_t action,
                              int32_t actionButton, int32_t flags, int32_t metaState,
                              int32_t buttonState, MotionClassification classification,
                              int32_t edgeFlags, uint32_t pointerCount,
                              const PointerProperties* pointerProperties,
                              const PointerCoords* pointerCoords, float xPrecision,
                              float yPrecision, float xCursorPosition, float yCursorPosition,
                              nsecs_t downTime,
                              const std::vector<TouchVideoFrame>& videoFrames) = 0;
    virtual void notifySwitch(nsecs_t eventTime, uint32_t switchValues, uint32_t switchMask) = 0;
    virtual void notifySensor(nsecs_t when, int32_t deviceId, InputDeviceSensorType sensorType,
                              InputDeviceSensorAccuracy accuracy, bool accuracyChanged,
                              nsecs_t timestamp, std::vector<float> values) = 0;
    virtual void notifyDeviceReset(nsecs_t when, int32_t deviceId) = 0;
    virtual void notifyPointerCaptureChanged(nsecs_t when, bool hasCapture) = 0;
};

} // namespace android

#endif // _UI_INPUTREADER_INPUT_READER_CONTEXT_H
