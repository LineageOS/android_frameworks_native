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

#pragma once

#include <input/InputDevice.h>
#include <input/KeyboardClassifier.h>
#include "NotifyArgs.h"

#include <vector>

namespace android {

class EventHubInterface;
class InputDevice;
class InputListenerInterface;
class InputMapper;
class InputReaderPolicyInterface;
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

    virtual void requestTimeoutAtTime(nsecs_t when) = 0;
    virtual int32_t bumpGeneration() = 0;

    virtual void getExternalStylusDevices(std::vector<InputDeviceInfo>& outDevices) = 0;
    [[nodiscard]] virtual std::list<NotifyArgs> dispatchExternalStylusState(
            const StylusState& outState) = 0;

    virtual InputReaderPolicyInterface* getPolicy() = 0;
    virtual EventHubInterface* getEventHub() = 0;

    virtual int32_t getNextId() = 0;

    virtual void updateLedMetaState(int32_t metaState) = 0;
    virtual int32_t getLedMetaState() = 0;

    virtual void setPreventingTouchpadTaps(bool prevent) = 0;
    virtual bool isPreventingTouchpadTaps() = 0;

    virtual void setLastKeyDownTimestamp(nsecs_t when) = 0;
    virtual nsecs_t getLastKeyDownTimestamp() = 0;

    virtual KeyboardClassifier& getKeyboardClassifier() = 0;
};

} // namespace android
