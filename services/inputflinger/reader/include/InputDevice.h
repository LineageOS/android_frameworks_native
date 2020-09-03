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

#ifndef _UI_INPUTREADER_INPUT_DEVICE_H
#define _UI_INPUTREADER_INPUT_DEVICE_H

#include "EventHub.h"
#include "InputReaderBase.h"
#include "InputReaderContext.h"

#include <input/DisplayViewport.h>
#include <input/InputDevice.h>
#include <input/PropertyMap.h>
#include <stdint.h>

#include <optional>
#include <vector>

namespace android {

class InputMapper;

/* Represents the state of a single input device. */
class InputDevice {
public:
    InputDevice(InputReaderContext* context, int32_t id, int32_t generation,
                int32_t controllerNumber, const InputDeviceIdentifier& identifier,
                uint32_t classes);
    ~InputDevice();

    inline InputReaderContext* getContext() { return mContext; }
    inline int32_t getId() const { return mId; }
    inline int32_t getControllerNumber() const { return mControllerNumber; }
    inline int32_t getGeneration() const { return mGeneration; }
    inline const std::string getName() const { return mIdentifier.name; }
    inline const std::string getDescriptor() { return mIdentifier.descriptor; }
    inline uint32_t getClasses() const { return mClasses; }
    inline uint32_t getSources() const { return mSources; }

    inline bool isExternal() { return mIsExternal; }
    inline void setExternal(bool external) { mIsExternal = external; }
    inline std::optional<uint8_t> getAssociatedDisplayPort() const {
        return mAssociatedDisplayPort;
    }

    inline void setMic(bool hasMic) { mHasMic = hasMic; }
    inline bool hasMic() const { return mHasMic; }

    inline bool isIgnored() { return mMappers.empty(); }

    bool isEnabled();
    void setEnabled(bool enabled, nsecs_t when);

    void dump(std::string& dump);
    void addMapper(InputMapper* mapper);
    void configure(nsecs_t when, const InputReaderConfiguration* config, uint32_t changes);
    void reset(nsecs_t when);
    void process(const RawEvent* rawEvents, size_t count);
    void timeoutExpired(nsecs_t when);
    void updateExternalStylusState(const StylusState& state);

    void getDeviceInfo(InputDeviceInfo* outDeviceInfo);
    int32_t getKeyCodeState(uint32_t sourceMask, int32_t keyCode);
    int32_t getScanCodeState(uint32_t sourceMask, int32_t scanCode);
    int32_t getSwitchState(uint32_t sourceMask, int32_t switchCode);
    bool markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes, const int32_t* keyCodes,
                               uint8_t* outFlags);
    void vibrate(const nsecs_t* pattern, size_t patternSize, ssize_t repeat, int32_t token);
    void cancelVibrate(int32_t token);
    void cancelTouch(nsecs_t when);

    int32_t getMetaState();
    void updateMetaState(int32_t keyCode);

    void fadePointer();

    void bumpGeneration();

    void notifyReset(nsecs_t when);

    inline const PropertyMap& getConfiguration() { return mConfiguration; }
    inline EventHubInterface* getEventHub() { return mContext->getEventHub(); }

    bool hasKey(int32_t code) { return getEventHub()->hasScanCode(mId, code); }

    bool hasAbsoluteAxis(int32_t code) {
        RawAbsoluteAxisInfo info;
        getEventHub()->getAbsoluteAxisInfo(mId, code, &info);
        return info.valid;
    }

    bool isKeyPressed(int32_t code) {
        return getEventHub()->getScanCodeState(mId, code) == AKEY_STATE_DOWN;
    }

    int32_t getAbsoluteAxisValue(int32_t code) {
        int32_t value;
        getEventHub()->getAbsoluteAxisValue(mId, code, &value);
        return value;
    }

    std::optional<int32_t> getAssociatedDisplay();

private:
    InputReaderContext* mContext;
    int32_t mId;
    int32_t mGeneration;
    int32_t mControllerNumber;
    InputDeviceIdentifier mIdentifier;
    std::string mAlias;
    uint32_t mClasses;

    std::vector<InputMapper*> mMappers;

    uint32_t mSources;
    bool mIsExternal;
    std::optional<uint8_t> mAssociatedDisplayPort;
    bool mHasMic;
    bool mDropUntilNextSync;

    typedef int32_t (InputMapper::*GetStateFunc)(uint32_t sourceMask, int32_t code);
    int32_t getState(uint32_t sourceMask, int32_t code, GetStateFunc getStateFunc);

    PropertyMap mConfiguration;
};

} // namespace android

#endif //_UI_INPUTREADER_INPUT_DEVICE_H
