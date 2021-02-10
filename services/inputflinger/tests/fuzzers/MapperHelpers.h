/*
 * Copyright 2020 The Android Open Source Project
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

#include <InputDevice.h>
#include <InputMapper.h>
#include <InputReader.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace android {

class FuzzEventHub : public EventHubInterface {
    InputDeviceIdentifier mIdentifier;
    std::vector<TouchVideoFrame> mVideoFrames;
    PropertyMap mFuzzConfig;
    std::mutex mEventLock;
    size_t mCount = 0;
    RawEvent mBuf[256];
    std::shared_ptr<FuzzedDataProvider> fdp;

public:
    FuzzEventHub(std::shared_ptr<FuzzedDataProvider> fdp) : fdp(fdp) {}
    ~FuzzEventHub() {}
    void addProperty(const String8& key, const String8 value) {
        mFuzzConfig.addProperty(key, value);
    }
    void addEvents(std::shared_ptr<FuzzedDataProvider> fdp) {
        std::lock_guard<std::mutex> guard(mEventLock);
        mCount = fdp->ConsumeIntegralInRange<size_t>(0, 256);

        for (size_t i = 0; i < mCount; i++)
            mBuf[i] = {fdp->ConsumeIntegral<nsecs_t>(), fdp->ConsumeIntegral<int32_t>(),
                       fdp->ConsumeIntegral<int32_t>(), fdp->ConsumeIntegral<int32_t>(),
                       fdp->ConsumeIntegral<int32_t>()};
    }
    uint32_t getDeviceClasses(int32_t deviceId) const override {
        return fdp->ConsumeIntegral<uint32_t>();
    }
    InputDeviceIdentifier getDeviceIdentifier(int32_t deviceId) const override {
        return mIdentifier;
    }
    int32_t getDeviceControllerNumber(int32_t deviceId) const override {
        return fdp->ConsumeIntegral<int32_t>();
    }
    void getConfiguration(int32_t deviceId, PropertyMap* outConfiguration) const override {
        *outConfiguration = mFuzzConfig;
    }
    status_t getAbsoluteAxisInfo(int32_t deviceId, int axis,
                                 RawAbsoluteAxisInfo* outAxisInfo) const override {
        return fdp->ConsumeIntegral<status_t>();
    }
    bool hasRelativeAxis(int32_t deviceId, int axis) const override { return fdp->ConsumeBool(); }
    bool hasInputProperty(int32_t deviceId, int property) const override {
        return fdp->ConsumeBool();
    }
    status_t mapKey(int32_t deviceId, int32_t scanCode, int32_t usageCode, int32_t metaState,
                    int32_t* outKeycode, int32_t* outMetaState, uint32_t* outFlags) const override {
        return fdp->ConsumeIntegral<status_t>();
    }
    status_t mapAxis(int32_t deviceId, int32_t scanCode, AxisInfo* outAxisInfo) const override {
        return fdp->ConsumeIntegral<status_t>();
    }
    void setExcludedDevices(const std::vector<std::string>& devices) override {}
    size_t getEvents(int timeoutMillis, RawEvent* buffer, size_t bufferSize) override {
        std::lock_guard<std::mutex> guard(mEventLock);
        for (size_t i = 0; i < mCount; i++) buffer[i] = mBuf[i];

        return mCount;
    }
    std::vector<TouchVideoFrame> getVideoFrames(int32_t deviceId) override { return mVideoFrames; }
    int32_t getScanCodeState(int32_t deviceId, int32_t scanCode) const override {
        return fdp->ConsumeIntegral<int32_t>();
    }
    int32_t getKeyCodeState(int32_t deviceId, int32_t keyCode) const override {
        return fdp->ConsumeIntegral<int32_t>();
    }
    int32_t getSwitchState(int32_t deviceId, int32_t sw) const override {
        return fdp->ConsumeIntegral<int32_t>();
    }
    status_t getAbsoluteAxisValue(int32_t deviceId, int32_t axis,
                                  int32_t* outValue) const override {
        return fdp->ConsumeIntegral<status_t>();
    }
    bool markSupportedKeyCodes(int32_t deviceId, size_t numCodes, const int32_t* keyCodes,
                               uint8_t* outFlags) const override {
        return fdp->ConsumeBool();
    }
    bool hasScanCode(int32_t deviceId, int32_t scanCode) const override {
        return fdp->ConsumeBool();
    }
    bool hasLed(int32_t deviceId, int32_t led) const override { return fdp->ConsumeBool(); }
    void setLedState(int32_t deviceId, int32_t led, bool on) override {}
    void getVirtualKeyDefinitions(
            int32_t deviceId, std::vector<VirtualKeyDefinition>& outVirtualKeys) const override {}
    sp<KeyCharacterMap> getKeyCharacterMap(int32_t deviceId) const override { return nullptr; }
    bool setKeyboardLayoutOverlay(int32_t deviceId, const sp<KeyCharacterMap>& map) override {
        return fdp->ConsumeBool();
    }
    void vibrate(int32_t deviceId, nsecs_t duration) override {}
    void cancelVibrate(int32_t deviceId) override {}
    void requestReopenDevices() override {}
    void wake() override {}
    void dump(std::string& dump) override {}
    void monitor() override {}
    bool isDeviceEnabled(int32_t deviceId) override { return fdp->ConsumeBool(); }
    status_t enableDevice(int32_t deviceId) override { return fdp->ConsumeIntegral<status_t>(); }
    status_t disableDevice(int32_t deviceId) override { return fdp->ConsumeIntegral<status_t>(); }
};

class FuzzPointerController : public PointerControllerInterface {
    std::shared_ptr<FuzzedDataProvider> fdp;

public:
    FuzzPointerController(std::shared_ptr<FuzzedDataProvider> fdp) : fdp(fdp) {}
    ~FuzzPointerController() {}
    bool getBounds(float* outMinX, float* outMinY, float* outMaxX, float* outMaxY) const override {
        return fdp->ConsumeBool();
    }
    void move(float deltaX, float deltaY) override {}
    void setButtonState(int32_t buttonState) override {}
    int32_t getButtonState() const override { return fdp->ConsumeIntegral<int32_t>(); }
    void setPosition(float x, float y) override {}
    void getPosition(float* outX, float* outY) const override {}
    void fade(Transition transition) override {}
    void unfade(Transition transition) override {}
    void setPresentation(Presentation presentation) override {}
    void setSpots(const PointerCoords* spotCoords, const uint32_t* spotIdToIndex,
                  BitSet32 spotIdBits, int32_t displayId) override {}
    void clearSpots() override {}
    int32_t getDisplayId() const override { return fdp->ConsumeIntegral<int32_t>(); }
    void setDisplayViewport(const DisplayViewport& displayViewport) override {}
};

class FuzzInputReaderPolicy : public InputReaderPolicyInterface {
    TouchAffineTransformation mTransform;
    std::shared_ptr<FuzzPointerController> mPointerController;
    std::shared_ptr<FuzzedDataProvider> fdp;

protected:
    ~FuzzInputReaderPolicy() {}

public:
    FuzzInputReaderPolicy(std::shared_ptr<FuzzedDataProvider> fdp) : fdp(fdp) {
        mPointerController = std::make_shared<FuzzPointerController>(fdp);
    }
    void getReaderConfiguration(InputReaderConfiguration* outConfig) override {}
    std::shared_ptr<PointerControllerInterface> obtainPointerController(int32_t deviceId) override {
        return mPointerController;
    }
    void notifyInputDevicesChanged(const std::vector<InputDeviceInfo>& inputDevices) override {}
    sp<KeyCharacterMap> getKeyboardLayoutOverlay(const InputDeviceIdentifier& identifier) override {
        return nullptr;
    }
    std::string getDeviceAlias(const InputDeviceIdentifier& identifier) {
        return fdp->ConsumeRandomLengthString(32);
    }
    TouchAffineTransformation getTouchAffineTransformation(const std::string& inputDeviceDescriptor,
                                                           int32_t surfaceRotation) override {
        return mTransform;
    }
    void setTouchAffineTransformation(const TouchAffineTransformation t) { mTransform = t; }
};

class FuzzInputListener : public virtual InputListenerInterface {
protected:
    ~FuzzInputListener() {}

public:
    FuzzInputListener() {}
    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) override {}
    void notifyKey(const NotifyKeyArgs* args) override {}
    void notifyMotion(const NotifyMotionArgs* args) override {}
    void notifySwitch(const NotifySwitchArgs* args) override {}
    void notifyDeviceReset(const NotifyDeviceResetArgs* args) override {}
};

class FuzzInputReaderContext : public InputReaderContext {
    std::shared_ptr<EventHubInterface> mEventHub;
    sp<InputReaderPolicyInterface> mPolicy;
    sp<InputListenerInterface> mListener;
    std::shared_ptr<FuzzedDataProvider> fdp;

public:
    FuzzInputReaderContext(std::shared_ptr<EventHubInterface> eventHub,
                           const sp<InputReaderPolicyInterface>& policy,
                           const sp<InputListenerInterface>& listener,
                           std::shared_ptr<FuzzedDataProvider> fdp)
          : mEventHub(eventHub), mPolicy(policy), mListener(listener), fdp(fdp) {}
    ~FuzzInputReaderContext() {}
    void updateGlobalMetaState() override {}
    int32_t getGlobalMetaState() { return fdp->ConsumeIntegral<int32_t>(); }
    void disableVirtualKeysUntil(nsecs_t time) override {}
    bool shouldDropVirtualKey(nsecs_t now, int32_t keyCode, int32_t scanCode) override {
        return fdp->ConsumeBool();
    }
    void fadePointer() override {}
    std::shared_ptr<PointerControllerInterface> getPointerController(int32_t deviceId) override {
        return mPolicy->obtainPointerController(0);
    }
    void requestTimeoutAtTime(nsecs_t when) override {}
    int32_t bumpGeneration() override { return fdp->ConsumeIntegral<int32_t>(); }
    void getExternalStylusDevices(std::vector<InputDeviceInfo>& outDevices) override {}
    void dispatchExternalStylusState(const StylusState& outState) override {}
    InputReaderPolicyInterface* getPolicy() override { return mPolicy.get(); }
    InputListenerInterface* getListener() override { return mListener.get(); }
    EventHubInterface* getEventHub() override { return mEventHub.get(); }
    int32_t getNextId() override { return fdp->ConsumeIntegral<int32_t>(); }
};

} // namespace android
