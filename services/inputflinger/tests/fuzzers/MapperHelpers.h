/*
 * Copyright 2022 The Android Open Source Project
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
#include <ThreadSafeFuzzedDataProvider.h>

constexpr size_t kValidTypes[] = {EV_SW,
                                  EV_SYN,
                                  SYN_REPORT,
                                  EV_ABS,
                                  EV_KEY,
                                  EV_MSC,
                                  EV_REL,
                                  android::EventHubInterface::DEVICE_ADDED,
                                  android::EventHubInterface::DEVICE_REMOVED,
                                  android::EventHubInterface::FINISHED_DEVICE_SCAN};

constexpr size_t kValidCodes[] = {
        SYN_REPORT,
        ABS_MT_SLOT,
        SYN_MT_REPORT,
        ABS_MT_POSITION_X,
        ABS_MT_POSITION_Y,
        ABS_MT_TOUCH_MAJOR,
        ABS_MT_TOUCH_MINOR,
        ABS_MT_WIDTH_MAJOR,
        ABS_MT_WIDTH_MINOR,
        ABS_MT_ORIENTATION,
        ABS_MT_TRACKING_ID,
        ABS_MT_PRESSURE,
        ABS_MT_DISTANCE,
        ABS_MT_TOOL_TYPE,
        SYN_MT_REPORT,
        MSC_SCAN,
        REL_X,
        REL_Y,
        REL_WHEEL,
        REL_HWHEEL,
        BTN_LEFT,
        BTN_RIGHT,
        BTN_MIDDLE,
        BTN_BACK,
        BTN_SIDE,
        BTN_FORWARD,
        BTN_EXTRA,
        BTN_TASK,
};

constexpr size_t kMaxSize = 256;

namespace android {

template<class Fdp>
ToolType getFuzzedToolType(Fdp& fdp) {
    const int32_t toolType = fdp.template ConsumeIntegralInRange<int32_t>(
                            static_cast<int32_t>(ToolType::ftl_first),
                            static_cast<int32_t>(ToolType::ftl_last));
    return static_cast<ToolType>(toolType);
}

class FuzzEventHub : public EventHubInterface {
    InputDeviceIdentifier mIdentifier;
    std::vector<TouchVideoFrame> mVideoFrames;
    PropertyMap mFuzzConfig;
    std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp;

public:
    FuzzEventHub(std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp) : mFdp(std::move(fdp)) {}
    ~FuzzEventHub() {}
    void addProperty(std::string key, std::string value) { mFuzzConfig.addProperty(key, value); }

    ftl::Flags<InputDeviceClass> getDeviceClasses(int32_t deviceId) const override {
        return ftl::Flags<InputDeviceClass>(mFdp->ConsumeIntegral<uint32_t>());
    }
    InputDeviceIdentifier getDeviceIdentifier(int32_t deviceId) const override {
        return mIdentifier;
    }
    int32_t getDeviceControllerNumber(int32_t deviceId) const override {
        return mFdp->ConsumeIntegral<int32_t>();
    }
    std::optional<PropertyMap> getConfiguration(int32_t deviceId) const override {
        return mFuzzConfig;
    }
    status_t getAbsoluteAxisInfo(int32_t deviceId, int axis,
                                 RawAbsoluteAxisInfo* outAxisInfo) const override {
        return mFdp->ConsumeIntegral<status_t>();
    }
    bool hasRelativeAxis(int32_t deviceId, int axis) const override { return mFdp->ConsumeBool(); }
    bool hasInputProperty(int32_t deviceId, int property) const override {
        return mFdp->ConsumeBool();
    }
    bool hasMscEvent(int32_t deviceId, int mscEvent) const override { return mFdp->ConsumeBool(); }
    status_t mapKey(int32_t deviceId, int32_t scanCode, int32_t usageCode, int32_t metaState,
                    int32_t* outKeycode, int32_t* outMetaState, uint32_t* outFlags) const override {
        return mFdp->ConsumeIntegral<status_t>();
    }
    status_t mapAxis(int32_t deviceId, int32_t scanCode, AxisInfo* outAxisInfo) const override {
        return mFdp->ConsumeIntegral<status_t>();
    }
    void setExcludedDevices(const std::vector<std::string>& devices) override {}
    std::vector<RawEvent> getEvents(int timeoutMillis) override {
        std::vector<RawEvent> events;
        const size_t count = mFdp->ConsumeIntegralInRange<size_t>(0, kMaxSize);
        for (size_t i = 0; i < count; ++i) {
            int32_t type = mFdp->ConsumeBool() ? mFdp->PickValueInArray(kValidTypes)
                                               : mFdp->ConsumeIntegral<int32_t>();
            int32_t code = mFdp->ConsumeBool() ? mFdp->PickValueInArray(kValidCodes)
                                               : mFdp->ConsumeIntegral<int32_t>();
            events.push_back({
                    .when = mFdp->ConsumeIntegral<nsecs_t>(),
                    .readTime = mFdp->ConsumeIntegral<nsecs_t>(),
                    .deviceId = mFdp->ConsumeIntegral<int32_t>(),
                    .type = type,
                    .code = code,
                    .value = mFdp->ConsumeIntegral<int32_t>(),
            });
        }
        return events;
    }
    std::vector<TouchVideoFrame> getVideoFrames(int32_t deviceId) override { return mVideoFrames; }

    base::Result<std::pair<InputDeviceSensorType, int32_t>> mapSensor(
            int32_t deviceId, int32_t absCode) const override {
        return base::ResultError("Fuzzer", UNKNOWN_ERROR);
    };
    // Raw batteries are sysfs power_supply nodes we found from the EventHub device sysfs node,
    // containing the raw info of the sysfs node structure.
    std::vector<int32_t> getRawBatteryIds(int32_t deviceId) const override { return {}; }
    std::optional<RawBatteryInfo> getRawBatteryInfo(int32_t deviceId,
                                                    int32_t BatteryId) const override {
        return std::nullopt;
    };

    std::vector<int32_t> getRawLightIds(int32_t deviceId) const override { return {}; };
    std::optional<RawLightInfo> getRawLightInfo(int32_t deviceId, int32_t lightId) const override {
        return std::nullopt;
    };
    std::optional<int32_t> getLightBrightness(int32_t deviceId, int32_t lightId) const override {
        return std::nullopt;
    };
    void setLightBrightness(int32_t deviceId, int32_t lightId, int32_t brightness) override{};
    std::optional<std::unordered_map<LightColor, int32_t>> getLightIntensities(
            int32_t deviceId, int32_t lightId) const override {
        return std::nullopt;
    };
    void setLightIntensities(int32_t deviceId, int32_t lightId,
                             std::unordered_map<LightColor, int32_t> intensities) override{};

    std::optional<RawLayoutInfo> getRawLayoutInfo(int32_t deviceId) const override {
        return std::nullopt;
    };

    int32_t getScanCodeState(int32_t deviceId, int32_t scanCode) const override {
        return mFdp->ConsumeIntegral<int32_t>();
    }
    int32_t getKeyCodeState(int32_t deviceId, int32_t keyCode) const override {
        return mFdp->ConsumeIntegral<int32_t>();
    }
    int32_t getSwitchState(int32_t deviceId, int32_t sw) const override {
        return mFdp->ConsumeIntegral<int32_t>();
    }
    void addKeyRemapping(int32_t deviceId, int32_t fromKeyCode, int32_t toKeyCode) const override {}
    int32_t getKeyCodeForKeyLocation(int32_t deviceId, int32_t locationKeyCode) const override {
        return mFdp->ConsumeIntegral<int32_t>();
    }
    status_t getAbsoluteAxisValue(int32_t deviceId, int32_t axis,
                                  int32_t* outValue) const override {
        return mFdp->ConsumeIntegral<status_t>();
    }
    base::Result<std::vector<int32_t>> getMtSlotValues(int32_t deviceId, int32_t axis,
                                                       size_t slotCount) const override {
        if (mFdp->ConsumeBool()) {
            std::vector<int32_t> outValues(slotCount + 1);
            for (size_t i = 0; i < outValues.size(); i++) {
                outValues.push_back(mFdp->ConsumeIntegral<int32_t>());
            }
            return std::move(outValues);
        } else {
            return base::ResultError("Fuzzer", UNKNOWN_ERROR);
        }
    }
    bool markSupportedKeyCodes(int32_t deviceId, const std::vector<int32_t>& keyCodes,
                               uint8_t* outFlags) const override {
        return mFdp->ConsumeBool();
    }
    bool hasScanCode(int32_t deviceId, int32_t scanCode) const override {
        return mFdp->ConsumeBool();
    }
    bool hasKeyCode(int32_t deviceId, int32_t keyCode) const override {
        return mFdp->ConsumeBool();
    }
    bool hasLed(int32_t deviceId, int32_t led) const override { return mFdp->ConsumeBool(); }
    void setLedState(int32_t deviceId, int32_t led, bool on) override {}
    void getVirtualKeyDefinitions(
            int32_t deviceId, std::vector<VirtualKeyDefinition>& outVirtualKeys) const override {}
    const std::shared_ptr<KeyCharacterMap> getKeyCharacterMap(int32_t deviceId) const override {
        return nullptr;
    }
    bool setKeyboardLayoutOverlay(int32_t deviceId, std::shared_ptr<KeyCharacterMap> map) override {
        return mFdp->ConsumeBool();
    }
    void vibrate(int32_t deviceId, const VibrationElement& effect) override {}
    void cancelVibrate(int32_t deviceId) override {}

    std::vector<int32_t> getVibratorIds(int32_t deviceId) const override { return {}; };

    /* Query battery level. */
    std::optional<int32_t> getBatteryCapacity(int32_t deviceId, int32_t batteryId) const override {
        return std::nullopt;
    };

    /* Query battery status. */
    std::optional<int32_t> getBatteryStatus(int32_t deviceId, int32_t batteryId) const override {
        return std::nullopt;
    };

    void requestReopenDevices() override {}
    void wake() override {}
    void dump(std::string& dump) const override {}
    void monitor() const override {}
    bool isDeviceEnabled(int32_t deviceId) const override { return mFdp->ConsumeBool(); }
    status_t enableDevice(int32_t deviceId) override { return mFdp->ConsumeIntegral<status_t>(); }
    status_t disableDevice(int32_t deviceId) override { return mFdp->ConsumeIntegral<status_t>(); }
    void sysfsNodeChanged(const std::string& sysfsNodePath) override {}
};

class FuzzPointerController : public PointerControllerInterface {
    std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp;

public:
    FuzzPointerController(std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp) : mFdp(mFdp) {}
    ~FuzzPointerController() {}
    std::optional<FloatRect> getBounds() const override {
        if (mFdp->ConsumeBool()) {
            return {};
        } else {
            return FloatRect{mFdp->ConsumeFloatingPoint<float>(),
                             mFdp->ConsumeFloatingPoint<float>(),
                             mFdp->ConsumeFloatingPoint<float>(),
                             mFdp->ConsumeFloatingPoint<float>()};
        }
    }
    void move(float deltaX, float deltaY) override {}
    void setPosition(float x, float y) override {}
    FloatPoint getPosition() const override {
        return {mFdp->ConsumeFloatingPoint<float>(), mFdp->ConsumeFloatingPoint<float>()};
    }
    void fade(Transition transition) override {}
    void unfade(Transition transition) override {}
    void setPresentation(Presentation presentation) override {}
    void setSpots(const PointerCoords* spotCoords, const uint32_t* spotIdToIndex,
                  BitSet32 spotIdBits, int32_t displayId) override {}
    void clearSpots() override {}
    int32_t getDisplayId() const override { return mFdp->ConsumeIntegral<int32_t>(); }
    void setDisplayViewport(const DisplayViewport& displayViewport) override {}
};

class FuzzInputReaderPolicy : public InputReaderPolicyInterface {
    TouchAffineTransformation mTransform;
    std::shared_ptr<FuzzPointerController> mPointerController;
    std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp;

protected:
    ~FuzzInputReaderPolicy() {}

public:
    FuzzInputReaderPolicy(std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp) : mFdp(mFdp) {
        mPointerController = std::make_shared<FuzzPointerController>(mFdp);
    }
    void getReaderConfiguration(InputReaderConfiguration* outConfig) override {}
    std::shared_ptr<PointerControllerInterface> obtainPointerController(int32_t deviceId) override {
        return mPointerController;
    }
    void notifyInputDevicesChanged(const std::vector<InputDeviceInfo>& inputDevices) override {}
    std::shared_ptr<KeyCharacterMap> getKeyboardLayoutOverlay(
            const InputDeviceIdentifier& identifier) override {
        return nullptr;
    }
    std::string getDeviceAlias(const InputDeviceIdentifier& identifier) {
        return mFdp->ConsumeRandomLengthString(32);
    }
    TouchAffineTransformation getTouchAffineTransformation(const std::string& inputDeviceDescriptor,
                                                           ui::Rotation surfaceRotation) override {
        return mTransform;
    }
    void setTouchAffineTransformation(const TouchAffineTransformation t) { mTransform = t; }
    void notifyStylusGestureStarted(int32_t, nsecs_t) {}
    bool isInputMethodConnectionActive() override { return mFdp->ConsumeBool(); }
};

class FuzzInputListener : public virtual InputListenerInterface {
public:
    void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) override {}
    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) override {}
    void notifyKey(const NotifyKeyArgs& args) override {}
    void notifyMotion(const NotifyMotionArgs& args) override {}
    void notifySwitch(const NotifySwitchArgs& args) override {}
    void notifySensor(const NotifySensorArgs& args) override{};
    void notifyVibratorState(const NotifyVibratorStateArgs& args) override{};
    void notifyDeviceReset(const NotifyDeviceResetArgs& args) override {}
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) override{};
};

class FuzzInputReaderContext : public InputReaderContext {
    std::shared_ptr<EventHubInterface> mEventHub;
    sp<InputReaderPolicyInterface> mPolicy;
    std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp;

public:
    FuzzInputReaderContext(std::shared_ptr<EventHubInterface> eventHub,
                           const sp<InputReaderPolicyInterface>& policy,
                           InputListenerInterface& listener,
                           std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp)
          : mEventHub(eventHub), mPolicy(policy), mFdp(mFdp) {}
    ~FuzzInputReaderContext() {}
    void updateGlobalMetaState() override {}
    int32_t getGlobalMetaState() { return mFdp->ConsumeIntegral<int32_t>(); }
    void disableVirtualKeysUntil(nsecs_t time) override {}
    bool shouldDropVirtualKey(nsecs_t now, int32_t keyCode, int32_t scanCode) override {
        return mFdp->ConsumeBool();
    }
    void fadePointer() override {}
    std::shared_ptr<PointerControllerInterface> getPointerController(int32_t deviceId) override {
        return mPolicy->obtainPointerController(0);
    }
    void requestTimeoutAtTime(nsecs_t when) override {}
    int32_t bumpGeneration() override { return mFdp->ConsumeIntegral<int32_t>(); }
    void getExternalStylusDevices(std::vector<InputDeviceInfo>& outDevices) override {}
    std::list<NotifyArgs> dispatchExternalStylusState(const StylusState& outState) override {
        return {};
    }
    InputReaderPolicyInterface* getPolicy() override { return mPolicy.get(); }
    EventHubInterface* getEventHub() override { return mEventHub.get(); }
    int32_t getNextId() override { return mFdp->ConsumeIntegral<int32_t>(); }

    void updateLedMetaState(int32_t metaState) override{};
    int32_t getLedMetaState() override { return mFdp->ConsumeIntegral<int32_t>(); };
    void notifyStylusGestureStarted(int32_t, nsecs_t) {}

    void setPreventingTouchpadTaps(bool prevent) {}
    bool isPreventingTouchpadTaps() { return mFdp->ConsumeBool(); };
};

} // namespace android
