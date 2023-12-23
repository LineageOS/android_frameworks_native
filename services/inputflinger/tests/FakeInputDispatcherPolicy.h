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

#include <android-base/logging.h>
#include "InputDispatcherPolicyInterface.h"

namespace android {

// --- FakeInputDispatcherPolicy ---

class FakeInputDispatcherPolicy : public InputDispatcherPolicyInterface {
public:
    FakeInputDispatcherPolicy() = default;
    virtual ~FakeInputDispatcherPolicy() = default;

private:
    void notifyConfigurationChanged(nsecs_t) override {}

    void notifyNoFocusedWindowAnr(
            const std::shared_ptr<InputApplicationHandle>& applicationHandle) override {
        LOG(ERROR) << "There is no focused window for " << applicationHandle->getName();
    }

    void notifyWindowUnresponsive(const sp<IBinder>& connectionToken, std::optional<gui::Pid> pid,
                                  const std::string& reason) override {
        LOG(ERROR) << "Window is not responding: " << reason;
    }

    void notifyWindowResponsive(const sp<IBinder>& connectionToken,
                                std::optional<gui::Pid> pid) override {}

    void notifyInputChannelBroken(const sp<IBinder>&) override {}

    void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) override {}

    void notifySensorEvent(int32_t deviceId, InputDeviceSensorType sensorType,
                           InputDeviceSensorAccuracy accuracy, nsecs_t timestamp,
                           const std::vector<float>& values) override {}

    void notifySensorAccuracy(int32_t deviceId, InputDeviceSensorType sensorType,
                              InputDeviceSensorAccuracy accuracy) override {}

    void notifyVibratorState(int32_t deviceId, bool isOn) override {}

    bool filterInputEvent(const InputEvent& inputEvent, uint32_t policyFlags) override {
        return true; // dispatch event normally
    }

    void interceptKeyBeforeQueueing(const KeyEvent&, uint32_t&) override {}

    void interceptMotionBeforeQueueing(int32_t, uint32_t, int32_t, nsecs_t, uint32_t&) override {}

    nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent&, uint32_t) override {
        return 0;
    }

    std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent&,
                                                 uint32_t) override {
        return {};
    }

    void notifySwitch(nsecs_t, uint32_t, uint32_t, uint32_t) override {}

    void pokeUserActivity(nsecs_t, int32_t, int32_t) override {}

    void onPointerDownOutsideFocus(const sp<IBinder>& newToken) override {}

    void setPointerCapture(const PointerCaptureRequest&) override {}

    void notifyDropWindow(const sp<IBinder>&, float x, float y) override {}

    void notifyDeviceInteraction(DeviceId deviceId, nsecs_t timestamp,
                                 const std::set<gui::Uid>& uids) override {}
};

} // namespace android
