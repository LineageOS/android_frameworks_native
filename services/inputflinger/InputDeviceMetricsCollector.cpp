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

#define LOG_TAG "InputDeviceMetricsCollector"
#include "InputDeviceMetricsCollector.h"

namespace android {

InputDeviceMetricsCollector::InputDeviceMetricsCollector(InputListenerInterface& listener)
      : mNextListener(listener){};

void InputDeviceMetricsCollector::notifyInputDevicesChanged(
        const NotifyInputDevicesChangedArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyConfigurationChanged(
        const NotifyConfigurationChangedArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyKey(const NotifyKeyArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyMotion(const NotifyMotionArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifySwitch(const NotifySwitchArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifySensor(const NotifySensorArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::notifyPointerCaptureChanged(
        const NotifyPointerCaptureChangedArgs& args) {
    mNextListener.notify(args);
}

void InputDeviceMetricsCollector::dump(std::string& dump) {
    dump += "InputDeviceMetricsCollector:\n";
}

} // namespace android
