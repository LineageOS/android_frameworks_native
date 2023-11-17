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

#define LOG_TAG "InputFilter"

#include "InputFilter.h"

namespace android {

using aidl::com::android::server::inputflinger::IInputFilter;
using AidlKeyEvent = aidl::com::android::server::inputflinger::KeyEvent;

AidlKeyEvent notifyKeyArgsToKeyEvent(const NotifyKeyArgs& args) {
    AidlKeyEvent event;
    event.id = args.id;
    event.eventTime = args.eventTime;
    event.deviceId = args.deviceId;
    event.source = args.source;
    event.displayId = args.displayId;
    event.policyFlags = args.policyFlags;
    event.action = args.action;
    event.flags = args.flags;
    event.keyCode = args.keyCode;
    event.scanCode = args.scanCode;
    event.metaState = args.metaState;
    event.downTime = args.downTime;
    event.readTime = args.readTime;
    return event;
}

NotifyKeyArgs keyEventToNotifyKeyArgs(const AidlKeyEvent& event) {
    return NotifyKeyArgs(event.id, event.eventTime, event.readTime, event.deviceId, event.source,
                         event.displayId, event.policyFlags, event.action, event.flags,
                         event.keyCode, event.scanCode, event.metaState, event.downTime);
}

namespace {

class RustCallbacks : public IInputFilter::BnInputFilterCallbacks {
public:
    RustCallbacks(InputListenerInterface& nextListener) : mNextListener(nextListener) {}
    ndk::ScopedAStatus sendKeyEvent(const AidlKeyEvent& event) override {
        mNextListener.notifyKey(keyEventToNotifyKeyArgs(event));
        return ndk::ScopedAStatus::ok();
    }

private:
    InputListenerInterface& mNextListener;
};

} // namespace

InputFilter::InputFilter(InputListenerInterface& listener, IInputFlingerRust& rust)
      : mNextListener(listener), mCallbacks(ndk::SharedRefBase::make<RustCallbacks>(listener)) {
    LOG_ALWAYS_FATAL_IF(!rust.createInputFilter(mCallbacks, &mInputFilterRust).isOk());
    LOG_ALWAYS_FATAL_IF(!mInputFilterRust);
}

void InputFilter::notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) {
    if (isFilterEnabled()) {
        std::vector<int32_t> deviceIds;
        for (auto info : args.inputDeviceInfos) {
            deviceIds.push_back(info.getId());
        }
        LOG_ALWAYS_FATAL_IF(!mInputFilterRust->notifyInputDevicesChanged(deviceIds).isOk());
    }
    mNextListener.notify(args);
}

void InputFilter::notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) {
    mNextListener.notify(args);
}

void InputFilter::notifyKey(const NotifyKeyArgs& args) {
    if (!isFilterEnabled()) {
        mNextListener.notifyKey(args);
        return;
    }
    LOG_ALWAYS_FATAL_IF(!mInputFilterRust->notifyKey(notifyKeyArgsToKeyEvent(args)).isOk());
}

void InputFilter::notifyMotion(const NotifyMotionArgs& args) {
    mNextListener.notify(args);
}

void InputFilter::notifySwitch(const NotifySwitchArgs& args) {
    mNextListener.notify(args);
}

void InputFilter::notifySensor(const NotifySensorArgs& args) {
    mNextListener.notify(args);
}

void InputFilter::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    mNextListener.notify(args);
}

void InputFilter::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    mNextListener.notify(args);
}

void InputFilter::notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) {
    mNextListener.notify(args);
}

bool InputFilter::isFilterEnabled() {
    bool result;
    LOG_ALWAYS_FATAL_IF(!mInputFilterRust->isEnabled(&result).isOk());
    return result;
}

void InputFilter::dump(std::string& dump) {
    dump += "InputFilter:\n";
}

} // namespace android
