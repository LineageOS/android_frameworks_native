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
using aidl::com::android::server::inputflinger::KeyEventAction;
using AidlDeviceInfo = aidl::com::android::server::inputflinger::DeviceInfo;
using aidl::android::hardware::input::common::Source;

AidlKeyEvent notifyKeyArgsToKeyEvent(const NotifyKeyArgs& args) {
    AidlKeyEvent event;
    event.id = args.id;
    event.eventTime = args.eventTime;
    event.deviceId = args.deviceId;
    event.source = static_cast<Source>(args.source);
    event.displayId = args.displayId;
    event.policyFlags = args.policyFlags;
    event.action = static_cast<KeyEventAction>(args.action);
    event.flags = args.flags;
    event.keyCode = args.keyCode;
    event.scanCode = args.scanCode;
    event.metaState = args.metaState;
    event.downTime = args.downTime;
    event.readTime = args.readTime;
    return event;
}

InputFilter::InputFilter(InputListenerInterface& listener, IInputFlingerRust& rust,
                         InputFilterPolicyInterface& policy)
      : mNextListener(listener),
        mCallbacks(ndk::SharedRefBase::make<InputFilterCallbacks>(listener, policy)),
        mPolicy(policy) {
    LOG_ALWAYS_FATAL_IF(!rust.createInputFilter(mCallbacks, &mInputFilterRust).isOk());
    LOG_ALWAYS_FATAL_IF(!mInputFilterRust);
}

void InputFilter::notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) {
    mDeviceInfos.clear();
    mDeviceInfos.reserve(args.inputDeviceInfos.size());
    for (auto info : args.inputDeviceInfos) {
        AidlDeviceInfo& aidlInfo = mDeviceInfos.emplace_back();
        aidlInfo.deviceId = info.getId();
        aidlInfo.external = info.isExternal();
    }
    if (isFilterEnabled()) {
        LOG_ALWAYS_FATAL_IF(!mInputFilterRust->notifyInputDevicesChanged(mDeviceInfos).isOk());
    }
    mNextListener.notify(args);
}

void InputFilter::notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) {
    mNextListener.notify(args);
}

void InputFilter::notifyKey(const NotifyKeyArgs& args) {
    if (isFilterEnabled()) {
        LOG_ALWAYS_FATAL_IF(!mInputFilterRust->notifyKey(notifyKeyArgsToKeyEvent(args)).isOk());
        return;
    }
    mNextListener.notify(args);
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

void InputFilter::setAccessibilityBounceKeysThreshold(nsecs_t threshold) {
    std::scoped_lock _l(mLock);

    if (mConfig.bounceKeysThresholdNs != threshold) {
        mConfig.bounceKeysThresholdNs = threshold;
        notifyConfigurationChangedLocked();
    }
}

void InputFilter::setAccessibilitySlowKeysThreshold(nsecs_t threshold) {
    std::scoped_lock _l(mLock);

    if (mConfig.slowKeysThresholdNs != threshold) {
        mConfig.slowKeysThresholdNs = threshold;
        notifyConfigurationChangedLocked();
    }
}

void InputFilter::setAccessibilityStickyKeysEnabled(bool enabled) {
    std::scoped_lock _l(mLock);

    if (mConfig.stickyKeysEnabled != enabled) {
        mConfig.stickyKeysEnabled = enabled;
        notifyConfigurationChangedLocked();
        if (!enabled) {
            // When Sticky keys is disabled, send callback to clear any saved sticky state.
            mPolicy.notifyStickyModifierStateChanged(0, 0);
        }
    }
}

void InputFilter::notifyConfigurationChangedLocked() {
    LOG_ALWAYS_FATAL_IF(!mInputFilterRust->notifyConfigurationChanged(mConfig).isOk());
    if (isFilterEnabled()) {
        LOG_ALWAYS_FATAL_IF(!mInputFilterRust->notifyInputDevicesChanged(mDeviceInfos).isOk());
    }
}

void InputFilter::dump(std::string& dump) {
    dump += "InputFilter:\n";
}

} // namespace android
