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

#include <aidl/com/android/server/inputflinger/IInputFlingerRust.h>
#include <utils/Mutex.h>
#include "InputListener.h"
#include "NotifyArgs.h"

namespace android {

/**
 * The C++ component of InputFilter designed as a wrapper around the rust implementation.
 */
class InputFilterInterface : public InputListenerInterface {
public:
    /**
     * This method may be called on any thread (usually by the input manager on a binder thread).
     */
    virtual void dump(std::string& dump) = 0;
    virtual void setAccessibilityBounceKeysThreshold(nsecs_t threshold) = 0;
};

class InputFilter : public InputFilterInterface {
public:
    using IInputFlingerRust = aidl::com::android::server::inputflinger::IInputFlingerRust;
    using IInputFilter = aidl::com::android::server::inputflinger::IInputFilter;
    using IInputFilterCallbacks =
            aidl::com::android::server::inputflinger::IInputFilter::IInputFilterCallbacks;
    using InputFilterConfiguration =
            aidl::com::android::server::inputflinger::InputFilterConfiguration;

    explicit InputFilter(InputListenerInterface& listener, IInputFlingerRust&);
    ~InputFilter() override = default;
    void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) override;
    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) override;
    void notifyKey(const NotifyKeyArgs& args) override;
    void notifyMotion(const NotifyMotionArgs& args) override;
    void notifySwitch(const NotifySwitchArgs& args) override;
    void notifySensor(const NotifySensorArgs& args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs& args) override;
    void notifyDeviceReset(const NotifyDeviceResetArgs& args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) override;
    void setAccessibilityBounceKeysThreshold(nsecs_t threshold) override;
    void dump(std::string& dump) override;

private:
    InputListenerInterface& mNextListener;
    std::shared_ptr<IInputFilterCallbacks> mCallbacks;
    std::shared_ptr<IInputFilter> mInputFilterRust;
    mutable std::mutex mLock;
    InputFilterConfiguration mConfig GUARDED_BY(mLock);

    bool isFilterEnabled();
};

} // namespace android
