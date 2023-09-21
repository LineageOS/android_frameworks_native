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

#include "InputListener.h"
#include "NotifyArgs.h"
#include "PointerChoreographerPolicyInterface.h"

namespace android {

/**
 * PointerChoreographer manages the icons shown by the system for input interactions.
 * This includes showing the mouse cursor, stylus hover icons, and touch spots.
 * It is responsible for accumulating the location of the mouse cursor, and populating
 * the cursor position for incoming events, if necessary.
 */
class PointerChoreographerInterface : public InputListenerInterface {
public:
    /**
     * This method may be called on any thread (usually by the input manager on a binder thread).
     */
    virtual void dump(std::string& dump) = 0;
};

class PointerChoreographer : public PointerChoreographerInterface {
public:
    explicit PointerChoreographer(InputListenerInterface& listener,
                                  PointerChoreographerPolicyInterface&);
    ~PointerChoreographer() override = default;

    void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) override;
    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) override;
    void notifyKey(const NotifyKeyArgs& args) override;
    void notifyMotion(const NotifyMotionArgs& args) override;
    void notifySwitch(const NotifySwitchArgs& args) override;
    void notifySensor(const NotifySensorArgs& args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs& args) override;
    void notifyDeviceReset(const NotifyDeviceResetArgs& args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) override;

    void dump(std::string& dump) override;

private:
    InputListenerInterface& mNextListener;
};

} // namespace android
