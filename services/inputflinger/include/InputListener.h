/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <vector>

#include <input/Input.h>
#include <input/InputDevice.h>
#include <input/TouchVideoFrame.h>
#include "NotifyArgs.h"

namespace android {

std::list<NotifyArgs>& operator+=(std::list<NotifyArgs>& keep, std::list<NotifyArgs>&& consume);

/*
 * The interface used by the InputReader to notify the InputListener about input events.
 */
class InputListenerInterface {
public:
    InputListenerInterface() { }
    InputListenerInterface(const InputListenerInterface&) = delete;
    InputListenerInterface& operator=(const InputListenerInterface&) = delete;
    virtual ~InputListenerInterface() { }

    virtual void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) = 0;
    virtual void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) = 0;
    virtual void notifyKey(const NotifyKeyArgs& args) = 0;
    virtual void notifyMotion(const NotifyMotionArgs& args) = 0;
    virtual void notifySwitch(const NotifySwitchArgs& args) = 0;
    virtual void notifySensor(const NotifySensorArgs& args) = 0;
    virtual void notifyVibratorState(const NotifyVibratorStateArgs& args) = 0;
    virtual void notifyDeviceReset(const NotifyDeviceResetArgs& args) = 0;
    virtual void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) = 0;

    void notify(const NotifyArgs& args);
};

/*
 * An implementation of the listener interface that queues up and defers dispatch
 * of decoded events until flushed.
 */
class QueuedInputListener : public InputListenerInterface {

public:
    explicit QueuedInputListener(InputListenerInterface& innerListener);

    virtual void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) override;
    virtual void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) override;
    virtual void notifyKey(const NotifyKeyArgs& args) override;
    virtual void notifyMotion(const NotifyMotionArgs& args) override;
    virtual void notifySwitch(const NotifySwitchArgs& args) override;
    virtual void notifySensor(const NotifySensorArgs& args) override;
    virtual void notifyDeviceReset(const NotifyDeviceResetArgs& args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs& args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) override;

    void flush();

private:
    InputListenerInterface& mInnerListener;
    std::vector<NotifyArgs> mArgsQueue;
};

} // namespace android
