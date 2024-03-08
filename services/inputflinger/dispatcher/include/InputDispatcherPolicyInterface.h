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

#pragma once

#include "InputDispatcherConfiguration.h"

#include <android-base/properties.h>
#include <binder/IBinder.h>
#include <gui/InputApplication.h>
#include <gui/PidUid.h>
#include <input/Input.h>
#include <input/InputDevice.h>
#include <utils/RefBase.h>
#include <set>

namespace android {

/*
 * Input dispatcher policy interface.
 *
 * The input dispatcher policy is used by the input dispatcher to interact with the Window Manager
 * and other system components.
 *
 * The actual implementation is partially supported by callbacks into the DVM
 * via JNI.  This interface is also mocked in the unit tests.
 */
class InputDispatcherPolicyInterface {
public:
    InputDispatcherPolicyInterface() = default;
    virtual ~InputDispatcherPolicyInterface() = default;

    /* Notifies the system that a configuration change has occurred. */
    virtual void notifyConfigurationChanged(nsecs_t when) = 0;

    /* Notifies the system that an application does not have a focused window.
     */
    virtual void notifyNoFocusedWindowAnr(
            const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle) = 0;

    /* Notifies the system that a window just became unresponsive. This indicates that ANR
     * should be raised for this window. The window can be identified via its input token and the
     * pid of the owner. The string reason contains information about the input event that we
     * haven't received a response for.
     */
    virtual void notifyWindowUnresponsive(const sp<IBinder>& token, std::optional<gui::Pid> pid,
                                          const std::string& reason) = 0;

    /* Notifies the system that a window just became responsive. This is only called after the
     * window was first marked "unresponsive". This indicates that ANR dialog (if any) should
     * no longer should be shown to the user. The window is eligible to cause a new ANR in the
     * future.
     */
    virtual void notifyWindowResponsive(const sp<IBinder>& token, std::optional<gui::Pid> pid) = 0;

    /* Notifies the system that an input channel is unrecoverably broken. */
    virtual void notifyInputChannelBroken(const sp<IBinder>& token) = 0;
    virtual void notifyFocusChanged(const sp<IBinder>& oldToken, const sp<IBinder>& newToken) = 0;
    virtual void notifySensorEvent(int32_t deviceId, InputDeviceSensorType sensorType,
                                   InputDeviceSensorAccuracy accuracy, nsecs_t timestamp,
                                   const std::vector<float>& values) = 0;
    virtual void notifySensorAccuracy(int32_t deviceId, InputDeviceSensorType sensorType,
                                      InputDeviceSensorAccuracy accuracy) = 0;
    virtual void notifyVibratorState(int32_t deviceId, bool isOn) = 0;

    /* Filters an input event.
     * Return true to dispatch the event unmodified, false to consume the event.
     * A filter can also transform and inject events later by passing POLICY_FLAG_FILTERED
     * to injectInputEvent.
     */
    virtual bool filterInputEvent(const InputEvent& inputEvent, uint32_t policyFlags) = 0;

    /* Intercepts a key event immediately before queueing it.
     * The policy can use this method as an opportunity to perform power management functions
     * and early event preprocessing such as updating policy flags.
     *
     * This method is expected to set the POLICY_FLAG_PASS_TO_USER policy flag if the event
     * should be dispatched to applications.
     */
    virtual void interceptKeyBeforeQueueing(const KeyEvent& keyEvent, uint32_t& policyFlags) = 0;

    /* Intercepts a touch, trackball or other motion event before queueing it.
     * The policy can use this method as an opportunity to perform power management functions
     * and early event preprocessing such as updating policy flags.
     *
     * This method is expected to set the POLICY_FLAG_PASS_TO_USER policy flag if the event
     * should be dispatched to applications.
     */
    virtual void interceptMotionBeforeQueueing(int32_t displayId, nsecs_t when,
                                               uint32_t& policyFlags) = 0;

    /* Allows the policy a chance to intercept a key before dispatching. */
    virtual nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>& token,
                                                  const KeyEvent& keyEvent,
                                                  uint32_t policyFlags) = 0;

    /* Allows the policy a chance to perform default processing for an unhandled key.
     * Returns an alternate key event to redispatch as a fallback, if needed. */
    virtual std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>& token,
                                                         const KeyEvent& keyEvent,
                                                         uint32_t policyFlags) = 0;

    /* Notifies the policy about switch events.
     */
    virtual void notifySwitch(nsecs_t when, uint32_t switchValues, uint32_t switchMask,
                              uint32_t policyFlags) = 0;

    /* Poke user activity for an event dispatched to a window. */
    virtual void pokeUserActivity(nsecs_t eventTime, int32_t eventType, int32_t displayId,
                                  int32_t keyCode) = 0;

    /*
     * Return true if the provided event is stale, and false otherwise. Used for determining
     * whether the dispatcher should drop the event.
     */
    virtual bool isStaleEvent(nsecs_t currentTime, nsecs_t eventTime) {
        static const std::chrono::duration STALE_EVENT_TIMEOUT =
                std::chrono::seconds(10) * android::base::HwTimeoutMultiplier();
        return std::chrono::nanoseconds(currentTime - eventTime) >= STALE_EVENT_TIMEOUT;
    }

    /* Notifies the policy that a pointer down event has occurred outside the current focused
     * window.
     *
     * The touchedToken passed as an argument is the window that received the input event.
     */
    virtual void onPointerDownOutsideFocus(const sp<IBinder>& touchedToken) = 0;

    /* Change the Pointer Capture state in InputReader.
     *
     * InputDispatcher is solely responsible for updating the Pointer Capture state.
     */
    virtual void setPointerCapture(const PointerCaptureRequest&) = 0;

    /* Notifies the policy that the drag window has moved over to another window */
    virtual void notifyDropWindow(const sp<IBinder>& token, float x, float y) = 0;

    /* Notifies the policy that there was an input device interaction with apps. */
    virtual void notifyDeviceInteraction(DeviceId deviceId, nsecs_t timestamp,
                                         const std::set<gui::Uid>& uids) = 0;
};

} // namespace android
