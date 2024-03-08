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

#include <android-base/thread_annotations.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "InputListener.h"

using std::chrono_literals::operator""ms;

namespace android {

// --- TestInputListener ---

class TestInputListener : public InputListenerInterface {
public:
    TestInputListener(std::chrono::milliseconds eventHappenedTimeout = 0ms,
                      std::chrono::milliseconds eventDidNotHappenTimeout = 0ms);
    virtual ~TestInputListener();

    using TimePoint = std::chrono::time_point<std::chrono::system_clock>;

    void assertNotifyInputDevicesChangedWasCalled(
            NotifyInputDevicesChangedArgs* outEventArgs = nullptr);

    void assertNotifyConfigurationChangedWasCalled(
            NotifyConfigurationChangedArgs* outEventArgs = nullptr);

    void assertNotifyConfigurationChangedWasNotCalled();

    void clearNotifyDeviceResetCalls();

    void assertNotifyDeviceResetWasCalled(const ::testing::Matcher<NotifyDeviceResetArgs>& matcher);

    void assertNotifyDeviceResetWasCalled(NotifyDeviceResetArgs* outEventArgs = nullptr);

    void assertNotifyDeviceResetWasNotCalled();

    void assertNotifyKeyWasCalled(NotifyKeyArgs* outEventArgs = nullptr);

    void assertNotifyKeyWasCalled(const ::testing::Matcher<NotifyKeyArgs>& matcher);

    void assertNotifyKeyWasNotCalled();

    void assertNotifyMotionWasCalled(NotifyMotionArgs* outEventArgs = nullptr,
                                     std::optional<TimePoint> waitUntil = {});

    void assertNotifyMotionWasCalled(const ::testing::Matcher<NotifyMotionArgs>& matcher,
                                     std::optional<TimePoint> waitUntil = {});

    void assertNotifyMotionWasNotCalled(std::optional<TimePoint> waitUntil = {});

    void assertNotifySwitchWasCalled(NotifySwitchArgs* outEventArgs = nullptr);

    void assertNotifyCaptureWasCalled(NotifyPointerCaptureChangedArgs* outEventArgs = nullptr);
    void assertNotifyCaptureWasNotCalled();
    void assertNotifySensorWasCalled(NotifySensorArgs* outEventArgs = nullptr);
    void assertNotifyVibratorStateWasCalled(NotifyVibratorStateArgs* outEventArgs = nullptr);

private:
    template <class NotifyArgsType>
    void assertCalled(NotifyArgsType* outEventArgs, std::string message,
                      std::optional<TimePoint> waitUntil = {});

    template <class NotifyArgsType>
    void assertNotCalled(std::string message, std::optional<TimePoint> timeout = {});

    template <class NotifyArgsType>
    void addToQueue(const NotifyArgsType& args);

    virtual void notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) override;

    virtual void notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) override;

    virtual void notifyDeviceReset(const NotifyDeviceResetArgs& args) override;

    virtual void notifyKey(const NotifyKeyArgs& args) override;

    virtual void notifyMotion(const NotifyMotionArgs& args) override;

    virtual void notifySwitch(const NotifySwitchArgs& args) override;

    virtual void notifySensor(const NotifySensorArgs& args) override;

    virtual void notifyVibratorState(const NotifyVibratorStateArgs& args) override;

    virtual void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) override;

    std::mutex mLock;
    std::condition_variable mCondition;
    const std::chrono::milliseconds mEventHappenedTimeout;
    const std::chrono::milliseconds mEventDidNotHappenTimeout;

    std::tuple<std::vector<NotifyInputDevicesChangedArgs>,   //
               std::vector<NotifyConfigurationChangedArgs>,  //
               std::vector<NotifyDeviceResetArgs>,           //
               std::vector<NotifyKeyArgs>,                   //
               std::vector<NotifyMotionArgs>,                //
               std::vector<NotifySwitchArgs>,                //
               std::vector<NotifySensorArgs>,                //
               std::vector<NotifyVibratorStateArgs>,         //
               std::vector<NotifyPointerCaptureChangedArgs>> //
            mQueues GUARDED_BY(mLock);
};

} // namespace android
