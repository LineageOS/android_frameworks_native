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

#ifndef _UI_TEST_INPUT_LISTENER_H
#define _UI_TEST_INPUT_LISTENER_H

#include <android-base/thread_annotations.h>
#include <gtest/gtest.h>
#include "InputListener.h"

using std::chrono_literals::operator""ms;

namespace android {

// --- TestInputListener ---

class TestInputListener : public InputListenerInterface {
protected:
    virtual ~TestInputListener();

public:
    TestInputListener(std::chrono::milliseconds eventHappenedTimeout = 0ms,
                      std::chrono::milliseconds eventDidNotHappenTimeout = 0ms);

    void assertNotifyConfigurationChangedWasCalled(
            NotifyConfigurationChangedArgs* outEventArgs = nullptr);

    void assertNotifyConfigurationChangedWasNotCalled();

    void assertNotifyDeviceResetWasCalled(NotifyDeviceResetArgs* outEventArgs = nullptr);

    void assertNotifyDeviceResetWasNotCalled();

    void assertNotifyKeyWasCalled(NotifyKeyArgs* outEventArgs = nullptr);

    void assertNotifyKeyWasNotCalled();

    void assertNotifyMotionWasCalled(NotifyMotionArgs* outEventArgs = nullptr);

    void assertNotifyMotionWasNotCalled();

    void assertNotifySwitchWasCalled(NotifySwitchArgs* outEventArgs = nullptr);

private:
    template <class NotifyArgsType>
    void assertCalled(NotifyArgsType* outEventArgs, std::string message);

    template <class NotifyArgsType>
    void assertNotCalled(std::string message);

    template <class NotifyArgsType>
    void notify(const NotifyArgsType* args);

    virtual void notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) override;

    virtual void notifyDeviceReset(const NotifyDeviceResetArgs* args) override;

    virtual void notifyKey(const NotifyKeyArgs* args) override;

    virtual void notifyMotion(const NotifyMotionArgs* args) override;

    virtual void notifySwitch(const NotifySwitchArgs* args) override;

    std::mutex mLock;
    std::condition_variable mCondition;
    const std::chrono::milliseconds mEventHappenedTimeout;
    const std::chrono::milliseconds mEventDidNotHappenTimeout;

    std::tuple<std::vector<NotifyConfigurationChangedArgs>, //
               std::vector<NotifyDeviceResetArgs>,          //
               std::vector<NotifyKeyArgs>,                  //
               std::vector<NotifyMotionArgs>,               //
               std::vector<NotifySwitchArgs>>               //
            mQueues GUARDED_BY(mLock);
};

} // namespace android
#endif
