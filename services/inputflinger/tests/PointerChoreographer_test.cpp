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

#include "../PointerChoreographer.h"

#include <gtest/gtest.h>
#include <vector>

#include "TestInputListener.h"

namespace android {

// Helpers to std::visit with lambdas.
template <typename... V>
struct Visitor : V... {};
template <typename... V>
Visitor(V...) -> Visitor<V...>;

// --- PointerChoreographerTest ---

class PointerChoreographerTest : public testing::Test, public PointerChoreographerPolicyInterface {
protected:
    TestInputListener mTestListener;
    PointerChoreographer mChoreographer{mTestListener, *this};

    std::shared_ptr<PointerControllerInterface> createPointerController() { return {}; }
};

TEST_F(PointerChoreographerTest, ForwardsArgsToInnerListener) {
    const std::vector<NotifyArgs> allArgs{NotifyInputDevicesChangedArgs{},
                                          NotifyConfigurationChangedArgs{},
                                          NotifyKeyArgs{},
                                          NotifyMotionArgs{},
                                          NotifySensorArgs{},
                                          NotifySwitchArgs{},
                                          NotifyDeviceResetArgs{},
                                          NotifyPointerCaptureChangedArgs{},
                                          NotifyVibratorStateArgs{}};

    for (auto notifyArgs : allArgs) {
        mChoreographer.notify(notifyArgs);
        EXPECT_NO_FATAL_FAILURE(
                std::visit(Visitor{
                                   [&](const NotifyInputDevicesChangedArgs& args) {
                                       mTestListener.assertNotifyInputDevicesChangedWasCalled();
                                   },
                                   [&](const NotifyConfigurationChangedArgs& args) {
                                       mTestListener.assertNotifyConfigurationChangedWasCalled();
                                   },
                                   [&](const NotifyKeyArgs& args) {
                                       mTestListener.assertNotifyKeyWasCalled();
                                   },
                                   [&](const NotifyMotionArgs& args) {
                                       mTestListener.assertNotifyMotionWasCalled();
                                   },
                                   [&](const NotifySensorArgs& args) {
                                       mTestListener.assertNotifySensorWasCalled();
                                   },
                                   [&](const NotifySwitchArgs& args) {
                                       mTestListener.assertNotifySwitchWasCalled();
                                   },
                                   [&](const NotifyDeviceResetArgs& args) {
                                       mTestListener.assertNotifyDeviceResetWasCalled();
                                   },
                                   [&](const NotifyPointerCaptureChangedArgs& args) {
                                       mTestListener.assertNotifyCaptureWasCalled();
                                   },
                                   [&](const NotifyVibratorStateArgs& args) {
                                       mTestListener.assertNotifyVibratorStateWasCalled();
                                   },
                           },
                           notifyArgs));
    }
}

} // namespace android
