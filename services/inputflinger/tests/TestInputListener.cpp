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

#include "TestInputListener.h"

#include <gtest/gtest.h>

namespace android {

// --- TestInputListener ---

TestInputListener::TestInputListener(std::chrono::milliseconds eventHappenedTimeout,
                                     std::chrono::milliseconds eventDidNotHappenTimeout)
      : mEventHappenedTimeout(eventHappenedTimeout),
        mEventDidNotHappenTimeout(eventDidNotHappenTimeout) {}

TestInputListener::~TestInputListener() {}

void TestInputListener::assertNotifyInputDevicesChangedWasCalled(
        NotifyInputDevicesChangedArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifyInputDevicesChangedArgs>(outEventArgs,
                                                        "Expected notifyInputDevicesChanged() "
                                                        "to have been called."));
}

void TestInputListener::assertNotifyConfigurationChangedWasCalled(
        NotifyConfigurationChangedArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifyConfigurationChangedArgs>(outEventArgs,
                                                         "Expected notifyConfigurationChanged() "
                                                         "to have been called."));
}

void TestInputListener::assertNotifyConfigurationChangedWasNotCalled() {
    ASSERT_NO_FATAL_FAILURE(assertNotCalled<NotifyConfigurationChangedArgs>(
            "notifyConfigurationChanged() should not be called."));
}

void TestInputListener::assertNotifyDeviceResetWasCalled(NotifyDeviceResetArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<
                    NotifyDeviceResetArgs>(outEventArgs,
                                           "Expected notifyDeviceReset() to have been called."));
}

void TestInputListener::assertNotifyDeviceResetWasNotCalled() {
    ASSERT_NO_FATAL_FAILURE(
            assertNotCalled<NotifyDeviceResetArgs>("notifyDeviceReset() should not be called."));
}

void TestInputListener::assertNotifyKeyWasCalled(NotifyKeyArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifyKeyArgs>(outEventArgs, "Expected notifyKey() to have been called."));
}

void TestInputListener::assertNotifyKeyWasCalled(const ::testing::Matcher<NotifyKeyArgs>& matcher) {
    NotifyKeyArgs outEventArgs;
    ASSERT_NO_FATAL_FAILURE(assertNotifyKeyWasCalled(&outEventArgs));
    ASSERT_THAT(outEventArgs, matcher);
}

void TestInputListener::assertNotifyKeyWasNotCalled() {
    ASSERT_NO_FATAL_FAILURE(assertNotCalled<NotifyKeyArgs>("notifyKey() should not be called."));
}

void TestInputListener::assertNotifyMotionWasCalled(NotifyMotionArgs* outEventArgs,
                                                    std::optional<TimePoint> waitUntil) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifyMotionArgs>(outEventArgs,
                                           "Expected notifyMotion() to have been called.",
                                           waitUntil));
}

void TestInputListener::assertNotifyMotionWasCalled(
        const ::testing::Matcher<NotifyMotionArgs>& matcher, std::optional<TimePoint> waitUntil) {
    NotifyMotionArgs outEventArgs;
    ASSERT_NO_FATAL_FAILURE(assertNotifyMotionWasCalled(&outEventArgs, waitUntil));
    ASSERT_THAT(outEventArgs, matcher);
}

void TestInputListener::assertNotifyMotionWasNotCalled(std::optional<TimePoint> waitUntil) {
    ASSERT_NO_FATAL_FAILURE(
            assertNotCalled<NotifyMotionArgs>("notifyMotion() should not be called.", waitUntil));
}

void TestInputListener::assertNotifySwitchWasCalled(NotifySwitchArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifySwitchArgs>(outEventArgs,
                                           "Expected notifySwitch() to have been called."));
}

void TestInputListener::assertNotifySensorWasCalled(NotifySensorArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifySensorArgs>(outEventArgs,
                                           "Expected notifySensor() to have been called."));
}

void TestInputListener::assertNotifyVibratorStateWasCalled(NotifyVibratorStateArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(assertCalled<NotifyVibratorStateArgs>(outEventArgs,
                                                                  "Expected notifyVibratorState() "
                                                                  "to have been called."));
}

void TestInputListener::assertNotifyCaptureWasCalled(
        NotifyPointerCaptureChangedArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifyPointerCaptureChangedArgs>(outEventArgs,
                                                          "Expected notifyPointerCaptureChanged() "
                                                          "to have been called."));
}

void TestInputListener::assertNotifyCaptureWasNotCalled() {
    ASSERT_NO_FATAL_FAILURE(assertNotCalled<NotifyPointerCaptureChangedArgs>(
            "notifyPointerCaptureChanged() should not be called."));
}

template <class NotifyArgsType>
void TestInputListener::assertCalled(NotifyArgsType* outEventArgs, std::string message,
                                     std::optional<TimePoint> waitUntil) {
    std::unique_lock<std::mutex> lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::vector<NotifyArgsType>& queue = std::get<std::vector<NotifyArgsType>>(mQueues);
    if (queue.empty()) {
        const auto time =
                waitUntil.value_or(std::chrono::system_clock::now() + mEventHappenedTimeout);
        const bool eventReceived = mCondition.wait_until(lock, time, [&queue]() REQUIRES(mLock) {
            return !queue.empty();
        });
        if (!eventReceived) {
            FAIL() << "Timed out waiting for event: " << message.c_str();
        }
    }
    if (outEventArgs) {
        *outEventArgs = *queue.begin();
    }
    queue.erase(queue.begin());
}

template <class NotifyArgsType>
void TestInputListener::assertNotCalled(std::string message, std::optional<TimePoint> waitUntil) {
    std::unique_lock<std::mutex> lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::vector<NotifyArgsType>& queue = std::get<std::vector<NotifyArgsType>>(mQueues);
    const auto time =
            waitUntil.value_or(std::chrono::system_clock::now() + mEventDidNotHappenTimeout);
    const bool eventReceived = mCondition.wait_until(lock, time, [&queue]() REQUIRES(mLock) {
        return !queue.empty();
    });
    if (eventReceived) {
        FAIL() << "Unexpected event: " << message.c_str();
    }
}

template <class NotifyArgsType>
void TestInputListener::addToQueue(const NotifyArgsType& args) {
    std::scoped_lock<std::mutex> lock(mLock);

    std::vector<NotifyArgsType>& queue = std::get<std::vector<NotifyArgsType>>(mQueues);
    queue.push_back(args);
    mCondition.notify_all();
}

void TestInputListener::notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) {
    addToQueue<NotifyInputDevicesChangedArgs>(args);
}

void TestInputListener::notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) {
    addToQueue<NotifyConfigurationChangedArgs>(args);
}

void TestInputListener::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    addToQueue<NotifyDeviceResetArgs>(args);
}

void TestInputListener::notifyKey(const NotifyKeyArgs& args) {
    addToQueue<NotifyKeyArgs>(args);
}

void TestInputListener::notifyMotion(const NotifyMotionArgs& args) {
    addToQueue<NotifyMotionArgs>(args);
}

void TestInputListener::notifySwitch(const NotifySwitchArgs& args) {
    addToQueue<NotifySwitchArgs>(args);
}

void TestInputListener::notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) {
    addToQueue<NotifyPointerCaptureChangedArgs>(args);
}

void TestInputListener::notifySensor(const NotifySensorArgs& args) {
    addToQueue<NotifySensorArgs>(args);
}

void TestInputListener::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    addToQueue<NotifyVibratorStateArgs>(args);
}

} // namespace android
