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

void TestInputListener::assertNotifyKeyWasNotCalled() {
    ASSERT_NO_FATAL_FAILURE(assertNotCalled<NotifyKeyArgs>("notifyKey() should not be called."));
}

void TestInputListener::assertNotifyMotionWasCalled(NotifyMotionArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifyMotionArgs>(outEventArgs,
                                           "Expected notifyMotion() to have been called."));
}

void TestInputListener::assertNotifyMotionWasNotCalled() {
    ASSERT_NO_FATAL_FAILURE(
            assertNotCalled<NotifyMotionArgs>("notifyMotion() should not be called."));
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

void TestInputListener::assertNotifyCaptureWasCalled(
        NotifyPointerCaptureChangedArgs* outEventArgs) {
    ASSERT_NO_FATAL_FAILURE(
            assertCalled<NotifyPointerCaptureChangedArgs>(outEventArgs,
                                                          "Expected notifyPointerCaptureChanged() "
                                                          "to have been called."));
}

template <class NotifyArgsType>
void TestInputListener::assertCalled(NotifyArgsType* outEventArgs, std::string message) {
    std::unique_lock<std::mutex> lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::vector<NotifyArgsType>& queue = std::get<std::vector<NotifyArgsType>>(mQueues);
    if (queue.empty()) {
        const bool eventReceived =
                mCondition.wait_for(lock, mEventHappenedTimeout,
                                    [&queue]() REQUIRES(mLock) { return !queue.empty(); });
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
void TestInputListener::assertNotCalled(std::string message) {
    std::unique_lock<std::mutex> lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::vector<NotifyArgsType>& queue = std::get<std::vector<NotifyArgsType>>(mQueues);
    const bool eventReceived =
            mCondition.wait_for(lock, mEventDidNotHappenTimeout,
                                [&queue]() REQUIRES(mLock) { return !queue.empty(); });
    if (eventReceived) {
        FAIL() << "Unexpected event: " << message.c_str();
    }
}

template <class NotifyArgsType>
void TestInputListener::notify(const NotifyArgsType* args) {
    std::scoped_lock<std::mutex> lock(mLock);

    std::vector<NotifyArgsType>& queue = std::get<std::vector<NotifyArgsType>>(mQueues);
    queue.push_back(*args);
    mCondition.notify_all();
}

void TestInputListener::notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) {
    notify<NotifyConfigurationChangedArgs>(args);
}

void TestInputListener::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
    notify<NotifyDeviceResetArgs>(args);
}

void TestInputListener::notifyKey(const NotifyKeyArgs* args) {
    notify<NotifyKeyArgs>(args);
}

void TestInputListener::notifyMotion(const NotifyMotionArgs* args) {
    notify<NotifyMotionArgs>(args);
}

void TestInputListener::notifySwitch(const NotifySwitchArgs* args) {
    notify<NotifySwitchArgs>(args);
}

void TestInputListener::notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) {
    notify<NotifyPointerCaptureChangedArgs>(args);
}

void TestInputListener::notifySensor(const NotifySensorArgs* args) {
    notify<NotifySensorArgs>(args);
}

} // namespace android
