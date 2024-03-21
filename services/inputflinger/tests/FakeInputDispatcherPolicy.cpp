/*
 * Copyright 2024 The Android Open Source Project
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

#include "FakeInputDispatcherPolicy.h"

#include <gtest/gtest.h>

namespace android {

// --- FakeInputDispatcherPolicy ---

void FakeInputDispatcherPolicy::assertFilterInputEventWasCalled(const NotifyKeyArgs& args) {
    assertFilterInputEventWasCalledInternal([&args](const InputEvent& event) {
        ASSERT_EQ(event.getType(), InputEventType::KEY);
        EXPECT_EQ(event.getDisplayId(), args.displayId);

        const auto& keyEvent = static_cast<const KeyEvent&>(event);
        EXPECT_EQ(keyEvent.getEventTime(), args.eventTime);
        EXPECT_EQ(keyEvent.getAction(), args.action);
    });
}

void FakeInputDispatcherPolicy::assertFilterInputEventWasCalled(const NotifyMotionArgs& args,
                                                                vec2 point) {
    assertFilterInputEventWasCalledInternal([&](const InputEvent& event) {
        ASSERT_EQ(event.getType(), InputEventType::MOTION);
        EXPECT_EQ(event.getDisplayId(), args.displayId);

        const auto& motionEvent = static_cast<const MotionEvent&>(event);
        EXPECT_EQ(motionEvent.getEventTime(), args.eventTime);
        EXPECT_EQ(motionEvent.getAction(), args.action);
        EXPECT_NEAR(motionEvent.getX(0), point.x, MotionEvent::ROUNDING_PRECISION);
        EXPECT_NEAR(motionEvent.getY(0), point.y, MotionEvent::ROUNDING_PRECISION);
        EXPECT_NEAR(motionEvent.getRawX(0), point.x, MotionEvent::ROUNDING_PRECISION);
        EXPECT_NEAR(motionEvent.getRawY(0), point.y, MotionEvent::ROUNDING_PRECISION);
    });
}

void FakeInputDispatcherPolicy::assertFilterInputEventWasNotCalled() {
    std::scoped_lock lock(mLock);
    ASSERT_EQ(nullptr, mFilteredEvent);
}

void FakeInputDispatcherPolicy::assertNotifyConfigurationChangedWasCalled(nsecs_t when) {
    std::scoped_lock lock(mLock);
    ASSERT_TRUE(mConfigurationChangedTime) << "Timed out waiting for configuration changed call";
    ASSERT_EQ(*mConfigurationChangedTime, when);
    mConfigurationChangedTime = std::nullopt;
}

void FakeInputDispatcherPolicy::assertNotifySwitchWasCalled(const NotifySwitchArgs& args) {
    std::scoped_lock lock(mLock);
    ASSERT_TRUE(mLastNotifySwitch);
    // We do not check id because it is not exposed to the policy
    EXPECT_EQ(args.eventTime, mLastNotifySwitch->eventTime);
    EXPECT_EQ(args.policyFlags, mLastNotifySwitch->policyFlags);
    EXPECT_EQ(args.switchValues, mLastNotifySwitch->switchValues);
    EXPECT_EQ(args.switchMask, mLastNotifySwitch->switchMask);
    mLastNotifySwitch = std::nullopt;
}

void FakeInputDispatcherPolicy::assertOnPointerDownEquals(const sp<IBinder>& touchedToken) {
    std::scoped_lock lock(mLock);
    ASSERT_EQ(touchedToken, mOnPointerDownToken);
    mOnPointerDownToken.clear();
}

void FakeInputDispatcherPolicy::assertOnPointerDownWasNotCalled() {
    std::scoped_lock lock(mLock);
    ASSERT_TRUE(mOnPointerDownToken == nullptr)
            << "Expected onPointerDownOutsideFocus to not have been called";
}

void FakeInputDispatcherPolicy::assertNotifyNoFocusedWindowAnrWasCalled(
        std::chrono::nanoseconds timeout,
        const std::shared_ptr<InputApplicationHandle>& expectedApplication) {
    std::unique_lock lock(mLock);
    android::base::ScopedLockAssertion assumeLocked(mLock);
    std::shared_ptr<InputApplicationHandle> application;
    ASSERT_NO_FATAL_FAILURE(
            application = getAnrTokenLockedInterruptible(timeout, mAnrApplications, lock));
    ASSERT_EQ(expectedApplication, application);
}

void FakeInputDispatcherPolicy::assertNotifyWindowUnresponsiveWasCalled(
        std::chrono::nanoseconds timeout, const sp<gui::WindowInfoHandle>& window) {
    LOG_ALWAYS_FATAL_IF(window == nullptr, "window should not be null");
    assertNotifyWindowUnresponsiveWasCalled(timeout, window->getToken(),
                                            window->getInfo()->ownerPid);
}

void FakeInputDispatcherPolicy::assertNotifyWindowUnresponsiveWasCalled(
        std::chrono::nanoseconds timeout, const sp<IBinder>& expectedToken,
        std::optional<gui::Pid> expectedPid) {
    std::unique_lock lock(mLock);
    android::base::ScopedLockAssertion assumeLocked(mLock);
    AnrResult result;
    ASSERT_NO_FATAL_FAILURE(result = getAnrTokenLockedInterruptible(timeout, mAnrWindows, lock));
    ASSERT_EQ(expectedToken, result.token);
    ASSERT_EQ(expectedPid, result.pid);
}

sp<IBinder> FakeInputDispatcherPolicy::getUnresponsiveWindowToken(
        std::chrono::nanoseconds timeout) {
    std::unique_lock lock(mLock);
    android::base::ScopedLockAssertion assumeLocked(mLock);
    AnrResult result = getAnrTokenLockedInterruptible(timeout, mAnrWindows, lock);
    const auto& [token, _] = result;
    return token;
}

void FakeInputDispatcherPolicy::assertNotifyWindowResponsiveWasCalled(
        const sp<IBinder>& expectedToken, std::optional<gui::Pid> expectedPid) {
    std::unique_lock lock(mLock);
    android::base::ScopedLockAssertion assumeLocked(mLock);
    AnrResult result;
    ASSERT_NO_FATAL_FAILURE(result = getAnrTokenLockedInterruptible(0s, mResponsiveWindows, lock));
    ASSERT_EQ(expectedToken, result.token);
    ASSERT_EQ(expectedPid, result.pid);
}

sp<IBinder> FakeInputDispatcherPolicy::getResponsiveWindowToken() {
    std::unique_lock lock(mLock);
    android::base::ScopedLockAssertion assumeLocked(mLock);
    AnrResult result = getAnrTokenLockedInterruptible(0s, mResponsiveWindows, lock);
    const auto& [token, _] = result;
    return token;
}

void FakeInputDispatcherPolicy::assertNotifyAnrWasNotCalled() {
    std::scoped_lock lock(mLock);
    ASSERT_TRUE(mAnrApplications.empty());
    ASSERT_TRUE(mAnrWindows.empty());
    ASSERT_TRUE(mResponsiveWindows.empty())
            << "ANR was not called, but please also consume the 'connection is responsive' "
               "signal";
}

PointerCaptureRequest FakeInputDispatcherPolicy::assertSetPointerCaptureCalled(
        const sp<gui::WindowInfoHandle>& window, bool enabled) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    if (!mPointerCaptureChangedCondition
                 .wait_for(lock, 100ms, [this, enabled, window]() REQUIRES(mLock) {
                     if (enabled) {
                         return mPointerCaptureRequest->isEnable() &&
                                 mPointerCaptureRequest->window == window->getToken();
                     } else {
                         return !mPointerCaptureRequest->isEnable();
                     }
                 })) {
        ADD_FAILURE() << "Timed out waiting for setPointerCapture(" << window->getName() << ", "
                      << enabled << ") to be called.";
        return {};
    }
    auto request = *mPointerCaptureRequest;
    mPointerCaptureRequest.reset();
    return request;
}

void FakeInputDispatcherPolicy::assertSetPointerCaptureNotCalled() {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    if (mPointerCaptureChangedCondition.wait_for(lock, 100ms) != std::cv_status::timeout) {
        FAIL() << "Expected setPointerCapture(request) to not be called, but was called. "
                  "enabled = "
               << std::to_string(mPointerCaptureRequest->isEnable());
    }
    mPointerCaptureRequest.reset();
}

void FakeInputDispatcherPolicy::assertDropTargetEquals(const InputDispatcherInterface& dispatcher,
                                                       const sp<IBinder>& targetToken) {
    dispatcher.waitForIdle();
    std::scoped_lock lock(mLock);
    ASSERT_TRUE(mNotifyDropWindowWasCalled);
    ASSERT_EQ(targetToken, mDropTargetWindowToken);
    mNotifyDropWindowWasCalled = false;
}

void FakeInputDispatcherPolicy::assertNotifyInputChannelBrokenWasCalled(const sp<IBinder>& token) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    std::optional<sp<IBinder>> receivedToken =
            getItemFromStorageLockedInterruptible(100ms, mBrokenInputChannels, lock,
                                                  mNotifyInputChannelBroken);
    ASSERT_TRUE(receivedToken.has_value()) << "Did not receive the broken channel token";
    ASSERT_EQ(token, *receivedToken);
}

void FakeInputDispatcherPolicy::setInterceptKeyTimeout(std::chrono::milliseconds timeout) {
    mInterceptKeyTimeout = timeout;
}

std::chrono::nanoseconds FakeInputDispatcherPolicy::getKeyWaitingForEventsTimeout() {
    return 500ms;
}

void FakeInputDispatcherPolicy::setStaleEventTimeout(std::chrono::nanoseconds timeout) {
    mStaleEventTimeout = timeout;
}

void FakeInputDispatcherPolicy::assertUserActivityNotPoked() {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::optional<UserActivityPokeEvent> pokeEvent =
            getItemFromStorageLockedInterruptible(500ms, mUserActivityPokeEvents, lock,
                                                  mNotifyUserActivity);

    ASSERT_FALSE(pokeEvent) << "Expected user activity not to have been poked";
}

void FakeInputDispatcherPolicy::assertUserActivityPoked(
        std::optional<UserActivityPokeEvent> expectedPokeEvent) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::optional<UserActivityPokeEvent> pokeEvent =
            getItemFromStorageLockedInterruptible(500ms, mUserActivityPokeEvents, lock,
                                                  mNotifyUserActivity);
    ASSERT_TRUE(pokeEvent) << "Expected a user poke event";

    if (expectedPokeEvent) {
        ASSERT_EQ(expectedPokeEvent, *pokeEvent);
    }
}

void FakeInputDispatcherPolicy::assertNotifyDeviceInteractionWasCalled(int32_t deviceId,
                                                                       std::set<gui::Uid> uids) {
    ASSERT_EQ(std::make_pair(deviceId, uids), mNotifiedInteractions.popWithTimeout(100ms));
}

void FakeInputDispatcherPolicy::assertNotifyDeviceInteractionWasNotCalled() {
    ASSERT_FALSE(mNotifiedInteractions.popWithTimeout(10ms));
}

void FakeInputDispatcherPolicy::setUnhandledKeyHandler(
        std::function<std::optional<KeyEvent>(const KeyEvent&)> handler) {
    std::scoped_lock lock(mLock);
    mUnhandledKeyHandler = handler;
}

void FakeInputDispatcherPolicy::assertUnhandledKeyReported(int32_t keycode) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    std::optional<int32_t> unhandledKeycode =
            getItemFromStorageLockedInterruptible(100ms, mReportedUnhandledKeycodes, lock,
                                                  mNotifyUnhandledKey);
    ASSERT_TRUE(unhandledKeycode) << "Expected unhandled key to be reported";
    ASSERT_EQ(unhandledKeycode, keycode);
}

void FakeInputDispatcherPolicy::assertUnhandledKeyNotReported() {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    std::optional<int32_t> unhandledKeycode =
            getItemFromStorageLockedInterruptible(10ms, mReportedUnhandledKeycodes, lock,
                                                  mNotifyUnhandledKey);
    ASSERT_FALSE(unhandledKeycode) << "Expected unhandled key NOT to be reported";
}

template <class T>
T FakeInputDispatcherPolicy::getAnrTokenLockedInterruptible(std::chrono::nanoseconds timeout,
                                                            std::queue<T>& storage,
                                                            std::unique_lock<std::mutex>& lock)
        REQUIRES(mLock) {
    // If there is an ANR, Dispatcher won't be idle because there are still events
    // in the waitQueue that we need to check on. So we can't wait for dispatcher to be idle
    // before checking if ANR was called.
    // Since dispatcher is not guaranteed to call notifyNoFocusedWindowAnr right away, we need
    // to provide it some time to act. 100ms seems reasonable.
    std::chrono::duration timeToWait = timeout + 100ms; // provide some slack
    const std::chrono::time_point start = std::chrono::steady_clock::now();
    std::optional<T> token =
            getItemFromStorageLockedInterruptible(timeToWait, storage, lock, mNotifyAnr);
    if (!token.has_value()) {
        ADD_FAILURE() << "Did not receive the ANR callback";
        return {};
    }

    const std::chrono::duration waited = std::chrono::steady_clock::now() - start;
    // Ensure that the ANR didn't get raised too early. We can't be too strict here because
    // the dispatcher started counting before this function was called
    if (std::chrono::abs(timeout - waited) > 100ms) {
        ADD_FAILURE() << "ANR was raised too early or too late. Expected "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count()
                      << "ms, but waited "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(waited).count()
                      << "ms instead";
    }
    return *token;
}

template <class T>
std::optional<T> FakeInputDispatcherPolicy::getItemFromStorageLockedInterruptible(
        std::chrono::nanoseconds timeout, std::queue<T>& storage,
        std::unique_lock<std::mutex>& lock, std::condition_variable& condition) REQUIRES(mLock) {
    condition.wait_for(lock, timeout, [&storage]() REQUIRES(mLock) { return !storage.empty(); });
    if (storage.empty()) {
        return std::nullopt;
    }
    T item = storage.front();
    storage.pop();
    return std::make_optional(item);
}

void FakeInputDispatcherPolicy::notifyConfigurationChanged(nsecs_t when) {
    std::scoped_lock lock(mLock);
    mConfigurationChangedTime = when;
}

void FakeInputDispatcherPolicy::notifyWindowUnresponsive(const sp<IBinder>& connectionToken,
                                                         std::optional<gui::Pid> pid,
                                                         const std::string&) {
    std::scoped_lock lock(mLock);
    mAnrWindows.push({connectionToken, pid});
    mNotifyAnr.notify_all();
}

void FakeInputDispatcherPolicy::notifyWindowResponsive(const sp<IBinder>& connectionToken,
                                                       std::optional<gui::Pid> pid) {
    std::scoped_lock lock(mLock);
    mResponsiveWindows.push({connectionToken, pid});
    mNotifyAnr.notify_all();
}

void FakeInputDispatcherPolicy::notifyNoFocusedWindowAnr(
        const std::shared_ptr<InputApplicationHandle>& applicationHandle) {
    std::scoped_lock lock(mLock);
    mAnrApplications.push(applicationHandle);
    mNotifyAnr.notify_all();
}

void FakeInputDispatcherPolicy::notifyInputChannelBroken(const sp<IBinder>& connectionToken) {
    std::scoped_lock lock(mLock);
    mBrokenInputChannels.push(connectionToken);
    mNotifyInputChannelBroken.notify_all();
}

void FakeInputDispatcherPolicy::notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) {}

void FakeInputDispatcherPolicy::notifySensorEvent(int32_t deviceId,
                                                  InputDeviceSensorType sensorType,
                                                  InputDeviceSensorAccuracy accuracy,
                                                  nsecs_t timestamp,
                                                  const std::vector<float>& values) {}

void FakeInputDispatcherPolicy::notifySensorAccuracy(int deviceId, InputDeviceSensorType sensorType,
                                                     InputDeviceSensorAccuracy accuracy) {}

void FakeInputDispatcherPolicy::notifyVibratorState(int32_t deviceId, bool isOn) {}

bool FakeInputDispatcherPolicy::filterInputEvent(const InputEvent& inputEvent,
                                                 uint32_t policyFlags) {
    std::scoped_lock lock(mLock);
    switch (inputEvent.getType()) {
        case InputEventType::KEY: {
            const KeyEvent& keyEvent = static_cast<const KeyEvent&>(inputEvent);
            mFilteredEvent = std::make_unique<KeyEvent>(keyEvent);
            break;
        }

        case InputEventType::MOTION: {
            const MotionEvent& motionEvent = static_cast<const MotionEvent&>(inputEvent);
            mFilteredEvent = std::make_unique<MotionEvent>(motionEvent);
            break;
        }
        default: {
            ADD_FAILURE() << "Should only filter keys or motions";
            break;
        }
    }
    return true;
}

void FakeInputDispatcherPolicy::interceptKeyBeforeQueueing(const KeyEvent& inputEvent, uint32_t&) {
    if (inputEvent.getAction() == AKEY_EVENT_ACTION_UP) {
        // Clear intercept state when we handled the event.
        mInterceptKeyTimeout = 0ms;
    }
}

void FakeInputDispatcherPolicy::interceptMotionBeforeQueueing(int32_t, uint32_t, int32_t, nsecs_t,
                                                              uint32_t&) {}

nsecs_t FakeInputDispatcherPolicy::interceptKeyBeforeDispatching(const sp<IBinder>&,
                                                                 const KeyEvent&, uint32_t) {
    nsecs_t delay = std::chrono::nanoseconds(mInterceptKeyTimeout).count();
    // Clear intercept state so we could dispatch the event in next wake.
    mInterceptKeyTimeout = 0ms;
    return delay;
}

std::optional<KeyEvent> FakeInputDispatcherPolicy::dispatchUnhandledKey(const sp<IBinder>&,
                                                                        const KeyEvent& event,
                                                                        uint32_t) {
    std::scoped_lock lock(mLock);
    mReportedUnhandledKeycodes.emplace(event.getKeyCode());
    mNotifyUnhandledKey.notify_all();
    return mUnhandledKeyHandler != nullptr ? mUnhandledKeyHandler(event) : std::nullopt;
}

void FakeInputDispatcherPolicy::notifySwitch(nsecs_t when, uint32_t switchValues,
                                             uint32_t switchMask, uint32_t policyFlags) {
    std::scoped_lock lock(mLock);
    // We simply reconstruct NotifySwitchArgs in policy because InputDispatcher is
    // essentially a passthrough for notifySwitch.
    mLastNotifySwitch =
            NotifySwitchArgs(InputEvent::nextId(), when, policyFlags, switchValues, switchMask);
}

void FakeInputDispatcherPolicy::pokeUserActivity(nsecs_t eventTime, int32_t eventType,
                                                 int32_t displayId) {
    std::scoped_lock lock(mLock);
    mNotifyUserActivity.notify_all();
    mUserActivityPokeEvents.push({eventTime, eventType, displayId});
}

bool FakeInputDispatcherPolicy::isStaleEvent(nsecs_t currentTime, nsecs_t eventTime) {
    return std::chrono::nanoseconds(currentTime - eventTime) >= mStaleEventTimeout;
}

void FakeInputDispatcherPolicy::onPointerDownOutsideFocus(const sp<IBinder>& newToken) {
    std::scoped_lock lock(mLock);
    mOnPointerDownToken = newToken;
}

void FakeInputDispatcherPolicy::setPointerCapture(const PointerCaptureRequest& request) {
    std::scoped_lock lock(mLock);
    mPointerCaptureRequest = {request};
    mPointerCaptureChangedCondition.notify_all();
}

void FakeInputDispatcherPolicy::notifyDropWindow(const sp<IBinder>& token, float x, float y) {
    std::scoped_lock lock(mLock);
    mNotifyDropWindowWasCalled = true;
    mDropTargetWindowToken = token;
}

void FakeInputDispatcherPolicy::notifyDeviceInteraction(int32_t deviceId, nsecs_t timestamp,
                                                        const std::set<gui::Uid>& uids) {
    ASSERT_TRUE(mNotifiedInteractions.emplace(deviceId, uids));
}

void FakeInputDispatcherPolicy::assertFilterInputEventWasCalledInternal(
        const std::function<void(const InputEvent&)>& verify) {
    std::scoped_lock lock(mLock);
    ASSERT_NE(nullptr, mFilteredEvent) << "Expected filterInputEvent() to have been called.";
    verify(*mFilteredEvent);
    mFilteredEvent = nullptr;
}

gui::Uid FakeInputDispatcherPolicy::getPackageUid(std::string pkg) {
    std::scoped_lock lock(mLock);
    auto it = mPackageUidMap.find(pkg);
    return it != mPackageUidMap.end() ? it->second : gui::Uid::INVALID;
}

void FakeInputDispatcherPolicy::addPackageUidMapping(std::string package, gui::Uid uid) {
    std::scoped_lock lock(mLock);
    mPackageUidMap.insert_or_assign(std::move(package), uid);
}

} // namespace android
