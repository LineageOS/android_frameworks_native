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

#include <variant>

#include <gtest/gtest.h>
#include <input/Input.h>

namespace android {

// How long to wait when we are expecting an event to occur.
// This should be long, so that tests are not flaky when the device is slow.
static constexpr std::chrono::nanoseconds EVENT_SHOULD_OCCUR_TIMEOUT = 5s;
// How long to wait when we are expecting an event to not occur.
// This should be short, so that the tests are fast.
static constexpr std::chrono::nanoseconds EVENT_SHOULD_NOT_OCCUR_TIMEOUT = 10ms;

// --- FakeInputDispatcherPolicy ---

void FakeInputDispatcherPolicy::assertFilterInputEventWasCalled(const NotifyKeyArgs& args) {
    assertFilterInputEventWasCalledInternal([&args](const InputEvent& event) {
        ASSERT_EQ(event.getType(), InputEventType::KEY);
        if (args.displayId != ui::LogicalDisplayId::INVALID) {
            EXPECT_EQ(event.getDisplayId(), args.displayId);
        } else {
            EXPECT_EQ(event.getDisplayId(), ui::LogicalDisplayId::DEFAULT);
        }

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

std::optional<FakeInputDispatcherPolicy::SensorEvent> FakeInputDispatcherPolicy::getSensorEvent(
        std::chrono::nanoseconds timeout) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    return getItemFromStorageLockedInterruptible(timeout, mSensorEvents, lock, mNotifySensorEvent);
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

/**
 * Asserts that notifyPreNoFocusedWindowAnr() was called within the given timeout
 * and validates the reported application and timing information.
 *
 * The method blocks until either:
 *  - a PreNoFocusedWindowAnrResult is received, or
 *  - the provided timeout elapses.
 *
 * @param waitDuration Maximum duration to wait for a pre–no-focused-window ANR callback.
 * @param expectedTimeout Expected ANR timeout duration reported by
 *        the callback. The elapsed duration is expected to be in the range
 *        [0, expectedTimeout] and may be 0ms if the timeout is smaller
 *        than the window ANR timeout.
 * @param expectedApplication The application handle expected to be associated
 *        with the reported ANR.
 */
void FakeInputDispatcherPolicy::assertNotifyPreNoFocusedWindowAnrWasCalled(
        std::chrono::nanoseconds waitDuration, std::chrono::milliseconds expectedTimeout,
        const std::shared_ptr<InputApplicationHandle>& expectedApplication) {
    std::unique_lock lock(mLock);
    android::base::ScopedLockAssertion assumeLocked(mLock);

    std::optional<PreNoFocusedWindowAnrResult> anrWarningResult =
            getItemFromStorageLockedInterruptible(waitDuration, mPreNoFocusedWindowAnrs, lock,
                                                  mNotifyPreNoFocusedWindowAnr);
    ASSERT_TRUE(anrWarningResult.has_value()) << "Did not receive ANR warning";

    ASSERT_EQ(expectedApplication, anrWarningResult.value().appHandle);
    // The elapsed duration should be between 0 and the timeout duration.
    // Note that it can be 0ms (< 1000us) if the timeout is smaller than
    // the window's anr timeout.
    ASSERT_GE(anrWarningResult.value().elapsedDuration, 0ms);
    ASSERT_LE(anrWarningResult.value().elapsedDuration, expectedTimeout);
    ASSERT_EQ(expectedTimeout, anrWarningResult.value().timeoutDuration);
}

void FakeInputDispatcherPolicy::assertNotifyPreNoFocusedWindowAnrWasNotCalled(
        std::chrono::nanoseconds timeout) {
    std::unique_lock lock(mLock);
    android::base::ScopedLockAssertion assumeLocked(mLock);
    const bool gotOne =
            mNotifyPreNoFocusedWindowAnr.wait_for(lock, timeout, [this]() REQUIRES(mLock) {
                return !mPreNoFocusedWindowAnrs.empty();
            });
    ASSERT_FALSE(gotOne) << "Unexpected pre-ANR notification was received";
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
        const sp<gui::WindowInfoHandle>& window, PointerCaptureMode mode) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    if (!mPointerCaptureChangedCondition.wait_for(lock, EVENT_SHOULD_OCCUR_TIMEOUT,
                                                  [this, mode, window]() REQUIRES(mLock) {
                                                      // Guard against spurious wakeups.
                                                      if (!mPointerCaptureRequest) {
                                                          return false;
                                                      }
                                                      if (mode != PointerCaptureMode::UNCAPTURED) {
                                                          return mPointerCaptureRequest->mode ==
                                                                  mode &&
                                                                  mPointerCaptureRequest->window ==
                                                                  window->getToken();
                                                      }
                                                      return mPointerCaptureRequest->mode == mode;
                                                  })) {
        ADD_FAILURE() << "Timed out waiting for setPointerCapture({" << window->getName() << ", "
                      << ftl::enum_string(mode) << "}) to be called.";
        return {};
    }
    auto request = *mPointerCaptureRequest;
    mPointerCaptureRequest.reset();
    return request;
}

void FakeInputDispatcherPolicy::assertSetPointerCaptureNotCalled() {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    if (mPointerCaptureChangedCondition.wait_for(lock, EVENT_SHOULD_NOT_OCCUR_TIMEOUT) !=
        std::cv_status::timeout) {
        FAIL() << "Expected setPointerCapture(request) to not be called, but was called. mode = "
               << ftl::enum_string(mPointerCaptureRequest->mode);
    }
    mPointerCaptureRequest.reset();
}

void FakeInputDispatcherPolicy::assertNotifyDropWindowWasCalled(
        const InputDispatcherInterface& dispatcher, const sp<IBinder>& targetToken, vec2 location,
        vec2 rawLocation) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::optional<DropEvent> event =
            getItemFromStorageLockedInterruptible(EVENT_SHOULD_OCCUR_TIMEOUT, mDropEvents, lock,
                                                  mNotifyDropWindow);
    ASSERT_NE(event, std::nullopt);
    ASSERT_EQ(targetToken, event->token);
    EXPECT_EQ(location, event->location);
    EXPECT_EQ(rawLocation, event->rawLocation);
}

void FakeInputDispatcherPolicy::assertNotifyInputChannelBrokenWasCalled(const sp<IBinder>& token) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    std::optional<sp<IBinder>> receivedToken =
            getItemFromStorageLockedInterruptible(EVENT_SHOULD_OCCUR_TIMEOUT, mBrokenInputChannels,
                                                  lock, mNotifyInputChannelBroken);
    ASSERT_TRUE(receivedToken.has_value()) << "Did not receive the broken channel token";
    ASSERT_EQ(token, *receivedToken);
}

std::chrono::nanoseconds FakeInputDispatcherPolicy::getKeyWaitingForEventsTimeout() {
    return 500ms;
}

void FakeInputDispatcherPolicy::setStaleEventTimeout(std::chrono::nanoseconds timeout) {
    mStaleEventTimeout = timeout;
}

void FakeInputDispatcherPolicy::setInterceptKeyBeforeDispatchingResult(
        std::variant<nsecs_t, inputdispatcher::KeyEntry::InterceptKeyResult> result) {
    mInterceptKeyBeforeDispatchingResult = result;
}

void FakeInputDispatcherPolicy::assertFocusedDisplayNotified(ui::LogicalDisplayId expectedDisplay) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    if (!mFocusedDisplayNotifiedCondition.wait_for(lock, EVENT_SHOULD_OCCUR_TIMEOUT,
                                                   [this, expectedDisplay]() REQUIRES(mLock) {
                                                       if (!mNotifiedFocusedDisplay.has_value() ||
                                                           mNotifiedFocusedDisplay.value() !=
                                                                   expectedDisplay) {
                                                           return false;
                                                       }
                                                       return true;
                                                   })) {
        ADD_FAILURE() << "Timed out waiting for notifyFocusedDisplayChanged(" << expectedDisplay
                      << ") to be called.";
    }
}

void FakeInputDispatcherPolicy::assertUserActivityNotPoked() {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::optional<UserActivityPokeEvent> pokeEvent =
            getItemFromStorageLockedInterruptible(EVENT_SHOULD_NOT_OCCUR_TIMEOUT,
                                                  mUserActivityPokeEvents, lock,
                                                  mNotifyUserActivity);

    ASSERT_FALSE(pokeEvent) << "Expected user activity not to have been poked";
}

void FakeInputDispatcherPolicy::assertUserActivityPoked(
        std::optional<UserActivityPokeEvent> expectedPokeEvent) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);

    std::optional<UserActivityPokeEvent> pokeEvent =
            getItemFromStorageLockedInterruptible(EVENT_SHOULD_OCCUR_TIMEOUT,
                                                  mUserActivityPokeEvents, lock,
                                                  mNotifyUserActivity);
    ASSERT_TRUE(pokeEvent) << "Expected a user poke event";

    if (expectedPokeEvent) {
        ASSERT_EQ(expectedPokeEvent, *pokeEvent);
    }
}

void FakeInputDispatcherPolicy::assertNotifyDeviceInteractionWasCalled(int32_t deviceId,
                                                                       std::set<gui::Uid> uids) {
    ASSERT_EQ(std::make_pair(deviceId, uids),
              mNotifiedInteractions.popWithTimeout(EVENT_SHOULD_OCCUR_TIMEOUT));
}

void FakeInputDispatcherPolicy::assertNotifyDeviceInteractionWasNotCalled() {
    ASSERT_FALSE(mNotifiedInteractions.popWithTimeout(EVENT_SHOULD_NOT_OCCUR_TIMEOUT));
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
            getItemFromStorageLockedInterruptible(EVENT_SHOULD_OCCUR_TIMEOUT,
                                                  mReportedUnhandledKeycodes, lock,
                                                  mNotifyUnhandledKey);
    ASSERT_TRUE(unhandledKeycode) << "Expected unhandled key to be reported";
    ASSERT_EQ(unhandledKeycode, keycode);
}

void FakeInputDispatcherPolicy::assertUnhandledKeyNotReported() {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    std::optional<int32_t> unhandledKeycode =
            getItemFromStorageLockedInterruptible(EVENT_SHOULD_NOT_OCCUR_TIMEOUT,
                                                  mReportedUnhandledKeycodes, lock,
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

void FakeInputDispatcherPolicy::notifyWindowUnresponsive(
        const sp<IBinder>& connectionToken, std::optional<gui::Pid> pid, const std::string&,
        int32_t eventId, nsecs_t eventTime, std::chrono::milliseconds timeoutDuration) {
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
        const std::shared_ptr<InputApplicationHandle>& applicationHandle, int32_t eventId,
        nsecs_t eventTime, std::chrono::milliseconds timeoutDuration) {
    std::scoped_lock lock(mLock);
    mAnrApplications.push(applicationHandle);
    mNotifyAnr.notify_all();
}

void FakeInputDispatcherPolicy::notifyPreNoFocusedWindowAnr(
        const std::shared_ptr<InputApplicationHandle>& applicationHandle, int32_t expectedEventId,
        std::chrono::milliseconds expectedElapsedDuration,
        std::chrono::milliseconds expectedTimeout) {
    std::scoped_lock lock(mLock);
    mPreNoFocusedWindowAnrs.push(
            {applicationHandle, expectedEventId, expectedElapsedDuration, expectedTimeout});
    mNotifyPreNoFocusedWindowAnr.notify_all();
}

void FakeInputDispatcherPolicy::notifyInputChannelBroken(const sp<IBinder>& connectionToken) {
    std::scoped_lock lock(mLock);
    mBrokenInputChannels.push(connectionToken);
    mNotifyInputChannelBroken.notify_all();
}

void FakeInputDispatcherPolicy::notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) {}

void FakeInputDispatcherPolicy::notifySensorEvent(DeviceId deviceId,
                                                  InputDeviceSensorType sensorType,
                                                  InputDeviceSensorAccuracy accuracy,
                                                  nsecs_t timestamp,
                                                  const std::vector<float>& values) {
    std::scoped_lock lock(mLock);
    mSensorEvents.push({deviceId, sensorType, accuracy, timestamp, values});
    mNotifySensorEvent.notify_all();
}

void FakeInputDispatcherPolicy::notifySensorAccuracy(DeviceId deviceId,
                                                     InputDeviceSensorType sensorType,
                                                     InputDeviceSensorAccuracy accuracy) {}

void FakeInputDispatcherPolicy::notifyVibratorState(DeviceId deviceId, bool isOn) {}

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
    {
        std::scoped_lock lock(mLock);
        mInterceptKeyBeforeQueueingEvent.push(inputEvent);
        mNotifyInterceptKeyBeforeQueueing.notify_all();
    }
    if (inputEvent.getAction() == AKEY_EVENT_ACTION_UP) {
        // Clear intercept state when we handled the event.
        if (std::holds_alternative<nsecs_t>(mInterceptKeyBeforeDispatchingResult)) {
            mInterceptKeyBeforeDispatchingResult = nsecs_t(0);
        }
    }
}

void FakeInputDispatcherPolicy::assertInterceptKeyBeforeQueueingWasCalled(
        const ::testing::Matcher<KeyEvent>& matcher) {
    std::unique_lock lock(mLock);
    base::ScopedLockAssertion assumeLocked(mLock);
    std::optional<KeyEvent> event =
            getItemFromStorageLockedInterruptible(EVENT_SHOULD_OCCUR_TIMEOUT,
                                                  mInterceptKeyBeforeQueueingEvent, lock,
                                                  mNotifyInterceptKeyBeforeQueueing);
    ASSERT_TRUE(event.has_value()) << "Expected interceptKeyBeforeQueueing to have been called.";
    ASSERT_THAT(*event, matcher);
}

void FakeInputDispatcherPolicy::interceptMotionBeforeQueueing(ui::LogicalDisplayId, uint32_t,
                                                              int32_t, nsecs_t, uint32_t&) {}

std::variant<nsecs_t, inputdispatcher::KeyEntry::InterceptKeyResult>
FakeInputDispatcherPolicy::interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent& event,
                                                         uint32_t) {
    if (inputdispatcher::KeyEntry::InterceptKeyResult* result =
                std::get_if<inputdispatcher::KeyEntry::InterceptKeyResult>(
                        &mInterceptKeyBeforeDispatchingResult)) {
        if (*result == inputdispatcher::KeyEntry::InterceptKeyResult::SKIP) {
            mKeysConsumedByPolicy.emplace(event);
        }
        return mInterceptKeyBeforeDispatchingResult;
    }

    nsecs_t delay =
            std::chrono::nanoseconds(std::get<nsecs_t>(mInterceptKeyBeforeDispatchingResult))
                    .count();
    if (delay == 0) {
        return inputdispatcher::KeyEntry::InterceptKeyResult::CONTINUE;
    }

    // Clear intercept state so we could dispatch the event in next wake.
    mInterceptKeyBeforeDispatchingResult = nsecs_t(0);
    return delay;
}

void FakeInputDispatcherPolicy::assertKeyConsumedByPolicy(
        const ::testing::Matcher<KeyEvent>& matcher) {
    ASSERT_THAT(*mKeysConsumedByPolicy.popWithTimeout(EVENT_SHOULD_OCCUR_TIMEOUT), matcher);
}

void FakeInputDispatcherPolicy::assertNoKeysConsumedByPolicy() {
    ASSERT_TRUE(mKeysConsumedByPolicy.empty());
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
                                                 ui::LogicalDisplayId displayId) {
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

void FakeInputDispatcherPolicy::notifyDropWindow(const sp<IBinder>& token, vec2 location,
                                                 vec2 rawLocation) {
    std::scoped_lock lock(mLock);
    mDropEvents.push({token, location, rawLocation});
    mNotifyDropWindow.notify_all();
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

void FakeInputDispatcherPolicy::notifyFocusedDisplayChanged(ui::LogicalDisplayId displayId) {
    std::scoped_lock lock(mLock);
    mNotifiedFocusedDisplay = displayId;
    mFocusedDisplayNotifiedCondition.notify_all();
}

} // namespace android
