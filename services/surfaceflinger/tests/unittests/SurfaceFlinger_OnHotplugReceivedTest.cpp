/*
 * Copyright 2020 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

namespace android {
namespace {

class OnHotplugReceivedTest : public DisplayTransactionTest {};

TEST_F(OnHotplugReceivedTest, hotplugEnqueuesEventsForDisplayTransaction) {
    constexpr int currentSequenceId = 123;
    constexpr HWDisplayId hwcDisplayId1 = 456;
    constexpr HWDisplayId hwcDisplayId2 = 654;

    // --------------------------------------------------------------------
    // Preconditions

    // Set the current sequence id for accepted events
    mFlinger.mutableComposerSequenceId() = currentSequenceId;

    // Set the main thread id so that the current thread does not appear to be
    // the main thread.
    mFlinger.mutableMainThreadId() = std::thread::id();

    // --------------------------------------------------------------------
    // Call Expectations

    // We expect invalidate() to be invoked once to trigger display transaction
    // processing.
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

    // --------------------------------------------------------------------
    // Invocation

    // Simulate two hotplug events (a connect and a disconnect)
    mFlinger.onHotplugReceived(currentSequenceId, hwcDisplayId1, Connection::CONNECTED);
    mFlinger.onHotplugReceived(currentSequenceId, hwcDisplayId2, Connection::DISCONNECTED);

    // --------------------------------------------------------------------
    // Postconditions

    // The display transaction needed flag should be set.
    EXPECT_TRUE(hasTransactionFlagSet(eDisplayTransactionNeeded));

    // All events should be in the pending event queue.
    const auto& pendingEvents = mFlinger.mutablePendingHotplugEvents();
    ASSERT_EQ(2u, pendingEvents.size());
    EXPECT_EQ(hwcDisplayId1, pendingEvents[0].hwcDisplayId);
    EXPECT_EQ(Connection::CONNECTED, pendingEvents[0].connection);
    EXPECT_EQ(hwcDisplayId2, pendingEvents[1].hwcDisplayId);
    EXPECT_EQ(Connection::DISCONNECTED, pendingEvents[1].connection);
}

TEST_F(OnHotplugReceivedTest, hotplugDiscardsUnexpectedEvents) {
    constexpr int currentSequenceId = 123;
    constexpr int otherSequenceId = 321;
    constexpr HWDisplayId displayId = 456;

    // --------------------------------------------------------------------
    // Preconditions

    // Set the current sequence id for accepted events
    mFlinger.mutableComposerSequenceId() = currentSequenceId;

    // Set the main thread id so that the current thread does not appear to be
    // the main thread.
    mFlinger.mutableMainThreadId() = std::thread::id();

    // --------------------------------------------------------------------
    // Call Expectations

    // We do not expect any calls to invalidate().
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(0);

    // --------------------------------------------------------------------
    // Invocation

    // Call with an unexpected sequence id
    mFlinger.onHotplugReceived(otherSequenceId, displayId, Connection::INVALID);

    // --------------------------------------------------------------------
    // Postconditions

    // The display transaction needed flag should not be set
    EXPECT_FALSE(hasTransactionFlagSet(eDisplayTransactionNeeded));

    // There should be no pending events
    EXPECT_TRUE(mFlinger.mutablePendingHotplugEvents().empty());
}

TEST_F(OnHotplugReceivedTest, hotplugProcessesEnqueuedEventsIfCalledOnMainThread) {
    constexpr int currentSequenceId = 123;
    constexpr HWDisplayId displayId1 = 456;

    // --------------------------------------------------------------------
    // Note:
    // --------------------------------------------------------------------
    // This test case is a bit tricky. We want to verify that
    // onHotplugReceived() calls processDisplayHotplugEventsLocked(), but we
    // don't really want to provide coverage for everything the later function
    // does as there are specific tests for it.
    // --------------------------------------------------------------------

    // --------------------------------------------------------------------
    // Preconditions

    // Set the current sequence id for accepted events
    mFlinger.mutableComposerSequenceId() = currentSequenceId;

    // Set the main thread id so that the current thread does appear to be the
    // main thread.
    mFlinger.mutableMainThreadId() = std::this_thread::get_id();

    // --------------------------------------------------------------------
    // Call Expectations

    // We expect invalidate() to be invoked once to trigger display transaction
    // processing.
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

    // --------------------------------------------------------------------
    // Invocation

    // Simulate a disconnect on a display id that is not connected. This should
    // be enqueued by onHotplugReceived(), and dequeued by
    // processDisplayHotplugEventsLocked(), but then ignored as invalid.
    mFlinger.onHotplugReceived(currentSequenceId, displayId1, Connection::DISCONNECTED);

    // --------------------------------------------------------------------
    // Postconditions

    // The display transaction needed flag should be set.
    EXPECT_TRUE(hasTransactionFlagSet(eDisplayTransactionNeeded));

    // There should be no event queued on return, as it should have been
    // processed.
    EXPECT_TRUE(mFlinger.mutablePendingHotplugEvents().empty());
}

} // namespace
} // namespace android