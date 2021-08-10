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

class HotplugTest : public DisplayTransactionTest {};

TEST_F(HotplugTest, enqueuesEventsForDisplayTransaction) {
    constexpr HWDisplayId hwcDisplayId1 = 456;
    constexpr HWDisplayId hwcDisplayId2 = 654;

    // --------------------------------------------------------------------
    // Preconditions

    // Set the main thread id so that the current thread does not appear to be
    // the main thread.
    mFlinger.mutableMainThreadId() = std::thread::id();

    // --------------------------------------------------------------------
    // Call Expectations

    // We expect a scheduled commit for the display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    // --------------------------------------------------------------------
    // Invocation

    // Simulate two hotplug events (a connect and a disconnect)
    mFlinger.onComposerHalHotplug(hwcDisplayId1, Connection::CONNECTED);
    mFlinger.onComposerHalHotplug(hwcDisplayId2, Connection::DISCONNECTED);

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

TEST_F(HotplugTest, processesEnqueuedEventsIfCalledOnMainThread) {
    constexpr HWDisplayId displayId1 = 456;

    // --------------------------------------------------------------------
    // Note:
    // --------------------------------------------------------------------
    // This test case is a bit tricky. We want to verify that
    // onComposerHalHotplug() calls processDisplayHotplugEventsLocked(), but we
    // don't really want to provide coverage for everything the later function
    // does as there are specific tests for it.
    // --------------------------------------------------------------------

    // --------------------------------------------------------------------
    // Preconditions

    // Set the main thread id so that the current thread does appear to be the
    // main thread.
    mFlinger.mutableMainThreadId() = std::this_thread::get_id();

    // --------------------------------------------------------------------
    // Call Expectations

    // We expect a scheduled commit for the display transaction.
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

    // --------------------------------------------------------------------
    // Invocation

    // Simulate a disconnect on a display id that is not connected. This should
    // be enqueued by onComposerHalHotplug(), and dequeued by
    // processDisplayHotplugEventsLocked(), but then ignored as invalid.
    mFlinger.onComposerHalHotplug(displayId1, Connection::DISCONNECTED);

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
