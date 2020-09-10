/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "../AnrTracker.h"

#include <binder/Binder.h>
#include <gtest/gtest.h>

namespace android {

namespace inputdispatcher {

// --- AnrTrackerTest ---

/**
 * Add a single entry and ensure it's returned as first, even if the token isn't valid
 */
TEST(AnrTrackerTest, SingleEntry_First) {
    AnrTracker tracker;

    tracker.insert(1, nullptr);

    ASSERT_EQ(1, tracker.firstTimeout());
    ASSERT_EQ(tracker.firstToken(), nullptr);
}

TEST(AnrTrackerTest, MultipleEntries_RemoveToken) {
    AnrTracker tracker;

    sp<IBinder> token1 = new BBinder();
    sp<IBinder> token2 = new BBinder();

    tracker.insert(1, token1);
    tracker.insert(2, token2);
    tracker.insert(3, token1);
    tracker.insert(4, token2);
    tracker.insert(5, token1);

    tracker.eraseToken(token1);

    ASSERT_EQ(2, tracker.firstTimeout());
}

TEST(AnrTrackerTest, AddAndRemove_Empty) {
    AnrTracker tracker;

    ASSERT_TRUE(tracker.empty());

    tracker.insert(1, nullptr);
    ASSERT_FALSE(tracker.empty());

    tracker.erase(1, nullptr);
    ASSERT_TRUE(tracker.empty());
}

TEST(AnrTrackerTest, Clear) {
    AnrTracker tracker;

    tracker.insert(1, nullptr);
    tracker.clear();
    ASSERT_TRUE(tracker.empty());
}

TEST(AnrTrackerTest, SingleToken_MaintainsOrder) {
    AnrTracker tracker;

    ASSERT_TRUE(tracker.empty());

    tracker.insert(2, nullptr);
    tracker.insert(5, nullptr);
    tracker.insert(0, nullptr);

    ASSERT_EQ(0, tracker.firstTimeout());
    ASSERT_EQ(nullptr, tracker.firstToken());
}

TEST(AnrTrackerTest, MultipleTokens_MaintainsOrder) {
    AnrTracker tracker;

    sp<IBinder> token1 = new BBinder();
    sp<IBinder> token2 = new BBinder();

    tracker.insert(2, token1);
    tracker.insert(5, token2);
    tracker.insert(0, token2);

    ASSERT_EQ(0, tracker.firstTimeout());
    ASSERT_EQ(token2, tracker.firstToken());
}

TEST(AnrTrackerTest, MultipleTokens_IdenticalTimes) {
    AnrTracker tracker;

    sp<IBinder> token1 = new BBinder();
    sp<IBinder> token2 = new BBinder();

    tracker.insert(2, token1);
    tracker.insert(2, token2);
    tracker.insert(10, token2);

    ASSERT_EQ(2, tracker.firstTimeout());
    // Doesn't matter which token is returned - both are valid results
    ASSERT_TRUE(token1 == tracker.firstToken() || token2 == tracker.firstToken());
}

TEST(AnrTrackerTest, MultipleTokens_IdenticalTimesRemove) {
    AnrTracker tracker;

    sp<IBinder> token1 = new BBinder();
    sp<IBinder> token2 = new BBinder();

    tracker.insert(2, token1);
    tracker.insert(2, token2);
    tracker.insert(10, token2);

    tracker.erase(2, token2);

    ASSERT_EQ(2, tracker.firstTimeout());
    ASSERT_EQ(token1, tracker.firstToken());
}

TEST(AnrTrackerTest, Empty_DoesntCrash) {
    AnrTracker tracker;

    ASSERT_TRUE(tracker.empty());

    ASSERT_EQ(LONG_LONG_MAX, tracker.firstTimeout());
    // Can't call firstToken() if tracker.empty()
}

TEST(AnrTrackerTest, RemoveInvalidItem_DoesntCrash) {
    AnrTracker tracker;

    tracker.insert(1, nullptr);

    // Remove with non-matching timestamp
    tracker.erase(2, nullptr);
    ASSERT_EQ(1, tracker.firstTimeout());
    ASSERT_EQ(nullptr, tracker.firstToken());

    // Remove with non-matching token
    tracker.erase(1, new BBinder());
    ASSERT_EQ(1, tracker.firstTimeout());
    ASSERT_EQ(nullptr, tracker.firstToken());

    // Remove with both non-matching
    tracker.erase(2, new BBinder());
    ASSERT_EQ(1, tracker.firstTimeout());
    ASSERT_EQ(nullptr, tracker.firstToken());
}

} // namespace inputdispatcher

} // namespace android
