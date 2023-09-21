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

#include "gestures/TimerProvider.h"

#include <vector>

#include <gtest/gtest.h>

#include "InterfaceMocks.h"
#include "TestConstants.h"
#include "include/gestures.h"

namespace android {

namespace {

class TestTimerProvider : public TimerProvider {
public:
    TestTimerProvider(InputReaderContext& context) : TimerProvider(context) {}

    void setCurrentTime(nsecs_t time) { mCurrentTime = time; }

protected:
    nsecs_t getCurrentTime() override { return mCurrentTime; }

private:
    nsecs_t mCurrentTime = 0;
};

stime_t pushTimeOntoVector(stime_t triggerTime, void* data) {
    std::vector<stime_t>* times = static_cast<std::vector<stime_t>*>(data);
    times->push_back(triggerTime);
    return NO_DEADLINE;
}

stime_t copyTimeToVariable(stime_t triggerTime, void* data) {
    stime_t* time = static_cast<stime_t*>(data);
    *time = triggerTime;
    return NO_DEADLINE;
}

stime_t incrementInt(stime_t triggerTime, void* data) {
    int* count = static_cast<int*>(data);
    *count += 1;
    return NO_DEADLINE;
}

} // namespace

using testing::AtLeast;

class TimerProviderTest : public testing::Test {
public:
    TimerProviderTest() : mProvider(mMockContext) {}

protected:
    void triggerCallbacksWithFakeTime(nsecs_t time) {
        mProvider.setCurrentTime(time);
        mProvider.triggerCallbacks(time);
    }

    MockInputReaderContext mMockContext;
    TestTimerProvider mProvider;
};

TEST_F(TimerProviderTest, SingleDeadlineTriggersWhenTimeoutIsExactlyOnTime) {
    GesturesTimer* timer = mProvider.createTimer();
    std::vector<stime_t> callTimes;
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(3);

    // Call through kGestureTimerProvider in this test case, so that we cover the stime_t to nsecs_t
    // conversion code. This is why the delay is 1.0 rather than 1'000'000'000 here.
    kGestureTimerProvider.set_fn(&mProvider, timer, 1.0, &pushTimeOntoVector, &callTimes);

    triggerCallbacksWithFakeTime(900'000'000);
    triggerCallbacksWithFakeTime(999'999'999);
    EXPECT_EQ(0u, callTimes.size());
    triggerCallbacksWithFakeTime(1'000'000'000);
    ASSERT_EQ(1u, callTimes.size());
    EXPECT_NEAR(1.0, callTimes[0], EPSILON);

    // Now that the timer has triggered, it shouldn't trigger again if we get another timeout from
    // InputReader.
    triggerCallbacksWithFakeTime(1'300'000'000);
    EXPECT_EQ(1u, callTimes.size());
}

TEST_F(TimerProviderTest, SingleDeadlineTriggersWhenTimeoutIsLate) {
    GesturesTimer* timer = mProvider.createTimer();
    stime_t callTime = -1.0;
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(1);
    mProvider.setDeadline(timer, 1'000'000'000, &copyTimeToVariable, &callTime);

    triggerCallbacksWithFakeTime(1'010'000'000);
    EXPECT_NEAR(1.01, callTime, EPSILON);
}

TEST_F(TimerProviderTest, SingleRescheduledDeadlineTriggers) {
    GesturesTimer* timer = mProvider.createTimer();
    std::vector<stime_t> callTimes;
    auto callback = [](stime_t triggerTime, void* callbackData) {
        std::vector<stime_t>* times = static_cast<std::vector<stime_t>*>(callbackData);
        times->push_back(triggerTime);
        if (times->size() < 2) {
            return 1.0;
        } else {
            return NO_DEADLINE;
        }
    };
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(1);
    // The deadline should be rescheduled for 2.01s, since the first triggerCallbacks call is 0.01s
    // late.
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(2'010'000'000)).Times(1);

    mProvider.setDeadline(timer, 1'000'000'000, callback, &callTimes);

    triggerCallbacksWithFakeTime(1'010'000'000);
    ASSERT_EQ(1u, callTimes.size());
    EXPECT_NEAR(1.01, callTimes[0], EPSILON);

    triggerCallbacksWithFakeTime(2'020'000'000);
    ASSERT_EQ(2u, callTimes.size());
    EXPECT_NEAR(1.01, callTimes[0], EPSILON);
    EXPECT_NEAR(2.02, callTimes[1], EPSILON);

    triggerCallbacksWithFakeTime(3'000'000'000);
    EXPECT_EQ(2u, callTimes.size());
}

TEST_F(TimerProviderTest, MultipleDeadlinesTriggerWithMultipleTimeouts) {
    GesturesTimer* timer = mProvider.createTimer();
    std::vector<stime_t> callTimes1;
    std::vector<stime_t> callTimes2;

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(AtLeast(1));
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'500'000'000)).Times(1);

    mProvider.setDeadline(timer, 1'000'000'000, &pushTimeOntoVector, &callTimes1);
    mProvider.setDeadline(timer, 1'500'000'000, &pushTimeOntoVector, &callTimes2);

    EXPECT_EQ(0u, callTimes1.size());
    EXPECT_EQ(0u, callTimes2.size());

    triggerCallbacksWithFakeTime(1'010'000'000);
    ASSERT_EQ(1u, callTimes1.size());
    EXPECT_NEAR(1.01, callTimes1[0], EPSILON);
    EXPECT_EQ(0u, callTimes2.size());

    triggerCallbacksWithFakeTime(1'500'000'000);
    EXPECT_EQ(1u, callTimes1.size());
    ASSERT_EQ(1u, callTimes2.size());
    EXPECT_NEAR(1.5, callTimes2[0], EPSILON);
}

TEST_F(TimerProviderTest, MultipleDeadlinesTriggerWithOneLateTimeout) {
    GesturesTimer* timer = mProvider.createTimer();
    stime_t callTime1 = -1.0;
    stime_t callTime2 = -1.0;

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(AtLeast(1));

    mProvider.setDeadline(timer, 1'000'000'000, &copyTimeToVariable, &callTime1);
    mProvider.setDeadline(timer, 1'500'000'000, &copyTimeToVariable, &callTime2);

    triggerCallbacksWithFakeTime(1'510'000'000);
    EXPECT_NEAR(1.51, callTime1, EPSILON);
    EXPECT_NEAR(1.51, callTime2, EPSILON);
}

TEST_F(TimerProviderTest, MultipleDeadlinesAtSameTimeTriggerTogether) {
    GesturesTimer* timer = mProvider.createTimer();
    stime_t callTime1 = -1.0;
    stime_t callTime2 = -1.0;

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(AtLeast(1));

    mProvider.setDeadline(timer, 1'000'000'000, &copyTimeToVariable, &callTime1);
    mProvider.setDeadline(timer, 1'000'000'000, &copyTimeToVariable, &callTime2);

    triggerCallbacksWithFakeTime(1'000'000'000);
    EXPECT_NEAR(1.0, callTime1, EPSILON);
    EXPECT_NEAR(1.0, callTime2, EPSILON);
}

TEST_F(TimerProviderTest, MultipleTimersTriggerCorrectly) {
    GesturesTimer* timer1 = mProvider.createTimer();
    GesturesTimer* timer2 = mProvider.createTimer();
    std::vector<stime_t> callTimes1;
    std::vector<stime_t> callTimes2;

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(500'000'000)).Times(AtLeast(1));
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'250'000'000)).Times(1);
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'500'000'000)).Times(1);

    mProvider.setDeadline(timer1, 500'000'000, &pushTimeOntoVector, &callTimes1);
    mProvider.setDeadline(timer1, 1'250'000'000, &pushTimeOntoVector, &callTimes1);
    mProvider.setDeadline(timer1, 1'500'000'000, &pushTimeOntoVector, &callTimes1);
    mProvider.setDeadline(timer2, 750'000'000, &pushTimeOntoVector, &callTimes2);
    mProvider.setDeadline(timer2, 1'250'000'000, &pushTimeOntoVector, &callTimes2);

    triggerCallbacksWithFakeTime(800'000'000);
    ASSERT_EQ(1u, callTimes1.size());
    EXPECT_NEAR(0.8, callTimes1[0], EPSILON);
    ASSERT_EQ(1u, callTimes2.size());
    EXPECT_NEAR(0.8, callTimes2[0], EPSILON);

    triggerCallbacksWithFakeTime(1'250'000'000);
    ASSERT_EQ(2u, callTimes1.size());
    EXPECT_NEAR(1.25, callTimes1[1], EPSILON);
    ASSERT_EQ(2u, callTimes2.size());
    EXPECT_NEAR(1.25, callTimes2[1], EPSILON);

    triggerCallbacksWithFakeTime(1'501'000'000);
    ASSERT_EQ(3u, callTimes1.size());
    EXPECT_NEAR(1.501, callTimes1[2], EPSILON);
    EXPECT_EQ(2u, callTimes2.size());
}

TEST_F(TimerProviderTest, CancelledTimerDoesntTrigger) {
    GesturesTimer* timer = mProvider.createTimer();
    int numCalls = 0;

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(500'000'000)).Times(AtLeast(1));
    mProvider.setDeadline(timer, 500'000'000, &incrementInt, &numCalls);
    mProvider.setDeadline(timer, 1'000'000'000, &incrementInt, &numCalls);
    mProvider.cancelTimer(timer);

    triggerCallbacksWithFakeTime(1'100'000'000);
    EXPECT_EQ(0, numCalls);
}

TEST_F(TimerProviderTest, CancellingOneTimerDoesntAffectOthers) {
    GesturesTimer* timer1 = mProvider.createTimer();
    GesturesTimer* timer2 = mProvider.createTimer();
    int numCalls1 = 0;
    int numCalls2 = 0;

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(500'000'000)).Times(AtLeast(1));
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(1);

    mProvider.setDeadline(timer1, 500'000'000, &incrementInt, &numCalls1);
    mProvider.setDeadline(timer2, 500'000'000, &incrementInt, &numCalls2);
    mProvider.setDeadline(timer2, 1'000'000'000, &incrementInt, &numCalls2);
    mProvider.cancelTimer(timer1);

    triggerCallbacksWithFakeTime(501'000'000);
    EXPECT_EQ(0, numCalls1);
    EXPECT_EQ(1, numCalls2);

    triggerCallbacksWithFakeTime(1'000'000'000);
    EXPECT_EQ(0, numCalls1);
    EXPECT_EQ(2, numCalls2);
}

TEST_F(TimerProviderTest, CancellingOneTimerCausesNewTimeoutRequestForAnother) {
    GesturesTimer* timer1 = mProvider.createTimer();
    GesturesTimer* timer2 = mProvider.createTimer();
    auto callback = [](stime_t, void*) { return NO_DEADLINE; };

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(500'000'000)).Times(AtLeast(1));

    mProvider.setDeadline(timer1, 500'000'000, callback, nullptr);
    mProvider.setDeadline(timer2, 1'000'000'000, callback, nullptr);

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(1);
    mProvider.cancelTimer(timer1);
}

TEST_F(TimerProviderTest, CancelledTimerCanBeReused) {
    GesturesTimer* timer = mProvider.createTimer();
    int numCallsBeforeCancellation = 0;
    int numCallsAfterCancellation = 0;

    EXPECT_CALL(mMockContext, requestTimeoutAtTime(500'000'000)).Times(1);
    EXPECT_CALL(mMockContext, requestTimeoutAtTime(1'000'000'000)).Times(1);

    mProvider.setDeadline(timer, 500'000'000, &incrementInt, &numCallsBeforeCancellation);
    mProvider.cancelTimer(timer);
    mProvider.setDeadline(timer, 1'000'000'000, &incrementInt, &numCallsAfterCancellation);

    triggerCallbacksWithFakeTime(1'000'000'000);
    EXPECT_EQ(0, numCallsBeforeCancellation);
    EXPECT_EQ(1, numCallsAfterCancellation);
}

TEST_F(TimerProviderTest, FreeingTimerCancelsFirst) {
    GesturesTimer* timer = mProvider.createTimer();
    int numCalls = 0;

    mProvider.setDeadline(timer, 1'000'000'000, &incrementInt, &numCalls);
    mProvider.freeTimer(timer);

    triggerCallbacksWithFakeTime(1'000'000'000);
    EXPECT_EQ(0, numCalls);
}

} // namespace android