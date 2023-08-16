/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "VibratorHalWrapperAidlTest"

#include <android-base/thread_annotations.h>
#include <android/hardware/vibrator/IVibrator.h>
#include <condition_variable>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>
#include <thread>

#include <vibratorservice/VibratorCallbackScheduler.h>

using std::chrono::milliseconds;
using std::chrono::steady_clock;
using std::chrono::time_point;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

// Delay allowed for the scheduler to process callbacks during this test.
static const auto TEST_TIMEOUT = 50ms;

class VibratorCallbackSchedulerTest : public Test {
public:
    void SetUp() override {
        mScheduler = std::make_unique<vibrator::CallbackScheduler>();
        std::lock_guard<std::mutex> lock(mMutex);
        mExpiredCallbacks.clear();
    }

protected:
    std::mutex mMutex;
    std::condition_variable_any mCondition;
    std::unique_ptr<vibrator::CallbackScheduler> mScheduler = nullptr;
    std::vector<int32_t> mExpiredCallbacks GUARDED_BY(mMutex);

    std::function<void()> createCallback(int32_t id) {
        return [=]() {
            {
                std::lock_guard<std::mutex> lock(mMutex);
                mExpiredCallbacks.push_back(id);
            }
            mCondition.notify_all();
        };
    }

    std::vector<int32_t> getExpiredCallbacks() {
        std::lock_guard<std::mutex> lock(mMutex);
        return std::vector<int32_t>(mExpiredCallbacks);
    }

    int32_t waitForCallbacks(int32_t callbackCount, milliseconds timeout) {
        time_point<steady_clock> expirationTime = steady_clock::now() + timeout + TEST_TIMEOUT;
        int32_t expiredCallbackCount = 0;
        while (steady_clock::now() < expirationTime) {
            std::lock_guard<std::mutex> lock(mMutex);
            expiredCallbackCount = mExpiredCallbacks.size();
            if (callbackCount <= expiredCallbackCount) {
                return expiredCallbackCount;
            }
            auto currentTimeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                    expirationTime - steady_clock::now());
            if (currentTimeout > currentTimeout.zero()) {
                // Use the monotonic steady clock to wait for the requested timeout via wait_for
                // instead of using a wall clock via wait_until.
                mCondition.wait_for(mMutex, currentTimeout);
            }
        }
        return expiredCallbackCount;
    }
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorCallbackSchedulerTest, TestScheduleRunsOnlyAfterDelay) {
    time_point<steady_clock> startTime = steady_clock::now();
    mScheduler->schedule(createCallback(1), 50ms);

    ASSERT_EQ(1, waitForCallbacks(1, 50ms));
    time_point<steady_clock> callbackTime = steady_clock::now();

    // Callback happened at least 50ms after the beginning of the test.
    ASSERT_TRUE(startTime + 50ms <= callbackTime);
    ASSERT_THAT(getExpiredCallbacks(), ElementsAre(1));
}

TEST_F(VibratorCallbackSchedulerTest, TestScheduleMultipleCallbacksRunsInDelayOrder) {
    // Schedule first callbacks long enough that all 3 will be scheduled together and run in order.
    mScheduler->schedule(createCallback(1), 50ms);
    mScheduler->schedule(createCallback(2), 40ms);
    mScheduler->schedule(createCallback(3), 10ms);

    ASSERT_EQ(3, waitForCallbacks(3, 50ms));
    ASSERT_THAT(getExpiredCallbacks(), ElementsAre(3, 2, 1));
}

TEST_F(VibratorCallbackSchedulerTest, TestDestructorDropsPendingCallbacksAndKillsThread) {
    // Schedule callback long enough that scheduler will be destroyed while it's still scheduled.
    mScheduler->schedule(createCallback(1), 50ms);
    mScheduler.reset(nullptr);

    // Should timeout waiting for callback to run.
    ASSERT_EQ(0, waitForCallbacks(1, 50ms));
    ASSERT_TRUE(getExpiredCallbacks().empty());
}
