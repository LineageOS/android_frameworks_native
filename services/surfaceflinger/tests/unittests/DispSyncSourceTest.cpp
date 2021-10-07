/*
 * Copyright 2019 The Android Open Source Project
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
#define LOG_NDEBUG 0

#include <inttypes.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <log/log.h>

#include "AsyncCallRecorder.h"
#include "Scheduler/DispSyncSource.h"
#include "Scheduler/VSyncDispatch.h"

namespace android {
namespace {

using namespace std::chrono_literals;
using namespace testing;

class MockVSyncDispatch : public scheduler::VSyncDispatch {
public:
    MOCK_METHOD2(registerCallback,
                 CallbackToken(std::function<void(nsecs_t, nsecs_t, nsecs_t)> const&, std::string));
    MOCK_METHOD1(unregisterCallback, void(CallbackToken));
    MOCK_METHOD2(schedule, scheduler::ScheduleResult(CallbackToken, ScheduleTiming));
    MOCK_METHOD1(cancel, scheduler::CancelResult(CallbackToken token));
    MOCK_CONST_METHOD1(dump, void(std::string&));

    MockVSyncDispatch() {
        ON_CALL(*this, registerCallback)
                .WillByDefault(
                        [this](std::function<void(nsecs_t, nsecs_t, nsecs_t)> const& callback,
                               std::string) {
                            CallbackToken token(mNextToken);
                            mNextToken++;

                            mCallbacks.emplace(token, CallbackData(callback));
                            ALOGD("registerCallback: %zu", token.value());
                            return token;
                        });

        ON_CALL(*this, unregisterCallback).WillByDefault([this](CallbackToken token) {
            ALOGD("unregisterCallback: %zu", token.value());
            mCallbacks.erase(token);
        });

        ON_CALL(*this, schedule).WillByDefault([this](CallbackToken token, ScheduleTiming timing) {
            ALOGD("schedule: %zu", token.value());
            if (mCallbacks.count(token) == 0) {
                ALOGD("schedule: callback %zu not registered", token.value());
                return scheduler::ScheduleResult{};
            }

            auto& callback = mCallbacks.at(token);
            callback.scheduled = true;
            callback.vsyncTime = timing.earliestVsync;
            callback.targetWakeupTime =
                    timing.earliestVsync - timing.workDuration - timing.readyDuration;
            ALOGD("schedule: callback %zu scheduled", token.value());
            return scheduler::ScheduleResult{callback.targetWakeupTime};
        });

        ON_CALL(*this, cancel).WillByDefault([this](CallbackToken token) {
            ALOGD("cancel: %zu", token.value());
            if (mCallbacks.count(token) == 0) {
                ALOGD("cancel: callback %zu is not registered", token.value());
                return scheduler::CancelResult::Error;
            }

            auto& callback = mCallbacks.at(token);
            callback.scheduled = false;
            ALOGD("cancel: callback %zu cancelled", token.value());
            return scheduler::CancelResult::Cancelled;
        });
    }

    void triggerCallbacks() {
        ALOGD("triggerCallbacks");
        for (auto& [token, callback] : mCallbacks) {
            if (callback.scheduled) {
                ALOGD("triggerCallbacks: callback %zu", token.value());
                callback.scheduled = false;
                callback.func(callback.vsyncTime, callback.targetWakeupTime, callback.readyTime);
            } else {
                ALOGD("triggerCallbacks: callback %zu is not scheduled", token.value());
            }
        }
    }

private:
    struct CallbackData {
        explicit CallbackData(std::function<void(nsecs_t, nsecs_t, nsecs_t)> func)
              : func(std::move(func)) {}

        std::function<void(nsecs_t, nsecs_t, nsecs_t)> func;
        bool scheduled = false;
        nsecs_t vsyncTime = 0;
        nsecs_t targetWakeupTime = 0;
        nsecs_t readyTime = 0;
    };

    std::unordered_map<CallbackToken, CallbackData> mCallbacks;
    size_t mNextToken;
};

class DispSyncSourceTest : public testing::Test, private VSyncSource::Callback {
protected:
    DispSyncSourceTest();
    ~DispSyncSourceTest() override;

    void createDispSync();
    void createDispSyncSource();

    void onVSyncEvent(nsecs_t when, nsecs_t expectedVSyncTimestamp,
                      nsecs_t deadlineTimestamp) override;

    std::unique_ptr<MockVSyncDispatch> mVSyncDispatch;
    std::unique_ptr<scheduler::DispSyncSource> mDispSyncSource;

    AsyncCallRecorder<void (*)(nsecs_t, nsecs_t, nsecs_t)> mVSyncEventCallRecorder;

    static constexpr std::chrono::nanoseconds mWorkDuration = 20ms;
    static constexpr std::chrono::nanoseconds mReadyDuration = 10ms;
    static constexpr int mIterations = 100;
    const scheduler::VSyncDispatch::CallbackToken mFakeToken{2398};
    const std::string mName = "DispSyncSourceTest";
};

DispSyncSourceTest::DispSyncSourceTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
}

DispSyncSourceTest::~DispSyncSourceTest() {
    const ::testing::TestInfo* const test_info =
            ::testing::UnitTest::GetInstance()->current_test_info();
    ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
}

void DispSyncSourceTest::onVSyncEvent(nsecs_t when, nsecs_t expectedVSyncTimestamp,
                                      nsecs_t deadlineTimestamp) {
    ALOGD("onVSyncEvent: %" PRId64, when);

    mVSyncEventCallRecorder.recordCall(when, expectedVSyncTimestamp, deadlineTimestamp);
}

void DispSyncSourceTest::createDispSync() {
    mVSyncDispatch = std::make_unique<MockVSyncDispatch>();
}

void DispSyncSourceTest::createDispSyncSource() {
    mDispSyncSource =
            std::make_unique<scheduler::DispSyncSource>(*mVSyncDispatch, mWorkDuration,
                                                        mReadyDuration, true, mName.c_str());
    mDispSyncSource->setCallback(this);
}

/* ------------------------------------------------------------------------
 * Test cases
 */

TEST_F(DispSyncSourceTest, createDispSync) {
    createDispSync();
    EXPECT_TRUE(mVSyncDispatch);
}

TEST_F(DispSyncSourceTest, createDispSyncSource) {
    createDispSync();

    InSequence seq;
    EXPECT_CALL(*mVSyncDispatch, registerCallback(_, mName)).WillOnce(Return(mFakeToken));
    EXPECT_CALL(*mVSyncDispatch, cancel(mFakeToken))
            .WillOnce(Return(scheduler::CancelResult::Cancelled));
    EXPECT_CALL(*mVSyncDispatch, unregisterCallback(mFakeToken)).WillOnce(Return());
    createDispSyncSource();

    EXPECT_TRUE(mDispSyncSource);
}

TEST_F(DispSyncSourceTest, noCallbackAfterInit) {
    createDispSync();

    InSequence seq;
    EXPECT_CALL(*mVSyncDispatch, registerCallback(_, mName)).Times(1);
    EXPECT_CALL(*mVSyncDispatch, cancel(_)).Times(1);
    EXPECT_CALL(*mVSyncDispatch, unregisterCallback(_)).Times(1);
    createDispSyncSource();

    EXPECT_TRUE(mDispSyncSource);

    // DispSyncSource starts with Vsync disabled
    mVSyncDispatch->triggerCallbacks();
    EXPECT_FALSE(mVSyncEventCallRecorder.waitForUnexpectedCall().has_value());
}

TEST_F(DispSyncSourceTest, waitForCallbacks) {
    createDispSync();

    InSequence seq;
    EXPECT_CALL(*mVSyncDispatch, registerCallback(_, mName)).Times(1);
    EXPECT_CALL(*mVSyncDispatch,
                schedule(_, Truly([&](auto timings) {
                             return timings.workDuration == mWorkDuration.count() &&
                                     timings.readyDuration == mReadyDuration.count();
                         })))
            .Times(mIterations + 1);
    EXPECT_CALL(*mVSyncDispatch, cancel(_)).Times(1);
    EXPECT_CALL(*mVSyncDispatch, unregisterCallback(_)).Times(1);
    createDispSyncSource();

    EXPECT_TRUE(mDispSyncSource);

    mDispSyncSource->setVSyncEnabled(true);
    for (int i = 0; i < mIterations; i++) {
        mVSyncDispatch->triggerCallbacks();
        const auto callbackData = mVSyncEventCallRecorder.waitForCall();
        ASSERT_TRUE(callbackData.has_value());
        const auto [when, expectedVSyncTimestamp, deadlineTimestamp] = callbackData.value();
        EXPECT_EQ(when, expectedVSyncTimestamp - mWorkDuration.count() - mReadyDuration.count());
    }
}

TEST_F(DispSyncSourceTest, waitForCallbacksWithDurationChange) {
    createDispSync();

    InSequence seq;
    EXPECT_CALL(*mVSyncDispatch, registerCallback(_, mName)).Times(1);
    EXPECT_CALL(*mVSyncDispatch,
                schedule(_, Truly([&](auto timings) {
                             return timings.workDuration == mWorkDuration.count() &&
                                     timings.readyDuration == mReadyDuration.count();
                         })))
            .Times(1);

    createDispSyncSource();

    EXPECT_TRUE(mDispSyncSource);

    mDispSyncSource->setVSyncEnabled(true);
    EXPECT_CALL(*mVSyncDispatch,
                schedule(_, Truly([&](auto timings) {
                             return timings.workDuration == mWorkDuration.count() &&
                                     timings.readyDuration == mReadyDuration.count();
                         })))
            .Times(mIterations);
    for (int i = 0; i < mIterations; i++) {
        mVSyncDispatch->triggerCallbacks();
        const auto callbackData = mVSyncEventCallRecorder.waitForCall();
        ASSERT_TRUE(callbackData.has_value());
        const auto [when, expectedVSyncTimestamp, deadlineTimestamp] = callbackData.value();
        EXPECT_EQ(when, expectedVSyncTimestamp - mWorkDuration.count() - mReadyDuration.count());
    }

    const auto newDuration = mWorkDuration / 2;
    EXPECT_CALL(*mVSyncDispatch, schedule(_, Truly([&](auto timings) {
                                              return timings.workDuration == newDuration.count() &&
                                                      timings.readyDuration == 0;
                                          })))
            .Times(1);
    mDispSyncSource->setDuration(newDuration, 0ns);

    EXPECT_CALL(*mVSyncDispatch, schedule(_, Truly([&](auto timings) {
                                              return timings.workDuration == newDuration.count() &&
                                                      timings.readyDuration == 0;
                                          })))
            .Times(mIterations);
    for (int i = 0; i < mIterations; i++) {
        mVSyncDispatch->triggerCallbacks();
        const auto callbackData = mVSyncEventCallRecorder.waitForCall();
        ASSERT_TRUE(callbackData.has_value());
        const auto [when, expectedVSyncTimestamp, deadlineTimestamp] = callbackData.value();
        EXPECT_EQ(when, expectedVSyncTimestamp - newDuration.count());
    }

    EXPECT_CALL(*mVSyncDispatch, cancel(_)).Times(1);
    EXPECT_CALL(*mVSyncDispatch, unregisterCallback(_)).Times(1);
}

} // namespace
} // namespace android
