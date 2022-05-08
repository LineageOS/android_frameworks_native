/*
 * Copyright 2022 The Android Open Source Project
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
#define LOG_TAG "AidlPowerHalWrapperTest"

#include <android-base/stringprintf.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/IPowerHintSession.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <memory>
#include "DisplayHardware/PowerAdvisor.h"
#include "android/hardware/power/WorkDuration.h"
#include "binder/Status.h"
#include "log/log_main.h"
#include "mock/DisplayHardware/MockIPower.h"
#include "mock/DisplayHardware/MockIPowerHintSession.h"
#include "utils/Timers.h"

using namespace android;
using namespace android::Hwc2::mock;
using namespace android::hardware::power;
using namespace std::chrono_literals;
using namespace testing;

namespace android::Hwc2::impl {

class AidlPowerHalWrapperTest : public testing::Test {
public:
    void SetUp() override;

protected:
    std::unique_ptr<AidlPowerHalWrapper> mWrapper = nullptr;
    sp<NiceMock<MockIPower>> mMockHal = nullptr;
    sp<NiceMock<MockIPowerHintSession>> mMockSession = nullptr;
    void verifyAndClearExpectations();
    void sendActualWorkDurationGroup(std::vector<WorkDuration> durations,
                                     std::chrono::nanoseconds sleepBeforeLastSend);
    std::chrono::nanoseconds mAllowedDeviation;
    std::chrono::nanoseconds mStaleTimeout;
};

void AidlPowerHalWrapperTest::SetUp() {
    mMockHal = new NiceMock<MockIPower>();
    mMockSession = new NiceMock<MockIPowerHintSession>();
    ON_CALL(*mMockHal.get(), getHintSessionPreferredRate(_)).WillByDefault(Return(Status::ok()));
    mWrapper = std::make_unique<AidlPowerHalWrapper>(mMockHal);
    mWrapper->setAllowedActualDeviation(std::chrono::nanoseconds{10ms}.count());
    mAllowedDeviation = std::chrono::nanoseconds{mWrapper->mAllowedActualDeviation};
    mStaleTimeout = AidlPowerHalWrapper::kStaleTimeout;
}

void AidlPowerHalWrapperTest::verifyAndClearExpectations() {
    Mock::VerifyAndClearExpectations(mMockHal.get());
    Mock::VerifyAndClearExpectations(mMockSession.get());
}

void AidlPowerHalWrapperTest::sendActualWorkDurationGroup(
        std::vector<WorkDuration> durations, std::chrono::nanoseconds sleepBeforeLastSend) {
    for (size_t i = 0; i < durations.size(); i++) {
        if (i == durations.size() - 1) {
            std::this_thread::sleep_for(sleepBeforeLastSend);
        }
        auto duration = durations[i];
        mWrapper->sendActualWorkDuration(duration.durationNanos, duration.timeStampNanos);
    }
}

WorkDuration toWorkDuration(std::chrono::nanoseconds durationNanos, int64_t timeStampNanos) {
    WorkDuration duration;
    duration.durationNanos = durationNanos.count();
    duration.timeStampNanos = timeStampNanos;
    return duration;
}

WorkDuration toWorkDuration(std::pair<std::chrono::nanoseconds, nsecs_t> timePair) {
    return toWorkDuration(timePair.first, timePair.second);
}

std::string printWorkDurations(const ::std::vector<WorkDuration>& durations) {
    std::ostringstream os;
    for (auto duration : durations) {
        os << duration.toString();
        os << "\n";
    }
    return os.str();
}

namespace {
TEST_F(AidlPowerHalWrapperTest, supportsPowerHintSession) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());
    Mock::VerifyAndClearExpectations(mMockHal.get());
    ON_CALL(*mMockHal.get(), getHintSessionPreferredRate(_))
            .WillByDefault(Return(Status::fromExceptionCode(Status::Exception::EX_ILLEGAL_STATE)));
    auto newWrapper = AidlPowerHalWrapper(mMockHal);
    EXPECT_FALSE(newWrapper.supportsPowerHintSession());
}

TEST_F(AidlPowerHalWrapperTest, startPowerHintSession) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());
    std::vector<int32_t> threadIds = {1, 2};
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    EXPECT_TRUE(mWrapper->startPowerHintSession());
    EXPECT_FALSE(mWrapper->startPowerHintSession());
}

TEST_F(AidlPowerHalWrapperTest, restartNewPowerHintSessionWithNewThreadIds) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());

    std::vector<int32_t> threadIds = {1, 2};
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_EQ(mWrapper->getPowerHintSessionThreadIds(), threadIds);
    ASSERT_TRUE(mWrapper->startPowerHintSession());
    verifyAndClearExpectations();

    threadIds = {2, 3};
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    EXPECT_CALL(*mMockSession.get(), close()).Times(1);
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_EQ(mWrapper->getPowerHintSessionThreadIds(), threadIds);
    verifyAndClearExpectations();

    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _)).Times(0);
    EXPECT_CALL(*mMockSession.get(), close()).Times(0);
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    verifyAndClearExpectations();
}

TEST_F(AidlPowerHalWrapperTest, setTargetWorkDuration) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());

    std::vector<int32_t> threadIds = {1, 2};
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    ASSERT_TRUE(mWrapper->startPowerHintSession());
    verifyAndClearExpectations();

    std::chrono::nanoseconds base = 100ms;
    // test cases with target work duration and whether it should update hint against baseline 100ms
    const std::vector<std::pair<std::chrono::nanoseconds, bool>> testCases =
            {{0ms, true}, {-1ms, true}, {200ms, true}, {2ms, true}, {100ms, false}, {109ms, true}};

    for (const auto& test : testCases) {
        // reset to 100ms baseline
        mWrapper->setTargetWorkDuration(1);
        mWrapper->setTargetWorkDuration(base.count());

        auto target = test.first;
        EXPECT_CALL(*mMockSession.get(), updateTargetWorkDuration(target.count()))
                .Times(test.second ? 1 : 0);
        mWrapper->setTargetWorkDuration(target.count());
        verifyAndClearExpectations();
    }
}

TEST_F(AidlPowerHalWrapperTest, setTargetWorkDuration_shouldReconnectOnError) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());

    std::vector<int32_t> threadIds = {1, 2};
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    ASSERT_TRUE(mWrapper->startPowerHintSession());
    verifyAndClearExpectations();

    EXPECT_CALL(*mMockSession.get(), updateTargetWorkDuration(1))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_ILLEGAL_STATE)));
    mWrapper->setTargetWorkDuration(1);
    EXPECT_TRUE(mWrapper->shouldReconnectHAL());
}

TEST_F(AidlPowerHalWrapperTest, sendActualWorkDuration) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());

    std::vector<int32_t> threadIds = {1, 2};
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    ASSERT_TRUE(mWrapper->startPowerHintSession());
    verifyAndClearExpectations();

    auto base = toWorkDuration(100ms, 0);
    // test cases with actual work durations and whether it should update hint against baseline
    // 100ms
    const std::vector<std::pair<std::vector<std::pair<std::chrono::nanoseconds, nsecs_t>>, bool>>
            testCases = {{{{-1ms, 100}}, false},
                         {{{100ms - (mAllowedDeviation / 2), 100}}, false},
                         {{{100ms + (mAllowedDeviation / 2), 100}}, false},
                         {{{100ms + (mAllowedDeviation + 1ms), 100}}, true},
                         {{{100ms - (mAllowedDeviation + 1ms), 100}}, true},
                         {{{100ms, 100}, {200ms, 200}}, true},
                         {{{100ms, 500}, {100ms, 600}, {3ms, 600}}, true}};

    for (const auto& test : testCases) {
        // reset actual duration
        sendActualWorkDurationGroup({base}, mStaleTimeout);

        auto raw = test.first;
        std::vector<WorkDuration> durations(raw.size());
        std::transform(raw.begin(), raw.end(), durations.begin(),
                       [](auto d) { return toWorkDuration(d); });
        EXPECT_CALL(*mMockSession.get(), reportActualWorkDuration(durations))
                .Times(test.second ? 1 : 0);
        sendActualWorkDurationGroup(durations, 0ms);
        verifyAndClearExpectations();
    }
}

TEST_F(AidlPowerHalWrapperTest, sendActualWorkDuration_exceedsStaleTime) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());

    std::vector<int32_t> threadIds = {1, 2};
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    ASSERT_TRUE(mWrapper->startPowerHintSession());
    verifyAndClearExpectations();

    auto base = toWorkDuration(100ms, 0);
    // test cases with actual work durations and whether it should update hint against baseline
    // 100ms
    const std::vector<std::tuple<std::vector<std::pair<std::chrono::nanoseconds, nsecs_t>>,
                                 std::chrono::nanoseconds, bool>>
            testCases = {{{{100ms, 100}}, mStaleTimeout, true},
                         {{{100ms + (mAllowedDeviation / 2), 100}}, mStaleTimeout, true},
                         {{{100ms, 100}}, mStaleTimeout / 2, false}};

    for (const auto& test : testCases) {
        // reset actual duration
        sendActualWorkDurationGroup({base}, mStaleTimeout);

        auto raw = std::get<0>(test);
        std::vector<WorkDuration> durations(raw.size());
        std::transform(raw.begin(), raw.end(), durations.begin(),
                       [](auto d) { return toWorkDuration(d); });
        EXPECT_CALL(*mMockSession.get(), reportActualWorkDuration(durations))
                .Times(std::get<2>(test) ? 1 : 0);
        sendActualWorkDurationGroup(durations, std::get<1>(test));
        verifyAndClearExpectations();
    }
}

TEST_F(AidlPowerHalWrapperTest, sendActualWorkDuration_shouldReconnectOnError) {
    ASSERT_TRUE(mWrapper->supportsPowerHintSession());

    std::vector<int32_t> threadIds = {1, 2};
    mWrapper->setPowerHintSessionThreadIds(threadIds);
    EXPECT_CALL(*mMockHal.get(), createHintSession(_, _, threadIds, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(mMockSession), Return(Status::ok())));
    ASSERT_TRUE(mWrapper->startPowerHintSession());
    verifyAndClearExpectations();
    WorkDuration duration;
    duration.durationNanos = 1;
    EXPECT_CALL(*mMockSession.get(), reportActualWorkDuration(_))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_ILLEGAL_STATE)));
    sendActualWorkDurationGroup({duration}, 0ms);
    EXPECT_TRUE(mWrapper->shouldReconnectHAL());
}

} // namespace
} // namespace android::Hwc2::impl
