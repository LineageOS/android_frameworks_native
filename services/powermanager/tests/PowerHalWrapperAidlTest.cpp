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

#define LOG_TAG "PowerHalWrapperAidlTest"

#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPowerHintSession.h>
#include <android/hardware/power/Mode.h>
#include <binder/IServiceManager.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <powermanager/PowerHalWrapper.h>
#include <utils/Log.h>

#include <unistd.h>
#include <thread>

using android::binder::Status;
using android::hardware::power::Boost;
using android::hardware::power::IPower;
using android::hardware::power::IPowerHintSession;
using android::hardware::power::Mode;

using namespace android;
using namespace android::power;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockIPower : public IPower {
public:
    MOCK_METHOD(Status, isBoostSupported, (Boost boost, bool* ret), (override));
    MOCK_METHOD(Status, setBoost, (Boost boost, int32_t durationMs), (override));
    MOCK_METHOD(Status, isModeSupported, (Mode mode, bool* ret), (override));
    MOCK_METHOD(Status, setMode, (Mode mode, bool enabled), (override));
    MOCK_METHOD(Status, createHintSession,
                (int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                 int64_t durationNanos, sp<IPowerHintSession>* session),
                (override));
    MOCK_METHOD(Status, getHintSessionPreferredRate, (int64_t * rate), (override));
    MOCK_METHOD(int32_t, getInterfaceVersion, (), (override));
    MOCK_METHOD(std::string, getInterfaceHash, (), (override));
    MOCK_METHOD(IBinder*, onAsBinder, (), (override));
};

// -------------------------------------------------------------------------------------------------

class PowerHalWrapperAidlTest : public Test {
public:
    void SetUp() override;

protected:
    std::unique_ptr<HalWrapper> mWrapper = nullptr;
    sp<StrictMock<MockIPower>> mMockHal = nullptr;
};

// -------------------------------------------------------------------------------------------------

void PowerHalWrapperAidlTest::SetUp() {
    mMockHal = new StrictMock<MockIPower>();
    mWrapper = std::make_unique<AidlHalWrapper>(mMockHal);
    ASSERT_NE(nullptr, mWrapper);
}

// -------------------------------------------------------------------------------------------------

TEST_F(PowerHalWrapperAidlTest, TestSetBoostSuccessful) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), isBoostSupported(Eq(Boost::DISPLAY_UPDATE_IMMINENT), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(true), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), setBoost(Eq(Boost::DISPLAY_UPDATE_IMMINENT), Eq(100)))
                .Times(Exactly(1));
    }

    auto result = mWrapper->setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 100);
    ASSERT_TRUE(result.isOk());
}

TEST_F(PowerHalWrapperAidlTest, TestSetBoostFailed) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), isBoostSupported(Eq(Boost::INTERACTION), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(true), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), setBoost(Eq(Boost::INTERACTION), Eq(100)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(-1)));
        EXPECT_CALL(*mMockHal.get(), isBoostSupported(Eq(Boost::DISPLAY_UPDATE_IMMINENT), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(-1)));
    }

    auto result = mWrapper->setBoost(Boost::INTERACTION, 100);
    ASSERT_TRUE(result.isFailed());
    result = mWrapper->setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 1000);
    ASSERT_TRUE(result.isFailed());
}

TEST_F(PowerHalWrapperAidlTest, TestSetBoostUnsupported) {
    EXPECT_CALL(*mMockHal.get(), isBoostSupported(Eq(Boost::INTERACTION), _))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<1>(false), Return(Status())));

    auto result = mWrapper->setBoost(Boost::INTERACTION, 1000);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->setBoost(Boost::CAMERA_SHOT, 10);
    ASSERT_TRUE(result.isUnsupported());
}

TEST_F(PowerHalWrapperAidlTest, TestSetBoostMultiThreadCheckSupportedOnlyOnce) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), isBoostSupported(Eq(Boost::INTERACTION), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(true), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), setBoost(Eq(Boost::INTERACTION), Eq(100))).Times(Exactly(10));
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() {
            auto result = mWrapper->setBoost(Boost::INTERACTION, 100);
            ASSERT_TRUE(result.isOk());
        }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });
}

TEST_F(PowerHalWrapperAidlTest, TestSetModeSuccessful) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), isModeSupported(Eq(Mode::DISPLAY_INACTIVE), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(true), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), setMode(Eq(Mode::DISPLAY_INACTIVE), Eq(false)))
                .Times(Exactly(1));
    }

    auto result = mWrapper->setMode(Mode::DISPLAY_INACTIVE, false);
    ASSERT_TRUE(result.isOk());
}

TEST_F(PowerHalWrapperAidlTest, TestSetModeFailed) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), isModeSupported(Eq(Mode::LAUNCH), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(true), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), setMode(Eq(Mode::LAUNCH), Eq(true)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(-1)));
        EXPECT_CALL(*mMockHal.get(), isModeSupported(Eq(Mode::DISPLAY_INACTIVE), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(-1)));
    }

    auto result = mWrapper->setMode(Mode::LAUNCH, true);
    ASSERT_TRUE(result.isFailed());
    result = mWrapper->setMode(Mode::DISPLAY_INACTIVE, false);
    ASSERT_TRUE(result.isFailed());
}

TEST_F(PowerHalWrapperAidlTest, TestSetModeUnsupported) {
    EXPECT_CALL(*mMockHal.get(), isModeSupported(Eq(Mode::LAUNCH), _))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<1>(false), Return(Status())));

    auto result = mWrapper->setMode(Mode::LAUNCH, true);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->setMode(Mode::CAMERA_STREAMING_HIGH, true);
    ASSERT_TRUE(result.isUnsupported());
}

TEST_F(PowerHalWrapperAidlTest, TestSetModeMultiThreadCheckSupportedOnlyOnce) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), isModeSupported(Eq(Mode::LAUNCH), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(true), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), setMode(Eq(Mode::LAUNCH), Eq(false))).Times(Exactly(10));
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() {
            auto result = mWrapper->setMode(Mode::LAUNCH, false);
            ASSERT_TRUE(result.isOk());
        }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });
}

TEST_F(PowerHalWrapperAidlTest, TestCreateHintSessionSuccessful) {
    std::vector<int> threadIds{gettid()};
    int32_t tgid = 999;
    int32_t uid = 1001;
    int64_t durationNanos = 16666666L;
    EXPECT_CALL(*mMockHal.get(),
                createHintSession(Eq(tgid), Eq(uid), Eq(threadIds), Eq(durationNanos), _))
            .Times(Exactly(1));
    auto result = mWrapper->createHintSession(tgid, uid, threadIds, durationNanos);
    ASSERT_TRUE(result.isOk());
}

TEST_F(PowerHalWrapperAidlTest, TestCreateHintSessionFailed) {
    int32_t tgid = 999;
    int32_t uid = 1001;
    std::vector<int> threadIds{};
    int64_t durationNanos = 16666666L;
    EXPECT_CALL(*mMockHal.get(),
                createHintSession(Eq(tgid), Eq(uid), Eq(threadIds), Eq(durationNanos), _))
            .Times(Exactly(1))
            .WillRepeatedly(Return(Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT)));
    auto result = mWrapper->createHintSession(tgid, uid, threadIds, durationNanos);
    ASSERT_TRUE(result.isFailed());
}

TEST_F(PowerHalWrapperAidlTest, TestGetHintSessionPreferredRate) {
    EXPECT_CALL(*mMockHal.get(), getHintSessionPreferredRate(_)).Times(Exactly(1));
    auto result = mWrapper->getHintSessionPreferredRate();
    ASSERT_TRUE(result.isOk());
    int64_t rate = result.value();
    ASSERT_GE(0, rate);
}
