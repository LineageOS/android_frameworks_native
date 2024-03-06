/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <aidl/android/hardware/power/IPowerHintSession.h>
#include <powermanager/PowerHintSessionWrapper.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using aidl::android::hardware::power::IPowerHintSession;
using android::power::PowerHintSessionWrapper;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

class MockIPowerHintSession : public IPowerHintSession {
public:
    MockIPowerHintSession() = default;
    MOCK_METHOD(::ndk::ScopedAStatus, updateTargetWorkDuration, (int64_t in_targetDurationNanos),
                (override));
    MOCK_METHOD(::ndk::ScopedAStatus, reportActualWorkDuration,
                (const std::vector<::aidl::android::hardware::power::WorkDuration>& in_durations),
                (override));
    MOCK_METHOD(::ndk::ScopedAStatus, pause, (), (override));
    MOCK_METHOD(::ndk::ScopedAStatus, resume, (), (override));
    MOCK_METHOD(::ndk::ScopedAStatus, close, (), (override));
    MOCK_METHOD(::ndk::ScopedAStatus, sendHint,
                (::aidl::android::hardware::power::SessionHint in_hint), (override));
    MOCK_METHOD(::ndk::ScopedAStatus, setThreads, (const std::vector<int32_t>& in_threadIds),
                (override));
    MOCK_METHOD(::ndk::ScopedAStatus, setMode,
                (::aidl::android::hardware::power::SessionMode in_type, bool in_enabled),
                (override));
    MOCK_METHOD(::ndk::ScopedAStatus, getSessionConfig,
                (::aidl::android::hardware::power::SessionConfig * _aidl_return), (override));
    MOCK_METHOD(::ndk::ScopedAStatus, getInterfaceVersion, (int32_t * _aidl_return), (override));
    MOCK_METHOD(::ndk::ScopedAStatus, getInterfaceHash, (std::string * _aidl_return), (override));
    MOCK_METHOD(::ndk::SpAIBinder, asBinder, (), (override));
    MOCK_METHOD(bool, isRemote, (), (override));
};

class PowerHintSessionWrapperTest : public Test {
public:
    void SetUp() override;

protected:
    std::shared_ptr<NiceMock<MockIPowerHintSession>> mMockSession = nullptr;
    std::unique_ptr<PowerHintSessionWrapper> mSession = nullptr;
};

void PowerHintSessionWrapperTest::SetUp() {
    mMockSession = ndk::SharedRefBase::make<NiceMock<MockIPowerHintSession>>();
    EXPECT_CALL(*mMockSession, getInterfaceVersion(_)).WillRepeatedly(([](int32_t* ret) {
        *ret = 5;
        return ndk::ScopedAStatus::ok();
    }));
    mSession = std::make_unique<PowerHintSessionWrapper>(mMockSession);
    ASSERT_NE(nullptr, mSession);
}

TEST_F(PowerHintSessionWrapperTest, updateTargetWorkDuration) {
    EXPECT_CALL(*mMockSession.get(), updateTargetWorkDuration(1000000000))
            .WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->updateTargetWorkDuration(1000000000);
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, reportActualWorkDuration) {
    EXPECT_CALL(*mMockSession.get(),
                reportActualWorkDuration(
                        std::vector<::aidl::android::hardware::power::WorkDuration>()))
            .WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->reportActualWorkDuration(
            std::vector<::aidl::android::hardware::power::WorkDuration>());
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, pause) {
    EXPECT_CALL(*mMockSession.get(), pause()).WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->pause();
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, resume) {
    EXPECT_CALL(*mMockSession.get(), resume()).WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->resume();
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, close) {
    EXPECT_CALL(*mMockSession.get(), close()).WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->close();
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, sendHint) {
    EXPECT_CALL(*mMockSession.get(),
                sendHint(::aidl::android::hardware::power::SessionHint::CPU_LOAD_UP))
            .WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->sendHint(::aidl::android::hardware::power::SessionHint::CPU_LOAD_UP);
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, setThreads) {
    EXPECT_CALL(*mMockSession.get(), setThreads(_)).WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->setThreads(std::vector<int32_t>{gettid()});
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, setMode) {
    EXPECT_CALL(*mMockSession.get(),
                setMode(::aidl::android::hardware::power::SessionMode::POWER_EFFICIENCY, true))
            .WillOnce(Return(ndk::ScopedAStatus::ok()));
    auto status = mSession->setMode(::aidl::android::hardware::power::SessionMode::POWER_EFFICIENCY,
                                    true);
    ASSERT_TRUE(status.isOk());
}

TEST_F(PowerHintSessionWrapperTest, getSessionConfig) {
    EXPECT_CALL(*mMockSession.get(), getSessionConfig(_))
            .WillOnce(DoAll(SetArgPointee<0>(
                                    aidl::android::hardware::power::SessionConfig{.id = 12L}),
                            Return(ndk::ScopedAStatus::ok())));
    auto status = mSession->getSessionConfig();
    ASSERT_TRUE(status.isOk());
}
