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

#define LOG_TAG "PowerHalWrapperHidlV1_1Test"

#include <aidl/android/hardware/power/Boost.h>
#include <aidl/android/hardware/power/IPower.h>
#include <aidl/android/hardware/power/Mode.h>
#include <android/hardware/power/1.1/IPower.h>
#include <binder/IServiceManager.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <powermanager/PowerHalWrapper.h>
#include <utils/Log.h>

using aidl::android::hardware::power::Boost;
using aidl::android::hardware::power::Mode;
using android::hardware::power::V1_0::Feature;
using android::hardware::power::V1_0::PowerHint;
using IPowerV1_1 = android::hardware::power::V1_1::IPower;

using namespace android;
using namespace android::power;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockIPowerV1_1 : public IPowerV1_1 {
public:
    MOCK_METHOD(hardware::Return<void>, setInteractive, (bool interactive), (override));
    MOCK_METHOD(hardware::Return<void>, powerHint, (PowerHint hint, int32_t data), (override));
    MOCK_METHOD(hardware::Return<void>, setFeature, (Feature feature, bool activate), (override));
    MOCK_METHOD(hardware::Return<void>, getPlatformLowPowerStats,
                (getPlatformLowPowerStats_cb _hidl_cb), (override));
    MOCK_METHOD(hardware::Return<void>, powerHintAsync, (PowerHint hint, int32_t data), (override));
    MOCK_METHOD(hardware::Return<void>, getSubsystemLowPowerStats,
                (getSubsystemLowPowerStats_cb _hidl_cb), (override));
};

// -------------------------------------------------------------------------------------------------

class PowerHalWrapperHidlV1_1Test : public Test {
public:
    void SetUp() override;

protected:
    std::unique_ptr<HalWrapper> mWrapper = nullptr;
    sp<StrictMock<MockIPowerV1_1>> mMockHal = nullptr;
};

// -------------------------------------------------------------------------------------------------

void PowerHalWrapperHidlV1_1Test::SetUp() {
    mMockHal = new StrictMock<MockIPowerV1_1>();
    mWrapper = std::make_unique<HidlHalWrapperV1_1>(mMockHal);
    ASSERT_NE(mWrapper, nullptr);
    EXPECT_CALL(*mMockHal.get(), powerHint(_, _)).Times(0);
}

// -------------------------------------------------------------------------------------------------

TEST_F(PowerHalWrapperHidlV1_1Test, TestSetBoostSuccessful) {
    EXPECT_CALL(*mMockHal.get(), powerHintAsync(Eq(PowerHint::INTERACTION), Eq(1000)))
            .Times(Exactly(1));

    auto result = mWrapper->setBoost(Boost::INTERACTION, 1000);
    ASSERT_TRUE(result.isOk());
}

TEST_F(PowerHalWrapperHidlV1_1Test, TestSetBoostFailed) {
    EXPECT_CALL(*mMockHal.get(), powerHintAsync(Eq(PowerHint::INTERACTION), Eq(1000)))
            .Times(Exactly(1))
            .WillRepeatedly([](PowerHint, int32_t) {
                return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
            });

    auto result = mWrapper->setBoost(Boost::INTERACTION, 1000);
    ASSERT_TRUE(result.isFailed());
}

TEST_F(PowerHalWrapperHidlV1_1Test, TestSetBoostUnsupported) {
    EXPECT_CALL(*mMockHal.get(), powerHintAsync(_, _)).Times(0);
    EXPECT_CALL(*mMockHal.get(), setInteractive(_)).Times(0);
    EXPECT_CALL(*mMockHal.get(), setFeature(_, _)).Times(0);

    auto result = mWrapper->setBoost(Boost::CAMERA_LAUNCH, 10);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->setBoost(Boost::ML_ACC, 10);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 10);
    ASSERT_TRUE(result.isUnsupported());
}

TEST_F(PowerHalWrapperHidlV1_1Test, TestSetMode) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), powerHintAsync(Eq(PowerHint::LAUNCH), Eq(true)))
                .Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), powerHintAsync(Eq(PowerHint::LOW_POWER), Eq(false)))
                .Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), powerHintAsync(Eq(PowerHint::SUSTAINED_PERFORMANCE), Eq(true)))
                .Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), powerHintAsync(Eq(PowerHint::VR_MODE), Eq(false)))
                .Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), setInteractive(Eq(true))).Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(),
                    setFeature(Eq(Feature::POWER_FEATURE_DOUBLE_TAP_TO_WAKE), Eq(false)))
                .Times(Exactly(1));
    }

    auto result = mWrapper->setMode(Mode::LAUNCH, true);
    ASSERT_TRUE(result.isOk());
    result = mWrapper->setMode(Mode::LOW_POWER, false);
    ASSERT_TRUE(result.isOk());
    result = mWrapper->setMode(Mode::SUSTAINED_PERFORMANCE, true);
    ASSERT_TRUE(result.isOk());
    result = mWrapper->setMode(Mode::VR, false);
    ASSERT_TRUE(result.isOk());
    result = mWrapper->setMode(Mode::INTERACTIVE, true);
    ASSERT_TRUE(result.isOk());
    result = mWrapper->setMode(Mode::DOUBLE_TAP_TO_WAKE, false);
    ASSERT_TRUE(result.isOk());
}

TEST_F(PowerHalWrapperHidlV1_1Test, TestSetModeFailed) {
    EXPECT_CALL(*mMockHal.get(), powerHintAsync(Eq(PowerHint::LAUNCH), Eq(true)))
            .Times(Exactly(1))
            .WillRepeatedly([](PowerHint, int32_t) {
                return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
            });

    auto result = mWrapper->setMode(Mode::LAUNCH, 1);
    ASSERT_TRUE(result.isFailed());
}

TEST_F(PowerHalWrapperHidlV1_1Test, TestSetModeIgnored) {
    EXPECT_CALL(*mMockHal.get(), powerHintAsync(_, _)).Times(0);
    EXPECT_CALL(*mMockHal.get(), setInteractive(_)).Times(0);
    EXPECT_CALL(*mMockHal.get(), setFeature(_, _)).Times(0);

    auto result = mWrapper->setMode(Mode::CAMERA_STREAMING_HIGH, true);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->setMode(Mode::EXPENSIVE_RENDERING, false);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->setMode(Mode::FIXED_PERFORMANCE, true);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->setMode(Mode::GAME_LOADING, false);
    ASSERT_TRUE(result.isUnsupported());
}
