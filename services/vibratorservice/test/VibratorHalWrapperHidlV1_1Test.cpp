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

#define LOG_TAG "VibratorHalWrapperHidlV1_1Test"

#include <android/hardware/vibrator/IVibrator.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>

#include <vibratorservice/VibratorHalWrapper.h>

#include "test_utils.h"

namespace V1_0 = android::hardware::vibrator::V1_0;
namespace V1_1 = android::hardware::vibrator::V1_1;

using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockIVibratorV1_1 : public V1_1::IVibrator {
public:
    MOCK_METHOD(hardware::Return<V1_0::Status>, on, (uint32_t timeoutMs), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, off, (), (override));
    MOCK_METHOD(hardware::Return<bool>, supportsAmplitudeControl, (), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, setAmplitude, (uint8_t amplitude), (override));
    MOCK_METHOD(hardware::Return<void>, perform,
                (V1_0::Effect effect, V1_0::EffectStrength strength, perform_cb cb), (override));
    MOCK_METHOD(hardware::Return<void>, perform_1_1,
                (V1_1::Effect_1_1 effect, V1_0::EffectStrength strength, perform_cb cb),
                (override));
};

// -------------------------------------------------------------------------------------------------

class VibratorHalWrapperHidlV1_1Test : public Test {
public:
    void SetUp() override {
        mMockHal = new StrictMock<MockIVibratorV1_1>();
        mWrapper = std::make_unique<vibrator::HidlHalWrapperV1_1>(mMockHal);
        ASSERT_NE(mWrapper, nullptr);
    }

protected:
    std::unique_ptr<vibrator::HalWrapper> mWrapper = nullptr;
    sp<StrictMock<MockIVibratorV1_1>> mMockHal = nullptr;
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorHalWrapperHidlV1_1Test, TestPerformEffectV1_0) {
    EXPECT_CALL(*mMockHal.get(),
                perform(Eq(V1_0::Effect::CLICK), Eq(V1_0::EffectStrength::LIGHT), _))
            .Times(Exactly(1))
            .WillRepeatedly(
                    [](V1_0::Effect, V1_0::EffectStrength, MockIVibratorV1_1::perform_cb cb) {
                        cb(V1_0::Status::OK, 100);
                        return hardware::Return<void>();
                    });

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());
    auto result = mWrapper->performEffect(Effect::CLICK, EffectStrength::LIGHT, callback);

    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(100ms, result.value());
    // TODO(b/153418251): check callback will be triggered once implemented
    ASSERT_EQ(0, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_1Test, TestPerformEffectV1_1) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_1(Eq(V1_1::Effect_1_1::TICK), Eq(V1_0::EffectStrength::LIGHT), _))
                .Times(Exactly(1))
                .WillRepeatedly([](V1_1::Effect_1_1, V1_0::EffectStrength,
                                   MockIVibratorV1_1::perform_cb cb) {
                    cb(V1_0::Status::OK, 10);
                    return hardware::Return<void>();
                });
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_1(Eq(V1_1::Effect_1_1::TICK), Eq(V1_0::EffectStrength::MEDIUM), _))
                .Times(Exactly(1))
                .WillRepeatedly([](V1_1::Effect_1_1, V1_0::EffectStrength,
                                   MockIVibratorV1_1::perform_cb cb) {
                    cb(V1_0::Status::UNSUPPORTED_OPERATION, 0);
                    return hardware::Return<void>();
                });
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_1(Eq(V1_1::Effect_1_1::TICK), Eq(V1_0::EffectStrength::STRONG), _))
                .Times(Exactly(2))
                .WillOnce([](V1_1::Effect_1_1, V1_0::EffectStrength,
                             MockIVibratorV1_1::perform_cb cb) {
                    cb(V1_0::Status::BAD_VALUE, 0);
                    return hardware::Return<void>();
                })
                .WillRepeatedly(
                        [](V1_1::Effect_1_1, V1_0::EffectStrength, MockIVibratorV1_1::perform_cb) {
                            return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
                        });
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performEffect(Effect::TICK, EffectStrength::LIGHT, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(10ms, result.value());
    // TODO(b/153418251): check callback will be triggered once implemented
    ASSERT_EQ(0, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::TICK, EffectStrength::MEDIUM, callback);
    ASSERT_TRUE(result.isUnsupported());
    // Callback not triggered
    ASSERT_EQ(0, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::TICK, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());
    // Callback not triggered
    ASSERT_EQ(0, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::TICK, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());
    // Callback not triggered
    ASSERT_EQ(0, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_1Test, TestPerformEffectUnsupported) {
    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());
    // Using THUD that is only available in v1.2
    auto result = mWrapper->performEffect(Effect::THUD, EffectStrength::LIGHT, callback);
    ASSERT_TRUE(result.isUnsupported());
    ASSERT_EQ(0, *callbackCounter.get());
}
