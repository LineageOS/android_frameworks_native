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

#define LOG_TAG "VibratorHalControllerTest"

#include <android/hardware/vibrator/IVibrator.h>
#include <cutils/atomic.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>
#include <thread>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalController.h>
#include <vibratorservice/VibratorHalWrapper.h>

#include "test_utils.h"

using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::CompositePrimitive;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;

using std::chrono::milliseconds;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockHalWrapper : public vibrator::HalWrapper {
public:
    MockHalWrapper(std::shared_ptr<vibrator::CallbackScheduler> scheduler)
          : HalWrapper(scheduler) {}
    virtual ~MockHalWrapper() = default;

    MOCK_METHOD(vibrator::HalResult<void>, ping, (), (override));
    MOCK_METHOD(vibrator::HalResult<void>, on,
                (milliseconds timeout, const std::function<void()>& completionCallback),
                (override));
    MOCK_METHOD(vibrator::HalResult<void>, off, (), (override));
    MOCK_METHOD(vibrator::HalResult<void>, setAmplitude, (int32_t amplitude), (override));
    MOCK_METHOD(vibrator::HalResult<void>, setExternalControl, (bool enabled), (override));
    MOCK_METHOD(vibrator::HalResult<void>, alwaysOnEnable,
                (int32_t id, Effect effect, EffectStrength strength), (override));
    MOCK_METHOD(vibrator::HalResult<void>, alwaysOnDisable, (int32_t id), (override));
    MOCK_METHOD(vibrator::HalResult<vibrator::Capabilities>, getCapabilities, (), (override));
    MOCK_METHOD(vibrator::HalResult<std::vector<Effect>>, getSupportedEffects, (), (override));
    MOCK_METHOD(vibrator::HalResult<milliseconds>, performEffect,
                (Effect effect, EffectStrength strength,
                 const std::function<void()>& completionCallback),
                (override));
    MOCK_METHOD(vibrator::HalResult<void>, performComposedEffect,
                (const std::vector<CompositeEffect>& primitiveEffects,
                 const std::function<void()>& completionCallback),
                (override));

    vibrator::CallbackScheduler* getCallbackScheduler() { return mCallbackScheduler.get(); }
};

class TestHalConnector : public vibrator::HalConnector {
public:
    TestHalConnector(int32_t* connectCounter, std::shared_ptr<MockHalWrapper> mockHal)
          : mConnectCounter(connectCounter), mMockHal(std::move(mockHal)) {}
    ~TestHalConnector() = default;

    std::shared_ptr<vibrator::HalWrapper> connect(
            std::shared_ptr<vibrator::CallbackScheduler>) override final {
        android_atomic_inc(mConnectCounter);
        return mMockHal;
    }

private:
    int32_t* mConnectCounter;
    std::shared_ptr<MockHalWrapper> mMockHal;
};

class FailingHalConnector : public vibrator::HalConnector {
public:
    FailingHalConnector(int32_t* connectCounter) : mConnectCounter(connectCounter) {}
    ~FailingHalConnector() = default;

    std::shared_ptr<vibrator::HalWrapper> connect(
            std::shared_ptr<vibrator::CallbackScheduler>) override final {
        android_atomic_inc(mConnectCounter);
        return nullptr;
    }

private:
    int32_t* mConnectCounter;
};

// -------------------------------------------------------------------------------------------------

class VibratorHalControllerTest : public Test {
public:
    void SetUp() override {
        mConnectCounter = 0;
        auto callbackScheduler = std::make_shared<vibrator::CallbackScheduler>();
        mMockHal = std::make_shared<StrictMock<MockHalWrapper>>(callbackScheduler);
        auto halConnector = std::make_unique<TestHalConnector>(&mConnectCounter, mMockHal);
        mController = std::make_unique<vibrator::HalController>(std::move(halConnector),
                                                                std::move(callbackScheduler));
        ASSERT_NE(mController, nullptr);
    }

protected:
    int32_t mConnectCounter;
    std::shared_ptr<MockHalWrapper> mMockHal;
    std::unique_ptr<vibrator::HalController> mController;

    void setHalExpectations(std::vector<CompositeEffect> compositeEffects,
                            vibrator::HalResult<void> voidResult,
                            vibrator::HalResult<vibrator::Capabilities> capabilitiesResult,
                            vibrator::HalResult<std::vector<Effect>> effectsResult,
                            vibrator::HalResult<milliseconds> durationResult) {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), ping()).Times(Exactly(1)).WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), on(Eq(10ms), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), off()).Times(Exactly(1)).WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(255)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), setExternalControl(Eq(true)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(),
                    alwaysOnEnable(Eq(1), Eq(Effect::CLICK), Eq(EffectStrength::LIGHT)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), alwaysOnDisable(Eq(1)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), getCapabilities())
                .Times(Exactly(1))
                .WillRepeatedly(Return(capabilitiesResult));
        EXPECT_CALL(*mMockHal.get(), getSupportedEffects())
                .Times(Exactly(1))
                .WillRepeatedly(Return(effectsResult));
        EXPECT_CALL(*mMockHal.get(), performEffect(Eq(Effect::CLICK), Eq(EffectStrength::LIGHT), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(durationResult));
        EXPECT_CALL(*mMockHal.get(), performComposedEffect(Eq(compositeEffects), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(voidResult));
    }
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorHalControllerTest, TestApiCallsAreForwardedToHal) {
    std::vector<Effect> supportedEffects;
    supportedEffects.push_back(Effect::CLICK);
    supportedEffects.push_back(Effect::TICK);
    std::vector<CompositeEffect> compositeEffects;
    compositeEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::SPIN, 100ms, 0.5f));
    compositeEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::THUD, 1000ms, 1.0f));

    setHalExpectations(compositeEffects, vibrator::HalResult<void>::ok(),
                       vibrator::HalResult<vibrator::Capabilities>::ok(
                               vibrator::Capabilities::ON_CALLBACK),
                       vibrator::HalResult<std::vector<Effect>>::ok(supportedEffects),
                       vibrator::HalResult<milliseconds>::ok(100ms));

    ASSERT_TRUE(mController->ping().isOk());
    ASSERT_TRUE(mController->on(10ms, []() {}).isOk());
    ASSERT_TRUE(mController->off().isOk());
    ASSERT_TRUE(mController->setAmplitude(255).isOk());
    ASSERT_TRUE(mController->setExternalControl(true).isOk());
    ASSERT_TRUE(mController->alwaysOnEnable(1, Effect::CLICK, EffectStrength::LIGHT).isOk());
    ASSERT_TRUE(mController->alwaysOnDisable(1).isOk());

    auto getCapabilitiesResult = mController->getCapabilities();
    ASSERT_TRUE(getCapabilitiesResult.isOk());
    ASSERT_EQ(vibrator::Capabilities::ON_CALLBACK, getCapabilitiesResult.value());

    auto getSupportedEffectsResult = mController->getSupportedEffects();
    ASSERT_TRUE(getSupportedEffectsResult.isOk());
    ASSERT_EQ(supportedEffects, getSupportedEffectsResult.value());

    auto performEffectResult =
            mController->performEffect(Effect::CLICK, EffectStrength::LIGHT, []() {});
    ASSERT_TRUE(performEffectResult.isOk());
    ASSERT_EQ(100ms, performEffectResult.value());

    ASSERT_TRUE(mController->performComposedEffect(compositeEffects, []() {}).isOk());

    // No reconnection attempt was made after the first one.
    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorHalControllerTest, TestUnsupportedApiResultDoNotResetHalConnection) {
    setHalExpectations(std::vector<CompositeEffect>(), vibrator::HalResult<void>::unsupported(),
                       vibrator::HalResult<vibrator::Capabilities>::unsupported(),
                       vibrator::HalResult<std::vector<Effect>>::unsupported(),
                       vibrator::HalResult<milliseconds>::unsupported());

    ASSERT_EQ(0, mConnectCounter);

    ASSERT_TRUE(mController->ping().isUnsupported());
    ASSERT_TRUE(mController->on(10ms, []() {}).isUnsupported());
    ASSERT_TRUE(mController->off().isUnsupported());
    ASSERT_TRUE(mController->setAmplitude(255).isUnsupported());
    ASSERT_TRUE(mController->setExternalControl(true).isUnsupported());
    ASSERT_TRUE(
            mController->alwaysOnEnable(1, Effect::CLICK, EffectStrength::LIGHT).isUnsupported());
    ASSERT_TRUE(mController->alwaysOnDisable(1).isUnsupported());
    ASSERT_TRUE(mController->getCapabilities().isUnsupported());
    ASSERT_TRUE(mController->getSupportedEffects().isUnsupported());
    ASSERT_TRUE(mController->performEffect(Effect::CLICK, EffectStrength::LIGHT, []() {})
                        .isUnsupported());
    ASSERT_TRUE(mController->performComposedEffect(std::vector<CompositeEffect>(), []() {})
                        .isUnsupported());

    // No reconnection attempt was made after the first one.
    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorHalControllerTest, TestFailedApiResultResetsHalConnection) {
    setHalExpectations(std::vector<CompositeEffect>(), vibrator::HalResult<void>::failed(),
                       vibrator::HalResult<vibrator::Capabilities>::failed(),
                       vibrator::HalResult<std::vector<Effect>>::failed(),
                       vibrator::HalResult<milliseconds>::failed());

    ASSERT_EQ(0, mConnectCounter);

    ASSERT_TRUE(mController->ping().isFailed());
    ASSERT_TRUE(mController->on(10ms, []() {}).isFailed());
    ASSERT_TRUE(mController->off().isFailed());
    ASSERT_TRUE(mController->setAmplitude(255).isFailed());
    ASSERT_TRUE(mController->setExternalControl(true).isFailed());
    ASSERT_TRUE(mController->alwaysOnEnable(1, Effect::CLICK, EffectStrength::LIGHT).isFailed());
    ASSERT_TRUE(mController->alwaysOnDisable(1).isFailed());
    ASSERT_TRUE(mController->getCapabilities().isFailed());
    ASSERT_TRUE(mController->getSupportedEffects().isFailed());
    ASSERT_TRUE(
            mController->performEffect(Effect::CLICK, EffectStrength::LIGHT, []() {}).isFailed());
    ASSERT_TRUE(
            mController->performComposedEffect(std::vector<CompositeEffect>(), []() {}).isFailed());

    // One reconnection attempt per api call.
    ASSERT_EQ(11, mConnectCounter);
}

TEST_F(VibratorHalControllerTest, TestMultiThreadConnectsOnlyOnce) {
    ASSERT_EQ(0, mConnectCounter);

    EXPECT_CALL(*mMockHal.get(), ping())
            .Times(Exactly(10))
            .WillRepeatedly(Return(vibrator::HalResult<void>::ok()));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() { ASSERT_TRUE(mController->ping().isOk()); }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    // Connector was called only by the first thread to use the api.
    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorHalControllerTest, TestNoHalReturnsUnsupportedAndAttemptsToReconnect) {
    auto failingHalConnector = std::make_unique<FailingHalConnector>(&mConnectCounter);
    mController =
            std::make_unique<vibrator::HalController>(std::move(failingHalConnector), nullptr);
    ASSERT_EQ(0, mConnectCounter);

    ASSERT_TRUE(mController->ping().isUnsupported());
    ASSERT_TRUE(mController->on(10ms, []() {}).isUnsupported());
    ASSERT_TRUE(mController->off().isUnsupported());
    ASSERT_TRUE(mController->setAmplitude(255).isUnsupported());
    ASSERT_TRUE(mController->setExternalControl(true).isUnsupported());
    ASSERT_TRUE(
            mController->alwaysOnEnable(1, Effect::CLICK, EffectStrength::LIGHT).isUnsupported());
    ASSERT_TRUE(mController->alwaysOnDisable(1).isUnsupported());
    ASSERT_TRUE(mController->getCapabilities().isUnsupported());
    ASSERT_TRUE(mController->getSupportedEffects().isUnsupported());
    ASSERT_TRUE(mController->performEffect(Effect::CLICK, EffectStrength::LIGHT, []() {})
                        .isUnsupported());
    ASSERT_TRUE(mController->performComposedEffect(std::vector<CompositeEffect>(), []() {})
                        .isUnsupported());

    // One reconnection attempt per api call.
    ASSERT_EQ(11, mConnectCounter);
}

TEST_F(VibratorHalControllerTest, TestScheduledCallbackSurvivesReconnection) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), on(Eq(10ms), _))
                .Times(Exactly(1))
                .WillRepeatedly([&](milliseconds timeout, std::function<void()> callback) {
                    mMockHal.get()->getCallbackScheduler()->schedule(callback, timeout);
                    return vibrator::HalResult<void>::ok();
                });
        EXPECT_CALL(*mMockHal.get(), ping())
                .Times(Exactly(1))
                .WillRepeatedly(Return(vibrator::HalResult<void>::failed()));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mController->on(10ms, callback).isOk());
    ASSERT_TRUE(mController->ping().isFailed()); // Delete connected HAL pointer from controller.
    mMockHal.reset();                            // Delete mock HAL pointer from test class.
    ASSERT_EQ(0, *callbackCounter.get());

    // Callback triggered even after HalWrapper was completely destroyed.
    std::this_thread::sleep_for(15ms);
    ASSERT_EQ(1, *callbackCounter.get());
}
