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

#define LOG_TAG "VibratorManagerHalControllerTest"

#include <cutils/atomic.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>

#include <vibratorservice/VibratorManagerHalWrapper.h>

#include "test_utils.h"

using namespace android;
using namespace testing;

static constexpr int MAX_ATTEMPTS = 2;

class MockManagerHalWrapper : public vibrator::ManagerHalWrapper {
public:
    MOCK_METHOD(vibrator::HalResult<void>, ping, (), (override));
    MOCK_METHOD(vibrator::HalResult<int32_t>, getCapabilities, (), (override));
    MOCK_METHOD(vibrator::HalResult<std::vector<int32_t>>, getVibratorIds, (), (override));
    MOCK_METHOD(vibrator::HalResult<std::shared_ptr<vibrator::HalController>>, getVibrator,
                (int32_t id), (override));
    MOCK_METHOD(vibrator::HalResult<void>, prepareSynced, (const std::vector<int32_t>& ids),
                (override));
    MOCK_METHOD(vibrator::HalResult<void>, triggerSynced,
                (const std::function<void()>& completionCallback), (override));
    MOCK_METHOD(vibrator::HalResult<void>, cancelSynced, (), (override));
};

class VibratorManagerHalControllerTest : public Test {
public:
    void SetUp() override {
        mConnectCounter = 0;
        auto callbackScheduler = std::make_shared<vibrator::CallbackScheduler>();
        mMockHal = std::make_shared<StrictMock<MockHalWrapper>>(callbackScheduler);
        mController = std::make_unique<
                vibrator::HalController>(std::move(callbackScheduler),
                                         [&](std::shared_ptr<vibrator::CallbackScheduler>) {
                                             android_atomic_inc(&(this->mConnectCounter));
                                             return this->mMockHal;
                                         });
        ASSERT_NE(mController, nullptr);
    }

protected:
    int32_t mConnectCounter;
    std::shared_ptr<MockManagerHalWrapper> mMockHal;
    std::unique_ptr<vibrator::ManagerHalController> mController;

    void setHalExpectations(int32_t cardinality, std::vector<int32_t> ids,
                            vibrator::HalResult<void> voidResult,
                            vibrator::HalResult<vibrator::ManagerCapabilities> capabilitiesResult,
                            vibrator::HalResult<std::vector<int32_t>> idsResult,
                            vibrator::HalResult<std::shared_ptr<HalController>> vibratorResult) {
        EXPECT_CALL(*mMockHal.get(), ping())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), getCapabilities())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(capabilitiesResult));
        EXPECT_CALL(*mMockHal.get(), getVibratorIds())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(idsResult));
        EXPECT_CALL(*mMockHal.get(), getVibrator(_))
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(vibratorResult));
        EXPECT_CALL(*mMockHal.get(), prepareSynced(_))
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), triggerSynced(_))
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), cancelSynced())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));

        if (cardinality > 1) {
            // One reconnection call after each failure.
            EXPECT_CALL(*mMockHal.get(), tryReconnect()).Times(Exactly(7 * cardinality));
        }
    }
};

TEST_F(VibratorManagerHalControllerTest, TestInit) {
    ASSERT_TRUE(mController->init());
    ASSERT_EQ(1, mConnectCounter);

    // Noop when wrapper was already initialized.
    ASSERT_TRUE(mController->init());
    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestApiCallsAreForwardedToHal) {
    std::vector<int32_t> ids;
    ids.push_back(1);
    ids.push_back(2);

    setHalExpectations(/* cardinality= */ 1, ids, vibrator::HalResult<void>::ok(),
                       vibrator::HalResult<vibrator::ManagerCapabilities>::ok(
                               vibrator::ManagerCapabilities::SYNC),
                       vibrator::HalResult<std::vector<int32_t>>::ok(ids),
                       vibrator::HalResult<std::shared_ptr<vibrator::HalController>>::ok(nullptr));

    ASSERT_TRUE(mController->ping().isOk());

    auto getCapabilitiesResult = mController->getCapabilities();
    ASSERT_TRUE(getCapabilitiesResult.isOk());
    ASSERT_EQ(vibrator::ManagerCapabilities::SYNC, getCapabilitiesResult.value());

    auto getVibratorIdsResult = mController->getVibratorIds();
    ASSERT_TRUE(getVibratorIdsResult.isOk());
    ASSERT_EQ(ids, getVibratorIdsResult.value());

    auto getVibratorResult = mController->getVibrator(1);
    ASSERT_TRUE(getVibratorResult.isOk());
    ASSERT_EQ(nullptr, getVibratorResult.value());

    ASSERT_TRUE(mController->prepareSynced(ids).isOk());
    ASSERT_TRUE(mController->triggerSynced([]() {}).isOk());
    ASSERT_TRUE(mController->cancelSynced().isOk());

    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestUnsupportedApiResultDoNotResetHalConnection) {
    std::vector<int32_t> ids;
    setHalExpectations(/* cardinality= */ 1, ids, vibrator::HalResult<void>::unsupported(),
                       vibrator::HalResult<vibrator::ManagerCapabilities>::unsupported(),
                       vibrator::HalResult<std::vector<int32_t>>::unsupported(),
                       vibrator::HalResult<
                               std::shared_ptr<vibrator::HalController>>::unsupported());

    ASSERT_EQ(0, mConnectCounter);

    ASSERT_TRUE(mController->ping().isUnsupported());
    ASSERT_TRUE(mController->getCapabilities().isUnsupported());
    ASSERT_TRUE(mController->getVibratorIds().isUnsupported());
    ASSERT_TRUE(mController->getVibrator(1).isUnsupported());
    ASSERT_TRUE(mController->prepareSynced(ids).isUnsupported());
    ASSERT_TRUE(mController->triggerSynced([]() {}).isUnsupported());
    ASSERT_TRUE(mController->cancelSynced().isUnsupported());

    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestFailedApiResultResetsHalConnection) {
    std::vector<int32_t> ids;
    setHalExpectations(/* cardinality= */ 1, ids, vibrator::HalResult<void>::failed("message"),
                       vibrator::HalResult<vibrator::ManagerCapabilities>::failed("message"),
                       vibrator::HalResult<std::vector<int32_t>>::failed("message"),
                       vibrator::HalResult<std::shared_ptr<vibrator::HalController>>::failed(
                               "message"));

    ASSERT_EQ(0, mConnectCounter);

    ASSERT_TRUE(mController->ping().isFailed());
    ASSERT_TRUE(mController->getCapabilities().isFailed());
    ASSERT_TRUE(mController->getVibratorIds().isFailed());
    ASSERT_TRUE(mController->getVibrator(1).isFailed());
    ASSERT_TRUE(mController->prepareSynced(ids).isFailed());
    ASSERT_TRUE(mController->triggerSynced([]() {}).isFailed());
    ASSERT_TRUE(mController->cancelSynced().isFailed());

    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestFailedApiResultReturnsSuccessAfterRetries) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), ping())
                .Times(Exactly(1))
                .WillRepeatedly(Return(vibrator::HalResult<void>::failed("message")));
        EXPECT_CALL(*mMockHal.get(), tryReconnect()).Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), ping())
                .Times(Exactly(1))
                .WillRepeatedly(Return(vibrator::HalResult<void>::ok()));
    }

    ASSERT_EQ(0, mConnectCounter);
    ASSERT_TRUE(mController->ping().isOk());
    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestMultiThreadConnectsOnlyOnce) {
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
