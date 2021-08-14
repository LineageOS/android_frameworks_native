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

#define LOG_TAG "PowerHalControllerTest"

#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/Mode.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <powermanager/PowerHalController.h>
#include <utils/Log.h>

#include <thread>

using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::hardware::power::V1_0::Feature;
using android::hardware::power::V1_0::IPower;
using android::hardware::power::V1_0::PowerHint;

using namespace android;
using namespace android::power;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockIPowerV1_0 : public IPower {
public:
    MOCK_METHOD(hardware::Return<void>, setInteractive, (bool interactive), (override));
    MOCK_METHOD(hardware::Return<void>, powerHint, (PowerHint hint, int32_t data), (override));
    MOCK_METHOD(hardware::Return<void>, setFeature, (Feature feature, bool activate), (override));
    MOCK_METHOD(hardware::Return<void>, getPlatformLowPowerStats,
                (getPlatformLowPowerStats_cb _hidl_cb), (override));
};

class TestPowerHalConnector : public HalConnector {
public:
    TestPowerHalConnector(sp<IPower> powerHal) : mHal(std::move(powerHal)) {}
    virtual ~TestPowerHalConnector() = default;

    virtual std::unique_ptr<HalWrapper> connect() override {
        mCountMutex.lock();
        ++mConnectedCount;
        mCountMutex.unlock();
        return std::make_unique<HidlHalWrapperV1_0>(mHal);
    }

    void reset() override {
        mCountMutex.lock();
        ++mResetCount;
        mCountMutex.unlock();
    }

    int getConnectCount() { return mConnectedCount; }

    int getResetCount() { return mResetCount; }

private:
    sp<IPower> mHal = nullptr;
    std::mutex mCountMutex;
    int mConnectedCount = 0;
    int mResetCount = 0;
};

class AlwaysFailingTestPowerHalConnector : public TestPowerHalConnector {
public:
    AlwaysFailingTestPowerHalConnector() : TestPowerHalConnector(nullptr) {}

    std::unique_ptr<HalWrapper> connect() override {
        // Call parent to update counter, but ignore connected HalWrapper.
        TestPowerHalConnector::connect();
        return nullptr;
    }
};

// -------------------------------------------------------------------------------------------------

class PowerHalControllerTest : public Test {
public:
    void SetUp() override {
        mMockHal = new StrictMock<MockIPowerV1_0>();
        std::unique_ptr<TestPowerHalConnector> halConnector =
                std::make_unique<TestPowerHalConnector>(mMockHal);
        mHalConnector = halConnector.get();
        mHalController = std::make_unique<PowerHalController>(std::move(halConnector));
    }

protected:
    sp<StrictMock<MockIPowerV1_0>> mMockHal = nullptr;
    TestPowerHalConnector* mHalConnector = nullptr;
    std::unique_ptr<PowerHalController> mHalController = nullptr;
};

// -------------------------------------------------------------------------------------------------

TEST_F(PowerHalControllerTest, TestInitConnectsToPowerHalOnlyOnce) {
    int powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 0);

    mHalController->init();
    mHalController->init();

    // PowerHalConnector was called only once and never reset.
    powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 1);
    int powerHalResetCount = mHalConnector->getResetCount();
    EXPECT_EQ(powerHalResetCount, 0);
}

TEST_F(PowerHalControllerTest, TestUnableToConnectToPowerHalIgnoresAllApiCalls) {
    std::unique_ptr<AlwaysFailingTestPowerHalConnector> halConnector =
            std::make_unique<AlwaysFailingTestPowerHalConnector>();
    AlwaysFailingTestPowerHalConnector* failingHalConnector = halConnector.get();
    PowerHalController halController(std::move(halConnector));

    int powerHalConnectCount = failingHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 0);

    // Still works with EmptyPowerHalWrapper as fallback ignoring every api call
    // and logging.
    auto result = halController.setBoost(Boost::INTERACTION, 1000);
    ASSERT_TRUE(result.isUnsupported());
    result = halController.setMode(Mode::LAUNCH, true);
    ASSERT_TRUE(result.isUnsupported());

    // PowerHalConnector was called every time to attempt to reconnect with
    // underlying service.
    powerHalConnectCount = failingHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 2);
    // PowerHalConnector was never reset.
    int powerHalResetCount = mHalConnector->getResetCount();
    EXPECT_EQ(powerHalResetCount, 0);
}

TEST_F(PowerHalControllerTest, TestAllApiCallsDelegatedToConnectedPowerHal) {
    int powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 0);

    {
        InSequence seg;
        EXPECT_CALL(*mMockHal.get(), powerHint(Eq(PowerHint::INTERACTION), Eq(100)))
                .Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), powerHint(Eq(PowerHint::LAUNCH), Eq(1))).Times(Exactly(1));
    }

    auto result = mHalController->setBoost(Boost::INTERACTION, 100);
    ASSERT_TRUE(result.isOk());
    result = mHalController->setMode(Mode::LAUNCH, true);
    ASSERT_TRUE(result.isOk());

    // PowerHalConnector was called only once and never reset.
    powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 1);
    int powerHalResetCount = mHalConnector->getResetCount();
    EXPECT_EQ(powerHalResetCount, 0);
}

TEST_F(PowerHalControllerTest, TestPowerHalRecoversFromFailureByRecreatingPowerHal) {
    int powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 0);

    ON_CALL(*mMockHal.get(), powerHint(Eq(PowerHint::LAUNCH), _))
            .WillByDefault([](PowerHint, int32_t) {
                return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
            });

    EXPECT_CALL(*mMockHal.get(), powerHint(_, _)).Times(Exactly(4));

    auto result = mHalController->setBoost(Boost::INTERACTION, 1000);
    ASSERT_TRUE(result.isOk());
    result = mHalController->setMode(Mode::LAUNCH, true);
    ASSERT_TRUE(result.isFailed());
    result = mHalController->setMode(Mode::VR, false);
    ASSERT_TRUE(result.isOk());
    result = mHalController->setMode(Mode::LOW_POWER, true);
    ASSERT_TRUE(result.isOk());

    // PowerHalConnector was called only twice: on first api call and after failed
    // call.
    powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 2);
    // PowerHalConnector was reset once after failed call.
    int powerHalResetCount = mHalConnector->getResetCount();
    EXPECT_EQ(powerHalResetCount, 1);
}

TEST_F(PowerHalControllerTest, TestPowerHalDoesNotTryToRecoverFromFailureOnUnsupportedCalls) {
    int powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 0);

    auto result = mHalController->setBoost(Boost::CAMERA_LAUNCH, 1000);
    ASSERT_TRUE(result.isUnsupported());
    result = mHalController->setMode(Mode::CAMERA_STREAMING_HIGH, true);
    ASSERT_TRUE(result.isUnsupported());

    // PowerHalConnector was called only once and never reset.
    powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 1);
    int powerHalResetCount = mHalConnector->getResetCount();
    EXPECT_EQ(powerHalResetCount, 0);
}

TEST_F(PowerHalControllerTest, TestMultiThreadConnectsOnlyOnce) {
    int powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 0);

    EXPECT_CALL(*mMockHal.get(), powerHint(_, _)).Times(Exactly(10));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() {
            auto result = mHalController->setBoost(Boost::INTERACTION, 1000);
            ASSERT_TRUE(result.isOk());
        }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    // PowerHalConnector was called only by the first thread to use the api and
    // never reset.
    powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 1);
    int powerHalResetCount = mHalConnector->getResetCount();
    EXPECT_EQ(powerHalResetCount, 0);
}

TEST_F(PowerHalControllerTest, TestMultiThreadWithFailureReconnectIsThreadSafe) {
    int powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_EQ(powerHalConnectCount, 0);

    ON_CALL(*mMockHal.get(), powerHint(Eq(PowerHint::LAUNCH), _))
            .WillByDefault([](PowerHint, int32_t) {
                return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
            });

    EXPECT_CALL(*mMockHal.get(), powerHint(_, _)).Times(Exactly(40));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() {
            auto result = mHalController->setBoost(Boost::INTERACTION, 1000);
            ASSERT_TRUE(result.isOk());
        }));
        threads.push_back(std::thread([&]() {
            auto result = mHalController->setMode(Mode::LAUNCH, true);
            ASSERT_TRUE(result.isFailed());
        }));
        threads.push_back(std::thread([&]() {
            auto result = mHalController->setMode(Mode::LOW_POWER, false);
            ASSERT_TRUE(result.isOk());
        }));
        threads.push_back(std::thread([&]() {
            auto result = mHalController->setMode(Mode::VR, true);
            ASSERT_TRUE(result.isOk());
        }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    // PowerHalConnector was called at least once by the first thread.
    // Reset and reconnect calls were made at most 10 times, once after each
    // failure.
    powerHalConnectCount = mHalConnector->getConnectCount();
    EXPECT_THAT(powerHalConnectCount, AllOf(Ge(1), Le(11)));
    int powerHalResetCount = mHalConnector->getResetCount();
    EXPECT_THAT(powerHalResetCount, Le(10));
}
