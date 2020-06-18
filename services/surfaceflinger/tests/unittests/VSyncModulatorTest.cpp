/*
 * Copyright 2020 The Android Open Source Project
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

#include "Scheduler/VSyncModulator.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing;

namespace android::scheduler {

class MockScheduler : public IPhaseOffsetControl {
public:
    void setPhaseOffset(ConnectionHandle handle, nsecs_t phaseOffset) {
        mPhaseOffset[handle] = phaseOffset;
    }

    nsecs_t getOffset(ConnectionHandle handle) { return mPhaseOffset[handle]; }

private:
    std::unordered_map<ConnectionHandle, nsecs_t> mPhaseOffset;
};

class VSyncModulatorTest : public testing::Test {
protected:
    static constexpr auto MIN_EARLY_FRAME_COUNT_TRANSACTION =
            VSyncModulator::MIN_EARLY_FRAME_COUNT_TRANSACTION;
    // Add a 1ms slack to avoid strange timer race conditions.
    static constexpr auto MARGIN_FOR_TX_APPLY = VSyncModulator::MARGIN_FOR_TX_APPLY + 1ms;

    // Used to enumerate the different offsets we have
    enum {
        SF_LATE,
        APP_LATE,
        SF_EARLY,
        APP_EARLY,
        SF_EARLY_GL,
        APP_EARLY_GL,
    };

    std::unique_ptr<VSyncModulator> mVSyncModulator;
    MockScheduler mMockScheduler;
    ConnectionHandle mAppConnection{1};
    ConnectionHandle mSfConnection{2};
    VSyncModulator::OffsetsConfig mOffsets = {{SF_EARLY, APP_EARLY},
                                              {SF_EARLY_GL, APP_EARLY_GL},
                                              {SF_LATE, APP_LATE}};

    void SetUp() override {
        mVSyncModulator = std::make_unique<VSyncModulator>(mMockScheduler, mAppConnection,
                                                           mSfConnection, mOffsets);
        mVSyncModulator->setPhaseOffsets(mOffsets);

        EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
    };

    void TearDown() override { mVSyncModulator.reset(); }
};

TEST_F(VSyncModulatorTest, Normal) {
    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::Normal);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
    }
}

TEST_F(VSyncModulatorTest, EarlyEnd) {
    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->onRefreshed(false);
    EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
}

TEST_F(VSyncModulatorTest, EarlyStart) {
    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyStart);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < 5 * MIN_EARLY_FRAME_COUNT_TRANSACTION; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->onRefreshed(false);
    EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
}

TEST_F(VSyncModulatorTest, EarlyStartWithEarly) {
    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyStart);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < 5 * MIN_EARLY_FRAME_COUNT_TRANSACTION; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::Early);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < 5 * MIN_EARLY_FRAME_COUNT_TRANSACTION; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->onRefreshed(false);
    EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
}

TEST_F(VSyncModulatorTest, EarlyStartWithMoreTransactions) {
    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyStart);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < 5 * MIN_EARLY_FRAME_COUNT_TRANSACTION; i++) {
        mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::Normal);
        std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->onRefreshed(false);
    EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
}

TEST_F(VSyncModulatorTest, EarlyStartAfterEarlyEnd) {
    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyStart);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < 5 * MIN_EARLY_FRAME_COUNT_TRANSACTION; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->onRefreshed(false);
    EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
}

TEST_F(VSyncModulatorTest, EarlyStartAfterEarlyEndWithMoreTransactions) {
    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyStart);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < 5 * MIN_EARLY_FRAME_COUNT_TRANSACTION; i++) {
        mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::Normal);
        std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->setTransactionStart(Scheduler::TransactionStart::EarlyEnd);
    std::this_thread::sleep_for(MARGIN_FOR_TX_APPLY);
    mVSyncModulator->onTransactionHandled();
    EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));

    for (int i = 0; i < MIN_EARLY_FRAME_COUNT_TRANSACTION - 1; i++) {
        mVSyncModulator->onRefreshed(false);
        EXPECT_EQ(APP_EARLY, mMockScheduler.getOffset(mAppConnection));
        EXPECT_EQ(SF_EARLY, mMockScheduler.getOffset(mSfConnection));
    }

    mVSyncModulator->onRefreshed(false);
    EXPECT_EQ(APP_LATE, mMockScheduler.getOffset(mAppConnection));
    EXPECT_EQ(SF_LATE, mMockScheduler.getOffset(mSfConnection));
}

} // namespace android::scheduler
