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

#include <binder/Binder.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "Scheduler/VsyncModulator.h"

namespace android::scheduler {

class TestableVsyncModulator : public VsyncModulator {
public:
    TestableVsyncModulator(const VsyncConfigSet& config, Now now) : VsyncModulator(config, now) {}

    void binderDied(const wp<IBinder>& token) { VsyncModulator::binderDied(token); }
};

class VsyncModulatorTest : public testing::Test {
    enum {
        SF_OFFSET_LATE,
        APP_OFFSET_LATE,
        SF_DURATION_LATE,
        APP_DURATION_LATE,
        SF_OFFSET_EARLY,
        APP_OFFSET_EARLY,
        SF_DURATION_EARLY,
        APP_DURATION_EARLY,
        SF_OFFSET_EARLY_GPU,
        APP_OFFSET_EARLY_GPU,
        SF_DURATION_EARLY_GPU,
        APP_DURATION_EARLY_GPU,
        HWC_MIN_WORK_DURATION,
    };

    static VsyncModulator::TimePoint Now() {
        static VsyncModulator::TimePoint now;
        return now += VsyncModulator::MIN_EARLY_TRANSACTION_TIME;
    }

protected:
    static constexpr auto MIN_EARLY_TRANSACTION_FRAMES =
            VsyncModulator::MIN_EARLY_TRANSACTION_FRAMES;

    using Schedule = scheduler::TransactionSchedule;
    using nanos = std::chrono::nanoseconds;
    const VsyncConfig kEarly{SF_OFFSET_EARLY, APP_OFFSET_EARLY, nanos(SF_DURATION_LATE),
                             nanos(APP_DURATION_LATE)};
    const VsyncConfig kEarlyGpu{SF_OFFSET_EARLY_GPU, APP_OFFSET_EARLY_GPU, nanos(SF_DURATION_EARLY),
                                nanos(APP_DURATION_EARLY)};
    const VsyncConfig kLate{SF_OFFSET_LATE, APP_OFFSET_LATE, nanos(SF_DURATION_EARLY_GPU),
                            nanos(APP_DURATION_EARLY_GPU)};

    const VsyncConfigSet mOffsets = {kEarly, kEarlyGpu, kLate, nanos(HWC_MIN_WORK_DURATION)};
    sp<TestableVsyncModulator> mVsyncModulator = sp<TestableVsyncModulator>::make(mOffsets, Now);

    void SetUp() override { EXPECT_EQ(kLate, mVsyncModulator->setVsyncConfigSet(mOffsets)); }
};

#define CHECK_COMMIT(result, configs)                          \
    EXPECT_EQ(result, mVsyncModulator->onTransactionCommit()); \
    EXPECT_EQ(configs, mVsyncModulator->getVsyncConfig());

#define CHECK_REFRESH(N, result, configs)                            \
    for (int i = 0; i < N; i++) {                                    \
        EXPECT_EQ(result, mVsyncModulator->onDisplayRefresh(false)); \
        EXPECT_EQ(configs, mVsyncModulator->getVsyncConfig());       \
    }

TEST_F(VsyncModulatorTest, Late) {
    EXPECT_FALSE(mVsyncModulator->setTransactionSchedule(Schedule::Late));

    CHECK_COMMIT(std::nullopt, kLate);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kLate);
}

TEST_F(VsyncModulatorTest, EarlyEnd) {
    const auto token = sp<BBinder>::make();
    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStart) {
    const auto token = sp<BBinder>::make();
    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyStart, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartWithMoreTransactions) {
    const auto token = sp<BBinder>::make();
    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyStart, token));

    CHECK_COMMIT(kEarly, kEarly);

    for (int i = 0; i < 5 * MIN_EARLY_TRANSACTION_FRAMES; i++) {
        EXPECT_FALSE(mVsyncModulator->setTransactionSchedule(Schedule::Late));
        CHECK_REFRESH(1, std::nullopt, kEarly);
    }

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartAfterEarlyEnd) {
    const auto token = sp<BBinder>::make();
    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyStart, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(1, kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartAfterEarlyEndWithMoreTransactions) {
    const auto token = sp<BBinder>::make();
    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyStart, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(1, kEarly, kEarly);

    for (int i = 0; i < 5 * MIN_EARLY_TRANSACTION_FRAMES; i++) {
        EXPECT_FALSE(mVsyncModulator->setTransactionSchedule(Schedule::Late));
        CHECK_REFRESH(1, std::nullopt, kEarly);
    }

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartDifferentClients) {
    const auto token1 = sp<BBinder>::make();
    const auto token2 = sp<BBinder>::make();
    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyStart, token1));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyStart, token2));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token1));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyEnd, token2));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartWithBinderDeath) {
    const auto token = sp<BBinder>::make();
    EXPECT_EQ(kEarly, mVsyncModulator->setTransactionSchedule(Schedule::EarlyStart, token));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    mVsyncModulator->binderDied(token);

    CHECK_COMMIT(std::nullopt, kLate);
}

} // namespace android::scheduler
