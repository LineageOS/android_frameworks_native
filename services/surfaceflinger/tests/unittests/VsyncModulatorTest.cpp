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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "Scheduler/VsyncModulator.h"

namespace android::scheduler {

class VsyncModulatorTest : public testing::Test {
    enum Offsets {
        SF_LATE,
        APP_LATE,
        SF_EARLY,
        APP_EARLY,
        SF_EARLY_GPU,
        APP_EARLY_GPU,
    };

    static VsyncModulator::TimePoint Now() {
        static VsyncModulator::TimePoint now;
        return now += VsyncModulator::MIN_EARLY_TRANSACTION_TIME;
    }

protected:
    static constexpr auto MIN_EARLY_TRANSACTION_FRAMES =
            VsyncModulator::MIN_EARLY_TRANSACTION_FRAMES;

    using Schedule = scheduler::TransactionSchedule;

    const VsyncModulator::Offsets kEarly{SF_EARLY, APP_EARLY};
    const VsyncModulator::Offsets kEarlyGpu{SF_EARLY_GPU, APP_EARLY_GPU};
    const VsyncModulator::Offsets kLate{SF_LATE, APP_LATE};

    const VsyncModulator::OffsetsConfig mOffsets = {kEarly, kEarlyGpu, kLate};
    VsyncModulator mVsyncModulator{mOffsets, Now};

    void SetUp() override { EXPECT_EQ(kLate, mVsyncModulator.setPhaseOffsets(mOffsets)); }
};

#define CHECK_COMMIT(result, offsets)                         \
    EXPECT_EQ(result, mVsyncModulator.onTransactionCommit()); \
    EXPECT_EQ(offsets, mVsyncModulator.getOffsets());

#define CHECK_REFRESH(N, result, offsets)                           \
    for (int i = 0; i < N; i++) {                                   \
        EXPECT_EQ(result, mVsyncModulator.onDisplayRefresh(false)); \
        EXPECT_EQ(offsets, mVsyncModulator.getOffsets());           \
    }

TEST_F(VsyncModulatorTest, Late) {
    EXPECT_FALSE(mVsyncModulator.setTransactionSchedule(Schedule::Late));

    CHECK_COMMIT(std::nullopt, kLate);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kLate);
}

TEST_F(VsyncModulatorTest, EarlyEnd) {
    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStart) {
    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyStart));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartWithEarly) {
    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyStart));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::Early));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartWithMoreTransactions) {
    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyStart));

    CHECK_COMMIT(kEarly, kEarly);

    for (int i = 0; i < 5 * MIN_EARLY_TRANSACTION_FRAMES; i++) {
        EXPECT_FALSE(mVsyncModulator.setTransactionSchedule(Schedule::Late));
        CHECK_REFRESH(1, std::nullopt, kEarly);
    }

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartAfterEarlyEnd) {
    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyStart));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(1, kEarly, kEarly);
    CHECK_REFRESH(5 * MIN_EARLY_TRANSACTION_FRAMES, std::nullopt, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

TEST_F(VsyncModulatorTest, EarlyStartAfterEarlyEndWithMoreTransactions) {
    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyStart));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(1, kEarly, kEarly);

    for (int i = 0; i < 5 * MIN_EARLY_TRANSACTION_FRAMES; i++) {
        EXPECT_FALSE(mVsyncModulator.setTransactionSchedule(Schedule::Late));
        CHECK_REFRESH(1, std::nullopt, kEarly);
    }

    EXPECT_EQ(kEarly, mVsyncModulator.setTransactionSchedule(Schedule::EarlyEnd));

    CHECK_COMMIT(kEarly, kEarly);
    CHECK_REFRESH(MIN_EARLY_TRANSACTION_FRAMES - 1, kEarly, kEarly);
    CHECK_REFRESH(1, kLate, kLate);
}

} // namespace android::scheduler
