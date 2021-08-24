/*
 * Copyright (C) 2021 The Android Open Source Project
 * Android BPF library - public API
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

#include <gtest/gtest.h>
#include "MultiStateCounter.h"

namespace android {
namespace battery {

typedef MultiStateCounter<double> DoubleMultiStateCounter;

template <>
bool DoubleMultiStateCounter::delta(const double& previousValue, const double& newValue,
                                    double* outValue) const {
    *outValue = newValue - previousValue;
    return *outValue >= 0;
}

template <>
void DoubleMultiStateCounter::add(double* value1, const double& value2, const uint64_t numerator,
                                  const uint64_t denominator) const {
    if (numerator != denominator) {
        // The caller ensures that denominator != 0
        *value1 += value2 * numerator / denominator;
    } else {
        *value1 += value2;
    }
}

template <>
std::string DoubleMultiStateCounter::valueToString(const double& v) const {
    return std::to_string(v);
}

class MultiStateCounterTest : public testing::Test {};

TEST_F(MultiStateCounterTest, constructor) {
    DoubleMultiStateCounter testCounter(3, 1, 0, 1000);
    testCounter.setState(1, 2000);
    testCounter.updateValue(3.14, 3000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(3.14, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));
}

TEST_F(MultiStateCounterTest, stateChange) {
    DoubleMultiStateCounter testCounter(3, 1, 0, 0);
    testCounter.setState(2, 1000);
    testCounter.updateValue(6.0, 3000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(2.0, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(4.0, testCounter.getCount(2));
}

TEST_F(MultiStateCounterTest, timeAdjustment_setState) {
    DoubleMultiStateCounter testCounter(3, 1, 0, 0);
    testCounter.setState(2, 2000);

    // Time moves back
    testCounter.setState(1, 1000);
    testCounter.updateValue(6.0, 3000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));

    // We were in state 1 from 0 to 2000, which was erased because the time moved back.
    // Then from 1000 to 3000, so we expect the count to be 6 * (2000/3000)
    EXPECT_DOUBLE_EQ(4.0, testCounter.getCount(1));

    // No time was effectively accumulated for state 2, because the timestamp moved back
    // while we were in state 2.
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));
}

TEST_F(MultiStateCounterTest, timeAdjustment_updateValue) {
    DoubleMultiStateCounter testCounter(1, 0, 0, 0);
    testCounter.updateValue(6.0, 2000);

    // Time moves back. The negative delta from 2000 to 1000 is ignored
    testCounter.updateValue(8.0, 1000);
    testCounter.updateValue(11.0, 3000);

    // The total accumulated count is:
    //  6.0          // For the period 0-2000
    //  +(11.0-8.0)  // For the period 1000-3000
    EXPECT_DOUBLE_EQ(9.0, testCounter.getCount(0));
}

} // namespace battery
} // namespace android
