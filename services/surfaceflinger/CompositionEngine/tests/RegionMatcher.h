/*
 * Copyright 2019 The Android Open Source Project
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

#pragma once

#include <gmock/gmock.h>

namespace {

using Region = android::Region;

struct RegionMatcher : public testing::MatcherInterface<const Region&> {
    const Region expected;

    explicit RegionMatcher(const Region& expectedValue) : expected(expectedValue) {}

    bool MatchAndExplain(const Region& actual, testing::MatchResultListener*) const override {
        return expected.hasSameRects(actual);
    }

    void DescribeTo(::std::ostream* os) const override { PrintTo(expected, os); }
};

testing::Matcher<const Region&> RegionEq(const Region& expected) {
    return MakeMatcher(new RegionMatcher(expected));
}

} // namespace
