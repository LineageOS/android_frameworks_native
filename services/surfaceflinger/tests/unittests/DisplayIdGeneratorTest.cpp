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

#include <gtest/gtest.h>
#include <ui/DisplayId.h>

#include <algorithm>
#include <iterator>
#include <vector>

#include "DisplayIdGenerator.h"

namespace android {

template <typename Id>
void testGenerateId() {
    DisplayIdGenerator<Id> generator;

    std::vector<std::optional<Id>> ids;
    std::generate_n(std::back_inserter(ids), 10, [&] { return generator.generateId(); });

    // All IDs should be different.
    for (auto it = ids.begin(); it != ids.end(); ++it) {
        EXPECT_TRUE(*it);

        for (auto dup = it + 1; dup != ids.end(); ++dup) {
            EXPECT_NE(*it, *dup);
        }
    }
}

TEST(DisplayIdGeneratorTest, generateGpuVirtualDisplayId) {
    testGenerateId<GpuVirtualDisplayId>();
}

TEST(DisplayIdGeneratorTest, generateHalVirtualDisplayId) {
    testGenerateId<HalVirtualDisplayId>();
}

TEST(DisplayIdGeneratorTest, releaseId) {
    constexpr size_t kMaxIdsCount = 5;
    DisplayIdGenerator<GpuVirtualDisplayId> generator(kMaxIdsCount);

    const auto id = generator.generateId();
    EXPECT_TRUE(id);

    for (size_t i = 1; i < kMaxIdsCount; i++) {
        EXPECT_TRUE(generator.generateId());
    }

    EXPECT_FALSE(generator.generateId());

    generator.releaseId(*id);
    EXPECT_TRUE(generator.generateId());
}

TEST(DisplayIdGeneratorTest, maxIdsCount) {
    constexpr size_t kMaxIdsCount = 5;
    DisplayIdGenerator<GpuVirtualDisplayId> generator(kMaxIdsCount);

    for (size_t i = 0; i < kMaxIdsCount; i++) {
        EXPECT_TRUE(generator.generateId());
    }

    EXPECT_FALSE(generator.generateId());
}

} // namespace android
