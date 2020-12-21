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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

#include <gtest/gtest.h>

#include <vector>

#include <ui/DisplayId.h>
#include "DisplayIdGenerator.h"

namespace android {

template <typename T>
void testNextId(DisplayIdGenerator<T>& generator) {
    constexpr int kNumIds = 5;
    std::vector<T> ids;
    for (int i = 0; i < kNumIds; i++) {
        const auto id = generator.nextId();
        ASSERT_TRUE(id);
        ids.push_back(*id);
    }

    // All IDs should be different.
    for (size_t i = 0; i < kNumIds; i++) {
        for (size_t j = i + 1; j < kNumIds; j++) {
            EXPECT_NE(ids[i], ids[j]);
        }
    }
}

TEST(DisplayIdGeneratorTest, nextIdGpuVirtual) {
    RandomDisplayIdGenerator<GpuVirtualDisplayId> generator;
    testNextId(generator);
}

TEST(DisplayIdGeneratorTest, nextIdHalVirtual) {
    RandomDisplayIdGenerator<HalVirtualDisplayId> generator;
    testNextId(generator);
}

TEST(DisplayIdGeneratorTest, markUnused) {
    constexpr size_t kMaxIdsCount = 5;
    RandomDisplayIdGenerator<GpuVirtualDisplayId> generator(kMaxIdsCount);

    const auto id = generator.nextId();
    EXPECT_TRUE(id);

    for (int i = 1; i < kMaxIdsCount; i++) {
        EXPECT_TRUE(generator.nextId());
    }

    EXPECT_FALSE(generator.nextId());

    generator.markUnused(*id);
    EXPECT_TRUE(generator.nextId());
}

TEST(DisplayIdGeneratorTest, maxIdsCount) {
    constexpr size_t kMaxIdsCount = 5;
    RandomDisplayIdGenerator<GpuVirtualDisplayId> generator(kMaxIdsCount);

    for (int i = 0; i < kMaxIdsCount; i++) {
        EXPECT_TRUE(generator.nextId());
    }

    EXPECT_FALSE(generator.nextId());
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"