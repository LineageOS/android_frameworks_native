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

#pragma once

#include <ui/DisplayId.h>

#include <limits>
#include <optional>
#include <random>
#include <unordered_set>

#include <log/log.h>

namespace android {

template <typename T>
class DisplayIdGenerator {
public:
    virtual std::optional<T> nextId() = 0;
    virtual void markUnused(T id) = 0;

protected:
    ~DisplayIdGenerator() {}
};

template <typename T>
class RandomDisplayIdGenerator final : public DisplayIdGenerator<T> {
public:
    explicit RandomDisplayIdGenerator(size_t maxIdsCount = std::numeric_limits<size_t>::max())
          : mMaxIdsCount(maxIdsCount) {}

    std::optional<T> nextId() override {
        if (mUsedIds.size() >= mMaxIdsCount) {
            return std::nullopt;
        }

        constexpr int kMaxAttempts = 1000;

        for (int attempts = 0; attempts < kMaxAttempts; attempts++) {
            const auto baseId = mDistribution(mGenerator);
            const T id(baseId);
            if (mUsedIds.count(id) == 0) {
                mUsedIds.insert(id);
                return id;
            }
        }

        LOG_ALWAYS_FATAL("Couldn't generate ID after %d attempts", kMaxAttempts);
    }

    void markUnused(T id) override { mUsedIds.erase(id); }

private:
    const size_t mMaxIdsCount;

    std::unordered_set<T> mUsedIds;
    std::default_random_engine mGenerator{std::random_device()()};
    std::uniform_int_distribution<typename T::BaseId> mDistribution;
};

} // namespace android