/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_FRAMEWORKS_BUFFERHUB_V1_0_ID_GENERATOR_H
#define ANDROID_FRAMEWORKS_BUFFERHUB_V1_0_ID_GENERATOR_H

#include <mutex>
#include <set>

#include <utils/Mutex.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

// A thread-safe incremental uint32_t id generator.
class BufferHubIdGenerator {
public:
    // 0 is considered invalid
    static constexpr uint32_t kInvalidId = 0UL;

    // Get the singleton instance of this class
    static BufferHubIdGenerator& getInstance();

    // Gets next available id. If next id is greater than std::numeric_limits<uint32_t>::max() (2 ^
    // 32 - 1), it will try to get an id start from 1 again.
    uint32_t getId();

    // Free a specific id. Return true on freed, false on not found.
    bool freeId(uint32_t id);

private:
    BufferHubIdGenerator() = default;
    ~BufferHubIdGenerator() = default;

    std::mutex mIdsInUseMutex;
    // Start from kInvalidID to avoid generating it.
    uint32_t mLastId = kInvalidId;
    std::set<uint32_t> mIdsInUse GUARDED_BY(mIdsInUseMutex);
};

} // namespace implementation
} // namespace V1_0
} // namespace bufferhub
} // namespace frameworks
} // namespace android

#endif // ANDROID_FRAMEWORKS_BUFFERHUB_V1_0_ID_GENERATOR_H
