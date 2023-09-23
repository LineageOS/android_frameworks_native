/******************************************************************************
 *
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <android-base/unique_fd.h>
#include <cputimeinstate.h>
#include <functional>

using namespace android::bpf;

static const uint16_t MAX_VEC_SIZE = 500;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    uint32_t uid = fdp.ConsumeIntegral<uint32_t>();
    uint64_t lastUpdate = fdp.ConsumeIntegral<uint64_t>();
    uint16_t aggregationKey = fdp.ConsumeIntegral<uint16_t>();
    pid_t pid = fdp.ConsumeIntegral<pid_t>();
    std::vector<uint16_t> aggregationKeys;
    uint16_t aggregationKeysSize = fdp.ConsumeIntegralInRange<size_t>(0, MAX_VEC_SIZE);
    for (uint16_t i = 0; i < aggregationKeysSize; i++) {
        aggregationKeys.push_back(fdp.ConsumeIntegral<uint16_t>());
    }

    // To randomize the API calls
     while (fdp.remaining_bytes() > 0) {
        auto func = fdp.PickValueInArray<const std::function<void()>>({
                [&]() { getUidCpuFreqTimes(uid); },
                [&]() { getUidsUpdatedCpuFreqTimes(&lastUpdate); },
                [&]() { getUidConcurrentTimes(uid);},
                [&]() { getUidsUpdatedConcurrentTimes(&lastUpdate); },
                [&]() { startAggregatingTaskCpuTimes(pid, aggregationKey); },
                [&]() { getAggregatedTaskCpuFreqTimes(pid, aggregationKeys); },
        });

        func();
    }

    return 0;
}
