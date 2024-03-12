/*
 * Copyright 2022 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>
#include <input/BlockingQueue.h>
#include <thread>

// Chosen to be a number large enough for variation in fuzzer runs, but not consume too much memory.
static constexpr size_t MAX_CAPACITY = 1024;

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    size_t capacity = fdp.ConsumeIntegralInRange<size_t>(1, MAX_CAPACITY);
    size_t filled = 0;
    BlockingQueue<int32_t> queue(capacity);

    while (fdp.remaining_bytes() > 0) {
        fdp.PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    size_t numPushes = fdp.ConsumeIntegralInRange<size_t>(0, capacity + 1);
                    for (size_t i = 0; i < numPushes; i++) {
                        queue.push(fdp.ConsumeIntegral<int32_t>());
                    }
                    filled = std::min(capacity, filled + numPushes);
                },
                [&]() -> void {
                    // Pops blocks if it is empty, so only pop up to num elements inserted.
                    size_t numPops = fdp.ConsumeIntegralInRange<size_t>(0, filled);
                    for (size_t i = 0; i < numPops; i++) {
                        queue.pop();
                    }
                    filled > numPops ? filled -= numPops : filled = 0;
                },
                [&]() -> void {
                    // Pops blocks if it is empty, so only pop up to num elements inserted.
                    size_t numPops = fdp.ConsumeIntegralInRange<size_t>(0, filled);
                    for (size_t i = 0; i < numPops; i++) {
                        // Provide a random timeout up to 1 second
                        queue.popWithTimeout(std::chrono::nanoseconds(
                                fdp.ConsumeIntegralInRange<int64_t>(0, 1E9)));
                    }
                    filled > numPops ? filled -= numPops : filled = 0;
                },
                [&]() -> void {
                    queue.clear();
                    filled = 0;
                },
                [&]() -> void {
                    int32_t eraseElement = fdp.ConsumeIntegral<int32_t>();
                    queue.erase_if([&](int32_t element) {
                        if (element == eraseElement) {
                            filled--;
                            return true;
                        }
                        return false;
                    });
                },
        })();
    }

    return 0;
}

} // namespace android
