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

#include <InputReader.h>
#include <MapperHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <chrono>
#include <thread>

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<FuzzedDataProvider> fdp = std::make_shared<FuzzedDataProvider>(data, size);

    sp<FuzzInputListener> fuzzListener = new FuzzInputListener();
    sp<FuzzInputReaderPolicy> fuzzPolicy = new FuzzInputReaderPolicy(fdp);
    std::shared_ptr<FuzzEventHub> fuzzEventHub = std::make_shared<FuzzEventHub>(fdp);
    std::unique_ptr<InputReader> reader =
            std::make_unique<InputReader>(fuzzEventHub, fuzzPolicy, fuzzListener);

    fuzzEventHub->addEvents(fdp);
    reader->start();

    // Loop through mapper operations until randomness is exhausted.
    while (fdp->remaining_bytes() > 0) {
        fdp->PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    std::string dump;
                    reader->dump(dump);
                },
                [&]() -> void { reader->monitor(); },
                [&]() -> void { fuzzEventHub->addEvents(fdp); },
                [&]() -> void {
                    std::vector<InputDeviceInfo> inputDevices;
                    reader->getInputDevices(inputDevices);
                },
                [&]() -> void { reader->isInputDeviceEnabled(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void {
                    reader->getScanCodeState(fdp->ConsumeIntegral<int32_t>(),
                                             fdp->ConsumeIntegral<uint32_t>(),
                                             fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->getKeyCodeState(fdp->ConsumeIntegral<int32_t>(),
                                            fdp->ConsumeIntegral<uint32_t>(),
                                            fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->getSwitchState(fdp->ConsumeIntegral<int32_t>(),
                                           fdp->ConsumeIntegral<uint32_t>(),
                                           fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void { reader->toggleCapsLockState(fdp->ConsumeIntegral<int32_t>()); },
                [&]() -> void {
                    size_t count = fdp->ConsumeIntegralInRange<size_t>(1, 1024);
                    uint8_t* outFlags = new uint8_t[count];
                    reader->hasKeys(fdp->ConsumeIntegral<int32_t>(),
                                    fdp->ConsumeIntegral<uint32_t>(), count, nullptr, outFlags);
                    delete[] outFlags;
                },
                [&]() -> void {
                    reader->requestRefreshConfiguration(fdp->ConsumeIntegral<uint32_t>());
                },
                [&]() -> void {
                    // 260 is slightly higher than the maximum intended size of 256.
                    size_t count = fdp->ConsumeIntegralInRange<size_t>(0, 260);
                    nsecs_t pattern[count];

                    for (size_t i = 0; i < count; i++) pattern[i] = fdp->ConsumeIntegral<nsecs_t>();

                    reader->vibrate(fdp->ConsumeIntegral<int32_t>(), pattern, count,
                                    fdp->ConsumeIntegral<ssize_t>(),
                                    fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->cancelVibrate(fdp->ConsumeIntegral<int32_t>(),
                                          fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    reader->canDispatchToDisplay(fdp->ConsumeIntegral<int32_t>(),
                                                 fdp->ConsumeIntegral<int32_t>());
                },
        })();
    }

    reader->stop();
    return 0;
}

} // namespace android
