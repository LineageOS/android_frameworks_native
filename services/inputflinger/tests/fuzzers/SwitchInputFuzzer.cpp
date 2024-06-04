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

#include <InputDevice.h>
#include <InputReaderBase.h>
#include <MapperHelpers.h>
#include <SwitchInputMapper.h>

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp =
            std::make_shared<ThreadSafeFuzzedDataProvider>(data, size);

    // Create mocked objects to support the fuzzed input mapper.
    std::shared_ptr<FuzzEventHub> eventHub = std::make_shared<FuzzEventHub>(fdp);
    FuzzInputReaderContext context(eventHub, fdp);
    InputDevice device = getFuzzedInputDevice(*fdp, &context);

    SwitchInputMapper& mapper =
            getMapperForDevice<ThreadSafeFuzzedDataProvider,
                               SwitchInputMapper>(*fdp.get(), device, InputReaderConfiguration{});

    // Loop through mapper operations until randomness is exhausted.
    while (fdp->remaining_bytes() > 0) {
        fdp->PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    std::string dump;
                    mapper.dump(dump);
                },
                [&]() -> void { mapper.getSources(); },
                [&]() -> void {
                    RawEvent rawEvent = getFuzzedRawEvent(*fdp);
                    std::list<NotifyArgs> unused = mapper.process(rawEvent);
                },
                [&]() -> void {
                    mapper.getSwitchState(fdp->ConsumeIntegral<uint32_t>(),
                                          fdp->ConsumeIntegral<int32_t>());
                },
        })();
    }

    return 0;
}

} // namespace android
