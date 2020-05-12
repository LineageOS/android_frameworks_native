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

#include <CursorInputMapper.h>
#include <FuzzContainer.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace android {

void addProperty(FuzzContainer& fuzzer, std::shared_ptr<FuzzedDataProvider> fdp) {
    // Pick a random property to set for the mapper to have set.
    fdp->PickValueInArray<std::function<void()>>(
            {[&]() -> void { fuzzer.addProperty(String8("cursor.mode"), String8("pointer")); },
             [&]() -> void { fuzzer.addProperty(String8("cursor.mode"), String8("navigation")); },
             [&]() -> void {
                 fuzzer.addProperty(String8("cursor.mode"),
                                    String8(fdp->ConsumeRandomLengthString(100).data()));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("cursor.orientationAware"),
                                    String8(fdp->ConsumeRandomLengthString(100).data()));
             }})();
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<FuzzedDataProvider> fdp = std::make_shared<FuzzedDataProvider>(data, size);
    FuzzContainer fuzzer = FuzzContainer(fdp);

    CursorInputMapper& mapper = fuzzer.getMapper<CursorInputMapper>();
    auto policyConfig = fuzzer.getPolicyConfig();

    // Loop through mapper operations until randomness is exhausted.
    while (fdp->remaining_bytes() > 0) {
        fdp->PickValueInArray<std::function<void()>>({
                [&]() -> void { addProperty(fuzzer, fdp); },
                [&]() -> void {
                    std::string dump;
                    mapper.dump(dump);
                },
                [&]() -> void { mapper.getSources(); },
                [&]() -> void {
                    mapper.configure(fdp->ConsumeIntegral<nsecs_t>(), &policyConfig,
                                     fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    // Need to reconfigure with 0 or you risk a NPE.
                    mapper.configure(fdp->ConsumeIntegral<nsecs_t>(), &policyConfig, 0);
                    InputDeviceInfo info;
                    mapper.populateDeviceInfo(&info);
                },
                [&]() -> void {
                    // Need to reconfigure with 0 or you risk a NPE.
                    mapper.configure(fdp->ConsumeIntegral<nsecs_t>(), &policyConfig, 0);
                    RawEvent rawEvent{fdp->ConsumeIntegral<nsecs_t>(),
                                      fdp->ConsumeIntegral<int32_t>(),
                                      fdp->ConsumeIntegral<int32_t>(),
                                      fdp->ConsumeIntegral<int32_t>(),
                                      fdp->ConsumeIntegral<int32_t>()};
                    mapper.process(&rawEvent);
                },
                [&]() -> void { mapper.reset(fdp->ConsumeIntegral<nsecs_t>()); },
                [&]() -> void {
                    mapper.getScanCodeState(fdp->ConsumeIntegral<uint32_t>(),
                                            fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    // Need to reconfigure with 0 or you risk a NPE.
                    mapper.configure(fdp->ConsumeIntegral<nsecs_t>(), &policyConfig, 0);
                    mapper.getAssociatedDisplayId();
                },
        })();
    }

    return 0;
}

} // namespace android
