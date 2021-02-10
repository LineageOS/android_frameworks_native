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

#include <FuzzContainer.h>
#include <MultiTouchInputMapper.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace android {

void addProperty(FuzzContainer& fuzzer, std::shared_ptr<FuzzedDataProvider> fdp) {
    // Pick a random property to set for the mapper to have set.
    fdp->PickValueInArray<std::function<void()>>(
            {[&]() -> void {
                 fuzzer.addProperty(String8("touch.deviceType"), String8("touchScreen"));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.deviceType"),
                                    String8(fdp->ConsumeRandomLengthString(8).data()));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.size.scale"),
                                    String8(fdp->ConsumeRandomLengthString(8).data()));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.size.bias"),
                                    String8(fdp->ConsumeRandomLengthString(8).data()));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.size.isSummed"),
                                    String8(fdp->ConsumeRandomLengthString(8).data()));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.size.calibration"),
                                    String8(fdp->ConsumeRandomLengthString(8).data()));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.pressure.scale"),
                                    String8(fdp->ConsumeRandomLengthString(8).data()));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.size.calibration"),
                                    fdp->ConsumeBool() ? String8("diameter") : String8("area"));
             },
             [&]() -> void {
                 fuzzer.addProperty(String8("touch.pressure.calibration"),
                                    String8(fdp->ConsumeRandomLengthString(8).data()));
             }})();
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<FuzzedDataProvider> fdp = std::make_shared<FuzzedDataProvider>(data, size);
    FuzzContainer fuzzer = FuzzContainer(fdp);

    MultiTouchInputMapper& mapper = fuzzer.getMapper<MultiTouchInputMapper>();
    auto policyConfig = fuzzer.getPolicyConfig();

    // Loop through mapper operations until randomness is exhausted.
    while (fdp->remaining_bytes() > 0) {
        fdp->PickValueInArray<std::function<void()>>({
                [&]() -> void { addProperty(fuzzer, fdp); },
                [&]() -> void {
                    std::string dump;
                    mapper.dump(dump);
                },
                [&]() -> void {
                    InputDeviceInfo info;
                    mapper.populateDeviceInfo(&info);
                },
                [&]() -> void { mapper.getSources(); },
                [&]() -> void {
                    mapper.configure(fdp->ConsumeIntegral<nsecs_t>(), &policyConfig,
                                     fdp->ConsumeIntegral<uint32_t>());
                },
                [&]() -> void { mapper.reset(fdp->ConsumeIntegral<nsecs_t>()); },
                [&]() -> void {
                    RawEvent rawEvent{fdp->ConsumeIntegral<nsecs_t>(),
                                      fdp->ConsumeIntegral<int32_t>(),
                                      fdp->ConsumeIntegral<int32_t>(),
                                      fdp->ConsumeIntegral<int32_t>(),
                                      fdp->ConsumeIntegral<int32_t>()};
                    mapper.process(&rawEvent);
                },
                [&]() -> void {
                    mapper.getKeyCodeState(fdp->ConsumeIntegral<uint32_t>(),
                                           fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    mapper.getScanCodeState(fdp->ConsumeIntegral<uint32_t>(),
                                            fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    mapper.markSupportedKeyCodes(fdp->ConsumeIntegral<uint32_t>(),
                                                 fdp->ConsumeIntegral<size_t>(), nullptr, nullptr);
                },
                [&]() -> void { mapper.cancelTouch(fdp->ConsumeIntegral<nsecs_t>()); },
                [&]() -> void { mapper.timeoutExpired(fdp->ConsumeIntegral<nsecs_t>()); },
                [&]() -> void {
                    StylusState state{fdp->ConsumeIntegral<nsecs_t>(),
                                      fdp->ConsumeFloatingPoint<float>(),
                                      fdp->ConsumeIntegral<uint32_t>(),
                                      fdp->ConsumeIntegral<int32_t>()};
                    mapper.updateExternalStylusState(state);
                },
                [&]() -> void { mapper.getAssociatedDisplayId(); },
        })();
    }

    return 0;
}

} // namespace android
