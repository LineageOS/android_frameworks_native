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

#include <FuzzContainer.h>
#include <MultiTouchInputMapper.h>

namespace android {

const int32_t kMaxKeycodes = 100;

static void addProperty(FuzzContainer& fuzzer, std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp) {
    // Pick a random property to set for the mapper to have set.
    fdp->PickValueInArray<std::function<void()>>(
            {[&]() -> void { fuzzer.addProperty("touch.deviceType", "touchScreen"); },
             [&]() -> void {
                 fuzzer.addProperty("touch.deviceType", fdp->ConsumeRandomLengthString(8).data());
             },
             [&]() -> void {
                 fuzzer.addProperty("touch.size.scale", fdp->ConsumeRandomLengthString(8).data());
             },
             [&]() -> void {
                 fuzzer.addProperty("touch.size.bias", fdp->ConsumeRandomLengthString(8).data());
             },
             [&]() -> void {
                 fuzzer.addProperty("touch.size.isSummed",
                                    fdp->ConsumeRandomLengthString(8).data());
             },
             [&]() -> void {
                 fuzzer.addProperty("touch.size.calibration",
                                    fdp->ConsumeRandomLengthString(8).data());
             },
             [&]() -> void {
                 fuzzer.addProperty("touch.pressure.scale",
                                    fdp->ConsumeRandomLengthString(8).data());
             },
             [&]() -> void {
                 fuzzer.addProperty("touch.size.calibration",
                                    fdp->ConsumeBool() ? "diameter" : "area");
             },
             [&]() -> void {
                 fuzzer.addProperty("touch.pressure.calibration",
                                    fdp->ConsumeRandomLengthString(8).data());
             }})();
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp =
            std::make_shared<ThreadSafeFuzzedDataProvider>(data, size);
    FuzzContainer fuzzer(fdp);

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
                    mapper.populateDeviceInfo(info);
                },
                [&]() -> void { mapper.getSources(); },
                [&]() -> void {
                    std::list<NotifyArgs> unused =
                            mapper.reconfigure(fdp->ConsumeIntegral<nsecs_t>(), policyConfig,
                                               fdp->ConsumeIntegral<uint32_t>());
                },
                [&]() -> void {
                    std::list<NotifyArgs> unused = mapper.reset(fdp->ConsumeIntegral<nsecs_t>());
                },
                [&]() -> void {
                    int32_t type = fdp->ConsumeBool() ? fdp->PickValueInArray(kValidTypes)
                                                      : fdp->ConsumeIntegral<int32_t>();
                    int32_t code = fdp->ConsumeBool() ? fdp->PickValueInArray(kValidCodes)
                                                      : fdp->ConsumeIntegral<int32_t>();
                    RawEvent rawEvent{fdp->ConsumeIntegral<nsecs_t>(),
                                      fdp->ConsumeIntegral<nsecs_t>(),
                                      fdp->ConsumeIntegral<int32_t>(),
                                      type,
                                      code,
                                      fdp->ConsumeIntegral<int32_t>()};
                    std::list<NotifyArgs> unused = mapper.process(&rawEvent);
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
                    std::vector<int32_t> keyCodes;
                    int32_t numBytes = fdp->ConsumeIntegralInRange<int32_t>(0, kMaxKeycodes);
                    for (int32_t i = 0; i < numBytes; ++i) {
                        keyCodes.push_back(fdp->ConsumeIntegral<int32_t>());
                    }
                    mapper.markSupportedKeyCodes(fdp->ConsumeIntegral<uint32_t>(), keyCodes,
                                                 nullptr);
                },
                [&]() -> void {
                    std::list<NotifyArgs> unused =
                            mapper.cancelTouch(fdp->ConsumeIntegral<nsecs_t>(),
                                               fdp->ConsumeIntegral<nsecs_t>());
                },
                [&]() -> void {
                    std::list<NotifyArgs> unused =
                            mapper.timeoutExpired(fdp->ConsumeIntegral<nsecs_t>());
                },
                [&]() -> void {
                    StylusState state{fdp->ConsumeIntegral<nsecs_t>(),
                                      fdp->ConsumeFloatingPoint<float>(),
                                      fdp->ConsumeIntegral<uint32_t>(), getFuzzedToolType(*fdp)};
                    std::list<NotifyArgs> unused = mapper.updateExternalStylusState(state);
                },
                [&]() -> void { mapper.getAssociatedDisplayId(); },
        })();
    }

    return 0;
}

} // namespace android
