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

#include <CursorInputMapper.h>
#include <InputDevice.h>
#include <InputReaderBase.h>
#include <MapperHelpers.h>

namespace android {

static void addProperty(FuzzEventHub& eventHub, std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp) {
    // Pick a random property to set for the mapper to have set.
    fdp->PickValueInArray<std::function<void()>>(
            {[&]() -> void { eventHub.addProperty("cursor.mode", "pointer"); },
             [&]() -> void { eventHub.addProperty("cursor.mode", "navigation"); },
             [&]() -> void {
                 eventHub.addProperty("cursor.mode", fdp->ConsumeRandomLengthString(100).data());
             },
             [&]() -> void {
                 eventHub.addProperty("cursor.orientationAware",
                                      fdp->ConsumeRandomLengthString(100).data());
             }})();
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp =
            std::make_shared<ThreadSafeFuzzedDataProvider>(data, size);

    // Create mocked objects to support the fuzzed input mapper.
    std::shared_ptr<FuzzEventHub> eventHub = std::make_shared<FuzzEventHub>(fdp);
    FuzzInputReaderContext context(eventHub, fdp);
    InputDevice device = getFuzzedInputDevice(*fdp, &context);

    InputReaderConfiguration policyConfig;
    CursorInputMapper& mapper =
            getMapperForDevice<ThreadSafeFuzzedDataProvider, CursorInputMapper>(*fdp.get(), device,
                                                                                policyConfig);

    // Loop through mapper operations until randomness is exhausted.
    while (fdp->remaining_bytes() > 0) {
        fdp->PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    addProperty(*eventHub.get(), fdp);
                    configureAndResetDevice(*fdp, device);
                },
                [&]() -> void {
                    std::string dump;
                    mapper.dump(dump);
                },
                [&]() -> void { mapper.getSources(); },
                [&]() -> void {
                    std::list<NotifyArgs> unused =
                            mapper.reconfigure(fdp->ConsumeIntegral<nsecs_t>(), policyConfig,
                                               InputReaderConfiguration::Change(
                                                       fdp->ConsumeIntegral<int32_t>()));
                },
                [&]() -> void {
                    // Need to reconfigure with 0 or you risk a NPE.
                    std::list<NotifyArgs> unused =
                            mapper.reconfigure(fdp->ConsumeIntegral<nsecs_t>(), policyConfig,
                                               InputReaderConfiguration::Change(0));
                    InputDeviceInfo info;
                    mapper.populateDeviceInfo(info);
                },
                [&]() -> void {
                    // Need to reconfigure with 0 or you risk a NPE.
                    std::list<NotifyArgs> unused =
                            mapper.reconfigure(fdp->ConsumeIntegral<nsecs_t>(), policyConfig,
                                               InputReaderConfiguration::Change(0));
                    RawEvent rawEvent = getFuzzedRawEvent(*fdp);
                    unused += mapper.process(rawEvent);
                },
                [&]() -> void {
                    std::list<NotifyArgs> unused = mapper.reset(fdp->ConsumeIntegral<nsecs_t>());
                },
                [&]() -> void {
                    mapper.getScanCodeState(fdp->ConsumeIntegral<uint32_t>(),
                                            fdp->ConsumeIntegral<int32_t>());
                },
                [&]() -> void {
                    // Need to reconfigure with 0 or you risk a NPE.
                    std::list<NotifyArgs> unused =
                            mapper.reconfigure(fdp->ConsumeIntegral<nsecs_t>(), policyConfig,
                                               InputReaderConfiguration::Change(0));
                    mapper.getAssociatedDisplayId();
                },
        })();
    }

    return 0;
}

} // namespace android
