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

#include <MapperHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "FuzzedInputStream.h"
#include "InputCommonConverter.h"
#include "InputProcessor.h"

namespace android {

namespace {

constexpr int32_t MAX_RANDOM_DISPLAYS = 4;

}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::unique_ptr<FuzzInputListener> mFuzzListener = std::make_unique<FuzzInputListener>();
    std::unique_ptr<InputProcessorInterface> mClassifier =
            std::make_unique<InputProcessor>(*mFuzzListener);
    IdGenerator idGenerator(IdGenerator::Source::OTHER);

    while (fdp.remaining_bytes() > 0) {
        fdp.PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    // SendToNextStage_NotifyConfigurationChangedArgs
                    mClassifier->notifyConfigurationChanged(
                            {/*sequenceNum=*/fdp.ConsumeIntegral<int32_t>(),
                             /*eventTime=*/fdp.ConsumeIntegral<nsecs_t>()});
                },
                [&]() -> void {
                    // SendToNextStage_NotifyKeyArgs
                    const nsecs_t eventTime =
                            fdp.ConsumeIntegralInRange<nsecs_t>(0,
                                                                systemTime(SYSTEM_TIME_MONOTONIC));
                    const nsecs_t readTime = fdp.ConsumeIntegralInRange<
                            nsecs_t>(eventTime, std::numeric_limits<nsecs_t>::max());
                    mClassifier->notifyKey({/*sequenceNum=*/fdp.ConsumeIntegral<int32_t>(),
                                            eventTime, readTime,
                                            /*deviceId=*/fdp.ConsumeIntegral<int32_t>(),
                                            AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_DEFAULT,
                                            /*policyFlags=*/fdp.ConsumeIntegral<uint32_t>(),
                                            AKEY_EVENT_ACTION_DOWN,
                                            /*flags=*/fdp.ConsumeIntegral<int32_t>(), AKEYCODE_HOME,
                                            /*scanCode=*/fdp.ConsumeIntegral<int32_t>(), AMETA_NONE,
                                            /*downTime=*/fdp.ConsumeIntegral<nsecs_t>()});
                },
                [&]() -> void {
                    // SendToNextStage_NotifyMotionArgs
                    mClassifier->notifyMotion(
                            generateFuzzedMotionArgs(idGenerator, fdp, MAX_RANDOM_DISPLAYS));
                },
                [&]() -> void {
                    // SendToNextStage_NotifySwitchArgs
                    mClassifier->notifySwitch({/*sequenceNum=*/fdp.ConsumeIntegral<int32_t>(),
                                               /*eventTime=*/fdp.ConsumeIntegral<nsecs_t>(),
                                               /*policyFlags=*/fdp.ConsumeIntegral<uint32_t>(),
                                               /*switchValues=*/fdp.ConsumeIntegral<uint32_t>(),
                                               /*switchMask=*/fdp.ConsumeIntegral<uint32_t>()});
                },
                [&]() -> void {
                    // SendToNextStage_NotifyDeviceResetArgs
                    mClassifier->notifyDeviceReset({/*sequenceNum=*/fdp.ConsumeIntegral<int32_t>(),
                                                    /*eventTime=*/fdp.ConsumeIntegral<nsecs_t>(),
                                                    /*deviceId=*/fdp.ConsumeIntegral<int32_t>()});
                },
                [&]() -> void {
                    // InputClassifierConverterTest
                    const NotifyMotionArgs motionArgs =
                            generateFuzzedMotionArgs(idGenerator, fdp, MAX_RANDOM_DISPLAYS);
                    aidl::android::hardware::input::common::MotionEvent motionEvent =
                            notifyMotionArgsToHalMotionEvent(motionArgs);
                },
        })();
    }
    return 0;
}

} // namespace android
