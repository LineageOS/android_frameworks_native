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
#include "InputCommonConverter.h"
#include "InputProcessor.h"

namespace android {

static constexpr int32_t MAX_AXES = 64;

// Used by two fuzz operations and a bit lengthy, so pulled out into a function.
NotifyMotionArgs generateFuzzedMotionArgs(FuzzedDataProvider &fdp) {
    // Create a basic motion event for testing
    PointerProperties properties;
    properties.id = 0;
    properties.toolType = getFuzzedToolType(fdp);
    PointerCoords coords;
    coords.clear();
    for (int32_t i = 0; i < fdp.ConsumeIntegralInRange<int32_t>(0, MAX_AXES); i++) {
        coords.setAxisValue(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeFloatingPoint<float>());
    }

    const nsecs_t downTime = 2;
    const nsecs_t readTime = downTime + fdp.ConsumeIntegralInRange<nsecs_t>(0, 1E8);
    NotifyMotionArgs motionArgs(/*sequenceNum=*/fdp.ConsumeIntegral<uint32_t>(),
                                /*eventTime=*/downTime, readTime,
                                /*deviceId=*/fdp.ConsumeIntegral<int32_t>(), AINPUT_SOURCE_ANY,
                                ADISPLAY_ID_DEFAULT,
                                /*policyFlags=*/fdp.ConsumeIntegral<uint32_t>(),
                                AMOTION_EVENT_ACTION_DOWN,
                                /*actionButton=*/fdp.ConsumeIntegral<int32_t>(),
                                /*flags=*/fdp.ConsumeIntegral<int32_t>(), AMETA_NONE,
                                /*buttonState=*/fdp.ConsumeIntegral<int32_t>(),
                                MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE,
                                /*pointerCount=*/1, &properties, &coords,
                                /*xPrecision=*/fdp.ConsumeFloatingPoint<float>(),
                                /*yPrecision=*/fdp.ConsumeFloatingPoint<float>(),
                                AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                AMOTION_EVENT_INVALID_CURSOR_POSITION, downTime,
                                /*videoFrames=*/{});
    return motionArgs;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::unique_ptr<FuzzInputListener> mFuzzListener = std::make_unique<FuzzInputListener>();
    std::unique_ptr<InputProcessorInterface> mClassifier =
            std::make_unique<InputProcessor>(*mFuzzListener);

    while (fdp.remaining_bytes() > 0) {
        fdp.PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    // SendToNextStage_NotifyConfigurationChangedArgs
                    NotifyConfigurationChangedArgs
                            args(/*sequenceNum=*/fdp.ConsumeIntegral<uint32_t>(),
                                 /*eventTime=*/fdp.ConsumeIntegral<nsecs_t>());
                    mClassifier->notifyConfigurationChanged(&args);
                },
                [&]() -> void {
                    // SendToNextStage_NotifyKeyArgs
                    const nsecs_t eventTime = fdp.ConsumeIntegral<nsecs_t>();
                    const nsecs_t readTime =
                            eventTime + fdp.ConsumeIntegralInRange<nsecs_t>(0, 1E8);
                    NotifyKeyArgs keyArgs(/*sequenceNum=*/fdp.ConsumeIntegral<uint32_t>(),
                                          eventTime, readTime,
                                          /*deviceId=*/fdp.ConsumeIntegral<int32_t>(),
                                          AINPUT_SOURCE_KEYBOARD, ADISPLAY_ID_DEFAULT,
                                          /*policyFlags=*/fdp.ConsumeIntegral<uint32_t>(),
                                          AKEY_EVENT_ACTION_DOWN,
                                          /*flags=*/fdp.ConsumeIntegral<int32_t>(), AKEYCODE_HOME,
                                          /*scanCode=*/fdp.ConsumeIntegral<int32_t>(), AMETA_NONE,
                                          /*downTime=*/fdp.ConsumeIntegral<nsecs_t>());

                    mClassifier->notifyKey(&keyArgs);
                },
                [&]() -> void {
                    // SendToNextStage_NotifyMotionArgs
                    NotifyMotionArgs motionArgs = generateFuzzedMotionArgs(fdp);
                    mClassifier->notifyMotion(&motionArgs);
                },
                [&]() -> void {
                    // SendToNextStage_NotifySwitchArgs
                    NotifySwitchArgs switchArgs(/*sequenceNum=*/fdp.ConsumeIntegral<uint32_t>(),
                                                /*eventTime=*/fdp.ConsumeIntegral<nsecs_t>(),
                                                /*policyFlags=*/fdp.ConsumeIntegral<uint32_t>(),
                                                /*switchValues=*/fdp.ConsumeIntegral<uint32_t>(),
                                                /*switchMask=*/fdp.ConsumeIntegral<uint32_t>());

                    mClassifier->notifySwitch(&switchArgs);
                },
                [&]() -> void {
                    // SendToNextStage_NotifyDeviceResetArgs
                    NotifyDeviceResetArgs resetArgs(
                            /*sequenceNum=*/fdp.ConsumeIntegral<uint32_t>(),
                            /*eventTime=*/fdp.ConsumeIntegral<nsecs_t>(),
                            /*deviceId=*/fdp.ConsumeIntegral<int32_t>());

                    mClassifier->notifyDeviceReset(&resetArgs);
                },
                [&]() -> void {
                    // InputClassifierConverterTest
                    const NotifyMotionArgs motionArgs = generateFuzzedMotionArgs(fdp);
                    aidl::android::hardware::input::common::MotionEvent motionEvent =
                            notifyMotionArgsToHalMotionEvent(motionArgs);
                },
        })();
    }
    return 0;
}

} // namespace android
