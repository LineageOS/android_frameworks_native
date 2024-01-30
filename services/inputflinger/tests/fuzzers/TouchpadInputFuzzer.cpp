/*
 * Copyright 2023 The Android Open Source Project
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

#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <linux/input-event-codes.h>

#include <InputDevice.h>
#include <InputReaderBase.h>
#include <MapperHelpers.h>
#include <TouchpadInputMapper.h>

namespace android {

namespace {

void setAxisInfo(ThreadSafeFuzzedDataProvider& fdp, FuzzEventHub& eventHub, int32_t id, int axis) {
    if (fdp.ConsumeBool()) {
        eventHub.setAbsoluteAxisInfo(id, axis,
                                     RawAbsoluteAxisInfo{
                                             .valid = fdp.ConsumeBool(),
                                             .minValue = fdp.ConsumeIntegral<int32_t>(),
                                             .maxValue = fdp.ConsumeIntegral<int32_t>(),
                                             .flat = fdp.ConsumeIntegral<int32_t>(),
                                             .fuzz = fdp.ConsumeIntegral<int32_t>(),
                                             .resolution = fdp.ConsumeIntegral<int32_t>(),
                                     });
    }
}

void setAxisInfos(ThreadSafeFuzzedDataProvider& fdp, FuzzEventHub& eventHub, int32_t id) {
    setAxisInfo(fdp, eventHub, id, ABS_MT_SLOT);
    setAxisInfo(fdp, eventHub, id, ABS_MT_POSITION_X);
    setAxisInfo(fdp, eventHub, id, ABS_MT_POSITION_Y);
    setAxisInfo(fdp, eventHub, id, ABS_MT_PRESSURE);
    setAxisInfo(fdp, eventHub, id, ABS_MT_ORIENTATION);
    setAxisInfo(fdp, eventHub, id, ABS_MT_TOUCH_MAJOR);
    setAxisInfo(fdp, eventHub, id, ABS_MT_TOUCH_MINOR);
    setAxisInfo(fdp, eventHub, id, ABS_MT_WIDTH_MAJOR);
    setAxisInfo(fdp, eventHub, id, ABS_MT_WIDTH_MINOR);
}

const std::vector<std::string> boolPropertiesToFuzz = {
        "gestureProp.Compute_Surface_Area_from_Pressure",
        "gestureProp.Drumroll_Suppression_Enable",
        "gestureProp.Fling_Buffer_Suppress_Zero_Length_Scrolls",
        "gestureProp.Stationary_Wiggle_Filter_Enabled",
};
const std::vector<std::string> doublePropertiesToFuzz = {
        "gestureProp.Fake_Timestamp_Delta",
        "gestureProp.Finger_Moving_Energy",
        "gestureProp.Finger_Moving_Hysteresis",
        "gestureProp.IIR_a1",
        "gestureProp.IIR_a2",
        "gestureProp.IIR_b0",
        "gestureProp.IIR_b1",
        "gestureProp.IIR_b2",
        "gestureProp.IIR_b3",
        "gestureProp.Max_Allowed_Pressure_Change_Per_Sec",
        "gestureProp.Max_Hysteresis_Pressure_Per_Sec",
        "gestureProp.Max_Stationary_Move_Speed",
        "gestureProp.Max_Stationary_Move_Speed_Hysteresis",
        "gestureProp.Max_Stationary_Move_Suppress_Distance",
        "gestureProp.Multiple_Palm_Width",
        "gestureProp.Palm_Edge_Zone_Width",
        "gestureProp.Palm_Eval_Timeout",
        "gestureProp.Palm_Pressure",
        "gestureProp.Palm_Width",
        "gestureProp.Pressure_Calibration_Offset",
        "gestureProp.Pressure_Calibration_Slope",
        "gestureProp.Tap_Exclusion_Border_Width",
        "gestureProp.Touchpad_Device_Output_Bias_on_X-Axis",
        "gestureProp.Touchpad_Device_Output_Bias_on_Y-Axis",
        "gestureProp.Two_Finger_Vertical_Close_Distance_Thresh",
};

void setDeviceSpecificConfig(ThreadSafeFuzzedDataProvider& fdp, FuzzEventHub& eventHub) {
    // There are a great many gesture properties offered by the Gestures library, all of which could
    // potentially be set in Input Device Configuration files. Maintaining a complete list is
    // impractical, so instead we only fuzz properties which are used in at least one IDC file, or
    // which are likely to be used in future (e.g. ones for controlling palm rejection).

    if (fdp.ConsumeBool()) {
        eventHub.addProperty("gestureProp.Touchpad_Stack_Version",
                             std::to_string(fdp.ConsumeIntegral<int>()));
    }

    for (auto& propertyName : boolPropertiesToFuzz) {
        if (fdp.ConsumeBool()) {
            eventHub.addProperty(propertyName, fdp.ConsumeBool() ? "1" : "0");
        }
    }

    for (auto& propertyName : doublePropertiesToFuzz) {
        if (fdp.ConsumeBool()) {
            eventHub.addProperty(propertyName, std::to_string(fdp.ConsumeFloatingPoint<double>()));
        }
    }

    if (fdp.ConsumeBool()) {
        eventHub.addProperty("gestureProp." + fdp.ConsumeRandomLengthString(),
                             std::to_string(fdp.ConsumeIntegral<int>()));
    }
}

void setTouchpadSettings(ThreadSafeFuzzedDataProvider& fdp, InputReaderConfiguration& config) {
    config.touchpadPointerSpeed = fdp.ConsumeIntegralInRange(-7, 7);
    config.touchpadNaturalScrollingEnabled = fdp.ConsumeBool();
    config.touchpadTapToClickEnabled = fdp.ConsumeBool();
    config.touchpadTapDraggingEnabled = fdp.ConsumeBool();
    config.touchpadRightClickZoneEnabled = fdp.ConsumeBool();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp =
            std::make_shared<ThreadSafeFuzzedDataProvider>(data, size);

    // Create mocked objects to support the fuzzed input mapper.
    std::shared_ptr<FuzzEventHub> eventHub = std::make_shared<FuzzEventHub>(fdp);
    FuzzInputReaderContext context(eventHub, fdp);
    InputDevice device = getFuzzedInputDevice(*fdp, &context);

    setAxisInfos(*fdp, *eventHub.get(), device.getId());
    setDeviceSpecificConfig(*fdp, *eventHub.get());

    InputReaderConfiguration policyConfig;
    // Some settings are fuzzed here, as well as in the main loop, to provide randomized data to the
    // TouchpadInputMapper constructor.
    setTouchpadSettings(*fdp, policyConfig);
    policyConfig.pointerCaptureRequest.enable = fdp->ConsumeBool();
    TouchpadInputMapper& mapper =
            getMapperForDevice<ThreadSafeFuzzedDataProvider, TouchpadInputMapper>(*fdp, device,
                                                                                  policyConfig);

    // Loop through mapper operations until randomness is exhausted.
    while (fdp->remaining_bytes() > 0) {
        fdp->PickValueInArray<std::function<void()>>({
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
                    setTouchpadSettings(*fdp, policyConfig);
                    policyConfig.pointerCaptureRequest.enable = fdp->ConsumeBool();
                    std::list<NotifyArgs> unused =
                            mapper.reconfigure(fdp->ConsumeIntegral<nsecs_t>(), policyConfig,
                                               InputReaderConfiguration::Change(
                                                       fdp->ConsumeIntegral<uint32_t>()));
                },
                [&]() -> void {
                    std::list<NotifyArgs> unused = mapper.reset(fdp->ConsumeIntegral<nsecs_t>());
                },
                [&]() -> void {
                    RawEvent event = getFuzzedRawEvent(*fdp);
                    std::list<NotifyArgs> unused = mapper.process(&event);
                },
        })();
    }

    return 0;
}

} // namespace android
