/******************************************************************************
 *
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 */
#include <fuzzer/FuzzedDataProvider.h>

#include <sensor/Sensor.h>
using namespace android;

const int MAX_STR_LEN = 32;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    struct sensor_t sensor_type;
    std::string name = fdp.ConsumeBytesAsString(MAX_STR_LEN);
    sensor_type.name = name.c_str();
    std::string vendor = fdp.ConsumeBytesAsString(MAX_STR_LEN);
    sensor_type.vendor = vendor.c_str();
    sensor_type.stringType = "";
    sensor_type.requiredPermission = "";
    sensor_type.version = fdp.ConsumeIntegral<int>();
    sensor_type.handle = fdp.ConsumeIntegral<int>();
    sensor_type.type = fdp.ConsumeIntegral<int>();
    sensor_type.maxRange = fdp.ConsumeFloatingPoint<float>();
    sensor_type.resolution = fdp.ConsumeFloatingPoint<float>();
    sensor_type.power = fdp.ConsumeFloatingPoint<float>();
    sensor_type.minDelay = fdp.ConsumeIntegral<int32_t>();
    sensor_type.fifoReservedEventCount = fdp.ConsumeIntegral<uint32_t>();
    sensor_type.fifoMaxEventCount = fdp.ConsumeIntegral<uint32_t>();
    int halVersion = fdp.ConsumeIntegral<int>();
    Sensor sensor1(&sensor_type, halVersion);
    uint8_t buffer[size];
    for (int i = 0; i < size; i++) buffer[i] = data[i];
    sensor1.flatten(buffer, size);
    std::vector<uint8_t> buffer1(sensor1.getFlattenedSize());
    auto ab = sensor1.unflatten(buffer1.data(), buffer1.size());
    return 0;
}

