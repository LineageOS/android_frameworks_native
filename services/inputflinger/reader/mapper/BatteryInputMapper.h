/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef _UI_INPUTREADER_BATTERY_INPUT_MAPPER_H
#define _UI_INPUTREADER_BATTERY_INPUT_MAPPER_H

#include "InputMapper.h"

namespace android {

class BatteryInputMapper : public InputMapper {
public:
    explicit BatteryInputMapper(InputDeviceContext& deviceContext);
    virtual ~BatteryInputMapper(){};

    uint32_t getSources() override;
    void populateDeviceInfo(InputDeviceInfo* deviceInfo) override;
    void process(const RawEvent* rawEvent) override;

    std::optional<int32_t> getBatteryCapacity() override;
    std::optional<int32_t> getBatteryStatus() override;

    void dump(std::string& dump) override;
};

} // namespace android

#endif // _UI_INPUTREADER_BATTERY_INPUT_MAPPER_H
