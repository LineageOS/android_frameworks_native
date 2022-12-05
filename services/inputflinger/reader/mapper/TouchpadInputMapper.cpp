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

#include "../Macros.h"

#include "TouchpadInputMapper.h"

namespace android {

TouchpadInputMapper::TouchpadInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext) {}

uint32_t TouchpadInputMapper::getSources() const {
    return AINPUT_SOURCE_MOUSE | AINPUT_SOURCE_TOUCHPAD;
}

std::list<NotifyArgs> TouchpadInputMapper::process(const RawEvent* rawEvent) {
    ALOGD("TODO: process event type=0x%x code=0x%x value=0x%x", rawEvent->type, rawEvent->code,
          rawEvent->value);
    return {};
}

} // namespace android
