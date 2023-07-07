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

#include "InstrumentedInputReader.h"

namespace android {

InstrumentedInputReader::InstrumentedInputReader(std::shared_ptr<EventHubInterface> eventHub,
                                                 const sp<InputReaderPolicyInterface>& policy,
                                                 InputListenerInterface& listener)
      : InputReader(eventHub, policy, listener), mFakeContext(this) {}

void InstrumentedInputReader::pushNextDevice(std::shared_ptr<InputDevice> device) {
    mNextDevices.push(device);
}

std::shared_ptr<InputDevice> InstrumentedInputReader::newDevice(int32_t deviceId,
                                                                const std::string& name,
                                                                const std::string& location) {
    InputDeviceIdentifier identifier;
    identifier.name = name;
    identifier.location = location;
    int32_t generation = deviceId + 1;
    return std::make_shared<InputDevice>(&mFakeContext, deviceId, generation, identifier);
}

std::shared_ptr<InputDevice> InstrumentedInputReader::createDeviceLocked(
        nsecs_t when, int32_t eventHubId, const InputDeviceIdentifier& identifier) REQUIRES(mLock) {
    if (!mNextDevices.empty()) {
        std::shared_ptr<InputDevice> device(std::move(mNextDevices.front()));
        mNextDevices.pop();
        return device;
    }
    return InputReader::createDeviceLocked(when, eventHubId, identifier);
}

} // namespace android
