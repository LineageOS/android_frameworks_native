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

#pragma once

#include <InputDevice.h>
#include <InputMapper.h>
#include <InputReader.h>
#include <MapperHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace android {

class FuzzContainer {
    int32_t meventID;
    std::shared_ptr<FuzzEventHub> mFuzzEventHub;
    sp<FuzzInputReaderPolicy> mFuzzPolicy;
    sp<FuzzInputListener> mFuzzListener;
    std::unique_ptr<FuzzInputReaderContext> mFuzzContext;
    std::unique_ptr<InputDevice> mFuzzDevice;
    InputReaderConfiguration mPolicyConfig;
    std::shared_ptr<FuzzedDataProvider> fdp;

public:
    FuzzContainer(std::shared_ptr<FuzzedDataProvider> fdp) : fdp(fdp) {
        // Setup parameters.
        std::string deviceName = fdp->ConsumeRandomLengthString(16);
        std::string deviceLocation = fdp->ConsumeRandomLengthString(12);
        int32_t deviceID = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
        int32_t deviceGeneration = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
        meventID = fdp->ConsumeIntegral<int32_t>();

        // Create mocked objects.
        mFuzzEventHub = std::make_shared<FuzzEventHub>(fdp);
        mFuzzPolicy = new FuzzInputReaderPolicy(fdp);
        mFuzzListener = new FuzzInputListener();
        mFuzzContext = std::make_unique<FuzzInputReaderContext>(mFuzzEventHub, mFuzzPolicy,
                                                                mFuzzListener, fdp);

        InputDeviceIdentifier identifier;
        identifier.name = deviceName;
        identifier.location = deviceLocation;
        mFuzzDevice = std::make_unique<InputDevice>(mFuzzContext.get(), deviceID, deviceGeneration,
                                                    identifier);
        mFuzzPolicy->getReaderConfiguration(&mPolicyConfig);
    }

    ~FuzzContainer() {}

    void configureDevice() {
        nsecs_t arbitraryTime = fdp->ConsumeIntegral<nsecs_t>();
        mFuzzDevice->configure(arbitraryTime, &mPolicyConfig, 0);
        mFuzzDevice->reset(arbitraryTime);
    }

    void addProperty(const String8& key, const String8& value) {
        mFuzzEventHub->addProperty(key, value);
        configureDevice();
    }

    InputReaderConfiguration& getPolicyConfig() { return mPolicyConfig; }

    template <class T, typename... Args>
    T& getMapper(Args... args) {
        T& mapper = mFuzzDevice->addMapper<T>(fdp->ConsumeIntegral<int32_t>(), args...);
        configureDevice();
        return mapper;
    }
};

} // namespace android
