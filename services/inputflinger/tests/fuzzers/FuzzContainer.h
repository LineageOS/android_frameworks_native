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

#pragma once

#include <InputDevice.h>
#include <InputMapper.h>
#include <InputReader.h>
#include <MapperHelpers.h>

namespace android {

class FuzzContainer {
    std::shared_ptr<FuzzEventHub> mFuzzEventHub;
    sp<FuzzInputReaderPolicy> mFuzzPolicy;
    FuzzInputListener mFuzzListener;
    std::unique_ptr<FuzzInputReaderContext> mFuzzContext;
    std::unique_ptr<InputDevice> mFuzzDevice;
    InputReaderConfiguration mPolicyConfig;
    std::shared_ptr<ThreadSafeFuzzedDataProvider> mFdp;

public:
    FuzzContainer(std::shared_ptr<ThreadSafeFuzzedDataProvider> fdp) : mFdp(fdp) {
        // Setup parameters.
        std::string deviceName = mFdp->ConsumeRandomLengthString(16);
        std::string deviceLocation = mFdp->ConsumeRandomLengthString(12);
        int32_t deviceID = mFdp->ConsumeIntegralInRange<int32_t>(0, 5);
        int32_t deviceGeneration = mFdp->ConsumeIntegralInRange<int32_t>(/*from*/ 0, /*to*/ 5);

        // Create mocked objects.
        mFuzzEventHub = std::make_shared<FuzzEventHub>(mFdp);
        mFuzzPolicy = sp<FuzzInputReaderPolicy>::make(mFdp);
        mFuzzContext = std::make_unique<FuzzInputReaderContext>(mFuzzEventHub, mFuzzPolicy,
                                                                mFuzzListener, mFdp);

        InputDeviceIdentifier identifier;
        identifier.name = deviceName;
        identifier.location = deviceLocation;
        mFuzzDevice = std::make_unique<InputDevice>(mFuzzContext.get(), deviceID, deviceGeneration,
                                                    identifier);
        mFuzzPolicy->getReaderConfiguration(&mPolicyConfig);
    }

    ~FuzzContainer() {}

    void configureDevice() {
        nsecs_t arbitraryTime = mFdp->ConsumeIntegral<nsecs_t>();
        std::list<NotifyArgs> out;
        out += mFuzzDevice->configure(arbitraryTime, mPolicyConfig, 0);
        out += mFuzzDevice->reset(arbitraryTime);
        for (const NotifyArgs& args : out) {
            mFuzzListener.notify(args);
        }
    }

    void addProperty(std::string key, std::string value) {
        mFuzzEventHub->addProperty(key, value);
        configureDevice();
    }

    InputReaderConfiguration& getPolicyConfig() { return mPolicyConfig; }

    template <class T, typename... Args>
    T& getMapper(Args... args) {
        T& mapper = mFuzzDevice->addMapper<T>(mFdp->ConsumeIntegral<int32_t>(), args...);
        configureDevice();
        return mapper;
    }
};

} // namespace android
