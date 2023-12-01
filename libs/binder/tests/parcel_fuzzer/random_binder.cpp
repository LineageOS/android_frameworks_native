/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <fuzzbinder/random_binder.h>

#include <fuzzbinder/random_parcel.h>

#include <android-base/logging.h>
#include <binder/IInterface.h>
#include <binder/IServiceManager.h>

size_t kRandomInterfaceLength = 50;
namespace android {

RandomBinder::RandomBinder(const String16& descriptor, std::vector<uint8_t>&& bytes)
      : mDescriptor(descriptor),
        mBytes(std::move(bytes)),
        mProvider(mBytes.data(), mBytes.size()) {}

const String16& RandomBinder::getInterfaceDescriptor() const {
    return mDescriptor;
}

status_t RandomBinder::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                  uint32_t flags) {
    (void)code;
    (void)data;
    (void)reply;
    (void)flags; // note - for maximum coverage even ignore if oneway

    if (mProvider.ConsumeBool()) {
        return mProvider.ConsumeIntegral<status_t>();
    }

    if (reply == nullptr) return OK;

    // TODO: things we could do to increase state space
    // - also pull FDs and binders from 'data'
    //     (optionally combine these into random parcel 'options')
    // - also pull FDs and binders from random parcel 'options'
    RandomParcelOptions options;

    // random output
    std::vector<uint8_t> subData = mProvider.ConsumeBytes<uint8_t>(
            mProvider.ConsumeIntegralInRange<size_t>(0, mProvider.remaining_bytes()));
    fillRandomParcel(reply, FuzzedDataProvider(subData.data(), subData.size()), &options);

    return OK;
}

sp<IBinder> getRandomBinder(FuzzedDataProvider* provider) {
    auto makeFunc = provider->PickValueInArray<const std::function<sp<IBinder>()>>({
            [&]() {
                // descriptor is the length of a class name, e.g.
                // "some.package.Foo"
                std::string str =
                        provider->ConsumeRandomLengthString(kRandomInterfaceLength /*max length*/);

                // arbitrarily consume remaining data to create a binder that can return
                // random results - coverage guided fuzzer should ensure all of the remaining
                // data isn't always used
                std::vector<uint8_t> bytes = provider->ConsumeBytes<uint8_t>(
                        provider->ConsumeIntegralInRange<size_t>(0, provider->remaining_bytes()));

                return new RandomBinder(String16(str.c_str()), std::move(bytes));
            },
            []() {
                // this is the easiest remote binder to get ahold of, and it
                // should be able to handle anything thrown at it, and
                // essentially every process can talk to it, so it's a good
                // candidate for checking usage of an actual BpBinder
                return IInterface::asBinder(defaultServiceManager());
            },
            [&]() -> sp<IBinder> { return nullptr; },
    });
    return makeFunc();
}

} // namespace android
