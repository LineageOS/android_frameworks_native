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

#pragma once

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace android {

class RandomBinder : public BBinder {
public:
    RandomBinder(const String16& descriptor, std::vector<uint8_t>&& bytes);
    const String16& getInterfaceDescriptor() const override;
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override;

private:
    String16 mDescriptor;
    // note may not all be used
    std::vector<uint8_t> mBytes;
    FuzzedDataProvider mProvider;
};

// Get a random binder object for use in fuzzing.
//
// May return nullptr.
sp<IBinder> getRandomBinder(FuzzedDataProvider* provider);

} // namespace android
