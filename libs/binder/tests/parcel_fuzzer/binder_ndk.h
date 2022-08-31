/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <android/binder_auto_utils.h>
#include <vector>

#include <android/binder_libbinder.h>
#include <android/binder_parcel.h>
#include "parcel_fuzzer.h"

class NdkParcelAdapter {
public:
    NdkParcelAdapter() : mParcel(AParcel_create()) {}

    const AParcel* aParcel() const { return mParcel.get(); }
    AParcel* aParcel() { return mParcel.get(); }

    const android::Parcel* parcel() const { return AParcel_viewPlatformParcel(aParcel()); }
    android::Parcel* parcel() { return AParcel_viewPlatformParcel(aParcel()); }

    const uint8_t* data() const { return parcel()->data(); }
    size_t dataSize() const { return parcel()->dataSize(); }
    size_t dataAvail() const { return parcel()->dataAvail(); }
    size_t dataPosition() const { return parcel()->dataPosition(); }
    size_t dataCapacity() const { return parcel()->dataCapacity(); }
    android::status_t setData(const uint8_t* buffer, size_t len) {
        return parcel()->setData(buffer, len);
    }

    android::status_t appendFrom(const NdkParcelAdapter* parcel, int32_t start, int32_t len) {
        return AParcel_appendFrom(parcel->aParcel(), aParcel(), start, len);
    }

private:
    ndk::ScopedAParcel mParcel;
};

extern std::vector<ParcelRead<NdkParcelAdapter>> BINDER_NDK_PARCEL_READ_FUNCTIONS;
