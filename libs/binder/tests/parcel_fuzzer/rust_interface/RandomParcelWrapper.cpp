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

#include <android-base/logging.h>
#include <android/binder_libbinder.h>
#include <android/binder_parcel.h>
#include <fuzzbinder/random_parcel.h>

extern "C" {

void createRandomParcel(void* aParcel, const uint8_t* data, size_t len) {
    CHECK_NE(aParcel, nullptr);
    AParcel* parcel = static_cast<AParcel*>(aParcel);
    FuzzedDataProvider provider(data, len);
    android::RandomParcelOptions options;

    android::Parcel* platformParcel = AParcel_viewPlatformParcel(parcel);
    fillRandomParcel(platformParcel, std::move(provider), &options);
}

} // extern "C"