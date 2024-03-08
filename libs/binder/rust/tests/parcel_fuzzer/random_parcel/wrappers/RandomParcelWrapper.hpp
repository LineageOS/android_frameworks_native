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
#include <cstdint>
#include <cstddef>

extern "C" {
    // This API is used by rust to fill random parcel.
    void createRandomParcel(void* aParcel, const uint8_t* data, size_t len);

    // This API is used by fuzzers to automatically fuzz aidl services
    void fuzzRustService(void** binders, size_t numBinders, const uint8_t* data, size_t len);
}
