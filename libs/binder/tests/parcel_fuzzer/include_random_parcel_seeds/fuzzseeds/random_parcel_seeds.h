/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "../../../../file.h"

#include <android-base/logging.h>

#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <binder/RecordedTransaction.h>

#include <private/android_filesystem_config.h>

#include <vector>

using android::Parcel;
using std::vector;

namespace android {
namespace impl {
// computes the bytes so that if they are passed to FuzzedDataProvider and
// provider.ConsumeIntegralInRange<T>(min, max) is called, it will return val
template <typename T>
void writeReversedBuffer(std::vector<std::byte>& integralBuffer, T min, T max, T val);

// Calls writeInBuffer method with min and max numeric limits of type T. This method
// is reversal of ConsumeIntegral<T>() in FuzzedDataProvider
template <typename T>
void writeReversedBuffer(std::vector<std::byte>& integralBuffer, T val);
} // namespace impl
void generateSeedsFromRecording(binder::borrowed_fd fd,
                                const binder::debug::RecordedTransaction& transaction);
} // namespace android
