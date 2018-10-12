/**
 * Copyright (c) 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_OS_DUMPSTATE_OPTIONS_H_
#define ANDROID_OS_DUMPSTATE_OPTIONS_H_

#include <binder/Parcelable.h>

namespace android {
namespace os {

struct DumpstateOptions : public android::Parcelable {
    // If true the caller can get callbacks with per-section progress details.
    bool get_section_details = false;

    // Name of the caller.
    std::string name;

    status_t writeToParcel(android::Parcel* parcel) const override;
    status_t readFromParcel(const android::Parcel* parcel) override;
};

}  // namespace os
}  // namespace android

#endif  // ANDROID_OS_DUMPSTATE_OPTIONS_H_
