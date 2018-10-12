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

#include <android/os/DumpstateOptions.h>

#include <binder/IBinder.h>
#include <binder/Parcel.h>

namespace android {
namespace os {

status_t DumpstateOptions::readFromParcel(const ::android::Parcel* parcel) {
    if (status_t err = parcel->readBool(&get_section_details)) {
        return err;
    }
    if (status_t err = parcel->readUtf8FromUtf16(&name)) {
        return err;
    }
    return android::OK;
}

status_t DumpstateOptions::writeToParcel(::android::Parcel* parcel) const {
    if (status_t err = parcel->writeBool(get_section_details)) {
        return err;
    }
    if (status_t err = parcel->writeUtf8AsUtf16(name)) {
        return err;
    }
    return android::OK;
}

}  // namespace os
}  // namespace android
