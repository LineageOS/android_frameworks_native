/*
 * Copyright (C) 2011 The Android Open Source Project
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

#define LOG_TAG "InputApplication"

#include <input/InputApplication.h>

#include <android/log.h>

namespace android {

status_t InputApplicationInfo::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    token = parcel->readStrongBinder();
    dispatchingTimeout = decltype(dispatchingTimeout)(parcel->readInt64());
    status_t status = parcel->readUtf8FromUtf16(&name);

    return status;
}

status_t InputApplicationInfo::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    status_t status = parcel->writeStrongBinder(token)
            ?: parcel->writeInt64(dispatchingTimeout.count())
            ?: parcel->writeUtf8AsUtf16(name) ;

    return status;
}

// --- InputApplicationHandle ---

InputApplicationHandle::InputApplicationHandle() {}

InputApplicationHandle::~InputApplicationHandle() {}

} // namespace android
