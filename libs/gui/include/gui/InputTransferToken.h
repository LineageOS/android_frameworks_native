/*
 * Copyright (C) 2024 The Android Open Source Project
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
#include <binder/Parcel.h>
#include <private/gui/ParcelUtils.h>
#include <utils/Errors.h>

namespace android {
struct InputTransferToken : public RefBase, Parcelable {
public:
    InputTransferToken() { mToken = new BBinder(); }

    InputTransferToken(const sp<IBinder>& token) { mToken = token; }

    status_t writeToParcel(Parcel* parcel) const override {
        SAFE_PARCEL(parcel->writeStrongBinder, mToken);
        return NO_ERROR;
    }

    status_t readFromParcel(const Parcel* parcel) {
        SAFE_PARCEL(parcel->readStrongBinder, &mToken);
        return NO_ERROR;
    };

    sp<IBinder> mToken;
};

static inline bool operator==(const sp<InputTransferToken>& token1,
                              const sp<InputTransferToken>& token2) {
    if (token1.get() == token2.get()) {
        return true;
    }
    return token1->mToken == token2->mToken;
}

} // namespace android