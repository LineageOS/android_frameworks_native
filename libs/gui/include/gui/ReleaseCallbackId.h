/*
 * Copyright 2022 The Android Open Source Project
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

#include <binder/Parcel.h>
#include <binder/Parcelable.h>

#include <cstdint>

namespace android::gui {

class ReleaseCallbackId : public Parcelable {
public:
    static const ReleaseCallbackId INVALID_ID;

    uint64_t bufferId;
    uint64_t framenumber;
    ReleaseCallbackId() {}
    ReleaseCallbackId(uint64_t bufferId, uint64_t framenumber)
          : bufferId(bufferId), framenumber(framenumber) {}
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    bool operator==(const ReleaseCallbackId& rhs) const {
        return bufferId == rhs.bufferId && framenumber == rhs.framenumber;
    }
    bool operator!=(const ReleaseCallbackId& rhs) const { return !operator==(rhs); }
    std::string to_string() const {
        if (*this == INVALID_ID) return "INVALID_ID";

        return "bufferId:" + std::to_string(bufferId) +
                " framenumber:" + std::to_string(framenumber);
    }
};

} // namespace android::gui
