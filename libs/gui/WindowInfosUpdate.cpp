/*
 * Copyright 2023 The Android Open Source Project
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

#include <gui/WindowInfosUpdate.h>
#include <private/gui/ParcelUtils.h>

namespace android::gui {

status_t WindowInfosUpdate::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    uint32_t size;

    SAFE_PARCEL(parcel->readUint32, &size);
    windowInfos.reserve(size);
    for (uint32_t i = 0; i < size; i++) {
        windowInfos.push_back({});
        SAFE_PARCEL(windowInfos.back().readFromParcel, parcel);
    }

    SAFE_PARCEL(parcel->readUint32, &size);
    displayInfos.reserve(size);
    for (uint32_t i = 0; i < size; i++) {
        displayInfos.push_back({});
        SAFE_PARCEL(displayInfos.back().readFromParcel, parcel);
    }

    SAFE_PARCEL(parcel->readInt64, &vsyncId);
    SAFE_PARCEL(parcel->readInt64, &timestamp);

    return OK;
}

status_t WindowInfosUpdate::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->writeUint32, static_cast<uint32_t>(windowInfos.size()));
    for (auto& windowInfo : windowInfos) {
        SAFE_PARCEL(windowInfo.writeToParcel, parcel);
    }

    SAFE_PARCEL(parcel->writeUint32, static_cast<uint32_t>(displayInfos.size()));
    for (auto& displayInfo : displayInfos) {
        SAFE_PARCEL(displayInfo.writeToParcel, parcel);
    }

    SAFE_PARCEL(parcel->writeInt64, vsyncId);
    SAFE_PARCEL(parcel->writeInt64, timestamp);

    return OK;
}

} // namespace android::gui
