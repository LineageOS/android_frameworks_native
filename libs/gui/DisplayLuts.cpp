/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "include/gui/DisplayLuts.h"

#include <cutils/ashmem.h>
#include <gui/DisplayLuts.h>
#include <private/gui/ParcelUtils.h>
#include <sys/stat.h>

namespace android::gui {

size_t DisplayLuts::Entry::getElementsNeededPerChannel() const {
    if (size <= 0) return 0;
    if (dimension == 1) {
        return static_cast<size_t>(size);
    } else if (dimension == 3) {
        size_t sizeCubed;
        if (__builtin_mul_overflow(static_cast<size_t>(size), static_cast<size_t>(size),
                                   &sizeCubed) ||
            __builtin_mul_overflow(sizeCubed, static_cast<size_t>(size), &sizeCubed)) {
            return 0;
        }
        return sizeCubed;
    }
    return 0;
}

size_t DisplayLuts::getMaxEndOffset() const {
    size_t maxEndOffset = 0;
    for (size_t i = 0; i < offsets.size(); i++) {
        size_t elementsNeededPerChannel = lutProperties[i].getElementsNeededPerChannel();
        if (elementsNeededPerChannel == 0) {
            ALOGW("%s: Invalid Entry at index %zu!", __func__, i);
            return 0;
        }

        size_t totalElementsNeeded;
        if (lutProperties[i].dimension == 1) {
            totalElementsNeeded = elementsNeededPerChannel;
        } else {
            if (__builtin_mul_overflow(elementsNeededPerChannel, 3, &totalElementsNeeded)) {
                ALOGW("%s: Integer overflow in totalElementsNeeded calculation at index %zu!",
                      __func__, i);
                return 0;
            }
        }

        if (offsets[i] < 0) {
            ALOGW("%s: Negative offset %d at index %zu!", __func__, offsets[i], i);
            return 0;
        }

        size_t endOffset;
        if (__builtin_add_overflow(static_cast<size_t>(offsets[i]), totalElementsNeeded,
                                   &endOffset)) {
            ALOGW("%s: Integer overflow in endOffset calculation at index %zu!", __func__, i);
            return 0;
        }
        if (endOffset > maxEndOffset) {
            maxEndOffset = endOffset;
        }
    }
    return maxEndOffset;
}

status_t DisplayLuts::Entry::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->readInt32, &dimension);
    SAFE_PARCEL(parcel->readInt32, &size);
    SAFE_PARCEL(parcel->readInt32, &samplingKey);

    return OK;
}

status_t DisplayLuts::Entry::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->writeInt32, dimension);
    SAFE_PARCEL(parcel->writeInt32, size);
    SAFE_PARCEL(parcel->writeInt32, samplingKey);

    return OK;
}

bool DisplayLuts::isValid() const {
    if (!fd.ok()) {
        ALOGW("%s: fd is not OK!", __func__);
        return false;
    }
    if (offsets.empty() || lutProperties.empty()) {
        ALOGW("%s: offsets or lutProperties is empty!", __func__);
        return false;
    }
    if (offsets.size() != lutProperties.size()) {
        ALOGW("%s: offsets.size() %zu != lutProperties.size() %zu!", __func__, offsets.size(),
              lutProperties.size());
        return false;
    }

    int ashmemSize = ashmem_get_size_region(fd.get());
    if (ashmemSize <= 0 || static_cast<size_t>(ashmemSize) % sizeof(float) != 0) {
        ALOGW("%s: Invalid ashmemSize %d!", __func__, ashmemSize);
        return false;
    }
    size_t ashmemFloatCount = static_cast<size_t>(ashmemSize) / sizeof(float);

    size_t maxEndOffset = getMaxEndOffset();
    if (maxEndOffset == 0) {
        return false;
    }

    if (maxEndOffset > ashmemFloatCount) {
        ALOGW("%s: LUT maxEndOffset %zu exceeds ashmemFloatCount %zu!", __func__, maxEndOffset,
              ashmemFloatCount);
        return false;
    }

    return true;
}

status_t DisplayLuts::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->readUniqueFileDescriptor, &fd);
    SAFE_PARCEL(parcel->readInt32Vector, &offsets);
    int32_t numLutProperties;
    SAFE_PARCEL(parcel->readInt32, &numLutProperties);
    lutProperties.reserve(numLutProperties);
    for (int32_t i = 0; i < numLutProperties; i++) {
        lutProperties.push_back({});
        SAFE_PARCEL(lutProperties.back().readFromParcel, parcel);
    }
    if (!isValid()) {
        ALOGW("DisplayLuts failed validation after readFromParcel!");
        fd.reset();
        offsets.clear();
        lutProperties.clear();
        return BAD_VALUE;
    }
    return OK;
}

status_t DisplayLuts::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->writeUniqueFileDescriptor, fd);
    SAFE_PARCEL(parcel->writeInt32Vector, offsets);
    SAFE_PARCEL(parcel->writeInt32, static_cast<int32_t>(lutProperties.size()));
    for (auto& entry : lutProperties) {
        SAFE_PARCEL(entry.writeToParcel, parcel);
    }
    return OK;
}
} // namespace android::gui