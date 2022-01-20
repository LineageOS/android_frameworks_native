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

#include "gui/VsyncEventData.h"
#include <gui/DisplayEventReceiver.h>
#include <private/gui/ParcelUtils.h>
#include <utils/Log.h>
#include <utils/Looper.h>
#include <cstdint>

namespace android::gui {

status_t VsyncEventData::readFromParcel(const Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->readInt64, &id)
    SAFE_PARCEL(parcel->readInt64, &deadlineTimestamp);
    SAFE_PARCEL(parcel->readInt64, &frameInterval);

    uint64_t uintPreferredFrameTimelineIndex;
    SAFE_PARCEL(parcel->readUint64, &uintPreferredFrameTimelineIndex);
    preferredFrameTimelineIndex = static_cast<size_t>(uintPreferredFrameTimelineIndex);

    std::vector<FrameTimeline> timelines;
    SAFE_PARCEL(parcel->readParcelableVector, &timelines);
    std::copy_n(timelines.begin(), timelines.size(), frameTimelines.begin());

    return OK;
}
status_t VsyncEventData::writeToParcel(Parcel* parcel) const {
    SAFE_PARCEL(parcel->writeInt64, id)
    SAFE_PARCEL(parcel->writeInt64, deadlineTimestamp);
    SAFE_PARCEL(parcel->writeInt64, frameInterval);
    SAFE_PARCEL(parcel->writeUint64, preferredFrameTimelineIndex);
    SAFE_PARCEL(parcel->writeParcelableVector,
                std::vector(frameTimelines.begin(), frameTimelines.end()));

    return OK;
}
status_t VsyncEventData::FrameTimeline::readFromParcel(const Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->readInt64, &id)
    SAFE_PARCEL(parcel->readInt64, &deadlineTimestamp);
    SAFE_PARCEL(parcel->readInt64, &expectedPresentTime);

    return OK;
}
status_t VsyncEventData::FrameTimeline::writeToParcel(Parcel* parcel) const {
    SAFE_PARCEL(parcel->writeInt64, id);
    SAFE_PARCEL(parcel->writeInt64, deadlineTimestamp);
    SAFE_PARCEL(parcel->writeInt64, expectedPresentTime);

    return OK;
}

}; // namespace android::gui
