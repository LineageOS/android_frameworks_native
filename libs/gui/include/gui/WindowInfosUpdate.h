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

#pragma once

#include <binder/Parcelable.h>
#include <gui/DisplayInfo.h>
#include <gui/WindowInfo.h>

namespace android::gui {

struct WindowInfosUpdate : public Parcelable {
    WindowInfosUpdate() {}

    WindowInfosUpdate(std::vector<WindowInfo> windowInfos, std::vector<DisplayInfo> displayInfos,
                      int64_t vsyncId, int64_t timestamp)
          : windowInfos(std::move(windowInfos)),
            displayInfos(std::move(displayInfos)),
            vsyncId(vsyncId),
            timestamp(timestamp) {}

    std::vector<WindowInfo> windowInfos;
    std::vector<DisplayInfo> displayInfos;
    int64_t vsyncId;
    int64_t timestamp;

    status_t writeToParcel(android::Parcel*) const override;
    status_t readFromParcel(const android::Parcel*) override;
};

} // namespace android::gui
