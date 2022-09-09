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

#include <functional>
#include <utility>

#include <ftl/algorithm.h>
#include <ftl/enum.h>

#include "DisplaySnapshot.h"

namespace android::display {

DisplaySnapshot::DisplaySnapshot(PhysicalDisplayId displayId,
                                 ui::DisplayConnectionType connectionType,
                                 DisplayModes&& displayModes,
                                 std::optional<DeviceProductInfo>&& deviceProductInfo)
      : mDisplayId(displayId),
        mConnectionType(connectionType),
        mDisplayModes(std::move(displayModes)),
        mDeviceProductInfo(std::move(deviceProductInfo)) {}

std::optional<DisplayModeId> DisplaySnapshot::translateModeId(hal::HWConfigId hwcId) const {
    return ftl::find_if(mDisplayModes,
                        [hwcId](const DisplayModes::value_type& pair) {
                            return pair.second->getHwcId() == hwcId;
                        })
            .transform(&ftl::to_key<DisplayModes>);
}

void DisplaySnapshot::dump(std::string& out) const {
    using namespace std::string_literals;

    out += "   connectionType="s;
    out += ftl::enum_string(mConnectionType);

    out += "\n   deviceProductInfo="s;
    if (mDeviceProductInfo) {
        mDeviceProductInfo->dump(out);
    } else {
        out += "{}"s;
    }
}

} // namespace android::display
