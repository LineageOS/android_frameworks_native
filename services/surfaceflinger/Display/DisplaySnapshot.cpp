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

#include <algorithm>
#include <functional>
#include <utility>

#include <ftl/algorithm.h>
#include <ftl/enum.h>
#include <ui/DebugUtils.h>

#include "DisplaySnapshot.h"

namespace android::display {

DisplaySnapshot::DisplaySnapshot(PhysicalDisplayId displayId,
                                 ui::DisplayConnectionType connectionType,
                                 DisplayModes&& displayModes, ui::ColorModes&& colorModes,
                                 std::optional<DeviceProductInfo>&& deviceProductInfo)
      : mDisplayId(displayId),
        mConnectionType(connectionType),
        mDisplayModes(std::move(displayModes)),
        mColorModes(std::move(colorModes)),
        mDeviceProductInfo(std::move(deviceProductInfo)) {}

std::optional<DisplayModeId> DisplaySnapshot::translateModeId(hal::HWConfigId hwcId) const {
    return ftl::find_if(mDisplayModes,
                        [hwcId](const DisplayModes::value_type& pair) {
                            return pair.second->getHwcId() == hwcId;
                        })
            .transform(&ftl::to_key<DisplayModes>);
}

ui::ColorModes DisplaySnapshot::filterColorModes(bool supportsWideColor) const {
    ui::ColorModes modes = mColorModes;

    // If the display is internal and the configuration claims it's not wide color capable, filter
    // out all wide color modes. The typical reason why this happens is that the hardware is not
    // good enough to support GPU composition of wide color, and thus the OEMs choose to disable
    // this capability.
    if (mConnectionType == ui::DisplayConnectionType::Internal && !supportsWideColor) {
        const auto it = std::remove_if(modes.begin(), modes.end(), ui::isWideColorMode);
        modes.erase(it, modes.end());
    }

    return modes;
}

void DisplaySnapshot::dump(utils::Dumper& dumper) const {
    using namespace std::string_view_literals;

    dumper.dump("connectionType"sv, ftl::enum_string(mConnectionType));

    dumper.dump("colorModes"sv);
    {
        utils::Dumper::Indent indent(dumper);
        for (const auto mode : mColorModes) {
            dumper.dump({}, decodeColorMode(mode));
        }
    }

    dumper.dump("deviceProductInfo"sv, mDeviceProductInfo);
}

} // namespace android::display
